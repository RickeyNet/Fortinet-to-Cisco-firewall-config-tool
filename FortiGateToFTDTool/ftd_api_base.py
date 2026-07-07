#!/usr/bin/env python3
"""
FTD FDM API Base Client
========================
Shared foundation for FTDAPIClient (importer) and FTDBulkDelete (cleanup).

Centralizes authentication, endpoint validation, and virtual-router
discovery so both tools stay in sync.
"""

import requests
import threading
import time
import urllib3
from requests.structures import CaseInsensitiveDict
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from flair import flair

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Endpoints probed by validate_endpoints()
_FDM_ENDPOINTS = [
    ("/devices/default/interfaces", "Physical Interfaces"),
    ("/devices/default/etherchannelinterfaces", "EtherChannels"),
    ("/devices/default/bridgegroupinterfaces", "Bridge Groups"),
    ("/object/securityzones", "Security Zones"),
    ("/object/networks", "Address Objects"),
    ("/object/networkgroups", "Address Groups"),
    ("/object/tcpports", "TCP Port Objects"),
    ("/object/udpports", "UDP Port Objects"),
    ("/object/portgroups", "Port Groups"),
    ("/devices/default/routing/virtualrouters", "Virtual Routers"),
    ("/policy/accesspolicies/default/accessrules", "Access Rules"),
]


class FTDBaseClient:
    """Shared base for FTD FDM API clients.

    Provides:
    - Session and credential management
    - ``authenticate()``
    - ``validate_endpoints()``
    - ``get_default_virtual_router_id()``
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        verify_ssl: bool = False,
        debug: bool = False,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.debug = debug

        self.base_url = f"https://{host}/api/fdm/latest"

        self.session = requests.Session()
        self.session.verify = verify_ssl
        # Auto-refresh on 401 for every request made through this session.
        self.session.hooks["response"].append(self._auto_refresh_hook)

        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.appliance_model: str = "generic"

        # Guards concurrent token-refresh attempts across worker threads.
        self._auth_lock = threading.Lock()
        # Epoch time of the last successful token refresh so threads that
        # wake up after another thread already refreshed don't refresh again.
        self._last_refresh_time: float = 0.0

    # ------------------------------------------------------------------
    # 401 auto-retry hook
    # ------------------------------------------------------------------
    def _auto_refresh_hook(self, response: Any, *args: Any, **kwargs: Any) -> Any:
        """Session hook: on 401, refresh the token once and retry the request.

        Skips the auth endpoint itself (refreshing during refresh would loop)
        and any request already retried (marked via the ``_ftd_retried`` attr).
        """
        if response.status_code != 401:
            return response
        if getattr(response.request, "_ftd_retried", False):
            return response
        if response.request.url and response.request.url.endswith("/fdm/token"):
            return response

        if not self.refresh_access_token():
            return response

        new_req = response.request.copy()
        new_req.headers["Authorization"] = self.session.headers.get("Authorization", "")
        new_req._ftd_retried = True
        # Reuse the original send settings (verify, cert, proxies, timeout).
        send_kwargs: Dict[str, Any] = {
            "verify": kwargs.get("verify", self.session.verify),
            "cert": kwargs.get("cert", self.session.cert),
            "proxies": kwargs.get("proxies"),
            "timeout": kwargs.get("timeout"),
            "allow_redirects": kwargs.get("allow_redirects", True),
            "stream": kwargs.get("stream", False),
        }
        return self.session.send(new_req, **send_kwargs)

    def _set_auth_headers(self) -> None:
        """Atomically install the bearer token on the session headers.

        Builds a complete new headers mapping and REBINDS it in a single
        assignment instead of mutating the existing dict in place.  Worker
        threads may be iterating ``session.headers`` while preparing
        requests, and an in-place ``.update()`` could raise
        "dictionary changed size during iteration".
        """
        new_headers = CaseInsensitiveDict(self.session.headers)
        new_headers["Authorization"] = f"Bearer {self.access_token}"
        new_headers["Content-Type"] = "application/json"
        new_headers["Accept"] = "application/json"
        self.session.headers = new_headers  # type: ignore[assignment]

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    def authenticate(self) -> bool:
        """Authenticate to the FTD FDM API and obtain access tokens.

        Uses OAuth 2.0 password grant.  On success the session headers are
        updated so all subsequent requests carry the bearer token.

        Returns:
            True if authentication successful, False otherwise.
        """
        print(f"\n{'='*60}")
        print(f"Authenticating to FTD at {self.host}")
        print(f"{'='*60}")

        auth_url = f"{self.base_url}/fdm/token"

        payload = {
            "grant_type": "password",
            "username": self.username,
            "password": self.password,
        }

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        try:
            response = self.session.post(
                auth_url, json=payload, headers=headers, timeout=120
            )

            if response.status_code == 200:
                tokens = response.json()
                self.access_token = tokens.get("access_token")
                self.refresh_token = tokens.get("refresh_token")

                self._set_auth_headers()

                print(flair("auth", "OK"))
                return True
            else:
                # Never dump raw response.text - FDM error replies can echo
                # submitted form fields including the password. Extract the
                # description if it's structured JSON; otherwise just the code.
                detail = self._safe_auth_error(response)
                print(flair("auth", "FAIL", detail=f"HTTP {response.status_code}: {detail}"))
                return False

        except requests.exceptions.RequestException as e:
            print(flair("auth", "FAIL", detail=f"connection error: {self._scrub_secrets(str(e))}"))
            return False

    def _safe_auth_error(self, response: requests.Response) -> str:
        """Extract a short error description from an FDM auth response.

        Avoids dumping the full body because FDM error replies sometimes
        include the submitted credentials. Falls back to a generic string
        if parsing fails or the description would leak the password.
        """
        try:
            data = response.json()
            messages = data.get("error", {}).get("messages", [])
            if messages and isinstance(messages[0], dict):
                desc = str(messages[0].get("description", "")).strip()
                if desc and (not self.password or self.password not in desc):
                    return desc
        except (ValueError, TypeError):
            pass
        return "authentication failed"

    def _scrub_secrets(self, text: str) -> str:
        """Remove the configured password from arbitrary text before logging."""
        if self.password and text:
            return text.replace(self.password, "***REDACTED***")
        return text

    # ------------------------------------------------------------------
    # Token refresh
    # ------------------------------------------------------------------
    def refresh_access_token(self) -> bool:
        """Silently refresh the access token using the stored refresh token.

        Called automatically when any request returns HTTP 401.  Uses a lock
        so that concurrent worker threads don't flood the auth endpoint; if
        another thread refreshed the token within the last few seconds the
        caller simply returns True and retries its request with the already-
        updated session header.

        Falls back to a full password re-authentication if the refresh-token
        grant fails.

        Returns:
            True if a new access token was obtained, False otherwise.
        """
        with self._auth_lock:
            # If another thread refreshed very recently, trust its result.
            if time.time() - self._last_refresh_time < 10.0:
                return True

            auth_url = f"{self.base_url}/fdm/token"

            # 1. Try the refresh-token grant first (cheaper, no password needed).
            if self.refresh_token:
                try:
                    resp = self.session.post(
                        auth_url,
                        json={"grant_type": "refresh_token", "refresh_token": self.refresh_token},
                        timeout=30,
                    )
                    if resp.status_code == 200:
                        tokens = resp.json()
                        self.access_token = tokens.get("access_token")
                        self.refresh_token = tokens.get("refresh_token")
                        self._set_auth_headers()
                        self._last_refresh_time = time.time()
                        print("  [AUTH] Token refreshed via refresh_token grant.")
                        return True
                except requests.exceptions.RequestException:
                    pass

            # 2. Fall back to full password re-authentication.
            try:
                resp = self.session.post(
                    auth_url,
                    json={"grant_type": "password", "username": self.username, "password": self.password},
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    timeout=30,
                )
                if resp.status_code == 200:
                    tokens = resp.json()
                    self.access_token = tokens.get("access_token")
                    self.refresh_token = tokens.get("refresh_token")
                    self._set_auth_headers()
                    self._last_refresh_time = time.time()
                    print("  [AUTH] Token refreshed via password re-authentication.")
                    return True
                print(f"  [AUTH] Token refresh failed: HTTP {resp.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"  [AUTH] Token refresh error: {e}")

            return False

    # ------------------------------------------------------------------
    # Shared pagination helpers
    # ------------------------------------------------------------------
    def get_paged_items(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        page_limit: int = 100,
        timeout: int = 30,
    ) -> Tuple[bool, Union[List[Dict[str, Any]], str]]:
        """Fetch every item from a list endpoint, following pagination.

        The offset advances by the *actual* number of items returned (a page
        may contain fewer than ``page_limit`` items), so short pages never
        cause objects to be skipped.

        Args:
            url: Full URL of the list endpoint.
            params: Optional extra query parameters merged into each page GET.
            page_limit: Page size to request.
            timeout: Per-request timeout in seconds.

        Returns:
            (True, items) on success, (False, error_message) on any
            HTTP/network/parse error.
        """
        all_items: List[Dict[str, Any]] = []
        offset = 0
        try:
            while True:
                page_params: Dict[str, Any] = dict(params or {})
                page_params.update({"offset": offset, "limit": page_limit})
                response = self.session.get(url, params=page_params, timeout=timeout)
                if response.status_code != 200:
                    return False, f"API error: {response.status_code}"
                data = response.json()
                items = data.get("items", [])
                if not items:
                    break
                all_items.extend(items)
                offset += len(items)
                paging = data.get("paging", {}) or {}
                count = paging.get("count")
                if isinstance(count, int):
                    if offset >= count:
                        break
                elif not paging.get("next"):
                    break
            return True, all_items
        except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
            return False, str(e)

    def find_object_by_name(
        self,
        url: str,
        name: str,
        match: Optional[Callable[[Dict[str, Any]], bool]] = None,
        page_limit: int = 100,
        timeout: int = 30,
    ) -> Tuple[bool, Union[Dict[str, Any], str]]:
        """Look up an object by name on a list endpoint.

        Tries the ``filter=name:...`` query first, then falls back to a full
        paginated scan.  An exact name match always wins; the optional
        ``match`` predicate is only used when no name match exists (for
        duplicates keyed on something other than name, e.g. a subinterface's
        VLAN ID).

        Returns:
            (True, object_dict) if found, (False, error_message) otherwise.
        """
        try:
            # Try the filter parameter first (cheap when supported).
            response = self.session.get(
                url, params={"filter": f"name:{name}", "limit": 10}, timeout=timeout,
            )
            if response.status_code == 200:
                for obj in response.json().get("items", []):
                    if obj.get("name") == name:
                        return True, obj

            # Fallback: paginated scan, advancing by the actual page size.
            fallback_obj = None
            offset = 0
            while True:
                response = self.session.get(
                    url, params={"offset": offset, "limit": page_limit}, timeout=timeout,
                )
                if response.status_code != 200:
                    return False, f"API error: {response.status_code}"
                data = response.json()
                items = data.get("items", [])
                for obj in items:
                    if obj.get("name") == name:
                        return True, obj
                    if fallback_obj is None and match is not None and match(obj):
                        fallback_obj = obj
                if not items:
                    break
                offset += len(items)
                paging = data.get("paging", {}) or {}
                count = paging.get("count")
                if isinstance(count, int):
                    if offset >= count:
                        break
                elif not paging.get("next"):
                    break
            if fallback_obj is not None:
                return True, fallback_obj
            return False, f"Object not found: {name}"
        except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
            return False, str(e)

    # ------------------------------------------------------------------
    # Deployment polling
    # ------------------------------------------------------------------
    _DEPLOY_SUCCESS_STATES = {"DEPLOYED"}
    _DEPLOY_FAILURE_STATES = {"FAILED", "CANCELLED"}

    def poll_deployment(
        self,
        deployment_id: str,
        timeout: float = 600.0,
        interval: float = 10.0,
    ) -> bool:
        """Poll a deployment task until it reaches a terminal state.

        Args:
            deployment_id: Task id returned by POST /operational/deploy.
            timeout: Maximum seconds to wait for a terminal state.
            interval: Seconds between status polls.

        Returns:
            True when the deployment finished successfully, False on
            deployment failure or timeout.
        """
        url = f"{self.base_url}/operational/deploy/{deployment_id}"
        deadline = time.time() + timeout
        start = time.time()
        last_state = ""
        while time.time() < deadline:
            try:
                resp = self.session.get(url, timeout=30)
                if resp.status_code == 200:
                    data = resp.json()
                    state = str(data.get("state", "")).upper()
                    if state != last_state:
                        elapsed = int(time.time() - start)
                        print(f"  Deployment state: {state or 'UNKNOWN'} ({elapsed}s elapsed)")
                        last_state = state
                    if state in self._DEPLOY_SUCCESS_STATES:
                        print("  Deployment completed successfully.")
                        return True
                    if state in self._DEPLOY_FAILURE_STATES:
                        detail = str(data.get("statusMessage") or state)
                        print(f"  Deployment failed: {detail}")
                        return False
                else:
                    print(f"  Deployment status check failed: HTTP {resp.status_code}")
            except (requests.exceptions.RequestException, ValueError, TypeError, KeyError) as e:
                print(f"  Deployment status check error: {e}")
            time.sleep(interval)
        print(f"  Deployment did not reach a terminal state within {int(timeout)}s - "
              "check the FDM web interface for status.")
        return False

    def start_and_wait_deployment(self, response: requests.Response) -> bool:
        """Poll the deployment task from a successful deploy POST response.

        Extracts the task id from the POST /operational/deploy response and
        polls it until a terminal state.  When no task id is present the
        deployment is assumed to be initiated (legacy behavior) and True is
        returned with a note.
        """
        dep_id = None
        try:
            dep_id = response.json().get("id")
        except (ValueError, TypeError, AttributeError):
            dep_id = None
        if not dep_id:
            print("  Deployment initiated, but no task id was returned - "
                  "check FDM web interface for status.")
            return True
        return self.poll_deployment(str(dep_id))

    # ------------------------------------------------------------------
    # Endpoint validation
    # ------------------------------------------------------------------
    def validate_endpoints(self) -> bool:
        """Probe required FDM API endpoints and print a capability summary.

        Each endpoint is tested with a lightweight GET (limit=1).  Intended
        as a fast preflight check before a long run.

        Returns:
            True if all endpoints are reachable, False otherwise.
        """
        print(f"\n{'='*60}")
        print("ENDPOINT VALIDATION")
        print(f"{'='*60}")

        all_ok = True
        for path, label in _FDM_ENDPOINTS:
            url = f"{self.base_url}{path}"
            try:
                resp = self.session.get(url, params={"limit": 1}, timeout=15)
                if resp.status_code == 200:
                    data = resp.json()
                    count = data.get("paging", {}).get("count", "?")
                    print(f"  {flair('validate', 'OK', f'{label:<25}', f'{count} objects')}")
                else:
                    print(f"  {flair('validate', 'FAIL', f'{label:<25}', f'HTTP {resp.status_code}')}")
                    all_ok = False
            except requests.exceptions.RequestException as e:
                print(f"  {flair('validate', 'FAIL', f'{label:<25}', str(e))}")
                all_ok = False

        print(f"{'='*60}")
        if all_ok:
            print("All endpoints reachable.")
        else:
            print("Some endpoints failed. Review errors above before proceeding.")
        print(f"{'='*60}")
        return all_ok

    # ------------------------------------------------------------------
    # Virtual router discovery
    # ------------------------------------------------------------------
    def get_default_virtual_router_id(self) -> Tuple[bool, Optional[str]]:
        """Get the ID of the default virtual router (typically 'Global').

        Static routes are scoped under a Virtual Router in the FDM API.
        The resolved ID is cached to avoid repeated API calls.

        Returns:
            (success, vr_id_or_error_message)
        """
        if hasattr(self, "_default_vr_id") and self._default_vr_id:
            return True, self._default_vr_id

        endpoint = f"{self.base_url}/devices/default/routing/virtualrouters"

        try:
            response = self.session.get(endpoint, timeout=30)
            if response.status_code != 200:
                return False, f"API error: {response.status_code}"

            data = response.json()
            items = data.get("items", [])

            # Prefer the well-known defaults first
            for vr in items:
                vr_name = str(vr.get("name", "")).strip().lower()
                if vr_name in {"global", "default", "global-vr"}:
                    self._default_vr_id = vr.get("id")
                    return True, self._default_vr_id

            # Fallback: pick the first VR if present
            if items:
                self._default_vr_id = items[0].get("id")
                return True, self._default_vr_id

            return False, "No virtual routers found"

        except requests.exceptions.RequestException as e:
            return False, str(e)
