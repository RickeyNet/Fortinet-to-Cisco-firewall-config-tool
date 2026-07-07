#!/usr/bin/env python3
"""
PAN-OS XML API Base Client
============================
Shared foundation for PAN-OS API importer and cleanup tools.

Centralizes:
    - API key generation (authentication)
    - Configuration set/get/delete operations via XPath
    - Commit with job polling
    - SSL and retry handling

PAN-OS XML API reference:
    - Auth: POST /api/?type=keygen&user=<user>&password=<pass>
    - Config: /api/?type=config&action=set|get|delete&xpath=<xpath>&element=<xml>
    - Commit: /api/?type=commit&cmd=<commit></commit>
    - Op: /api/?type=op&cmd=<xml>
"""

import time
import xml.etree.ElementTree as ET
from typing import Dict, Optional, Tuple

import requests
import urllib3

# Disable SSL warnings for self-signed certificates (common on firewalls)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# XPath bases for vsys1 on a standalone firewall
_VSYS_BASE = (
    "/config/devices/entry[@name='localhost.localdomain']"
    "/vsys/entry[@name='vsys1']"
)
_DEVICE_BASE = "/config/devices/entry[@name='localhost.localdomain']"

XPATHS = {
    "address":            f"{_VSYS_BASE}/address",
    "address_group":      f"{_VSYS_BASE}/address-group",
    "service":            f"{_VSYS_BASE}/service",
    "service_group":      f"{_VSYS_BASE}/service-group",
    "security_rule":      f"{_VSYS_BASE}/rulebase/security/rules",
    "zone":               f"{_VSYS_BASE}/zone",
    "static_route":       (
        f"{_DEVICE_BASE}/network/virtual-router"
        "/entry[@name='default']/routing-table/ip/static-route"
    ),
    "ethernet":           f"{_DEVICE_BASE}/network/interface/ethernet",
    "aggregate_ethernet": f"{_DEVICE_BASE}/network/interface/aggregate-ethernet",
    "vlan":               f"{_DEVICE_BASE}/network/vlan",
    "vlan_interface":     f"{_DEVICE_BASE}/network/interface/vlan/units",
}


class PANOSBaseClient:
    """Shared base for PAN-OS XML API clients.

    Provides:
        - ``authenticate()`` - obtain API key
        - ``config_set()`` / ``config_get()`` / ``config_delete()``
        - ``commit()`` with job polling
        - ``validate_connection()``
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

        self.base_url = f"https://{host}/api/"
        self.api_key: Optional[str] = None

        self.session = requests.Session()
        self.session.verify = verify_ssl

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    def authenticate(self) -> bool:
        """Generate an API key using username/password.

        Returns:
            True if API key was obtained successfully.
        """
        print(f"\n{'=' * 60}")
        print(f"Authenticating to PAN-OS at {self.host}")
        print(f"{'=' * 60}")

        try:
            # POST the credentials in the form body, never in the URL query
            # string - otherwise the password appears in connection-error
            # tracebacks, proxy logs, and any tool that echoes request URLs.
            resp = self.session.post(
                self.base_url,
                data={
                    "type": "keygen",
                    "user": self.username,
                    "password": self.password,
                },
                timeout=30,
            )

            if resp.status_code != 200:
                print(f"[FAIL] Authentication failed: HTTP {resp.status_code}")
                return False

            root = ET.fromstring(resp.text)
            status = root.attrib.get("status", "")

            if status == "success":
                key_elem = root.find(".//key")
                if key_elem is not None and key_elem.text:
                    self.api_key = key_elem.text
                    print("Authentication successful!")
                    return True

            # Parse error message - never fall through to raw resp.text since
            # PAN-OS error replies sometimes echo submitted parameters.
            msg_elem = self._find_msg_elem(root)
            msg = msg_elem.text if msg_elem is not None else "auth failed"
            print(f"[FAIL] Authentication failed: {msg}")
            return False

        except requests.exceptions.RequestException as e:
            # Defense-in-depth: scrub any password value that might appear in
            # the exception string (e.g. if a future caller reverts to GET or
            # an underlying library echoes the URL).
            print(f"[FAIL] Connection error: {self._scrub_secrets(str(e))}")
            return False

    def _scrub_secrets(self, text: str) -> str:
        """Remove the password and API key from arbitrary text before logging."""
        if not text:
            return text
        if self.password:
            text = text.replace(self.password, "***REDACTED***")
        if self.api_key:
            text = text.replace(self.api_key, "***REDACTED***")
        return text

    @staticmethod
    def _find_msg_elem(root: ET.Element):
        """Return the <msg> element, falling back to <line>.

        Uses explicit ``is not None`` checks - Elements without children are
        falsy, so ``find(...) or find(...)`` would drop a present <msg>.
        """
        msg_elem = root.find(".//msg")
        if msg_elem is None:
            msg_elem = root.find(".//line")
        return msg_elem

    # ------------------------------------------------------------------
    # Configuration operations
    # ------------------------------------------------------------------
    def config_set(self, xpath: str, element: str) -> Tuple[bool, str]:
        """Set (create/merge) configuration at the given XPath.

        Args:
            xpath: PAN-OS configuration XPath
            element: XML element string to set

        Returns:
            (success, message)
        """
        return self._config_request("set", xpath, element=element)

    def config_get(self, xpath: str) -> Tuple[bool, str]:
        """Get configuration at the given XPath (candidate config).

        Returns:
            (success, message) - like all _config_request wrappers this
            returns the <msg>/<line> text ("OK" for a successful get). Use
            :meth:`config_get_xml` when the actual configuration XML is needed.
        """
        return self._config_request("get", xpath)

    def config_get_xml(self, xpath: str) -> Tuple[bool, str]:
        """Get configuration at the given XPath, returning the raw response XML.

        Unlike ``config_get()``, the full API response body is returned so
        callers can parse the ``<entry>`` elements inside ``<result>``.

        Returns:
            (success, raw_response_xml_or_error_message)
        """
        if not self.api_key:
            return False, "Not authenticated"

        params: Dict[str, str] = {
            "type": "config",
            "action": "get",
            "xpath": xpath,
            "key": self.api_key,
        }

        try:
            resp = self.session.post(self.base_url, data=params, timeout=120)

            if resp.status_code != 200:
                return False, f"HTTP {resp.status_code}: {resp.text[:200]}"

            root = ET.fromstring(resp.text)
            if root.attrib.get("status", "") == "success":
                return True, resp.text

            msg_elem = self._find_msg_elem(root)
            msg = msg_elem.text if msg_elem is not None and msg_elem.text else ""
            return False, msg or resp.text[:200]

        except ET.ParseError as e:
            return False, f"XML parse error: {e}"
        except requests.exceptions.RequestException as e:
            return False, f"Request error: {self._scrub_secrets(str(e))}"

    def config_delete(self, xpath: str) -> Tuple[bool, str]:
        """Delete configuration at the given XPath.

        Returns:
            (success, message)
        """
        return self._config_request("delete", xpath)

    def _config_request(
        self, action: str, xpath: str, element: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Execute a type=config API request."""
        if not self.api_key:
            return False, "Not authenticated"

        params: Dict[str, str] = {
            "type": "config",
            "action": action,
            "xpath": xpath,
            "key": self.api_key,
        }
        if element:
            params["element"] = element

        try:
            resp = self.session.post(
                self.base_url, data=params, timeout=120
            )

            if resp.status_code != 200:
                return False, f"HTTP {resp.status_code}: {resp.text[:200]}"

            root = ET.fromstring(resp.text)
            status = root.attrib.get("status", "")
            msg_elem = self._find_msg_elem(root)
            msg = msg_elem.text if msg_elem is not None else ""

            if status == "success":
                return True, msg or "OK"
            return False, msg or resp.text[:200]

        except ET.ParseError as e:
            return False, f"XML parse error: {e}"
        except requests.exceptions.RequestException as e:
            return False, f"Request error: {e}"

    # ------------------------------------------------------------------
    # Commit
    # ------------------------------------------------------------------
    def commit(self, timeout: int = 300) -> Tuple[bool, str]:
        """Commit the candidate configuration and wait for completion.

        Args:
            timeout: Maximum seconds to wait for the commit job.

        Returns:
            (success, message)
        """
        if not self.api_key:
            return False, "Not authenticated"

        print("\nCommitting configuration...")

        try:
            resp = self.session.post(
                self.base_url,
                data={
                    "type": "commit",
                    "cmd": "<commit></commit>",
                    "key": self.api_key,
                },
                timeout=120,
            )

            if resp.status_code != 200:
                return False, f"HTTP {resp.status_code}"

            root = ET.fromstring(resp.text)
            status = root.attrib.get("status", "")

            if status != "success":
                msg_elem = root.find(".//msg")
                msg = msg_elem.text if msg_elem is not None else resp.text[:200]
                return False, f"Commit rejected: {msg}"

            # Extract job ID
            job_elem = root.find(".//job")
            if job_elem is None or not job_elem.text:
                # Some PAN-OS versions return success without a job for empty commits
                return True, "Commit completed (no changes pending)"

            job_id = job_elem.text
            print(f"  Commit job started: {job_id}")

            # Poll for completion
            return self._poll_job(job_id, timeout)

        except requests.exceptions.RequestException as e:
            return False, f"Commit error: {e}"

    def _poll_job(self, job_id: str, timeout: int = 300) -> Tuple[bool, str]:
        """Poll a PAN-OS job until completion."""
        start_time = time.time()
        poll_interval = 2

        while time.time() - start_time < timeout:
            time.sleep(poll_interval)

            try:
                # POST the API key in the form body, never in the URL query
                # string (it would land in proxy/webserver logs).
                resp = self.session.post(
                    self.base_url,
                    data={
                        "type": "op",
                        "cmd": f"<show><jobs><id>{job_id}</id></jobs></show>",
                        "key": self.api_key,
                    },
                    timeout=30,
                )

                if resp.status_code != 200:
                    continue

                root = ET.fromstring(resp.text)
                result_elem = root.find(".//result")
                if result_elem is None:
                    continue

                status_elem = result_elem.find("status")
                if status_elem is None:
                    continue

                job_status = status_elem.text or ""

                if job_status == "FIN":
                    # Check result
                    job_result = result_elem.find("result")
                    if job_result is not None and job_result.text == "OK":
                        print("  Commit completed successfully!")
                        return True, "Commit successful"
                    else:
                        details = result_elem.find("details")
                        detail_text = ""
                        if details is not None:
                            lines = details.findall(".//line")
                            detail_text = " ".join(
                                l.text for l in lines if l.text
                            )
                        return False, f"Commit failed: {detail_text or 'unknown error'}"

                # Still in progress
                progress_elem = result_elem.find("progress")
                progress = progress_elem.text if progress_elem is not None else "?"
                elapsed = int(time.time() - start_time)
                print(f"  Commit in progress... {progress}% ({elapsed}s)")

                # Adaptive polling: slow down for long commits
                if elapsed > 30:
                    poll_interval = 5
                if elapsed > 120:
                    poll_interval = 10

            except (ET.ParseError, requests.exceptions.RequestException):
                continue

        return False, f"Commit timed out after {timeout}s"

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    def validate_connection(self) -> bool:
        """Verify connectivity and API key by reading system info.

        Returns:
            True if connection is valid.
        """
        print(f"\n{'=' * 60}")
        print("VALIDATING CONNECTION")
        print(f"{'=' * 60}")

        try:
            # POST the API key in the form body, never in the URL query string.
            resp = self.session.post(
                self.base_url,
                data={
                    "type": "op",
                    "cmd": "<show><system><info></info></system></show>",
                    "key": self.api_key,
                },
                timeout=15,
            )

            if resp.status_code != 200:
                print(f"  [FAIL] HTTP {resp.status_code}")
                return False

            root = ET.fromstring(resp.text)
            status = root.attrib.get("status", "")

            if status == "success":
                result = root.find(".//result")
                if result is not None:
                    hostname = self._get_text(result, "hostname", "unknown")
                    model = self._get_text(result, "model", "unknown")
                    sw_version = self._get_text(result, "sw-version", "unknown")
                    serial = self._get_text(result, "serial", "unknown")

                    print(f"  Hostname:  {hostname}")
                    print(f"  Model:     {model}")
                    print(f"  PAN-OS:    {sw_version}")
                    print(f"  Serial:    {serial}")
                    print(f"{'=' * 60}")
                    print("Connection validated successfully.")
                    return True

            # Don't dump raw resp.text - PAN-OS error replies can echo input
            # parameters. Extract the <msg>/<line> element if available.
            try:
                root = ET.fromstring(resp.text)
                msg_elem = self._find_msg_elem(root)
                msg = msg_elem.text if msg_elem is not None and msg_elem.text else "unexpected response"
            except ET.ParseError:
                msg = "unexpected response"
            print(f"  [FAIL] {msg}")
            return False

        except requests.exceptions.RequestException as e:
            print(f"  [FAIL] Connection error: {self._scrub_secrets(str(e))}")
            return False

    @staticmethod
    def _get_text(parent: ET.Element, tag: str, default: str = "") -> str:
        """Safely extract text from an XML element."""
        elem = parent.find(tag)
        return elem.text if elem is not None and elem.text else default
