#!/usr/bin/env python3
"""
Cisco FTD FDM API Importer
===========================
This script imports converted FortiGate configurations into Cisco FTD
using the Firewall Device Manager (FDM) API.

REQUIREMENTS:
    - Python 3.6 or higher
    - requests library (install with: pip install requests)
    - urllib3 library (install with: pip install urllib3)

SUPPORTED FTD VERSIONS:
    - FTD 7.4.x with FDM (tested on 7.4.2.4-9)
    - Local management via FDM

WHAT THIS SCRIPT DOES:
    1. Authenticates to FTD FDM API
    2. Imports address objects
    3. Imports address groups
    4. Imports port objects
    5. Imports port groups
    6. Imports static routes
    7. Imports access rules
    8. Deploys the configuration changes
    9. Provides detailed progress and error reporting

HOW TO RUN:
    python ftd_api_importer.py --host 192.168.1.1 --username admin --password YourPassword

IMPORTANT NOTES:
    - SSL certificate verification is disabled by default (self-signed certs)
    - Always test on a non-production firewall first
    - Back up your FTD configuration before running
    - The script uses the /api/fdm/latest/ endpoint
    - Objects are imported in the correct dependency order
"""

import requests
import json
import argparse
import sys
import time
import getpass
import urllib3
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, cast
from concurrency_utils import run_with_retry, run_indexed_thread_pool
from platform_profiles import is_ftd_1000, is_ftd_3100
from ftd_api_base import FTDBaseClient


# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FTDAPIClient(FTDBaseClient):
    """
    Client for interacting with Cisco FTD Firewall Device Manager (FDM) API.

    This class handles:
    - Authentication and token management
    - CRUD operations for network objects, services, routes, and policies
    - Deployment of configuration changes
    - Error handling and retry logic
    """

    def __init__(self, host: str, username: str, password: str, verify_ssl: bool = False, update_existing: bool = True) -> None:
        """
        Initialize the FTD API client.

        Args:
            host: FTD management IP address or hostname
            username: FDM username (typically 'admin')
            password: FDM password
            verify_ssl: Whether to verify SSL certificates (False for self-signed)
            update_existing: When True, update objects that already exist instead of skipping them.
                             Defaults to True so existing objects are always brought in sync.
        """
        super().__init__(host, username, password, verify_ssl)
        self.update_existing = update_existing
        self._stats_lock = threading.Lock()

        # =================================================================
        # REFERENCE CACHES - Prefetch and cache name->id mappings
        # =================================================================
        # These caches store FTD object references to avoid repeated API calls
        # Format: hardware_name -> {id, type, name, .full object}
        self._physical_interface_cache = {}      # Ethernet1/1 -> {id: xxx, .}
        self._etherchannel_cache = {}            # Port-channel1 -> {id: xxx, .}
        self._bridge_group_cache = {}            # BVI/BridgeGroup name -> {id: xxx, .}  (NO hardwareName)
        self._network_object_cache = {}          # object_name -> {id: xxx, .}
        self._caches_populated = False


        # Track individual failed items for the failure summary report
        self.failed_items: List[Dict[str, str]] = []
        self._failed_items_lock = threading.Lock()

        # Phases that failed outright without producing per-item stats
        # (e.g. a missing input file). compute_outcome treats a non-empty
        # list as a failed run even when the item counters show no failures.
        self.phase_failures: List[str] = []

        # Track statistics
        self.stats = {
            "address_objects_created": 0,
            "address_objects_updated": 0,
            "address_objects_failed": 0,
            "address_objects_skipped": 0,
            "address_groups_created": 0,
            "address_groups_updated": 0,
            "address_groups_failed": 0,
            "address_groups_skipped": 0,
            "port_objects_created": 0,
            "port_objects_updated": 0,
            "port_objects_failed": 0,
            "port_objects_skipped": 0,
            "port_groups_created": 0,
            "port_groups_updated": 0,
            "port_groups_failed": 0,
            "port_groups_skipped": 0,
            "security_zones_created": 0,
            "security_zones_updated": 0,
            "security_zones_failed": 0,
            "security_zones_skipped": 0,
            "routes_created": 0,
            "routes_updated": 0,
            "routes_failed": 0,
            "routes_skipped": 0,
            "rules_created": 0,
            "rules_updated": 0,
            "rules_failed": 0,
            "rules_skipped": 0,
            "physical_interfaces_updated": 0,
            "physical_interfaces_failed": 0,
            "physical_interfaces_skipped": 0,
            "subinterfaces_created": 0,
            "subinterfaces_updated": 0,
            "subinterfaces_failed": 0,
            "subinterfaces_skipped": 0,
            "etherchannels_created": 0,
            "etherchannels_updated": 0,
            "etherchannels_failed": 0,
            "etherchannels_skipped": 0,
            "bridge_groups_created": 0,
            "bridge_groups_updated": 0,
            "bridge_groups_failed": 0,
            "bridge_groups_skipped": 0
        }

    def record_stat(self, key: str) -> None:
        """Thread-safe increment for statistics counters."""
        with self._stats_lock:
            self.stats[key] += 1

    def record_failure(self, object_type: str, name: str, error: Optional[str]) -> None:
        """Thread-safe recording of a failed import item."""
        with self._failed_items_lock:
            self.failed_items.append({
                "object_type": object_type,
                "name": name,
                "error": str(error)
            })

    def record_phase_failure(self, label: str) -> None:
        """Record a phase that failed outright (e.g. missing input file)."""
        self.phase_failures.append(label)

    def compute_outcome(self) -> tuple:
        """Determine overall run outcome from stats and phase failures.

        Returns:
            (exit_code, outcome_label) where:
                0, "SUCCESS"         - every item succeeded or was skipped
                2, "PARTIAL_FAILURE" - at least one item/phase failed but some succeeded/skipped
                3, "ALL_FAILED"      - every attempted item/phase failed (nothing created/updated/skipped)
        """
        total_failed = sum(v for k, v in self.stats.items() if k.endswith("_failed"))
        total_ok = sum(
            v for k, v in self.stats.items()
            if k.endswith(("_created", "_updated", "_skipped"))
        )
        if total_failed == 0 and not self.phase_failures:
            return 0, "SUCCESS"
        if total_ok > 0:
            return 2, "PARTIAL_FAILURE"
        return 3, "ALL_FAILED"

    def _extract_error_message(self, response: requests.Response, default: str = "Unknown error") -> str:
        """Best-effort API error extraction with safe fallbacks."""
        try:
            error_data = response.json()
            messages = error_data.get("error", {}).get("messages", [])
            if messages and isinstance(messages[0], dict):
                return str(messages[0].get("description", default))
            return str(error_data)
        except (ValueError, TypeError, KeyError):
            text = (response.text or "").strip()
            return text if text else default

    def _get_object_by_name_from_endpoint(
        self, endpoint: str, name: str,
        match: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ) -> Tuple[bool, Union[Dict[str, Any], str]]:
        """
        Look up an existing FTD object by name from the given list endpoint.

        Uses the filter parameter first, then falls back to paginated search.

        Args:
            endpoint: The list endpoint (e.g. /object/networks)
            name: Object name to find
            match: Optional fallback predicate. During the paginated scan,
                   any object for which ``match(obj)`` is True is returned
                   even if its name differs. Used for duplicates keyed on
                   something other than name (e.g. an etherchannel's
                   Port-channel ID, a subinterface's VLAN ID).

        Returns:
            (True, object_dict) if found, (False, error_message) otherwise.
        """
        # Shared filter-first + paginated-scan lookup lives in FTDBaseClient.
        return self.find_object_by_name(endpoint, name, match=match)

    # FDM bookkeeping fields that are present on every GET response but never
    # part of the converter's create payload. Excluded from the
    # equality check so two semantically identical objects compare equal.
    _FDM_META_KEYS = frozenset({
        "id", "version", "links", "self", "metadata",
        "isSystemDefined", "kind",  # "type" is intentionally NOT in here:
                                    # it's part of the object's identity (e.g.
                                    # HOST vs NETWORK vs RANGE for NetworkObject)
    })

    def _payload_matches_existing(self, existing: Dict, payload: Dict) -> bool:
        """
        Return True if ``payload`` would not actually change ``existing``.

        Compares value-bearing fields only - FDM bookkeeping (id, version,
        links, metadata, ...) is ignored at every nesting level, so a group
        whose member refs are ``{name, type}`` in the payload still matches
        the GET response where those refs carry id/version. For any field
        present in the new payload, the existing value must match. Existing
        fields not mentioned in the payload are tolerated (FDM defaults).
        List values must match element-by-element in order - a reordered
        member list is treated as a change (safe fallback to PUT).
        """
        return self._values_match(existing, payload)

    @classmethod
    def _values_match(cls, existing_val: Any, new_val: Any) -> bool:
        """Recursive comparison helper for _payload_matches_existing."""
        if isinstance(new_val, dict) and isinstance(existing_val, dict):
            for key, val in new_val.items():
                if key in cls._FDM_META_KEYS:
                    continue
                if not cls._values_match(existing_val.get(key), val):
                    return False
            return True
        if isinstance(new_val, list) and isinstance(existing_val, list):
            if len(new_val) != len(existing_val):
                return False
            return all(
                cls._values_match(e, n) for e, n in zip(existing_val, new_val)
            )
        return existing_val == new_val

    def _update_existing_object(
        self,
        endpoint: str,
        payload: Dict,
        stat_prefix: str,
        track_stats: bool = True,
        match: Optional[Callable[[Dict[str, Any]], bool]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Look up an existing object by name and PUT an update.

        Used by _create_api_object when a duplicate is detected and
        update_existing is True.

        Args:
            endpoint: The collection endpoint (e.g. /object/networks).
            payload: The desired object payload (must contain "name").
            stat_prefix: Stat key prefix for _updated / _failed counters.
            track_stats: Whether to record stats.
            match: Optional fallback predicate for finding the existing
                   object when the duplicate is keyed on something other
                   than name (passed to _get_object_by_name_from_endpoint).

        Returns:
            (success, object_id or error message)
        """
        obj_name = payload.get("name", "")
        found, existing = self._get_object_by_name_from_endpoint(endpoint, obj_name, match=match)
        if not found or not isinstance(existing, dict):
            if track_stats:
                self.record_stat(f"{stat_prefix}_failed")
            return False, f"Could not look up existing object for update: {existing}"

        obj_id = existing.get("id")
        obj_version = existing.get("version")
        if not obj_id:
            if track_stats:
                self.record_stat(f"{stat_prefix}_failed")
            return False, f"Existing object has no ID: {obj_name}"

        # Short-circuit: if every value-bearing field already matches what we
        # would PUT, treat as SKIP - no need to hit the API and no risk of an
        # FDM "no changes detected" rejection.
        if self._payload_matches_existing(existing, payload):
            if track_stats:
                self.record_stat(f"{stat_prefix}_skipped")
            return True, f"SKIPPED: identical to existing '{obj_name}'"

        try:
            for attempt in range(2):
                # Merge: keep the existing id/version, apply new payload on top
                update_payload = dict(existing)
                update_payload.update(payload)
                update_payload["id"] = obj_id
                update_payload["version"] = obj_version
                # Read-only metadata from the GET response - not valid in a PUT body
                update_payload.pop("links", None)

                put_url = f"{endpoint}/{obj_id}"
                response = self.session.put(put_url, json=update_payload, timeout=30)

                if response.status_code in (200, 201):
                    updated_obj = response.json()
                    if track_stats:
                        self.record_stat(f"{stat_prefix}_updated")
                    return True, f"UPDATED:{updated_obj.get('id', obj_id)}"

                error_msg = self._extract_error_message(response, response.text)

                # GET+PUT race: a concurrent writer may have bumped the
                # object version between our GET and PUT. Re-GET once and
                # retry the PUT with the fresh version.
                if attempt == 0 and self._is_version_conflict(response.status_code, error_msg):
                    found, fresh = self._get_object_by_name_from_endpoint(endpoint, obj_name, match=match)
                    if found and isinstance(fresh, dict) and fresh.get("id"):
                        existing = fresh
                        obj_id = fresh.get("id")
                        obj_version = fresh.get("version")
                        continue

                if track_stats:
                    self.record_stat(f"{stat_prefix}_failed")
                return False, f"Update failed (HTTP {response.status_code}): {error_msg}"

            # Unreachable: the loop always returns or continues at most once.
            return False, "Update failed: version conflict retry exhausted"
        except requests.exceptions.RequestException as e:
            if track_stats:
                self.record_stat(f"{stat_prefix}_failed")
            return False, f"Update request error: {e}"

    @staticmethod
    def _is_version_conflict(status_code: int, error_msg: str) -> bool:
        """Return True when a failed PUT looks like an FDM version conflict."""
        if status_code == 409:
            return True
        msg = (error_msg or "").lower()
        return "version" in msg and any(
            marker in msg for marker in ("conflict", "stale", "mismatch", "not match", "does not match", "modified")
        )

    def _create_api_object(
        self,
        endpoint: str,
        payload: Dict,
        stat_prefix: str,
        track_stats: bool = True,
    ) -> Tuple[bool, Optional[str]]:
        """
        Generic POST-create with duplicate detection, optional update, and stat recording.

        This is the shared implementation behind create_network_object,
        create_network_group, create_port_object, create_port_group,
        create_access_rule, and create_static_route.

        When ``self.update_existing`` is True and the POST returns 422 with
        "already exists" / "duplicate", the method will GET the existing
        object by name and PUT an update instead of skipping.

        Args:
            endpoint: Full API URL to POST to.
            payload: JSON-serializable body.
            stat_prefix: Stat key prefix (e.g. "address_objects"). Counters
                         "{prefix}_created", "{prefix}_updated",
                         "{prefix}_skipped", and "{prefix}_failed" are
                         incremented as appropriate.
            track_stats: When False, skip stat recording (callers that use
                         run_with_retry handle stats externally).

        Returns:
            Tuple of (success: bool, object_id or message).
        """
        try:
            response = self.session.post(endpoint, json=payload, timeout=30)

            if response.status_code in (200, 201):
                created_obj = response.json()
                if track_stats:
                    self.record_stat(f"{stat_prefix}_created")
                return True, created_obj.get("id")

            if response.status_code == 422:
                error_msg = self._extract_error_message(response)
                if "already exists" in error_msg.lower() or "duplicate" in error_msg.lower():
                    # Object exists - try to update it if update_existing is enabled
                    if self.update_existing:
                        return self._update_existing_object(
                            endpoint, payload, stat_prefix, track_stats,
                        )
                    if track_stats:
                        self.record_stat(f"{stat_prefix}_skipped")
                    return True, f"SKIPPED: {error_msg}"
                if track_stats:
                    self.record_stat(f"{stat_prefix}_failed")
                return False, error_msg

            if track_stats:
                self.record_stat(f"{stat_prefix}_failed")
            return False, self._extract_error_message(response)

        except requests.exceptions.RequestException as e:
            if track_stats:
                self.record_stat(f"{stat_prefix}_failed")
            return False, str(e)

    def _handle_422_conflict(
        self,
        response: requests.Response,
        endpoint: str,
        payload: Dict,
        stat_prefix: str,
        match: Optional[Callable[[Dict[str, Any]], bool]] = None,
        error_prefix: str = "",
    ) -> Tuple[bool, Optional[str]]:
        """
        Shared 422 handling for the interface-style create methods.

        A duplicate ("already exists"/"duplicate") is updated in place when
        ``update_existing`` is enabled, otherwise skipped.  Any other 422 is
        reported as a failure with the parsed error message.

        Returns:
            (success, message) in the same shape as the create methods.
        """
        error_msg = self._extract_error_message(response)
        if 'already exists' in error_msg.lower() or 'duplicate' in error_msg.lower():
            if self.update_existing:
                return self._update_existing_object(endpoint, payload, stat_prefix, match=match)
            self.record_stat(f"{stat_prefix}_skipped")
            return True, f"SKIPPED: {error_msg}"
        self.record_stat(f"{stat_prefix}_failed")
        return False, f"{error_prefix}{error_msg}"

    def _disable_cts_settings_for_member_prep(self, payload: Dict[str, Any]) -> int:
        """
        Disable CTS/TrustSec-like settings in an interface payload before PUT.

        Returns:
            Number of fields modified.
        """
        changed = 0

        def walk(node: Any) -> Any:
            nonlocal changed

            if isinstance(node, dict):
                updated = {}
                for key, value in node.items():
                    key_name = str(key)
                    if _is_cts_related_key(key_name):
                        if isinstance(value, bool):
                            if value:
                                changed += 1
                            updated[key] = False
                            continue
                        if isinstance(value, str):
                            normalized = value.strip().upper()
                            if normalized in {"ENABLED", "ENABLE", "TRUE", "ON", "YES"}:
                                changed += 1
                                updated[key] = "DISABLED"
                            else:
                                updated[key] = value
                            continue
                        if isinstance(value, (int, float)):
                            if value != 0:
                                changed += 1
                            updated[key] = 0
                            continue
                        if isinstance(value, dict):
                            nested = walk(value)
                            if nested == value:
                                # If nested object had no obvious on/off values, clear it.
                                # This avoids carrying an enabled CTS profile into EC members.
                                changed += 1
                                updated[key] = {}
                            else:
                                updated[key] = nested
                            continue
                        if isinstance(value, list):
                            if value:
                                changed += 1
                            updated[key] = []
                            continue
                        if value is not None:
                            changed += 1
                        updated[key] = None
                        continue

                    updated[key] = walk(value)
                return updated

            if isinstance(node, list):
                return [walk(item) for item in node]

            return node

        patched = walk(payload)
        payload.clear()
        payload.update(patched)
        return changed
    
    # =========================================================================
    # REFERENCE CACHING METHODS
    # =========================================================================
    
    def prefetch_interface_cache(self) -> None:
        """
        Prefetch and cache all physical interfaces and etherchannels.
        
        This should be called ONCE before importing subinterfaces to avoid
        repeated API calls for parent interface lookups.
        """
        if self._caches_populated:
            return
        
        print("  Prefetching interface references...")

        # Fetch all physical interfaces (paginated)
        endpoint = f"{self.base_url}/devices/default/interfaces"
        ok, interfaces = self.get_paged_items(endpoint, page_limit=200)
        if ok and isinstance(interfaces, list):
            for intf in interfaces:
                # Only keep physical interfaces in this cache (consistent
                # with populate_physical_interface_cache)
                if intf.get("type") != "physicalinterface":
                    continue
                hardware_name = intf.get('hardwareName', '')
                if hardware_name:
                    self._physical_interface_cache[hardware_name] = intf
            print(f"    Cached {len(self._physical_interface_cache)} physical interfaces")
        else:
            print(f"    Warning: Failed to cache physical interfaces: {interfaces}")

        # Fetch all etherchannels (paginated)
        endpoint = f"{self.base_url}/devices/default/etherchannelinterfaces"
        ok, etherchannels = self.get_paged_items(endpoint, page_limit=100)
        if ok and isinstance(etherchannels, list):
            for ec in etherchannels:
                hardware_name = ec.get('hardwareName', '')
                if hardware_name:
                    self._etherchannel_cache[hardware_name] = ec
            print(f"    Cached {len(self._etherchannel_cache)} etherchannels")
        else:
            print(f"    Warning: Failed to cache etherchannels: {etherchannels}")

        # Fetch all bridge-group interfaces (these often do NOT have hardwareName)
        endpoint = f"{self.base_url}/devices/default/bridgegroupinterfaces"
        ok, bgs = self.get_paged_items(endpoint, page_limit=200)
        if ok and isinstance(bgs, list):
            for bg in bgs:
                bg_name = (bg.get("name") or "").strip()
                if bg_name:
                    self._bridge_group_cache[bg_name] = bg
            print(f"    Cached {len(self._bridge_group_cache)} bridge groups")
        else:
            print(f"    Warning: Failed to cache bridge groups: {bgs}")

        self._caches_populated = True


    def prefetch_network_object_cache(self) -> None:
        """
        Prefetch and cache all network objects.
        
        This should be called ONCE before importing routes to avoid
        repeated API calls for network object lookups. Handles pagination
        to fetch all objects regardless of count.
        """
        if self._network_object_cache:
            # Already populated
            return
        
        print("  Prefetching network object references...")

        endpoint = f"{self.base_url}/object/networks"
        ok, items = self.get_paged_items(endpoint, page_limit=200, timeout=60)
        if not ok or not isinstance(items, list):
            print(f"    Warning: Failed to cache network objects: {items}")
            return

        # Cache each object by name
        for obj in items:
            obj_name = obj.get('name', '')
            if obj_name:
                self._network_object_cache[obj_name] = obj

        print(f"    Cached {len(self._network_object_cache)} network objects")
    
    def get_cached_physical_interface(self, hardware_name: str) -> Tuple[bool, Union[Dict[str, Any], str, None]]:
        """
        Get a physical interface from cache (or fetch if not cached).
        
        Args:
            hardware_name: FTD hardware name (e.g., 'Ethernet1/1')
            
        Returns:
            Tuple of (found: bool, interface_dict or error_message)
        """
        # Check cache first
        if hardware_name in self._physical_interface_cache:
            return True, self._physical_interface_cache[hardware_name]
        
        # Not in cache - do a direct lookup and cache it
        success, result = self.get_physical_interface(hardware_name)
        if success and isinstance(result, dict):
            self._physical_interface_cache[hardware_name] = result
        return success, result
    
    def get_cached_etherchannel(self, hardware_name: str) -> Tuple[bool, Union[Dict[str, Any], str, None]]:
        """
        Get an etherchannel from cache (or fetch if not cached).
        
        Args:
            hardware_name: FTD hardware name (e.g., 'Port-channel1')
            
        Returns:
            Tuple of (found: bool, etherchannel_dict or error_message)
        """
        # Check cache first
        if hardware_name in self._etherchannel_cache:
            return True, self._etherchannel_cache[hardware_name]
        
        # Not in cache - do a direct lookup and cache it
        success, result = self._get_etherchannel_by_hardware(hardware_name)
        if success and isinstance(result, dict):
            self._etherchannel_cache[hardware_name] = result
        return success, result
    
    def populate_physical_interface_cache(self) -> None:
        """
        Fetch all existing physical interfaces and cache them by hardwareName for quick lookup.
        Caching behavior:
        - Only caches objects where type == 'physicalinterface'
        - Keyed by hardwareName (e.g., 'Ethernet1/1')
        - Overwrites any prior cache contents

        Returns:
            None
        """
        print("  Fetching existing physical interfaces from FTD for update detection...")
        endpoint = f"{self.base_url}/devices/default/interfaces"

        self._physical_interface_cache.clear()

        ok, items = self.get_paged_items(endpoint, page_limit=200)
        if not ok or not isinstance(items, list):
            print(f"[WARN] Could not fetch interfaces list: {items}")
            return

        for intf in items:
            # Only keep physical interfaces in this cache
            if intf.get("type") != "physicalinterface":
                continue

            hw = intf.get("hardwareName")
            if hw:
                self._physical_interface_cache[hw] = intf

        print(f"    Cached {len(self._physical_interface_cache)} existing physical interfaces")

    def clear_caches(self) -> None:
        """Clear all reference caches."""
        self._physical_interface_cache.clear()
        self._etherchannel_cache.clear()
        self._bridge_group_cache.clear()
        self._network_object_cache.clear()
        self._caches_populated = False

    def create_network_object(self, obj: Dict, track_stats: bool = True) -> Tuple[bool, Optional[str]]:
        """
        Create a network object (address object) in FTD.

        Args:
            obj: Dictionary containing network object data
            track_stats: Record stats internally (False when caller handles stats)

        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        return self._create_api_object(
            f"{self.base_url}/object/networks", obj, "address_objects", track_stats,
        )
    
    def create_network_group(self, group: Dict, track_stats: bool = True) -> Tuple[bool, Optional[str]]:
        """
        Create a network object group (address group) in FTD.

        Args:
            group: Dictionary containing network group data
            track_stats: Record stats internally (False when caller handles stats)

        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        return self._create_api_object(
            f"{self.base_url}/object/networkgroups", group, "address_groups", track_stats,
        )
    
    def create_port_object(self, obj: Dict, track_stats: bool = True) -> Tuple[bool, Optional[str]]:
        """
        Create a port object (service object) in FTD.

        Args:
            obj: Dictionary containing port object data
            track_stats: Record stats internally (False when caller handles stats)

        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        obj_type = obj.get("type", "tcpportobject")
        if obj_type == "tcpportobject":
            endpoint = f"{self.base_url}/object/tcpports"
        elif obj_type == "udpportobject":
            endpoint = f"{self.base_url}/object/udpports"
        elif obj_type == "icmpv4portobject":
            endpoint = f"{self.base_url}/object/icmpv4ports"
        elif obj_type == "icmpv6portobject":
            endpoint = f"{self.base_url}/object/icmpv6ports"
        else:
            if track_stats:
                self.record_stat("port_objects_failed")
            return False, f"Unknown port type: {obj_type}"

        return self._create_api_object(endpoint, obj, "port_objects", track_stats)
    
    def create_port_group(self, group: Dict, track_stats: bool = True) -> Tuple[bool, Optional[str]]:
        """
        Create a port object group (service group) in FTD.

        Args:
            group: Dictionary containing port group data
            track_stats: Record stats internally (False when caller handles stats)

        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        return self._create_api_object(
            f"{self.base_url}/object/portgroups", group, "port_groups", track_stats,
        )
        
    def resolve_route_references(self, route: Dict) -> Tuple[bool, Union[Dict[str, Any], str]]:
        """
        Resolve all object references in a route to include IDs and versions.
        
        Routes reference network objects, interfaces, etc. by name, but the API
        requires full object references with id and version fields.
        
        Args:
            route: Route dictionary with minimal object references
            
        Returns:
            Tuple of (success: bool, resolved route dict or error message)
        """
        resolved_route = route.copy()
        
        # Resolve interface reference
        if "iface" in route and isinstance(route["iface"], dict):
            iface_ref = route["iface"]
            hardware_name = iface_ref.get("hardwareName")
            iface_name = iface_ref.get("name")
            iface_type = iface_ref.get("type")

            intf_obj = None

            if hardware_name:
                # Look up interface by hardware name (fast path)
                success, intf_obj = self.get_interface_by_hardware_name(hardware_name)
                if not (success and isinstance(intf_obj, dict)):
                    return False, f"Could not resolve interface by hardwareName: {hardware_name}"
            else:
                # Fallback: resolve by logical name (needed for bridgegroupinterface, etc.)
                success, intf_obj = self.get_interface_by_name(str(iface_name or ""), iface_type=str(iface_type or ""))
                if not (success and isinstance(intf_obj, dict)):
                    return False, f"Could not resolve interface by name: {iface_name}"

            # Hard validation: if id is missing, FDM will throw "UUID null"
            intf_id = intf_obj.get("id")
            if not intf_id:
                return False, f"Resolved interface has no id (would become UUID null): {intf_obj.get('name')}"

            # Use minimal reference with id and version
            resolved_route["iface"] = {
                "version": intf_obj.get("version"),
                "name": intf_obj.get("name"),
                "hardwareName": intf_obj.get("hardwareName"),
                "id": intf_id,
                "type": intf_obj.get("type"),
            }

        
        # Resolve network object references in networks array
        if 'networks' in route:
            resolved_networks = []
            for net_ref in route['networks']:
                net_name = net_ref.get('name')
                
                # Special case: any-ipv4 is a built-in object
                if net_name == 'any-ipv4':
                    success, net_obj = self.get_network_object_by_name('any-ipv4')
                    if success and isinstance(net_obj, dict):
                        resolved_networks.append({
                            "version": net_obj.get('version'),
                            "name": net_obj.get('name'),
                            "id": net_obj.get('id'),
                            "type": "networkobject"
                        })
                    else:
                        return False, "Could not resolve built-in object: any-ipv4"
                else:
                    success, net_obj = self.get_network_object_by_name(net_name)
                    if success and isinstance(net_obj, dict):
                        resolved_networks.append({
                            "version": net_obj.get('version'),
                            "name": net_obj.get('name'),
                            "id": net_obj.get('id'),
                            "type": "networkobject"
                        })
                    else:
                        return False, f"Could not resolve network object: {net_name}"
            
            resolved_route['networks'] = resolved_networks
        
        # Resolve gateway network object reference
        if 'gateway' in route:
            gw_ref = route['gateway']
            gw_name = gw_ref.get('name')
            
            success, gw_obj = self.get_network_object_by_name(gw_name)
            if success and isinstance(gw_obj, dict):
                resolved_route['gateway'] = {
                    "version": gw_obj.get('version'),
                    "name": gw_obj.get('name'),
                    "id": gw_obj.get('id'),
                    "type": "networkobject"
                }
            else:
                return False, f"Could not resolve gateway object: {gw_name}"
        
        return True, resolved_route

    def create_static_route(self, route: Dict) -> Tuple[bool, Optional[str]]:
        """
        Create a static route in FTD.

        Args:
            route: Dictionary containing static route data (with minimal object references)

        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        success, vr_id = self.get_default_virtual_router_id()
        if not success:
            self.record_stat("routes_failed")
            return False, f"Failed to get virtual router ID: {vr_id}"

        success, resolved_route = self.resolve_route_references(route)
        if not success:
            self.record_stat("routes_failed")
            return False, f"Failed to resolve references: {resolved_route}"

        endpoint = f"{self.base_url}/devices/default/routing/virtualrouters/{vr_id}/staticrouteentries"
        return self._create_api_object(endpoint, cast(Dict[str, Any], resolved_route), "routes")
    
    def create_access_rule(self, rule: Dict) -> Tuple[bool, Optional[str]]:
        """
        Create an access rule (firewall policy) in FTD.

        Args:
            rule: Dictionary containing access rule data

        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        return self._create_api_object(
            f"{self.base_url}/policy/accesspolicies/default/accessrules", rule, "rules",
        )
    
    def get_interface_by_name(self, name: str, iface_type: Optional[str] = None) -> Tuple[bool, Union[Dict[str, Any], str]]:
        """
        Resolve an interface by *logical name* when hardwareName is not available.

        This is primarily needed for interface types like bridgegroupinterface, where FDM objects
        may not include a hardwareName, but routes still require a valid interface UUID (id).

        Args:
            name: Interface logical name (e.g., "Bull_uplink", "BVI10", etc.)
            iface_type: Optional expected interface type (e.g., "bridgegroupinterface")

        Returns:
            Tuple of (success: bool, interface dict or error message)
        """
        search = (name or "").strip()
        if not search:
            return False, "Empty interface name"

        # Ensure caches are populated
        self.prefetch_interface_cache()

        # 1) If explicitly bridge-group, check bridge-group cache first
        if iface_type == "bridgegroupinterface":
            bg = self._bridge_group_cache.get(search)
            if bg:
                return True, bg
            return False, f"Bridge-group interface {search} not found"

        # 2) Check physical/etherchannel caches by *name* (not hardwareName)
        for d in (self._physical_interface_cache, self._etherchannel_cache):
            for obj in d.values():
                if (obj.get("name") or "").strip() == search:
                    return True, obj

        # 3) Check bridge-group cache by name as a fallback
        bg = self._bridge_group_cache.get(search)
        if bg:
            return True, bg

        return False, f"Interface {search} not found"


    def get_physical_interface(self, hardware_name: str) -> Tuple[bool, Union[Dict[str, Any], str]]:
        """
        Get a physical interface by hardware name to retrieve its ID.
        
        Args:
            hardware_name: Hardware name (e.g., 'Ethernet1/1')
            
        Returns:
            Tuple of (success: bool, interface dict or error message)
        """
        endpoint = f"{self.base_url}/devices/default/interfaces"

        # Normalize the hardware name for comparison (case-insensitive)
        search_name = hardware_name.lower().strip()

        # Use the shared pagination helper to get all interfaces
        ok, all_interfaces = self.get_paged_items(endpoint)
        if not ok or not isinstance(all_interfaces, list):
            return False, str(all_interfaces)

        # Search for the interface (case-insensitive)
        for intf in all_interfaces:
            intf_hardware = intf.get('hardwareName', '').lower().strip()
            if intf_hardware == search_name:
                return True, intf

        # Interface not found - this might be because it's disabled/unconfigured
        return False, f"Interface {hardware_name} not found (may be disabled or not present on this device)"
        
    def get_interface_by_hardware_name(self, hardware_name: str) -> Tuple[bool, Union[Dict[str, Any], str]]:
        """
        Get any interface (physical, subinterface, etherchannel, bridge group) by hardware name.
        
        Args:
            hardware_name: Hardware name (e.g., 'Ethernet1/1', 'Port-channel1.100')
            
        Returns:
            Tuple of (success: bool, interface dict or error message)
        """
        # Try physical interfaces cache first
        if hardware_name in self._physical_interface_cache:
            return True, self._physical_interface_cache[hardware_name]
        
        # Try etherchannel cache
        if hardware_name in self._etherchannel_cache:
            return True, self._etherchannel_cache[hardware_name]
        
        # Check if this looks like a subinterface (contains a dot like "Port-channel1.108")
        is_subinterface = '.' in hardware_name

        # Try all physical interfaces endpoint first (paginated)
        endpoint = f"{self.base_url}/devices/default/interfaces"
        ok, fetched = self.get_paged_items(endpoint, page_limit=200)
        items: List[Dict] = fetched if ok and isinstance(fetched, list) else []

        for intf in items:
            if intf.get('hardwareName') == hardware_name:
                # Cache it for future lookups
                self._physical_interface_cache[hardware_name] = intf
                return True, intf

        # Fetch all etherchannels once (paginated); used for both the
        # subinterface parent search and the direct etherchannel match.
        ec_endpoint = f"{self.base_url}/devices/default/etherchannelinterfaces"
        ok, fetched = self.get_paged_items(ec_endpoint, page_limit=100)
        etherchannels: List[Dict] = fetched if ok and isinstance(fetched, list) else []

        # If it's a subinterface, search subinterfaces under physical interfaces
        if is_subinterface:
            # Extract parent hardware name (e.g., "Port-channel1" from "Port-channel1.108")
            parent_hw_name = hardware_name.split('.')[0]

            # First check if parent is an etherchannel
            for ec in etherchannels:
                if ec.get('hardwareName') == parent_hw_name:
                    # Found parent etherchannel, now get its subinterfaces
                    parent_id = ec.get('id')
                    sub_endpoint = f"{self.base_url}/devices/default/etherchannelinterfaces/{parent_id}/subinterfaces"
                    ok, subinterfaces = self.get_paged_items(sub_endpoint, page_limit=100)
                    if ok and isinstance(subinterfaces, list):
                        for sub in subinterfaces:
                            if sub.get('hardwareName') == hardware_name:
                                return True, sub

            # Check if parent is a physical interface
            for intf in items:
                if intf.get('hardwareName') == parent_hw_name:
                    # Found parent physical interface, now get its subinterfaces
                    parent_id = intf.get('id')
                    sub_endpoint = f"{self.base_url}/devices/default/interfaces/{parent_id}/subinterfaces"
                    ok, subinterfaces = self.get_paged_items(sub_endpoint, page_limit=100)
                    if ok and isinstance(subinterfaces, list):
                        for sub in subinterfaces:
                            if sub.get('hardwareName') == hardware_name:
                                return True, sub

        # Also try a direct etherchannel match
        for intf in etherchannels:
            if intf.get('hardwareName') == hardware_name:
                self._etherchannel_cache[hardware_name] = intf
                return True, intf

        return False, f"Interface not found: {hardware_name}"
    
    def _apply_model_specific_media_defaults(self, existing_intf: Dict, update_payload: Dict,) -> None:
        """
        Apply platform/model-specific media defaults for copper (non-SFP) interfaces.

        Why:
            Some platforms (notably 3100-series like FTD 3120) do not accept speedType='AUTO'
            on copper ports the same way smaller platforms (e.g., 1010) do. Instead they expect:
                - explicit speedType (HUNDRED/THOUSAND, etc.)
                - auto-negotiation enabled

        This helper makes the behavior deterministic and keeps the branching localized.

        Args:
            existing_intf: The current interface object fetched from FDM (source of truth)
            update_payload: The PUT payload being assembled (mutated in place)

        Returns:
            None
        """
        model = str(getattr(self, "appliance_model", "generic")).lower().strip()

        # Treat DETECT_SFP / SFP_DETECT as SFP - we don't override those here.
        speed = str(existing_intf.get("speedType", "")).upper()
        if speed in {"DETECT_SFP", "SFP_DETECT"}:
            return

        if is_ftd_1000(model):
            # 1000-series: autoNeg field must be null/omitted
            # Remove autoNeg fields if present (they cause API errors)
            update_payload.pop("autoNeg", None)
            update_payload.pop("autoNegotiation", None)
            # Use AUTO speed and duplex
            update_payload["speedType"] = "AUTO"
            update_payload["duplexType"] = "AUTO"
            
        elif is_ftd_3100(model):
            # 3100-series: Require explicit speed + autoNeg enabled
            update_payload["autoNegotiation"] = True
            update_payload["autoNeg"] = True
            # Keep existing explicit speed if present, otherwise default to THOUSAND
            explicit_ok = {"TEN", "HUNDRED", "THOUSAND", "TEN_THOUSAND"}
            if speed in explicit_ok:
                update_payload["speedType"] = speed
            else:
                update_payload["speedType"] = "THOUSAND"
            update_payload["duplexType"] = "AUTO"
            
        else:
            # Default behavior for 2000-series and unknown platforms
            # Use AUTO speed and duplex, set autoNeg if platform supports it
            update_payload["speedType"] = "AUTO"
            update_payload["duplexType"] = "AUTO"
            # Try setting autoNeg - some platforms may ignore it
            update_payload["autoNegotiation"] = True

    def update_physical_interface(self, intf: Dict) -> Tuple[bool, Optional[str]]:
        """
        Update a physical interface in FTD (PUT request).
        
        Physical interfaces already exist in FTD - we update them with
        name, description, IP address, etc.
        
        IMPORTANT: This method handles:
        - Converting switchport mode to routed mode (required for L3 config)
        - Preserving existing hardware settings (speed, duplex, FEC, auto-negotiation)
        
        Args:
            intf: Dictionary containing physical interface data
            
        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        hardware_name = intf.get('hardwareName')
        
        # First, get the existing interface to retrieve its ID and version
        if not isinstance(hardware_name, str) or not hardware_name.strip():
            self.record_stat("physical_interfaces_failed")
            return False, "Missing or invalid hardwareName"

        success, existing = self.get_physical_interface(hardware_name)
        if not success or not isinstance(existing, dict):
            # Interface not found - skip it instead of failing
            self.record_stat("physical_interfaces_skipped")
            return True, f"SKIPPED: {existing}"
        
        # Merge our updates with the existing interface
        intf_id = existing.get('id')
        if not intf_id:
            self.record_stat("physical_interfaces_failed")
            return False, f"Resolved interface {hardware_name} has no ID"
        
        # Check if interface is in switchport mode
        current_mode = existing.get('mode', None)
        is_switchport = current_mode == 'SWITCHPORT' or existing.get('switchPortMode') is not None
        
        # If interface is a switchport and we want to configure it as routed,
        # we need to change it to routed mode first
        if is_switchport:
            if self.debug:
                print(f"\n      [DEBUG] Interface {hardware_name} switchport details:")
                print(f"              Mode: {current_mode}")
                print(f"              SwitchPortMode: {existing.get('switchPortMode')}")
                print(f"              Has VLAN config: {existing.get('vlanId') is not None}")
            
            print(f"\n      [INFO] {hardware_name} is in switchport mode, converting to routed mode...", end=" ")
            
            convert_success, convert_msg = self._convert_switchport_to_routed(existing)
            if not convert_success:
                self.record_stat("physical_interfaces_failed")
                if self.debug:
                    print(f"\n      [DEBUG] Conversion failure details: {convert_msg}")
                return False, f"Failed to convert from switchport: {convert_msg}"
            
            print("[OK]")
            
            # Re-fetch the interface after mode change to get updated version
            success, existing = self.get_physical_interface(hardware_name)
            if not success or not isinstance(existing, dict):
                self.record_stat("physical_interfaces_failed")
                return False, f"Failed to re-fetch interface after mode change: {existing}"
            
            intf_id = existing.get('id')
            if not intf_id:
                self.record_stat("physical_interfaces_failed")
                return False, f"Interface {hardware_name} has no ID after mode conversion"
        
        # Start with the existing interface configuration
        # This preserves ALL existing settings including hardware config
        update_payload = existing.copy()
        
        # Only update the fields we want to change (logical config)
        # Name - only update if we have a name to set
        if intf.get('name'):
            update_payload['name'] = intf['name']
        
        # Description - only update if provided
        if 'description' in intf:
            update_payload['description'] = intf.get('description', '')
        
        # Enabled - only update if explicitly provided
        if 'enabled' in intf:
            update_payload['enabled'] = intf['enabled']
        
        # Update IPv4 if provided
        if 'ipv4' in intf and intf['ipv4'] is not None:
            update_payload['ipv4'] = intf['ipv4']
        
        # Update MTU if provided (cap at 9000 - FTD maximum for most interfaces)
        if 'mtu' in intf and intf['mtu'] is not None:
            mtu_value = intf['mtu']
            if mtu_value > 9000:
                mtu_value = 9000
            update_payload['mtu'] = mtu_value
        
        # Ensure mode is set to ROUTED for L3 interfaces
        # (This should already be set after conversion, but ensure it)
        if 'ipv4' in intf and intf['ipv4'] is not None:
            update_payload['mode'] = 'ROUTED'
        
        # Get current interface speed type to determine if SFP or copper
        current_speed = existing.get("speedType", "AUTO")
        is_sfp_port = current_speed in {"DETECT_SFP", "SFP_DETECT"}
        
        # Get appliance model for platform-specific behavior
        model = str(getattr(self, "appliance_model", "generic")).lower().strip()
        # Handle speed/duplex/autoNeg settings based on port type and platform
        # CRITICAL: SFP ports must preserve SFP_DETECT speed - never override!
        if is_sfp_port:
            # SFP interface - preserve existing speed, use FULL duplex
            update_payload["speedType"] = current_speed
            update_payload["duplexType"] = "FULL"
            if 'fecMode' in existing:
                update_payload["fecMode"] = "AUTO"
            # Only set autoNeg for platforms that support it
            if not is_ftd_1000(model):
                update_payload["autoNegotiation"] = True
                update_payload["autoNeg"] = True
            else:
                update_payload.pop("autoNeg", None)
                update_payload.pop("autoNegotiation", None)
        else:
            # Copper interface - apply platform-specific defaults
            # Only apply converter's duplex/autoNeg if NOT on a platform that needs special handling
            if is_ftd_3100(model):
                # 3100-series copper: preserve existing speed, use FULL duplex
                explicit_ok = {'TEN', 'HUNDRED', 'THOUSAND', 'TEN_THOUSAND'}
                if current_speed in explicit_ok:
                    update_payload['speedType'] = current_speed
                else:
                    update_payload['speedType'] = 'THOUSAND'
                update_payload['duplexType'] = 'FULL'
                update_payload['autoNegotiation'] = True
                update_payload['autoNeg'] = True
            elif is_ftd_1000(model):
                # 1000-series copper: AUTO speed, no autoNeg field
                update_payload['speedType'] = 'AUTO'
                update_payload['duplexType'] = 'AUTO'
                update_payload.pop("autoNeg", None)
                update_payload.pop("autoNegotiation", None)
            else:
                # Default/2000-series: use converter settings or AUTO
                if 'duplexType' in intf:
                    update_payload['duplexType'] = intf['duplexType']
                if 'autoNegotiation' in intf:
                    update_payload['autoNegotiation'] = intf['autoNegotiation']
        
        # If this is an EtherChannel member prep (name is empty string),
        # ensure name is cleared and CTS/TrustSec is disabled.
        if intf.get('name') == '':
            update_payload['name'] = ''
            cts_fields_changed = self._disable_cts_settings_for_member_prep(update_payload)
            if self.debug and cts_fields_changed > 0:
                print(f"\n      [DEBUG] Cleared/disabled {cts_fields_changed} CTS-related field(s) on {hardware_name}")

        
        # Remove switchport-specific fields if present (they're not valid in routed mode)
        switchport_fields = ['switchPortMode', 'switchPortConfig', 'nativeVlan',
                            'allowedVlans', 'voiceVlan', 'spanningTreePortfast']
        for field in switchport_fields:
            update_payload.pop(field, None)

        # Always disable propagateSecurityGroupTag on all interfaces
        update_payload['propagateSecurityGroupTag'] = False

        # HA monitoring: enable only on standalone physical interfaces,
        # disable on etherchannel member preps (subinterfaces handled separately)
        if intf.get('name') == '':
            # EtherChannel member prep - only the etherchannel itself should be monitored
            update_payload['monitorInterface'] = False
        else:
            # Standalone physical interface - enable HA monitoring
            update_payload['monitorInterface'] = True

        endpoint = f"{self.base_url}/devices/default/interfaces/{intf_id}"
        
        try:
            response = self.session.put(endpoint, json=update_payload, timeout=30)
            
            if response.status_code in [200, 201]:
                updated_obj = response.json()
                self.record_stat("physical_interfaces_updated")
                return True, updated_obj.get("id")
            elif response.status_code == 422:
                error_msg = self._extract_error_message(response)
                self.record_stat("physical_interfaces_failed")
                return False, error_msg
            else:
                self.record_stat("physical_interfaces_failed")
                error_msg = f"HTTP {response.status_code}: {self._extract_error_message(response)}"
                return False, error_msg
                
        except (ValueError, TypeError, KeyError) as e:
            self.record_stat("physical_interfaces_failed")
            return False, f"Invalid interface update response payload: {e}"
        except requests.exceptions.RequestException as e:
            self.record_stat("physical_interfaces_failed")
            return False, str(e)
    
    def _convert_switchport_to_routed(self, intf: Dict) -> Tuple[bool, str]:
        """
        Convert a physical interface from switchport mode to routed mode.
        
        This is required before configuring L3 settings (IP address, etc.)
        on an interface that is in switchport mode by default.
        
        Args:
            intf: The existing interface configuration from FTD
            
        Returns:
            Tuple of (success: bool, error_message: str)
        """
        intf_id = intf.get('id')
        
        if not intf_id:
            return False, "Interface has no ID"
        
        # Build a minimal payload to change the mode
        # We need to preserve required fields but change mode to ROUTED
        convert_payload = intf.copy()
        
        # Set mode to ROUTED
        convert_payload['mode'] = 'ROUTED'
        
        # Remove ALL switchport-specific fields that conflict with ROUTED mode
        # This list must be comprehensive to avoid 422 validation errors
        switchport_fields = [
            'switchPortMode',       # Access/trunk mode
            'switchPortConfig',     # Switchport configuration object
            'nativeVlan',           # Native VLAN (trunk only)
            'allowedVlans',         # Allowed VLAN list
            'voiceVlan',            # Voice VLAN
            'spanningTreePortfast', # STP portfast
            'stpGuardType',         # STP guard (root/loop/bpdu)
            'stpPathCost',          # STP path cost
            'stpPortPriority',      # STP port priority
            'vlanId'                # VLAN assignment for switchport
        ]
        for field in switchport_fields:
            convert_payload.pop(field, None)
        
        # Clear any VLAN-related config
        convert_payload.pop('vlanId', None)
        
        endpoint = f"{self.base_url}/devices/default/interfaces/{intf_id}"
        
        try:
            response = self.session.put(endpoint, json=convert_payload, timeout=30)
            
            if response.status_code in [200, 201]:
                return True, ""
            elif response.status_code == 422:
                error_msg = self._extract_error_message(response)
                return False, f"HTTP 422: {error_msg}"
            else:
                return False, f"HTTP {response.status_code}: {self._extract_error_message(response)}"
                
        except requests.exceptions.RequestException as e:
            return False, str(e)
    
    def create_subinterface(self, intf: Dict) -> Tuple[bool, Optional[str]]:
        """
        Create a subinterface (VLAN interface) in FTD.
        
        Subinterfaces in FTD require a reference to their parent interface.
        The parent can be a physical interface or an etherchannel.
        
        Endpoints:
        - Physical interface parent: POST /devices/default/interfaces/{parentId}/subinterfaces
        - EtherChannel parent: POST /devices/default/etherchannelinterfaces/{parentId}/subinterfaces
        
        Args:
            intf: Dictionary containing subinterface data
            
        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        # Extract parent interface info from hardware name
        # Hardware name format: "Ethernet1/1.100" or "Port-channel1.100"
        hardware_name = intf.get('hardwareName', '')
        
        if '.' not in hardware_name:
            self.record_stat("subinterfaces_failed")
            return False, f"Invalid hardwareName format: {hardware_name} (expected parent.vlanid)"
        
        parent_hardware, vlan_str = hardware_name.rsplit('.', 1)
        
        try:
            vlan_id = int(vlan_str)
        except ValueError:
            self.record_stat("subinterfaces_failed")
            return False, f"Invalid VLAN ID: {vlan_str}"
        
        # We need to find the parent interface ID
        # Check if parent is an etherchannel (Port-channel) or physical interface
        # Based on hardware name pattern
        parent_is_etherchannel = parent_hardware.lower().startswith('port-channel')
        
        if self.debug:
            print("\n      [DEBUG] Parent interface lookup:")
            print(f"              Hardware name: {parent_hardware}")
            print(f"              Type: {'EtherChannel' if parent_is_etherchannel else 'Physical'}")
        
        # USE CACHED LOOKUPS for performance
        if parent_is_etherchannel:
            # Try to find it as an etherchannel (from cache)
            success, parent_intf = self.get_cached_etherchannel(parent_hardware)
            if self.debug and not success:
                print("              Result: EtherChannel not found in cache")
        else:
            # Try to find it as a physical interface (from cache)
            success, parent_intf = self.get_cached_physical_interface(parent_hardware)
            if self.debug and not success:
                print("              Result: Physical interface not found in cache")
        
        if not success:
            # Parent interface not found - skip
            self.record_stat("subinterfaces_skipped")
            if self.debug:
                print("              Skipping subinterface creation (parent not available)")
            return True, f"SKIPPED: Parent interface {parent_hardware} not found"

        if not isinstance(parent_intf, dict):
            self.record_stat("subinterfaces_failed")
            return False, f"Resolved parent interface is invalid: {parent_intf}"
        
        if self.debug:
            print(f"              Found: {parent_intf.get('name')} (ID: {parent_intf.get('id')})")
        
        parent_id = parent_intf.get('id')
        if not parent_id:
            self.record_stat("subinterfaces_failed")
            return False, f"Parent interface {parent_hardware} has no ID"

        parent_type = parent_intf.get('type', 'physicalinterface')
        
        # Get interface name - ensure it's valid
        subintf_name = intf.get('name', '')
        if not subintf_name:
            subintf_name = f"vlan{vlan_id}"
        
        # Get MTU (cap at 9000 - FTD maximum)
        mtu_value = intf.get('mtu', 1500)
        if mtu_value > 9000:
            mtu_value = 9000
        
        # Build the subinterface payload - FTD FDM API format
        subintf_payload = {
            "name": subintf_name,
            "subIntfId": vlan_id,
            "vlanId": vlan_id,
            "type": "subinterface",
            "enabled": intf.get('enabled', True),
            "managementOnly": False,
            "mtu": mtu_value,
            "parentInterface": {
                "id": parent_id,
                "type": parent_type
            }
        }
        
        # Add description if provided
        if intf.get('description'):
            subintf_payload['description'] = str(intf['description'])
        
        # Add IPv4 if provided
        if intf.get('ipv4'):
            ipv4_data = intf['ipv4']
            ip_address_obj = ipv4_data.get('ipAddress', {})
            
            ip_addr = None
            netmask = None
            
            if isinstance(ip_address_obj, dict):
                ip_addr = ip_address_obj.get('ipAddress')
                netmask = ip_address_obj.get('netmask')
            
            if ip_addr and netmask:
                subintf_payload['ipv4'] = {
                    "ipType": "STATIC",
                    "defaultRouteUsingDHCP": False,
                    "ipAddress": {
                        "ipAddress": ip_addr,
                        "netmask": netmask,
                        "type": "haipv4address"
                    },
                    "type": "interfaceipv4"
                }
        
        # Always disable propagateSecurityGroupTag and HA monitoring on subinterfaces
        subintf_payload['propagateSecurityGroupTag'] = False
        subintf_payload['monitorInterface'] = False

        # Print debug info
        if self.debug:
            print(f"\n      [DEBUG] Subinterface payload: {subintf_payload}")

        # DIFFERENT ENDPOINTS for physical vs etherchannel parents
        if parent_is_etherchannel:
            # EtherChannel parent: /devices/default/etherchannelinterfaces/{parentId}/subinterfaces
            endpoint = f"{self.base_url}/devices/default/etherchannelinterfaces/{parent_id}/subinterfaces"
        else:
            # Physical interface parent: /devices/default/interfaces/{parentId}/subinterfaces
            endpoint = f"{self.base_url}/devices/default/interfaces/{parent_id}/subinterfaces"
        
        if self.debug:
            print(f"      [DEBUG] Endpoint: {endpoint}")
            print(f"      [DEBUG] Parent type: {'EtherChannel' if parent_is_etherchannel else 'Physical'}")
        
        try:
            response = self.session.post(endpoint, json=subintf_payload, timeout=30)
            
            if response.status_code in [200, 201]:
                created_obj = response.json()
                self.record_stat("subinterfaces_created")
                return True, created_obj.get("id")
            elif response.status_code == 422:
                # The duplicate may be keyed on the VLAN ID under this parent
                # rather than the logical name. The endpoint is already
                # parent-scoped, so matching on vlanId/subIntfId is safe.
                return self._handle_422_conflict(
                    response, endpoint, subintf_payload, "subinterfaces",
                    match=(lambda o: o.get('vlanId') == vlan_id or o.get('subIntfId') == vlan_id),
                    error_prefix="422: ",
                )
            else:
                self.record_stat("subinterfaces_failed")
                return False, f"HTTP {response.status_code}: {self._extract_error_message(response)}"
                
        except requests.exceptions.RequestException as e:
            self.record_stat("subinterfaces_failed")
            return False, str(e)
    
    def _get_etherchannel_by_hardware(self, hardware_name: str) -> Tuple[bool, Union[Dict[str, Any], str]]:
        """
        Get an etherchannel interface by hardware name.
        
        Args:
            hardware_name: Hardware name (e.g., 'Port-channel1')
            
        Returns:
            Tuple of (success: bool, interface dict or error message)
        """
        endpoint = f"{self.base_url}/devices/default/etherchannelinterfaces"
        search_name = hardware_name.lower().strip()

        ok, interfaces = self.get_paged_items(endpoint)
        if not ok or not isinstance(interfaces, list):
            return False, str(interfaces)

        for intf in interfaces:
            intf_hardware = intf.get('hardwareName', '').lower().strip()
            if intf_hardware == search_name:
                return True, intf

        return False, f"EtherChannel {hardware_name} not found"
    
    def create_etherchannel(self, intf: Dict) -> Tuple[bool, Optional[str]]:
        """
        Create an EtherChannel (port-channel) interface in FTD.
        
        Args:
            intf: Dictionary containing etherchannel data
            
        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        endpoint = f"{self.base_url}/devices/default/etherchannelinterfaces"
        
        # Cap MTU at 9000 if present
        if 'mtu' in intf and intf['mtu'] is not None:
            if intf['mtu'] > 9000:
                intf['mtu'] = 9000
        
        # For etherchannels, we need to resolve member interface IDs
        # Also get the speedType from the first member interface
        member_speed_type = None
        is_sfp_member = False
        if 'memberInterfaces' in intf:
            requested_members = intf['memberInterfaces']
            resolved_members = []
            for member in requested_members:
                hardware_name = member.get('hardwareName')
                success, existing = self.get_physical_interface(hardware_name)
                if success and isinstance(existing, dict):
                    resolved_members.append({
                        "id": existing.get('id'),
                        "type": "physicalinterface"
                    })
                    # Get speedType from first member interface
                    if member_speed_type is None:
                        member_speed_type = existing.get('speedType')
                        if member_speed_type in {'DETECT_SFP', 'SFP_DETECT'}:
                            is_sfp_member = True
                else:
                    print(f"    Warning: Could not resolve member {hardware_name}")
            intf['memberInterfaces'] = resolved_members

            # Fail outright when members were requested but NONE resolved -
            # creating an empty etherchannel would silently drop the intent.
            # (Warn-and-continue only when at least some members resolved.)
            if requested_members and not resolved_members:
                self.record_stat("etherchannels_failed")
                return False, "No valid member interfaces found (all members failed to resolve)"
        
        # Get appliance model for platform-specific behavior
        model = str(getattr(self, "appliance_model", "generic")).lower().strip()
        # Set speedType and duplexType based on member interfaces and platform
        # CRITICAL: Use correct field names (speedType, duplexType) NOT (speed, duplex)
        if is_sfp_member:
            # SFP members - use SFP_DETECT speed
            intf['speedType'] = member_speed_type  # Preserve SFP_DETECT
            intf['duplexType'] = 'FULL'
            if not is_ftd_1000(model):
                intf['autoNeg'] = True
        elif is_ftd_3100(model):
            # 3100-series: Cannot use AUTO speed, use explicit speed
            explicit_ok = {'TEN', 'HUNDRED', 'THOUSAND', 'TEN_THOUSAND'}
            if member_speed_type in explicit_ok:
                intf['speedType'] = member_speed_type
            else:
                intf['speedType'] = 'TEN_THOUSAND'  # Default for 3100-series
            intf['duplexType'] = 'FULL'
            intf['autoNeg'] = True
        elif is_ftd_1000(model):
            # 1000-series: Support AUTO speed, no autoNeg field
            intf['speedType'] = 'AUTO'
            intf['duplexType'] = 'AUTO'
            # Don't set autoNeg - not supported
        else:
            # Default/2000-series: use AUTO or member speed
            if member_speed_type and member_speed_type != 'AUTO':
                intf['speedType'] = member_speed_type
            else:
                intf['speedType'] = 'AUTO'
            intf['duplexType'] = 'AUTO'
            intf['autoNeg'] = True
        
        # Remove old incorrect field names if present
        intf.pop('speed', None)
        intf.pop('duplex', None)

        # Always disable propagateSecurityGroupTag
        intf['propagateSecurityGroupTag'] = False
        # Enable HA monitoring on the etherchannel itself
        intf['monitorInterface'] = True

        try:
            response = self.session.post(endpoint, json=intf, timeout=30)

            if response.status_code in [200, 201]:
                created_obj = response.json()
                self.record_stat("etherchannels_created")
                return True, created_obj.get("id")
            elif response.status_code == 422:
                # The duplicate may be keyed on the Port-channel ID rather
                # than the logical name, so also match on hardwareName
                # (e.g. "Port-channel1").
                ec_hw = str(intf.get('hardwareName', '')).lower().strip()
                return self._handle_422_conflict(
                    response, endpoint, intf, "etherchannels",
                    match=(lambda o: bool(ec_hw) and str(o.get('hardwareName', '')).lower().strip() == ec_hw),
                )
            else:
                self.record_stat("etherchannels_failed")
                error_msg = f"HTTP {response.status_code}: {self._extract_error_message(response)}"
                return False, error_msg

        except (ValueError, TypeError, KeyError) as e:
            self.record_stat("etherchannels_failed")
            return False, f"Invalid etherchannel response payload: {e}"
        except requests.exceptions.RequestException as e:
            self.record_stat("etherchannels_failed")
            return False, str(e)

    def create_bridge_group(self, intf: Dict) -> Tuple[bool, Optional[str]]:
        """
        Create a Bridge Group interface in FTD.
        
        Bridge groups require member interfaces to be:
        1. In ROUTED mode (FTD automatically manages bridge membership)
        2. Referenced by ID (not hardware name)
        
        Args:
            intf: Dictionary containing bridge group data
            
        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        endpoint = f"{self.base_url}/devices/default/bridgegroupinterfaces"
        
        # Cap MTU at 9000 if present
        if 'mtu' in intf and intf['mtu'] is not None:
            if intf['mtu'] > 9000:
                intf['mtu'] = 9000
        
        # CRITICAL: Resolve member interface IDs
        # The converter provides hardware names, but the API requires IDs
        # Bridge groups use "selectedInterfaces" field (not "memberInterfaces")
        if 'selectedInterfaces' in intf:
            resolved_members = []
            for member in intf['selectedInterfaces']:
                hardware_name = member.get('hardwareName')
                
                # Look up the physical interface by hardware name
                success, existing = self.get_physical_interface(hardware_name)
                if success and isinstance(existing, dict):
                    # Add the member with ID reference
                    # Note: Member should be in ROUTED mode - FTD will manage bridge membership
                    resolved_members.append({
                        "id": existing.get('id'),
                        "type": "physicalinterface"
                    })
                    
                    if self.debug:
                        current_mode = existing.get('mode')
                        print(f"\n      [DEBUG] Resolved member: {hardware_name} -> ID {existing.get('id')} (mode: {current_mode})")
                else:
                    # Member interface not found - this is a problem
                    print(f"\n      [WARNING] Could not resolve member {hardware_name}")
                    if self.debug:
                        print(f"                Error: {existing}")
            
            # Update the interface config with resolved member IDs
            # Use "selectedInterfaces" for bridge groups (API requirement)
            intf['selectedInterfaces'] = resolved_members
            
            if not resolved_members:
                self.record_stat("bridge_groups_failed")
                return False, "No valid member interfaces found (all members failed to resolve)"
        
        if self.debug:
            print("\n      [DEBUG] Bridge group payload:")
            print(f"                Name: {intf.get('name')}")
            print(f"                Members: {len(intf.get('selectedInterfaces', []))}")
        
        try:
            response = self.session.post(endpoint, json=intf, timeout=30)
            
            if response.status_code in [200, 201]:
                created_obj = response.json()
                self.record_stat("bridge_groups_created")
                return True, created_obj.get("id")
            elif response.status_code == 422:
                return self._handle_422_conflict(
                    response, endpoint, intf, "bridge_groups",
                )
            else:
                self.record_stat("bridge_groups_failed")
                error_msg = f"HTTP {response.status_code}: {self._extract_error_message(response)}"
                return False, error_msg
                
        except (ValueError, TypeError, KeyError) as e:
            self.record_stat("bridge_groups_failed")
            return False, f"Invalid bridge-group response payload: {e}"
        except requests.exceptions.RequestException as e:
            self.record_stat("bridge_groups_failed")
            return False, str(e)
        
    def create_security_zone(self, zone: Dict) -> Tuple[bool, Optional[str]]:
        """
        Create a security zone in FTD.
        
        Security zones are required for firewall policies. Each interface
        used in access rules must be assigned to a security zone.
        
        Args:
            zone: Dictionary containing security zone data
            
        Returns:
            Tuple of (success: bool, object_id: str or error message)
        """
        endpoint = f"{self.base_url}/object/securityzones"
        
        # Build the zone payload - resolve interface references
        zone_payload = {
            "name": zone.get("name"),
            "description": zone.get("description", ""),
            "mode": zone.get("mode", "ROUTED"),
            "type": "securityzone"
        }
        
        # Resolve interface references if present
        if "interfaces" in zone and zone["interfaces"]:
            resolved_interfaces = []
            for intf_ref in zone["interfaces"]:
                hardware_name = intf_ref.get("hardwareName")
                intf_type = intf_ref.get("type", "physicalinterface")
                
                # Try to get the interface ID from FTD
                if hardware_name:
                    success, intf_obj = self.get_interface_by_hardware_name(hardware_name)
                    if success and isinstance(intf_obj, dict):
                        resolved_interfaces.append({
                            "id": intf_obj.get("id"),
                            "name": intf_obj.get("name"),
                            "hardwareName": intf_obj.get("hardwareName"),
                            "type": intf_obj.get("type", intf_type)
                        })
                    else:
                        if self.debug:
                            print(f"\n      [DEBUG] Interface not found: {hardware_name}")
            
            if resolved_interfaces:
                zone_payload["interfaces"] = resolved_interfaces
        
        if self.debug:
            print("\n      [DEBUG] Creating security zone:")
            print(f"              Name: {zone_payload.get('name')}")
            print(f"              Interfaces: {len(zone_payload.get('interfaces', []))}")
        
        try:
            response = self.session.post(endpoint, json=zone_payload, timeout=30)
            
            if response.status_code in [200, 201]:
                created_obj = response.json()
                self.record_stat("security_zones_created")
                return True, created_obj.get("id")
            elif response.status_code == 422:
                return self._handle_422_conflict(
                    response, endpoint, zone_payload, "security_zones",
                )
            else:
                self.record_stat("security_zones_failed")
                error_msg = f"HTTP {response.status_code}: {self._extract_error_message(response)}"
                return False, error_msg

        except (ValueError, TypeError, KeyError) as e:
            self.record_stat("security_zones_failed")
            return False, f"Invalid security-zone response payload: {e}"
        except requests.exceptions.RequestException as e:
            self.record_stat("security_zones_failed")
            return False, str(e)

    def get_network_object_by_name(self, name: str) -> Tuple[bool, Union[Dict[str, Any], str]]:
        """
        Get a network object by name to retrieve its ID and version.
        
        This method first checks the local cache, then uses the FTD API's 
        filter parameter for efficient lookup, with fallback to paginated 
        search if filtering is not supported.
        
        Args:
            name: Network object name
            
        Returns:
            Tuple of (success: bool, network object dict or error message)
        """
        # Check cache first (fastest path)
        if name in self._network_object_cache:
            return True, self._network_object_cache[name]

        endpoint = f"{self.base_url}/object/networks"

        # Shared filter-first + paginated-scan lookup lives in FTDBaseClient.
        found, result = self.find_object_by_name(endpoint, name)
        if found and isinstance(result, dict):
            # Cache for future lookups
            self._network_object_cache[name] = result
            return True, result
        return False, str(result)
    
    def deploy_changes(self) -> bool:
        """
        Deploy pending configuration changes to the FTD device.
        
        After creating/modifying objects, changes must be deployed
        for them to take effect on the firewall.  The returned deployment
        task is polled until it reaches a terminal state.

        Returns:
            True if deployment completed successfully, False otherwise
        """
        print(f"\n{'='*60}")
        print("Deploying configuration changes...")
        print(f"{'='*60}")

        endpoint = f"{self.base_url}/operational/deploy"

        try:
            response = self.session.post(endpoint, json={}, timeout=30)

            if response.status_code in [200, 201, 202]:
                print("  Deployment initiated successfully")
                print("  Note: Deployment may take several minutes to complete")
                # Poll the deployment task until it finishes (shared poller
                # in FTDBaseClient).
                return self.start_and_wait_deployment(response)
            else:
                print(f"FAIL Deployment failed: {response.status_code}")
                print(f"  Response: {self._extract_error_message(response)}")
                return False

        except requests.exceptions.RequestException as e:
            print(f"FAIL Deployment error: {e}")
            return False
    
    def print_statistics(self) -> None:
        """
        Print a summary of import statistics.
        """
        print(f"\n{'='*60}")
        print("IMPORT STATISTICS")
        if self.update_existing:
            print("  (Update-existing mode enabled)")
        print(f"{'='*60}")
        print("\nPhysical Interfaces:")
        print(f"  Updated: {self.stats['physical_interfaces_updated']}")
        print(f"  Skipped: {self.stats['physical_interfaces_skipped']}")
        print(f"  Failed:  {self.stats['physical_interfaces_failed']}")
        print("\nEtherChannels:")
        print(f"  Created: {self.stats['etherchannels_created']}")
        print(f"  Updated: {self.stats['etherchannels_updated']}")
        print(f"  Skipped: {self.stats['etherchannels_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['etherchannels_failed']}")
        print("\nBridge Groups:")
        print(f"  Created: {self.stats['bridge_groups_created']}")
        print(f"  Updated: {self.stats['bridge_groups_updated']}")
        print(f"  Skipped: {self.stats['bridge_groups_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['bridge_groups_failed']}")
        print("\nSubinterfaces:")
        print(f"  Created: {self.stats['subinterfaces_created']}")
        print(f"  Updated: {self.stats['subinterfaces_updated']}")
        print(f"  Skipped: {self.stats['subinterfaces_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['subinterfaces_failed']}")
        print("\nSecurity Zones:")
        print(f"  Created: {self.stats['security_zones_created']}")
        print(f"  Updated: {self.stats['security_zones_updated']}")
        print(f"  Skipped: {self.stats['security_zones_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['security_zones_failed']}")
        print("\nAddress Objects:")
        print(f"  Created: {self.stats['address_objects_created']}")
        print(f"  Updated: {self.stats['address_objects_updated']}")
        print(f"  Skipped: {self.stats['address_objects_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['address_objects_failed']}")
        print("\nAddress Groups:")
        print(f"  Created: {self.stats['address_groups_created']}")
        print(f"  Updated: {self.stats['address_groups_updated']}")
        print(f"  Skipped: {self.stats['address_groups_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['address_groups_failed']}")
        print("\nPort Objects:")
        print(f"  Created: {self.stats['port_objects_created']}")
        print(f"  Updated: {self.stats['port_objects_updated']}")
        print(f"  Skipped: {self.stats['port_objects_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['port_objects_failed']}")
        print("\nPort Groups:")
        print(f"  Created: {self.stats['port_groups_created']}")
        print(f"  Updated: {self.stats['port_groups_updated']}")
        print(f"  Skipped: {self.stats['port_groups_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['port_groups_failed']}")
        print("\nStatic Routes:")
        print(f"  Created: {self.stats['routes_created']}")
        print(f"  Updated: {self.stats['routes_updated']}")
        print(f"  Skipped: {self.stats['routes_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['routes_failed']}")
        print("\nAccess Rules:")
        print(f"  Created: {self.stats['rules_created']}")
        print(f"  Updated: {self.stats['rules_updated']}")
        print(f"  Skipped: {self.stats['rules_skipped']} (already exist)")
        print(f"  Failed:  {self.stats['rules_failed']}")

        exit_code, outcome = self.compute_outcome()
        print(f"\nOutcome: {outcome} (exit code {exit_code})")
        print(f"{'='*60}")

    def print_failure_summary(self) -> None:
        """Print a detailed summary of every item that failed to import."""
        if not self.failed_items:
            return

        print(f"\n{'='*60}")
        print(f"FAILED IMPORTS SUMMARY ({len(self.failed_items)} items)")
        print(f"{'='*60}")

        # Group failures by object type
        by_type: Dict[str, List[Dict[str, str]]] = {}
        for item in self.failed_items:
            obj_type = item["object_type"]
            if obj_type not in by_type:
                by_type[obj_type] = []
            by_type[obj_type].append(item)

        for obj_type, items in by_type.items():
            print(f"\n  {obj_type} ({len(items)} failed):")
            for item in items:
                print(f"    - {item['name']}")
                print(f"      Error: {item['error']}")

        print(f"\n{'='*60}")


def load_json_file(filename: str) -> Optional[List[Dict]]:
    """
    Load a JSON file containing configuration objects.
    
    Args:
        filename: Path to the JSON file
        
    Returns:
        List of objects from the file, or None if error
    """
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
            return data
    except FileNotFoundError:
        print(f"FAIL File not found: {filename}")
        return None
    except json.JSONDecodeError as e:
        print(f"FAIL Invalid JSON in {filename}: {e}")
        return None
    
def load_metadata_file(path: str) -> dict:
    """
    Load conversion metadata emitted by fortigate_converter.py.

    Args:
        path: Path to metadata JSON file

    Returns:
        Dict (empty on failure)
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (FileNotFoundError, OSError, json.JSONDecodeError, TypeError, ValueError):
        return {}


def write_json_report(path: str, payload: Dict[str, Any]) -> bool:
    """Write a machine-readable run report to disk."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        return True
    except (OSError, TypeError, ValueError):
        return False


def auto_discover_metadata(base_name: str) -> dict:
    """
    Auto-discover metadata file based on the --base argument.
    
    Checks for {base}_metadata.json in the current directory.
    This eliminates the need to manually specify --metadata-file
    when using standard naming conventions.
    
    Args:
        base_name: Base name from --base argument (e.g., 'ftd_config')
        
    Returns:
        Metadata dict if found, empty dict otherwise
    """
    import os
    
    # Build expected metadata filename
    metadata_path = f"{base_name}_metadata.json"
    
    # Check if file exists
    if os.path.isfile(metadata_path):
        print(f"[INFO] Auto-discovered metadata file: {metadata_path}")
        return load_metadata_file(metadata_path)
    
    return {}

    

def physical_interface_matches_json_config(current: Dict, desired_json: Dict) -> bool:
    """
    Determine whether the *current* FTD interface configuration already matches the
    *desired* JSON configuration produced by the converter.

    Important design choice:
        - We only compare keys that are present in desired_json (the converter output).
          This prevents false diffs when the converter intentionally omits fields.
        - We normalize common API differences (None vs "", missing ipv4/ipv6 vs None).

    Args:
        current: Interface object retrieved from FTD (GET/cache)
        desired_json: Interface object from converted JSON file

    Returns:
        True if no update is required, False otherwise.
    """
    # Keys we allow the converter to manage for physical interfaces
    managed_keys = (
        "name",
        "description",
        "mtu",
        "enabled",
        "managementOnly",
        "mode",
        "monitorInterface",
    )

    def _norm_scalar(v: Any) -> Any:
        # Normalize empty strings vs None (FDM sometimes flips these)
        if v == "":
            return None
        return v

    # Compare only fields actually present in JSON
    for key in managed_keys:
        if key in desired_json:
            if _norm_scalar(current.get(key)) != _norm_scalar(desired_json.get(key)):
                return False

    # Compare ipv4/ipv6 blocks only if present in JSON
    for ip_key in ("ipv4", "ipv6"):
        if ip_key in desired_json:
            cur_block = current.get(ip_key)
            des_block = desired_json.get(ip_key)

            # Normalize missing vs None
            if cur_block == {}:
                cur_block = None
            if des_block == {}:
                des_block = None

            # Reuse the recursive _values_match comparison so FDM
            # bookkeeping fields (version, id, ...) inside the block from a
            # GET don't force a re-PUT of an otherwise unchanged interface.
            if not FTDAPIClient._values_match(cur_block, des_block):
                return False

    return True


def _is_cts_related_key(key: str) -> bool:
    """Return True when a key name appears related to CTS/TrustSec settings."""
    lowered = str(key).lower()
    markers = ("cts", "trustsec", "trust_sec", "securitygroup", "security_group", "sgt")
    return any(marker in lowered for marker in markers)


def _is_enabled_like_value(value: Any) -> bool:
    """Return True for values that semantically represent an enabled state."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().upper() in {"ENABLED", "ENABLE", "TRUE", "ON", "YES"}
    return False


def interface_has_cts_enabled(obj: Any) -> bool:
    """
    Best-effort recursive check for CTS/TrustSec enabled flags in an interface object.

    This is intentionally permissive so we can avoid false "no change" skips for
    EtherChannel member prep updates.
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            if _is_cts_related_key(str(key)):
                if _is_enabled_like_value(value):
                    return True
                if isinstance(value, dict) and interface_has_cts_enabled(value):
                    return True
                if isinstance(value, list):
                    for item in value:
                        if interface_has_cts_enabled(item):
                            return True
            elif interface_has_cts_enabled(value):
                return True
        return False

    if isinstance(obj, list):
        return any(interface_has_cts_enabled(item) for item in obj)

    return False


def import_address_objects(client: FTDAPIClient, filename: str, max_workers: int = 1, max_attempts: int = 4, base_backoff: float = 0.3, max_jitter: float = 0.25) -> bool:
    """
    Import address objects from JSON file to FTD.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to address objects JSON file
        
    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Importing Address Objects from {filename}")
    print(f"{'-'*60}")
    
    objects = load_json_file(filename)
    if objects is None:
        return False
    
    if not objects:
        print("  No objects to import")
        return True
    
    total = len(objects)
    max_workers = max(1, max_workers)
    print_lock = threading.Lock()
    failure_flag = [False]

    def worker(idx: int, obj: Dict) -> None:
        name = obj.get("name", "Unknown")
        success, result = run_with_retry(
            lambda: client.create_network_object(obj, track_stats=False),
            max_attempts=max_attempts,
            base_backoff=base_backoff,
            max_jitter=max_jitter,
        )
        if success:
            if isinstance(result, str) and str(result).startswith("SKIPPED"):
                client.record_stat("address_objects_skipped")
                line = f"  [{idx+1}/{total}] Creating: {name}... SKIP"
            elif isinstance(result, str) and str(result).startswith("UPDATED"):
                client.record_stat("address_objects_updated")
                line = f"  [{idx+1}/{total}] Updating: {name}... OK"
            else:
                client.record_stat("address_objects_created")
                line = f"  [{idx+1}/{total}] Creating: {name}... OK"
            with print_lock:
                print(line, flush=True)
            return

        client.record_stat("address_objects_failed")
        client.record_failure("Address Object", name, result)
        line = f"  [{idx+1}/{total}] Creating: {name}... FAIL {result}"
        with print_lock:
            print(line, flush=True)
        failure_flag[0] = True
        return

    run_indexed_thread_pool(max_workers=max_workers, items=objects, worker=worker)

    return not failure_flag[0]


def import_address_groups(client: FTDAPIClient, filename: str, delay: float = 0.2) -> bool:
    """
    Import address groups from JSON file to FTD.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to address groups JSON file
        
    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Importing Address Groups from {filename}")
    print(f"{'-'*60}")
    
    groups = load_json_file(filename)
    if groups is None:
        return False
    
    if not groups:
        print("  No groups to import")
        return True
    
    all_success = True
    for i, group in enumerate(groups, 1):
        name = group.get("name", "Unknown")
        
        # Clean the group object - ensure member objects only have name and type
        cleaned_group = clean_group_object(group)
        
        print(f"  [{i}/{len(groups)}] Creating: {name}...", end=" ")

        success, result = client.create_network_group(cleaned_group)
        if success:
            if isinstance(result, str) and str(result).startswith("SKIPPED"):
                print("[SKIP]")
            elif isinstance(result, str) and str(result).startswith("UPDATED"):
                print("[UPDATED]")
            else:
                print("[OK]")
        else:
            print(f"[FAIL {result}]")
            client.record_failure("Address Group", name, result)
            all_success = False

        time.sleep(delay)

    return all_success


def clean_group_object(group: Dict) -> Dict:
    """
    Clean a group object to ensure member references only have name and type.
    
    FTD groups reference member objects by name only. Remove any UUIDs, IDs,
    versions, or other fields that might cause "cannot find entity" errors.
    
    Args:
        group: Group object dictionary
        
    Returns:
        Cleaned group object
    """
    cleaned = group.copy()
    
    # Clean the member objects in the "objects" array
    if "objects" in cleaned and isinstance(cleaned["objects"], list):
        cleaned_members = []
        for member in cleaned["objects"]:
            if isinstance(member, dict):
                # Keep ONLY name and type - remove everything else
                cleaned_member = {
                    "name": member.get("name"),
                    "type": member.get("type", "networkobject")
                }
                cleaned_members.append(cleaned_member)
            else:
                # If member is just a string, convert to proper format
                cleaned_members.append({
                    "name": str(member),
                    "type": "networkobject"
                })
        
        cleaned["objects"] = cleaned_members
    
    # Remove any UUID, id, or version fields from the group itself that came from FortiGate
    cleaned.pop("uuid", None)
    cleaned.pop("id", None) 
    cleaned.pop("version", None)
    
    return cleaned


def import_service_objects(client: FTDAPIClient, filename: str, max_workers: int = 1, max_attempts: int = 4, base_backoff: float = 0.3, max_jitter: float = 0.25) -> bool:
    """
    Import service port objects from JSON file to FTD.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to service objects JSON file
        
    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Importing Service Objects from {filename}")
    print(f"{'-'*60}")
    
    objects = load_json_file(filename)
    if objects is None:
        return False
    
    if not objects:
        print("  No objects to import")
        return True
    
    total = len(objects)
    max_workers = max(1, max_workers)
    print_lock = threading.Lock()
    failure_flag = [False]

    def worker(idx: int, obj: Dict) -> None:
        name = obj.get("name", "Unknown")
        obj_type = obj.get("type", "")
        success, result = run_with_retry(
            lambda: client.create_port_object(obj, track_stats=False),
            max_attempts=max_attempts,
            base_backoff=base_backoff,
            max_jitter=max_jitter,
        )
        if success:
            if isinstance(result, str) and str(result).startswith("SKIPPED"):
                client.record_stat("port_objects_skipped")
                line = f"  [{idx+1}/{total}] Creating: {name} ({obj_type})... SKIP"
            elif isinstance(result, str) and str(result).startswith("UPDATED"):
                client.record_stat("port_objects_updated")
                line = f"  [{idx+1}/{total}] Updating: {name} ({obj_type})... OK"
            else:
                client.record_stat("port_objects_created")
                line = f"  [{idx+1}/{total}] Creating: {name} ({obj_type})... OK"
            with print_lock:
                print(line, flush=True)
            return

        client.record_stat("port_objects_failed")
        client.record_failure("Port Object", name, result)
        line = f"  [{idx+1}/{total}] Creating: {name} ({obj_type})... FAIL {result}"
        with print_lock:
            print(line, flush=True)
        failure_flag[0] = True
        return

    run_indexed_thread_pool(max_workers=max_workers, items=objects, worker=worker)

    return not failure_flag[0]


def import_service_groups(client: FTDAPIClient, filename: str, delay: float = 0.2) -> bool:
    """
    Import service port groups from JSON file to FTD.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to service groups JSON file
        
    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Importing Service Groups from {filename}")
    print(f"{'-'*60}")
    
    groups = load_json_file(filename)
    if groups is None:
        return False
    
    if not groups:
        print("  No groups to import")
        return True
    
    all_success = True
    for i, group in enumerate(groups, 1):
        name = group.get("name", "Unknown")
        
        # Clean the group object - ensure member objects only have name and type
        cleaned_group = clean_group_object(group)
        
        print(f"  [{i}/{len(groups)}] Creating: {name}...", end=" ")

        success, result = client.create_port_group(cleaned_group)
        if success:
            if isinstance(result, str) and str(result).startswith("SKIPPED"):
                print("[SKIP]")
            elif isinstance(result, str) and str(result).startswith("UPDATED"):
                print("[UPDATED]")
            else:
                print("[OK]")
        else:
            print(f"[FAIL {result}]")
            client.record_failure("Port Group", name, result)
            all_success = False

        time.sleep(delay)

    return all_success


def import_physical_interfaces(client: FTDAPIClient, filename: str, delay: float = 0.2) -> bool:
    """
    Update existing physical interfaces using PUT if they exist on the device.
    Physical interfaces cannot be created via POST - they are pre-provisioned.
    This function uses the pre-populated _physical_interface_cache to detect existing interfaces,
    merges converted settings (name, description, IP, MTU, etc.) onto the real interface object,
    and sends a PUT request.
    
    NOTE: Interfaces not found on the FTD (wrong model, disabled ports, etc.) will be skipped.
    NOTE: Hardware settings (speed, duplex, FEC, auto-neg) are preserved.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to physical interfaces JSON file
        
    Returns:
        True if all attempted updates were successful (skips don't count as failure)
    """
    print(f"\n{'-'*60}")
    print(f"Updating Physical Interfaces from {filename}")
    print(f"{'-'*60}")
    print("  - Physical Interfaces")
    print("  NOTE: Auto-negotiation=ENABLED, Duplex=FULL will be set")
    print("  NOTE: Interfaces not found on FTD will be skipped")
    
    interfaces = load_json_file(filename)
    if interfaces is None:
        return False
    
    if not interfaces:
        print("  No physical interfaces to update")
        return True
    
    # Cache physical interfaces once so we can do fast update detection by hardwareName
    client.populate_physical_interface_cache()
    
    all_success = True
    skipped_count = 0
    updated_count = 0
    failed_count = 0
    
    for i, intf in enumerate(interfaces, 1):
        name = intf.get("name", "")  # Empty string if not provided
        hardware = intf.get("hardwareName", "Unknown")
        
        # Display name - show hardware if name is empty
        display_name = name if name else f"<{hardware}>"
        print(f"  [{i}/{len(interfaces)}] Processing: {display_name} ({hardware})...", end=" ")

        if not hardware or hardware not in client._physical_interface_cache:
            print("[SKIP] (not present on this FTD model)")
            skipped_count += 1
            client.record_stat("physical_interfaces_skipped")
            continue

        # Get the original interface from cache
        original = client._physical_interface_cache[hardware]

        is_etherchannel_member_prep = intf.get("name") == ""
        member_has_cts_enabled = is_etherchannel_member_prep and interface_has_cts_enabled(original)

        # Check if the interface already matches the desired JSON config.
        # For EtherChannel member prep, force an update when CTS is still enabled
        # on the existing FTD interface object.
        if physical_interface_matches_json_config(original, intf) and not member_has_cts_enabled:
            print("[OK] No changes needed.")
            skipped_count += 1
            client.record_stat("physical_interfaces_skipped")
            continue

        if member_has_cts_enabled:
            print("[INFO] CTS detected, forcing member prep update...", end=" ")

        # Use the client's update_physical_interface method
        # This method properly handles:
        # - Switchport to routed mode conversion
        # - Removal of switchport-specific fields
        # - Version management
        # - Error handling
        success, result = client.update_physical_interface(intf)
        
        if success:
            if "SKIPPED" in str(result):
                print(f"[SKIP] {result}")
                skipped_count += 1
            else:
                # Update successful
                print("[OK]")
                updated_count += 1
        else:
            # Update failed
            print(f"[FAIL] {result}")
            if client.debug:
                print(f"       Error details: {result}")
            client.record_failure("Physical Interface", display_name, result)
            failed_count += 1
            all_success = False

        time.sleep(delay)
    
    # Print summary
    print(f"\n  Summary: {updated_count} updated, {skipped_count} skipped (not present or no changes needed), {failed_count} failed")
    
    return all_success


def import_etherchannels(client: FTDAPIClient, filename: str, delay: float = 0.2) -> bool:
    """
    Import EtherChannel interfaces from JSON file to FTD.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to etherchannels JSON file
        
    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Creating EtherChannels from {filename}")
    print(f"{'-'*60}")
    print("  - EtherChannels")
    interfaces = load_json_file(filename)
    if interfaces is None:
        return False
    
    if not interfaces:
        print("  No etherchannels to create")
        return True
    
    all_success = True
    for i, intf in enumerate(interfaces, 1):
        name = intf.get("name", "Unknown")
        hardware = intf.get("hardwareName", "Unknown")
        print(f"  [{i}/{len(interfaces)}] Creating: {name} ({hardware})...", end=" ")
        
        success, result = client.create_etherchannel(intf)
        if success:
            if isinstance(result, str) and result.startswith("SKIPPED"):
                if "already exists" in result.lower():
                    print("[SKIP] already exists")
                else:
                    print(f"[SKIP] {result.split('SKIPPED:')[-1].strip()[:50]}")
            elif isinstance(result, str) and result.startswith("UPDATED"):
                print("[UPDATED]")
            else:
                print("[OK]")
        else:
            print(f"[FAIL] {result}")
            client.record_failure("EtherChannel", name, result)
            all_success = False

        time.sleep(delay)

    return all_success


def import_bridge_groups(client: FTDAPIClient, filename: str, delay: float = 0.2) -> bool:
    """
    Import Bridge Group interfaces from JSON file to FTD.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to bridge groups JSON file
        
    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Creating Bridge Groups from {filename}")
    print(f"{'-'*60}")
    print("  - Bridge Groups")

    interfaces = load_json_file(filename)
    if interfaces is None:
        return False
    
    if not interfaces:
        print("  No bridge groups to create")
        return True
    
    all_success = True
    for i, intf in enumerate(interfaces, 1):
        name = intf.get("name", "Unknown")
        print(f"  [{i}/{len(interfaces)}] Creating: {name}...", end=" ")
        
        success, result = client.create_bridge_group(intf)
        if success:
            if isinstance(result, str) and result.startswith("SKIPPED"):
                if "already exists" in result.lower():
                    print("[SKIP] already exists")
                else:
                    print(f"[SKIP] {result.split('SKIPPED:')[-1].strip()[:50]}")
            elif isinstance(result, str) and result.startswith("UPDATED"):
                print("[UPDATED]")
            else:
                print("[OK]")
        else:
            print(f"[FAIL] {result}")
            client.record_failure("Bridge Group", name, result)
            all_success = False

        time.sleep(delay)

    return all_success


def import_subinterfaces(client: FTDAPIClient, filename: str, parent_type_filter: Optional[str] = None, delay: float = 0.2) -> bool:
    """
    Import subinterfaces (VLANs) from JSON file to FTD.
    
    This function can filter subinterfaces by parent type to support
    two-phase import:
    - Phase 1: Import subinterfaces on physical interfaces (before EtherChannels)
    - Phase 2: Import subinterfaces on EtherChannels (after EtherChannels created)
    
    Args:
        client: Authenticated FTD API client
        filename: Path to subinterfaces JSON file
        parent_type_filter: Optional filter - 'physical' or 'etherchannel' or None for all
        
    Returns:
        True if all imports successful, False if any failed
    """
    # Determine header based on filter
    if parent_type_filter == 'physical':
        print("  - Subinterfaces (two-phase import)")
        print("    Phase 1: Physical interface parents")
        header = f"Creating Subinterfaces (Physical Interface Parents) from {filename}"
    elif parent_type_filter == 'etherchannel':
        print("    Phase 2: EtherChannel parents")
        header = f"Creating Subinterfaces (EtherChannel Parents) from {filename}"
    else:
        header = f"Creating Subinterfaces from {filename}"
    
    print(f"\n{'-'*60}")
    print(header)
    print(f"{'-'*60}")
    interfaces = load_json_file(filename)
    if interfaces is None:
        return False
    
    if not interfaces:
        print("  No subinterfaces to create")
        return True
    
    # Filter interfaces based on parent type if requested
    filtered_interfaces = []
    skipped_count = 0
    
    for intf in interfaces:
        hardware_name = intf.get('hardwareName', '')
        
        # Extract parent hardware name
        if '.' in hardware_name:
            parent_hardware = hardware_name.rsplit('.', 1)[0]
            parent_is_etherchannel = parent_hardware.lower().startswith('port-channel')
            
            # Apply filter if specified
            if parent_type_filter == 'physical' and not parent_is_etherchannel:
                filtered_interfaces.append(intf)
            elif parent_type_filter == 'etherchannel' and parent_is_etherchannel:
                filtered_interfaces.append(intf)
            elif parent_type_filter is None:
                filtered_interfaces.append(intf)
            else:
                skipped_count += 1
        else:
            # Invalid format - include it to let create_subinterface handle the error
            filtered_interfaces.append(intf)
    
    if skipped_count > 0:
        print(f"  Filtered out {skipped_count} subinterfaces (wrong parent type for this phase)")
    
    if not filtered_interfaces:
        print("  No subinterfaces match filter criteria")
        return True
    
    print(f"  Processing {len(filtered_interfaces)} subinterfaces...")
    
    all_success = True
    created_count = 0
    skipped_api_count = 0
    failed_count = 0
    
    for i, intf in enumerate(filtered_interfaces, 1):
        name = intf.get("name", "Unknown")
        hardware = intf.get("hardwareName", "Unknown")
        print(f"  [{i}/{len(filtered_interfaces)}] Creating: {name} ({hardware})...", end=" ")
        
        success, result = client.create_subinterface(intf)
        if success:
            if isinstance(result, str) and result.startswith("SKIPPED"):
                if "already exists" in result.lower():
                    print("[SKIP] already exists")
                else:
                    print(f"[SKIP] {result.split('SKIPPED:')[-1].strip()[:50]}")
                skipped_api_count += 1
            elif isinstance(result, str) and result.startswith("UPDATED"):
                print("[UPDATED]")
                created_count += 1
            else:
                print("[OK]")
                created_count += 1
        else:
            print(f"[FAIL] {result}")
            client.record_failure("Subinterface", name, result)
            failed_count += 1
            all_success = False

        time.sleep(delay)

    # Print summary
    print(f"\n  Summary: {created_count} created/updated, {skipped_api_count} skipped, {failed_count} failed")
    
    return all_success

def import_security_zones(client: FTDAPIClient, filename: str, delay: float = 0.2) -> bool:
    """
    Import security zones from JSON file to FTD.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to security zones JSON file
        
    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Importing Security Zones from {filename}")
    print(f"{'-'*60}")
    
    zones = load_json_file(filename)
    if zones is None:
        return False
    
    if not zones:
        print("  No security zones to import")
        return True
    
    all_success = True
    for i, zone in enumerate(zones, 1):
        name = zone.get("name", "Unknown")
        print(f"  [{i}/{len(zones)}] Creating zone: {name}...", end=" ")
        
        success, result = client.create_security_zone(zone)
        if success:
            if isinstance(result, str) and result.startswith("SKIPPED"):
                print("[SKIPPED]")
            elif isinstance(result, str) and result.startswith("UPDATED"):
                print("[UPDATED]")
            else:
                print("[OK]")
        else:
            print(f"[FAIL {result}]")
            client.record_failure("Security Zone", name, result)
            all_success = False

        time.sleep(delay)

    return all_success

def import_static_routes(client: FTDAPIClient, filename: str, delay: float = 0.2) -> bool:
    """
    Import static routes from JSON file to FTD.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to static routes JSON file
        
    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Importing Static Routes from {filename}")
    print(f"{'-'*60}")
    
    routes = load_json_file(filename)
    if routes is None:
        return False
    
    if not routes:
        print("  No routes to import")
        return True
    
    # Prefetch interfaces AND network objects for faster lookups.
    # Interfaces are required to resolve route iface UUIDs (id) and avoid "UUID null" errors.
    client.prefetch_interface_cache()
    client.prefetch_network_object_cache()

    
    all_success = True
    for i, route in enumerate(routes, 1):
        name = route.get("name", "Unknown")
        print(f"  [{i}/{len(routes)}] Creating: {name}...", end=" ")
        
        success, result = client.create_static_route(route)
        if success:
            if isinstance(result, str) and str(result).startswith("UPDATED"):
                print("[UPDATED]")
            else:
                print("[OK]")
        else:
            print(f"[FAIL {result}]")
            client.record_failure("Static Route", name, result)
            all_success = False

        time.sleep(delay)

    return all_success

def import_access_rules(client: FTDAPIClient, filename: str, delay: float = 0.2) -> bool:
    """
    Import access rules from JSON file to FTD.
    
    Args:
        client: Authenticated FTD API client
        filename: Path to access rules JSON file
        
    Returns:
        True if all imports successful, False if any failed
    """
    print(f"\n{'-'*60}")
    print(f"Importing Access Rules from {filename}")
    print(f"{'-'*60}")
    
    rules = load_json_file(filename)
    if rules is None:
        return False
    
    if not rules:
        print("  No rules to import")
        return True
    
    all_success = True
    for i, rule in enumerate(rules, 1):
        name = rule.get("name", "Unknown")
        action = rule.get("ruleAction", "")
        print(f"  [{i}/{len(rules)}] Creating: {name} ({action})...", end=" ")
        
        success, result = client.create_access_rule(rule)
        if success:
            if isinstance(result, str) and str(result).startswith("UPDATED"):
                print("[UPDATED]")
            else:
                print("[OK]")
        else:
            print(f"[FAIL {result}]")
            client.record_failure("Access Rule", name, result)
            all_success = False

        time.sleep(delay)

    return all_success


def main(argv: Optional[List[str]] = None) -> int:
    """
    Main function that orchestrates the import process.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:] when None).
    """
    parser = argparse.ArgumentParser(
        description='Import FortiGate converted configurations to Cisco FTD via FDM API',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Import everything (all files)
  python ftd_api_importer.py --host 192.168.1.1 --username admin --password MyPass123
  
  # Import only address objects
  python ftd_api_importer.py --host 192.168.1.1 -u admin --only-address-objects
  
  # Import only service objects and groups
  python ftd_api_importer.py --host 192.168.1.1 -u admin --only-service-objects --only-service-groups
  
  # Import a specific file
  python ftd_api_importer.py --host 192.168.1.1 -u admin --file my_addresses.json --type address-objects
  
  # Import and deploy
  python ftd_api_importer.py --host 192.168.1.1 -u admin --only-routes --deploy
        """
    )
    
    parser.add_argument('--host', required=True,
                       help='FTD management IP address or hostname')
    parser.add_argument('-u', '--username', required=True,
                       help='FDM username (typically "admin")')
    parser.add_argument('-p', '--password',
                       help='FDM password (will prompt if not provided)')
    parser.add_argument('--base', default='ftd_config',
                       help='Base name of converted JSON files (default: ftd_config)')
    parser.add_argument('--deploy', action='store_true',
                       help='Automatically deploy changes after import')
    parser.add_argument('--verify-ssl', action='store_true', default=False,
                       help='Verify the FTD management SSL certificate '
                            '(default: disabled - mgmt certs are usually self-signed)')
    parser.add_argument('--skip-verify', action='store_true', default=False,
                       help='(DEPRECATED, ignored) SSL verification is already '
                            'disabled by default; use --verify-ssl to enable it')
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug output (shows API payloads)')
    parser.add_argument("--metadata-file", default="",
                       help="Path to *_metadata.json generated by fortigate_converter.py (used for model-specific behavior).",)
    def _positive_int(value: str) -> int:
        ivalue = int(value)
        if ivalue < 1 or ivalue > 32:
            raise argparse.ArgumentTypeError(f"workers must be between 1 and 32, got {ivalue}")
        return ivalue
    parser.add_argument('--workers', type=_positive_int, default=6,
                       help='Max concurrent workers for address/service object imports (1-32, default: 6)')
    parser.add_argument('--max-attempts', type=int, default=4,
                       help='Max retry attempts for transient API errors (default: 4)')
    parser.add_argument('--base-backoff', type=float, default=0.3,
                       help='Initial backoff delay in seconds between retries (default: 0.3)')
    parser.add_argument('--max-jitter', type=float, default=0.25,
                       help='Max random jitter in seconds added to backoff (default: 0.25)')
    parser.add_argument('--delay', type=float, default=0.2,
                       help='Delay in seconds between sequential API calls (default: 0.2)')
    parser.add_argument('--json-report', default='',
                       help='Write run summary to a JSON report file')
    parser.add_argument('--validate-only', action='store_true',
                       help='Authenticate and probe all API endpoints without importing anything')
    parser.add_argument('--skip-existing', action='store_true',
                       help='Skip objects that already exist instead of updating them (default: update)')

    # Selective import options - allows importing only specific object types
    parser.add_argument('--only-physical-interfaces', action='store_true',
                       help='Update only physical interfaces')
    parser.add_argument('--only-etherchannels', action='store_true',
                       help='Create only etherchannels')
    parser.add_argument('--only-bridge-groups', action='store_true',
                       help='Create only bridge groups')
    parser.add_argument('--only-subinterfaces', action='store_true',
                       help='Create only subinterfaces')
    parser.add_argument('--only-security-zones', action='store_true',
                       help='Create only security zones')
    parser.add_argument('--only-address-objects', action='store_true',
                       help='Import only address objects')
    parser.add_argument('--only-address-groups', action='store_true',
                       help='Import only address groups')
    parser.add_argument('--only-service-objects', action='store_true',
                       help='Import only service objects')
    parser.add_argument('--only-service-groups', action='store_true',
                       help='Import only service groups')
    parser.add_argument('--only-routes', action='store_true',
                       help='Import only static routes')
    parser.add_argument('--only-rules', action='store_true',
                       help='Import only access rules')
    
    # Alternative: specify a single file directly
    parser.add_argument('--file', 
                       help='Import a specific JSON file (overrides --base and --only flags)')
    parser.add_argument('--type',
                       choices=['address-objects', 'address-groups', 'service-objects', 
                               'service-groups', 'routes', 'rules', 'security-zones',
                               'physical-interfaces', 'etherchannels', 'bridge-groups', 'subinterfaces'],
                       help='Type of objects in the file (required with --file)')
    
    args = parser.parse_args(argv)

    # Validate --file requires --type
    if args.file and not args.type:
        parser.error("--file requires --type to be specified")
    
    # Prompt for password if not provided
    if not args.password:
        args.password = getpass.getpass(f"Enter password for {args.username}: ")

    if args.skip_verify:
        print("[DEPRECATED] --skip-verify is ignored: SSL verification is "
              "already disabled by default. Use --verify-ssl to enable it.")

    # Create API client
    client = FTDAPIClient(
        host=args.host,
        username=args.username,
        password=args.password,
        verify_ssl=args.verify_ssl,
        update_existing=not args.skip_existing,
    )

    # Track per-phase timings for simple performance comparisons
    phase_timings = []

    def record_phase(label: str, func: Callable[..., Any], *func_args: Any, **func_kwargs: Any) -> Any:
        """Run a phase, time it, and capture success for summary output."""
        # Snapshot stats before the phase to compute per-phase counts
        stats_before = dict(client.stats)
        start = time.perf_counter()
        result = func(*func_args, **func_kwargs)
        duration = time.perf_counter() - start

        # Compute per-phase created/updated/skipped vs failed
        phase_ok = sum(
            client.stats[k] - stats_before[k]
            for k in client.stats
            if k.endswith(("_created", "_updated", "_skipped"))
        )
        phase_failed = sum(
            client.stats[k] - stats_before[k]
            for k in client.stats
            if k.endswith("_failed")
        )

        # A phase that returned False without recording any per-item
        # failures failed outright (e.g. missing input file). Track it so
        # compute_outcome does not report SUCCESS.
        phase_hard_failed = result is False and phase_failed == 0
        if phase_hard_failed:
            client.record_phase_failure(label)

        if phase_hard_failed:
            status = "FAIL"
        elif phase_failed == 0:
            status = "OK"
        elif phase_ok > 0:
            status = "PARTIAL"
        else:
            status = "FAIL"

        phase_timings.append({
            "label": label, "seconds": duration,
            "success": phase_failed == 0 and not phase_hard_failed, "status": status,
            "ok_count": phase_ok, "failed_count": phase_failed,
        })
        return result
    
    # Load metadata: explicit file takes priority, then auto-discover from --base
    metadata = {}
    if args.metadata_file:
        metadata = load_metadata_file(args.metadata_file)
    else:
        # Auto-discover metadata based on --base argument
        metadata = auto_discover_metadata(args.base)
    
    # Store model hint on the client for downstream logic
    target_model = str(metadata.get("target_model", "generic")).lower().strip()
    client.appliance_model = target_model
    
    if target_model and target_model != "generic":
        print(f"[INFO] Target firewall model: {target_model}")

    # Set debug mode if requested
    if args.debug:
        client.debug = True
        print("[DEBUG MODE ENABLED]")

    if args.skip_existing:
        print("[INFO] Skip-existing mode: objects that already exist will be skipped")
    else:
        print("[INFO] Update mode: objects that already exist will be updated to match the new config")

    # Authenticate
    if not client.authenticate():
        print("\n[FAIL] Authentication failed. Exiting.")
        return 1

    # Validate-only mode: probe endpoints and exit
    if args.validate_only:
        ok = client.validate_endpoints()
        return 0 if ok else 1

    # Populate required caches before importing interfaces
    client.populate_physical_interface_cache()
    
    # Determine what to import
    print(f"\n{'='*60}")
    print("Starting Import Process")
    print(f"{'='*60}")
    
    # Check if specific file is provided
    if args.file:
        print(f"\nImporting single file: {args.file}")
        print(f"Object type: {args.type}")
        
        # Import based on type
        if args.type == 'physical-interfaces':
            record_phase("Physical Interfaces", import_physical_interfaces, client, args.file, delay=args.delay)
        elif args.type == 'etherchannels':
            record_phase("EtherChannels", import_etherchannels, client, args.file, delay=args.delay)
        elif args.type == 'bridge-groups':
            record_phase("Bridge Groups", import_bridge_groups, client, args.file, delay=args.delay)
        elif args.type == 'subinterfaces':
            # Import subinterfaces in two phases for correct parent dependency order
            print("\nPhase 1: Subinterfaces on Physical Interfaces")
            record_phase("Subinterfaces (physical parents)", import_subinterfaces, client, args.file, parent_type_filter='physical', delay=args.delay)
            print("\nPhase 2: Subinterfaces on EtherChannels")
            record_phase("Subinterfaces (etherchannel parents)", import_subinterfaces, client, args.file, parent_type_filter='etherchannel', delay=args.delay)
        elif args.type == 'security-zones':
            record_phase("Security Zones", import_security_zones, client, args.file, delay=args.delay)
        elif args.type == 'address-objects':
            record_phase("Address Objects", import_address_objects, client, args.file, args.workers, args.max_attempts, args.base_backoff, args.max_jitter)
        elif args.type == 'address-groups':
            record_phase("Address Groups", import_address_groups, client, args.file, delay=args.delay)
        elif args.type == 'service-objects':
            record_phase("Service Objects", import_service_objects, client, args.file, args.workers, args.max_attempts, args.base_backoff, args.max_jitter)
        elif args.type == 'service-groups':
            record_phase("Service Groups", import_service_groups, client, args.file, delay=args.delay)
        elif args.type == 'routes':
            record_phase("Static Routes", import_static_routes, client, args.file, delay=args.delay)
        elif args.type == 'rules':
            record_phase("Access Rules", import_access_rules, client, args.file, delay=args.delay)
    
    # Check if any --only flags are set
    elif any([args.only_physical_interfaces, args.only_etherchannels,
              args.only_bridge_groups, args.only_subinterfaces,
              args.only_security_zones,
              args.only_address_objects, args.only_address_groups, 
              args.only_service_objects, args.only_service_groups,
              args.only_routes, args.only_rules]):
        
        print("\nSelective Import Mode:")
        imported_any = False
        
        if args.only_physical_interfaces:
            record_phase("Physical Interfaces", import_physical_interfaces, client, f"{args.base}_physical_interfaces.json", delay=args.delay)
            imported_any = True

        if args.only_etherchannels:
            record_phase("EtherChannels", import_etherchannels, client, f"{args.base}_etherchannels.json", delay=args.delay)
            imported_any = True

        if args.only_bridge_groups:
            record_phase("Bridge Groups", import_bridge_groups, client, f"{args.base}_bridge_groups.json", delay=args.delay)
            imported_any = True

        if args.only_subinterfaces:
            record_phase("Subinterfaces (physical parents)", import_subinterfaces, client, f"{args.base}_subinterfaces.json", parent_type_filter='physical', delay=args.delay)
            record_phase("Subinterfaces (etherchannel parents)", import_subinterfaces, client, f"{args.base}_subinterfaces.json", parent_type_filter='etherchannel', delay=args.delay)
            imported_any = True

        if args.only_security_zones:
            print("  - Security Zones")
            record_phase("Security Zones", import_security_zones, client, f"{args.base}_security_zones.json", delay=args.delay)
            imported_any = True

        if args.only_address_objects:
            print("  - Address Objects")
            record_phase("Address Objects", import_address_objects, client, f"{args.base}_address_objects.json", args.workers, args.max_attempts, args.base_backoff, args.max_jitter)
            imported_any = True

        if args.only_address_groups:
            print("  - Address Groups")
            record_phase("Address Groups", import_address_groups, client, f"{args.base}_address_groups.json", delay=args.delay)
            imported_any = True

        if args.only_service_objects:
            print("  - Service Objects")
            record_phase("Service Objects", import_service_objects, client, f"{args.base}_service_objects.json", args.workers, args.max_attempts, args.base_backoff, args.max_jitter)
            imported_any = True

        if args.only_service_groups:
            print("  - Service Groups")
            record_phase("Service Groups", import_service_groups, client, f"{args.base}_service_groups.json", delay=args.delay)
            imported_any = True

        if args.only_routes:
            print("  - Static Routes")
            record_phase("Static Routes", import_static_routes, client, f"{args.base}_static_routes.json", delay=args.delay)
            imported_any = True

        if args.only_rules:
            print("  - Access Rules")
            record_phase("Access Rules", import_access_rules, client, f"{args.base}_access_rules.json", delay=args.delay)
            imported_any = True
        
        if not imported_any:
            print("\nFAIL No import flags specified. Nothing to import.")
            return 1
    # Default: Import everything in order
    else:
        print("\nFull Import Mode - All objects in order:")
        print("  1. Physical Interfaces (update)")
        print("  2. Subinterfaces on Physical Interfaces (create)")
        print("  3. EtherChannels (create)")
        print("  4. Subinterfaces on EtherChannels (create)")
        print("  5. Bridge Groups (create)")
        print("  6. Security Zones (create)")
        print("  7. Address Objects")
        print("  8. Address Groups")
        print("  9. Service Objects")
        print("  10. Service Groups")
        print("  11. Static Routes")
        print("  12. Access Rules")
        
        # Step 1: Update physical interfaces
        record_phase("Physical Interfaces", import_physical_interfaces, client, f"{args.base}_physical_interfaces.json", delay=args.delay)

        # Step 2: Create subinterfaces on physical interfaces BEFORE adding them to EtherChannels
        record_phase("Subinterfaces (physical parents)", import_subinterfaces, client, f"{args.base}_subinterfaces.json", parent_type_filter='physical', delay=args.delay)

        # Step 3: Create etherchannels (this may add physical interfaces as members)
        record_phase("EtherChannels", import_etherchannels, client, f"{args.base}_etherchannels.json", delay=args.delay)

        # Step 4: Create subinterfaces on EtherChannels AFTER they are created
        record_phase("Subinterfaces (etherchannel parents)", import_subinterfaces, client, f"{args.base}_subinterfaces.json", parent_type_filter='etherchannel', delay=args.delay)

        # Step 5: Create bridge groups
        record_phase("Bridge Groups", import_bridge_groups, client, f"{args.base}_bridge_groups.json", delay=args.delay)

        # Step 6: Create security zones (required for access rules)
        record_phase("Security Zones", import_security_zones, client, f"{args.base}_security_zones.json", delay=args.delay)

        # Step 7: Import address objects
        record_phase("Address Objects", import_address_objects, client, f"{args.base}_address_objects.json", args.workers, args.max_attempts, args.base_backoff, args.max_jitter)

        # Step 8: Import address groups
        record_phase("Address Groups", import_address_groups, client, f"{args.base}_address_groups.json", delay=args.delay)

        # Step 9: Import service objects
        record_phase("Service Objects", import_service_objects, client, f"{args.base}_service_objects.json", args.workers, args.max_attempts, args.base_backoff, args.max_jitter)

        # Step 10: Import service groups
        record_phase("Service Groups", import_service_groups, client, f"{args.base}_service_groups.json", delay=args.delay)

        # Step 11: Import static routes
        record_phase("Static Routes", import_static_routes, client, f"{args.base}_static_routes.json", delay=args.delay)

        # Step 12: Import access rules
        record_phase("Access Rules", import_access_rules, client, f"{args.base}_access_rules.json", delay=args.delay)

    if phase_timings:
        print(f"\n{'='*60}")
        print("TIMING SUMMARY (seconds)")
        print(f"{'='*60}")
        total_seconds = 0.0
        for entry in phase_timings:
            total_seconds += entry["seconds"]
            status = entry.get("status", "OK" if entry["success"] else "FAIL")
            detail = ""
            if status == "PARTIAL":
                detail = f"  ({entry['ok_count']} ok, {entry['failed_count']} failed)"
            print(f"{entry['label']:<35}{entry['seconds']:.2f}s [{status}]{detail}")
        print("-"*60)
        print(f"{'Total':<35}{total_seconds:.2f}s")
    else:
        total_seconds = 0.0
    
    # Print statistics
    client.print_statistics()

    # Print and save failed items summary
    client.print_failure_summary()
    if client.failed_items:
        failed_report_path = f"{args.base}_failed_imports.json"
        failed_payload = {
            "total_failed": len(client.failed_items),
            "failed_items": client.failed_items
        }
        if write_json_report(failed_report_path, failed_payload):
            print(f"[OK] Failed imports report written: {failed_report_path}")
        else:
            print(f"[FAIL] Could not write failed imports report: {failed_report_path}")

    # Deploy changes if requested
    deploy_ok = True
    if args.deploy:
        deploy_ok = client.deploy_changes()
    else:
        print(f"\n{'='*60}")
        print("Import complete. Changes are pending deployment.")
        print("To deploy, either:")
        print("  1. Run this script again with --deploy flag")
        print("  2. Deploy manually from the FDM web interface")
        print(f"{'='*60}")

    exit_code, outcome = client.compute_outcome()

    # A failed deployment must be reflected in the exit code even when
    # every individual import succeeded.
    if args.deploy and not deploy_ok and exit_code == 0:
        exit_code, outcome = 2, "DEPLOY_FAILED"

    if args.json_report:
        report_payload = {
            "host": args.host,
            "mode": "file" if args.file else ("selective" if any([
                args.only_physical_interfaces,
                args.only_etherchannels,
                args.only_bridge_groups,
                args.only_subinterfaces,
                args.only_security_zones,
                args.only_address_objects,
                args.only_address_groups,
                args.only_service_objects,
                args.only_service_groups,
                args.only_routes,
                args.only_rules,
            ]) else "full"),
            "workers": args.workers,
            "update_existing": not args.skip_existing,
            "deploy_requested": args.deploy,
            "target_model": target_model,
            "stats": client.stats,
            "phase_failures": client.phase_failures,
            "phase_timings": phase_timings,
            "total_seconds": total_seconds,
            "exit_code": exit_code,
            "outcome": outcome,
        }
        if write_json_report(args.json_report, report_payload):
            print(f"[OK] JSON report written: {args.json_report}")
        else:
            print(f"[FAIL] Could not write JSON report: {args.json_report}")

    return exit_code


if __name__ == '__main__':
    sys.exit(main())