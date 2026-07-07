#!/usr/bin/env python3
"""
FortiGate Address Object Converter - Palo Alto PAN-OS Target
=============================================================
Converts FortiGate ``firewall_address`` entries to PAN-OS address objects.

PAN-OS address types:
    ip-netmask  - Host (/32) or subnet (10.0.0.0/24)
    ip-range    - 10.0.0.1-10.0.0.10
    fqdn        - dns.google

Output JSON (later converted to XML by the importer):
    {
        "name": "webserver",
        "type": "ip-netmask",
        "value": "10.10.20.100/32",
        "description": "Web server"
    }
"""

from typing import Any, Dict, List, Set

from pa_common import (
    sanitize_name,
    netmask_to_cidr,
    is_default_fortigate_address,
    first_item,
    dedup_name,
)


class PAAddressConverter:
    """Convert FortiGate address objects to PAN-OS address format."""

    def __init__(self, fortigate_config: Dict[str, Any]) -> None:
        self.fg_config = fortigate_config
        self.pa_address_objects: List[Dict] = []
        self.failed_items: List[Dict] = []

        # FortiGate name (raw and sanitized) -> final PAN-OS name. Consumed by
        # the address-group and policy converters so dedup renames propagate.
        self._name_map: Dict[str, str] = {}
        # Names (raw and sanitized) of addresses that were skipped or are
        # FortiGate defaults - group members / policy refs to these are filtered.
        self._skipped_addresses: Set[str] = set()

    def convert(self) -> List[Dict]:
        """Convert all FortiGate address objects to PAN-OS format.

        Returns:
            List of dicts, each representing a PAN-OS address object.
        """
        addresses = self.fg_config.get("firewall_address", [])
        if not addresses:
            print("Warning: No address objects found in FortiGate configuration")
            return []

        results: List[Dict] = []
        used_names: Dict[str, int] = {}

        for addr_dict in addresses:
            item = first_item(addr_dict)
            if item is None:
                continue
            object_name, properties = item

            # Silently ignore FortiGate factory-default objects. These exist on
            # every appliance and are not meaningful to migrate, so they are not
            # reported as skipped/failed items.
            if is_default_fortigate_address(object_name):
                print(f"  Ignored: {object_name} (FortiGate default object)")
                self._mark_skipped(object_name)
                continue

            # Determine PAN-OS type and value
            pa_type = self._determine_type(properties)
            pa_value = self._extract_value(properties, pa_type)

            if not pa_value or pa_value.strip() == "":
                print(f"  Skipped: {object_name} (empty value)")
                self.failed_items.append({
                    "name": object_name,
                    "reason": "empty value",
                    "config": properties,
                })
                self._mark_skipped(object_name)
                continue

            # Validate non-FQDN values
            if pa_type != "fqdn" and not self._is_valid_address(pa_value):
                print(f"  Skipped: {object_name} (invalid value: {pa_value})")
                self.failed_items.append({
                    "name": object_name,
                    "reason": f"invalid value: {pa_value}",
                    "config": properties,
                })
                self._mark_skipped(object_name)
                continue

            # Sanitize and deduplicate name
            sanitized = dedup_name(sanitize_name(object_name), used_names)
            self._name_map[object_name] = sanitized
            self._name_map.setdefault(sanitize_name(object_name), sanitized)

            pa_object = {
                "name": sanitized,
                "type": pa_type,
                "value": pa_value,
                "description": str(properties.get("comment", "")),
            }
            results.append(pa_object)

            if object_name != sanitized:
                print(f"  Converted: {object_name} -> {sanitized} [{pa_type}] ({pa_value})")
            else:
                print(f"  Converted: {sanitized} -> {pa_type} ({pa_value})")

        self.pa_address_objects = results
        return results

    # ------------------------------------------------------------------
    # Public accessors (consumed by group and policy converters)
    # ------------------------------------------------------------------

    def get_name_map(self) -> Dict[str, str]:
        """FortiGate name (raw and sanitized) -> final PAN-OS object name."""
        return dict(self._name_map)

    def get_skipped_addresses(self) -> Set[str]:
        """Names (raw and sanitized) of addresses that were not converted."""
        return set(self._skipped_addresses)

    def _mark_skipped(self, object_name: str) -> None:
        self._skipped_addresses.add(str(object_name))
        self._skipped_addresses.add(sanitize_name(object_name))

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _determine_type(self, properties: Dict) -> str:
        """Map FortiGate address properties to PAN-OS address type."""

        if properties.get("type") == "iprange":
            start_ip = str(properties.get("start-ip", ""))
            end_ip = str(properties.get("end-ip", ""))
            if start_ip and end_ip and start_ip == end_ip:
                return "ip-netmask"  # single host
            return "ip-range"

        if properties.get("type") == "fqdn":
            return "fqdn"

        if "subnet" in properties:
            # All subnet-based addresses use ip-netmask in PAN-OS
            return "ip-netmask"

        # Default: treat as host
        return "ip-netmask"

    def _extract_value(self, properties: Dict, pa_type: str) -> str:
        """Extract and format the address value for PAN-OS."""

        if pa_type == "ip-range":
            start_ip = str(properties.get("start-ip", "")).strip()
            end_ip = str(properties.get("end-ip", "")).strip()
            if start_ip and end_ip:
                if start_ip == end_ip:
                    return f"{start_ip}/32"
                return f"{start_ip}-{end_ip}"
            return ""

        if pa_type == "fqdn":
            # Only the fqdn field is a valid value. Never fall back to the
            # comment - it is free text, not a hostname. Missing fqdn -> ""
            # so the caller skips the object with a failed_items entry.
            fqdn = properties.get("fqdn", "")
            return str(fqdn).strip().strip('"').strip("'")

        # ip-netmask type
        # Single-host iprange (start-ip == end-ip): _determine_type maps it to
        # ip-netmask, so build the value from start-ip as a /32 host.
        if properties.get("type") == "iprange":
            start_ip = str(properties.get("start-ip", "")).strip()
            if start_ip:
                return f"{start_ip}/32"
            return ""

        if "subnet" in properties:
            subnet = properties["subnet"]
            if isinstance(subnet, list) and len(subnet) >= 2:
                ip_addr = str(subnet[0]).strip()
                netmask = str(subnet[1]).strip()
                cidr = netmask_to_cidr(netmask)
                # PAN-OS always uses CIDR notation, including /32 for hosts
                return f"{ip_addr}/{cidr}"
            elif isinstance(subnet, str):
                return subnet.strip()
        return ""

    @staticmethod
    def _is_valid_address(value: str) -> bool:
        """Basic validation for ip-netmask and ip-range values."""
        if not value:
            return False
        # ip-range: two IPs separated by dash
        if "-" in value and "/" not in value:
            parts = value.split("-")
            return len(parts) == 2 and all(_looks_like_ip(p.strip()) for p in parts)
        # ip-netmask: IP/CIDR
        if "/" in value:
            parts = value.split("/")
            return len(parts) == 2 and _looks_like_ip(parts[0])
        # Bare IP
        return _looks_like_ip(value)


def _looks_like_ip(s: str) -> bool:
    """Quick check if string looks like an IPv4 address."""
    parts = s.strip().split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
