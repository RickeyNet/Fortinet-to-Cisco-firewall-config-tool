#!/usr/bin/env python3
"""
FortiGate Service Group Converter - Palo Alto PAN-OS Target
============================================================
Converts FortiGate ``firewall_service_group`` entries to PAN-OS service groups.

PAN-OS service groups can contain both individual services and nested groups.
When a FortiGate service was split (TCP+UDP), all resulting PAN-OS objects
are added as separate members.

Output JSON:
    {
        "name": "web_services",
        "members": ["tcp_80", "tcp_443", "udp_53"]
    }
"""

from typing import Any, Dict, List, Set, Tuple

from pa_common import sanitize_name, build_group_lookup, first_item, dedup_name


class PAServiceGroupConverter:
    """Convert FortiGate service groups to PAN-OS service-group format."""

    def __init__(self, fortigate_config: Dict[str, Any]) -> None:
        self.fg_config = fortigate_config
        self.pa_service_groups: List[Dict] = []
        self.failed_items: List[Dict] = []

        # Set by the orchestrator after service conversion
        self._split_services: Set[str] = set()
        self._service_name_mapping: Dict[str, List[Tuple[str, str]]] = {}
        self._skipped_services: Set[str] = set()

        # FortiGate group name (raw and sanitized) -> final PAN-OS group name.
        self._name_map: Dict[str, str] = {}
        # Groups that were skipped entirely (no members / all filtered).
        self._skipped_groups: Set[str] = set()

    def set_split_services(
        self,
        split_services: Set[str],
        service_name_mapping: Dict[str, List[Tuple[str, str]]],
        skipped_services: Set[str],
    ) -> None:
        """Provide service conversion context (called before convert)."""
        self._split_services = split_services
        self._service_name_mapping = service_name_mapping
        self._skipped_services = skipped_services

    def get_name_map(self) -> Dict[str, str]:
        """FortiGate group name (raw and sanitized) -> final PAN-OS name."""
        return dict(self._name_map)

    def get_skipped_groups(self) -> Set[str]:
        """Names (raw and sanitized) of groups that were not converted."""
        return set(self._skipped_groups)

    def convert(self) -> List[Dict]:
        """Convert all FortiGate service groups to PAN-OS format.

        Returns:
            List of dicts, each representing a PAN-OS service group.
        """
        groups = self.fg_config.get("firewall_service_group", [])
        if not groups:
            print("Warning: No service groups found in FortiGate configuration")
            return []

        # Build lookup for nested-group expansion
        group_lookup = build_group_lookup(groups)

        results: List[Dict] = []
        used_names: Dict[str, int] = {}

        for group_dict in groups:
            item = first_item(group_dict)
            if item is None:
                continue
            group_name, properties = item

            # Extract raw members
            members_raw = properties.get("member", [])
            if isinstance(members_raw, str):
                members_raw = [members_raw]
            elif not isinstance(members_raw, list):
                members_raw = []

            if not members_raw:
                print(f"  Skipped: {group_name} (no members)")
                self.failed_items.append({
                    "name": group_name,
                    "reason": "no members",
                    "config": properties,
                })
                self._mark_skipped(group_name)
                continue

            # Resolve each member through the service name mapping
            resolved_members: List[str] = []
            for member in members_raw:
                sanitized_member = sanitize_name(member)

                # Skip protocols that have no PAN-OS service object
                if sanitized_member in self._skipped_services:
                    print(f"    Filtered skipped service '{sanitized_member}' from group '{group_name}'")
                    continue

                # If this member was split into multiple PAN-OS objects, add them all
                if sanitized_member in self._service_name_mapping:
                    mapped = self._service_name_mapping[sanitized_member]
                    for pa_name, _proto in mapped:
                        if pa_name not in resolved_members:
                            resolved_members.append(pa_name)
                elif sanitized_member in group_lookup:
                    # Nested group reference - keep as-is (PAN-OS supports nesting)
                    if sanitized_member not in resolved_members:
                        resolved_members.append(sanitized_member)
                else:
                    # Direct object reference
                    if sanitized_member not in resolved_members:
                        resolved_members.append(sanitized_member)

            if not resolved_members:
                print(f"  Skipped: {group_name} (all members filtered out)")
                self.failed_items.append({
                    "name": group_name,
                    "reason": "all members filtered out",
                    "config": properties,
                })
                self._mark_skipped(group_name)
                continue

            # Sanitize group name (deduplicate)
            sanitized = dedup_name(sanitize_name(group_name), used_names)
            self._name_map[group_name] = sanitized
            self._name_map.setdefault(sanitize_name(group_name), sanitized)

            pa_group = {
                "name": sanitized,
                "members": resolved_members,
            }
            results.append(pa_group)

            if group_name != sanitized:
                print(f"  Converted: {group_name} -> {sanitized} ({len(resolved_members)} members)")
            else:
                print(f"  Converted: {sanitized} ({len(resolved_members)} members)")

        self.pa_service_groups = results
        return results

    def _mark_skipped(self, group_name: str) -> None:
        self._skipped_groups.add(str(group_name))
        self._skipped_groups.add(sanitize_name(group_name))
