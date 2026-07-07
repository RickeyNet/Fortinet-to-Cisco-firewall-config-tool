#!/usr/bin/env python3
"""
FortiGate Address Group Converter - Palo Alto PAN-OS Target
============================================================
Converts FortiGate ``firewall_addrgrp`` entries to PAN-OS address groups.

PAN-OS supports nested address groups natively, so no flattening is needed
(unlike FTD).

Output JSON:
    {
        "name": "web_servers",
        "members": ["webserver1", "webserver2"],
        "description": "Web server group"
    }
"""

from typing import Any, Dict, List, Optional, Set

from pa_common import sanitize_name, first_item, dedup_name


class PAAddressGroupConverter:
    """Convert FortiGate address groups to PAN-OS address-group format."""

    def __init__(self, fortigate_config: Dict[str, Any]) -> None:
        self.fg_config = fortigate_config
        self.pa_address_groups: List[Dict] = []
        self.failed_items: List[Dict] = []

        # Context from the address converter (set by the orchestrator).
        self._skipped_addresses: Set[str] = set()
        self._address_name_map: Dict[str, str] = {}

        # FortiGate group name (raw and sanitized) -> final PAN-OS group name.
        self._name_map: Dict[str, str] = {}
        # Groups that were skipped entirely (no members / all filtered).
        self._skipped_groups: Set[str] = set()

    def set_address_context(
        self,
        skipped_addresses: Optional[Set[str]] = None,
        address_name_map: Optional[Dict[str, str]] = None,
    ) -> None:
        """Provide address conversion context (called before convert)."""
        self._skipped_addresses = set(skipped_addresses or set())
        self._address_name_map = dict(address_name_map or {})

    def get_name_map(self) -> Dict[str, str]:
        """FortiGate group name (raw and sanitized) -> final PAN-OS name."""
        return dict(self._name_map)

    def get_skipped_groups(self) -> Set[str]:
        """Names (raw and sanitized) of groups that were not converted."""
        return set(self._skipped_groups)

    def convert(self) -> List[Dict]:
        """Convert all FortiGate address groups to PAN-OS format.

        Returns:
            List of dicts, each representing a PAN-OS address group.
        """
        groups = self.fg_config.get("firewall_addrgrp", [])
        if not groups:
            print("Warning: No address groups found in FortiGate configuration")
            return []

        results: List[Dict] = []
        used_names: Dict[str, int] = {}

        for group_dict in groups:
            item = first_item(group_dict)
            if item is None:
                continue
            group_name, properties = item

            # Extract members (can be string or list)
            members_raw = properties.get("member", [])
            if isinstance(members_raw, str):
                members_list = [members_raw]
            elif isinstance(members_raw, list):
                members_list = members_raw
            else:
                members_list = []

            if not members_list:
                print(f"  Skipped: {group_name} (no members)")
                self.failed_items.append({
                    "name": group_name,
                    "reason": "no members",
                    "config": properties,
                })
                self._mark_skipped(group_name)
                continue

            # Resolve member names: filter members whose address object was
            # skipped/dropped, and follow dedup renames from the address
            # converter. Nested group references are kept as-is (PAN-OS
            # supports nesting).
            sanitized_members: List[str] = []
            filtered: List[str] = []
            for member in members_list:
                member_raw = str(member)
                member_sanitized = sanitize_name(member_raw)
                if (member_raw in self._skipped_addresses
                        or member_sanitized in self._skipped_addresses):
                    print(f"    Filtered skipped address '{member_raw}' "
                          f"from group '{group_name}'")
                    filtered.append(member_raw)
                    continue
                resolved = self._address_name_map.get(
                    member_raw,
                    self._address_name_map.get(member_sanitized, member_sanitized),
                )
                if resolved and resolved not in sanitized_members:
                    sanitized_members.append(resolved)

            if not sanitized_members:
                print(f"  Skipped: {group_name} (all members filtered out)")
                self.failed_items.append({
                    "name": group_name,
                    "reason": "all members filtered out"
                              + (f" ({', '.join(filtered)})" if filtered else ""),
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
                "members": sanitized_members,
                "description": str(properties.get("comment", "")),
            }
            results.append(pa_group)

            if group_name != sanitized:
                print(f"  Converted: {group_name} -> {sanitized} ({len(sanitized_members)} members)")
            else:
                print(f"  Converted: {sanitized} ({len(sanitized_members)} members)")

        self.pa_address_groups = results
        return results

    def _mark_skipped(self, group_name: str) -> None:
        self._skipped_groups.add(str(group_name))
        self._skipped_groups.add(sanitize_name(group_name))
