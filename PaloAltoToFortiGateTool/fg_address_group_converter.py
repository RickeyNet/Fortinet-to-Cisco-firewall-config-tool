#!/usr/bin/env python3
"""PAN-OS Address Group Converter - FortiGate Target
======================================================
Converts PAN-OS address groups to FortiGate ``firewall addrgrp`` CLI config.

PAN-OS supports nested address groups natively, as does FortiGate - no
flattening is required (unlike the FTD converter which must flatten).
Groups are emitted in dependency order (members before the groups that
reference them) because FortiGate rejects forward references; cycles are
broken with a warning.

Member references are resolved through the address converter's name map so
deduplication renames don't produce dangling references.  Members that the
address converter skipped are dropped; a group whose members are all
dropped is skipped itself (fail closed) and recorded in ``failed_items``.
Dynamic (tag-based) PAN-OS address groups cannot be represented on
FortiGate and are recorded as failures.

FortiGate CLI output format:
    config firewall addrgrp
        edit "web-servers"
            set member "web1" "web2" "app1"
            set comment "All web servers"
        next
    end
"""

from typing import Any, Dict, List, Optional, Set

from fg_common import (
    dedup_fg_name,
    escape_fg_string,
    fg_members_str,
    sanitize_fg_name,
    topo_sort_groups,
)


class FGAddressGroupConverter:
    """Convert PAN-OS address groups to FortiGate addrgrp format."""

    def __init__(
        self,
        pa_config: Dict[str, Any],
        address_name_map: Optional[Dict[str, str]] = None,
        skipped_addresses: Optional[Set[str]] = None,
    ) -> None:
        self.pa_config = pa_config
        self._address_name_map = dict(address_name_map or {})
        self._skipped_addresses = set(skipped_addresses or ())
        self.failed_items: List[Dict] = []
        # Maps sanitized original PA group name -> final FG name
        self._name_map: Dict[str, str] = {}
        # Sanitized names of groups that could not be converted
        self._skipped_names: Set[str] = set()
        self._stats = {"total": 0, "skipped": 0}

    def convert(self) -> str:
        """Convert all address groups and return FortiGate CLI block.

        Returns:
            A string containing the ``config firewall addrgrp`` block,
            or an empty string if there are no groups.
        """
        groups = self.pa_config.get("address_groups", [])
        if not groups:
            return ""

        entries: List[str] = []
        used_names: Dict[str, int] = {}
        # Accumulates address renames plus group renames as groups convert,
        # so nested group references resolve to post-dedup names.
        member_map: Dict[str, str] = dict(self._address_name_map)

        for grp in topo_sort_groups(groups):
            orig_name = sanitize_fg_name(grp.get("name", ""))
            if not orig_name:
                continue

            if grp.get("dynamic"):
                self._record_failure(grp, "dynamic address group not supported")
                continue

            raw_members = grp.get("members", [])
            members: List[str] = []
            seen: set = set()
            for m in raw_members:
                sanitized_m = sanitize_fg_name(m)
                if not sanitized_m:
                    continue
                if (
                    sanitized_m in self._skipped_addresses
                    or sanitized_m in self._skipped_names
                ):
                    print(
                        f"  Warning: dropping unconverted member "
                        f"'{sanitized_m}' from group '{orig_name}'"
                    )
                    continue
                resolved = member_map.get(sanitized_m, sanitized_m)
                if resolved not in seen:
                    members.append(resolved)
                    seen.add(resolved)

            if not members:
                reason = "no members" if not raw_members else "all members skipped"
                self._record_failure(grp, reason)
                continue

            # Deduplicate after validation so skipped groups don't consume
            # suffix slots; record rename for downstream references.
            name = dedup_fg_name(orig_name, used_names)
            self._name_map[orig_name] = name
            member_map[orig_name] = name

            description = grp.get("description", "").strip()

            lines = [
                f'    edit "{name}"',
                f"        set member {fg_members_str(members)}",
            ]
            if description:
                lines.append(f'        set comment "{escape_fg_string(description)}"')
            lines.append("    next")

            entries.append("\n".join(lines))
            self._stats["total"] += 1
            print(f"  Converted address group: {name} ({len(members)} members)")

        if not entries:
            return ""

        block = "config firewall addrgrp\n"
        block += "\n".join(entries)
        block += "\nend\n"
        return block

    def get_statistics(self) -> Dict[str, int]:
        return dict(self._stats)

    def get_name_map(self) -> Dict[str, str]:
        """Return mapping: sanitized original PA group name -> final FG name."""
        return dict(self._name_map)

    def get_skipped_names(self) -> Set[str]:
        """Return sanitized names of groups that were not converted."""
        return set(self._skipped_names)

    def _record_failure(self, grp: Dict, reason: str) -> None:
        name = grp.get("name", "unknown")
        print(f"  Skipped address group: {name} ({reason})")
        self.failed_items.append({"name": name, "reason": reason})
        self._skipped_names.add(sanitize_fg_name(name))
        self._stats["skipped"] += 1
