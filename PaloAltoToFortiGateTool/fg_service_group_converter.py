#!/usr/bin/env python3
"""PAN-OS Service Group Converter - FortiGate Target
======================================================
Converts PAN-OS service groups to FortiGate ``firewall service group``
CLI config.

Member references are resolved through the service converter's name map so
deduplication renames don't produce dangling references.  When a group
references BOTH halves of a merged TCP+UDP companion pair, the pair is
collapsed to the merged service; a single half keeps its individual object.
Members that the service converter skipped are dropped; a group whose
members are all dropped is skipped itself (fail closed) and recorded in
``failed_items``.  Groups are emitted in dependency order (members before
the groups that reference them); cycles are broken with a warning.

FortiGate CLI output format:
    config firewall service group
        edit "web-services"
            set member "HTTP" "HTTPS" "HTTP_8080"
        next
    end
"""

from typing import Any, Dict, List, Optional, Set

from fg_common import dedup_fg_name, fg_members_str, sanitize_fg_name, topo_sort_groups
from fg_service_converter import collapse_merged_pairs


class FGServiceGroupConverter:
    """Convert PAN-OS service groups to FortiGate service group format."""

    def __init__(
        self,
        pa_config: Dict[str, Any],
        service_name_map: Dict[str, str],
        skipped_services: Optional[Set[str]] = None,
        merged_pairs: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        self.pa_config = pa_config
        self._name_map = service_name_map
        self._skipped_services = set(skipped_services or ())
        self._merged_pairs = dict(merged_pairs or {})
        self.failed_items: List[Dict] = []
        # Maps sanitized original PA group name -> final FG name
        self._group_name_map: Dict[str, str] = {}
        # Sanitized names of groups that could not be converted
        self._skipped_names: Set[str] = set()
        self._stats = {"total": 0, "skipped": 0}

    def convert(self) -> str:
        """Convert all service groups and return FortiGate CLI block.

        Returns:
            A string containing the ``config firewall service group`` block,
            or an empty string if there are no service groups.
        """
        groups = self.pa_config.get("service_groups", [])
        if not groups:
            return ""

        entries: List[str] = []
        used_names: Dict[str, int] = {}
        # Accumulates service renames plus group renames as groups convert,
        # so nested group references resolve to post-dedup names.
        member_map: Dict[str, str] = dict(self._name_map)

        for grp in topo_sort_groups(groups):
            orig_name = sanitize_fg_name(grp.get("name", ""))
            if not orig_name:
                continue

            raw_members = grp.get("members", [])
            members: List[str] = []
            seen: set = set()
            for m in raw_members:
                sanitized_m = sanitize_fg_name(m)
                if not sanitized_m:
                    continue
                if (
                    sanitized_m in self._skipped_services
                    or sanitized_m in self._skipped_names
                ):
                    print(
                        f"  Warning: dropping unconverted member "
                        f"'{sanitized_m}' from service group '{orig_name}'"
                    )
                    continue
                # Resolve through name map (handles dedup renames)
                resolved = member_map.get(sanitized_m, sanitized_m)
                if resolved and resolved not in seen:
                    members.append(resolved)
                    seen.add(resolved)

            # Collapse TCP+UDP companion pairs referenced together
            members = collapse_merged_pairs(members, self._merged_pairs)

            if not members:
                self._record_failure(grp, "no resolvable members")
                continue

            # Deduplicate after validation so skipped groups don't consume
            # suffix slots; record rename for downstream references.
            name = dedup_fg_name(orig_name, used_names)
            self._group_name_map[orig_name] = name
            member_map[orig_name] = name

            lines = [
                f'    edit "{name}"',
                f"        set member {fg_members_str(members)}",
                "    next",
            ]
            entries.append("\n".join(lines))
            self._stats["total"] += 1
            print(f"  Converted service group: {name} ({len(members)} members)")

        if not entries:
            return ""

        block = "config firewall service group\n"
        block += "\n".join(entries)
        block += "\nend\n"
        return block

    def get_statistics(self) -> Dict[str, int]:
        return dict(self._stats)

    def get_name_map(self) -> Dict[str, str]:
        """Return mapping: sanitized original PA group name -> final FG name."""
        return dict(self._group_name_map)

    def get_skipped_names(self) -> Set[str]:
        """Return sanitized names of groups that were not converted."""
        return set(self._skipped_names)

    def _record_failure(self, grp: Dict, reason: str) -> None:
        name = grp.get("name", "unknown")
        print(f"  Skipped service group: {name} ({reason})")
        self.failed_items.append({"name": name, "reason": reason})
        self._skipped_names.add(sanitize_fg_name(name))
        self._stats["skipped"] += 1
