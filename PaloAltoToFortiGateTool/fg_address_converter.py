#!/usr/bin/env python3
"""PAN-OS Address Object Converter - FortiGate Target
======================================================
Converts PAN-OS address objects to FortiGate ``firewall address`` CLI config.

PAN-OS address types and their FortiGate equivalents:
    ip-netmask  -> set type subnet / set subnet <ip> <mask>
    ip-range    -> set type iprange / set start-ip / set end-ip
    fqdn        -> set type fqdn / set fqdn <domain>

FortiGate CLI output format:
    config firewall address
        edit "webserver"
            set subnet 10.10.20.100 255.255.255.255
            set comment "Web server"
        next
        edit "branch_range"
            set type iprange
            set start-ip 10.0.0.1
            set end-ip 10.0.0.10
        next
        edit "update_server"
            set type fqdn
            set fqdn "updates.example.com"
        next
    end
"""

from typing import Any, Dict, List, Set

from fg_common import dedup_fg_name, escape_fg_string, sanitize_fg_name, split_cidr


class FGAddressConverter:
    """Convert PAN-OS address objects to FortiGate address format."""

    def __init__(self, pa_config: Dict[str, Any]) -> None:
        self.pa_config = pa_config
        self.failed_items: List[Dict] = []
        # Maps sanitized original PA name -> final FG name (after dedup);
        # consumed by group/policy converters so renames don't break refs.
        self._name_map: Dict[str, str] = {}
        # Sanitized names of addresses that could not be converted
        self._skipped_names: Set[str] = set()
        self._stats = {
            "total": 0,
            "subnet": 0,
            "iprange": 0,
            "fqdn": 0,
            "skipped": 0,
        }

    def convert(self) -> str:
        """Convert all address objects and return FortiGate CLI block.

        Returns:
            A string containing the ``config firewall address`` block,
            or an empty string if there are no address objects.
        """
        addresses = self.pa_config.get("addresses", [])
        if not addresses:
            print("  Warning: No address objects found in PAN-OS configuration")
            return ""

        entries: List[str] = []
        used_names: Dict[str, int] = {}

        for addr in addresses:
            orig_name = sanitize_fg_name(addr.get("name", ""))
            if not orig_name:
                continue

            addr_type = addr.get("type", "")
            value = addr.get("value", "").strip()
            description = addr.get("description", "").strip()

            # Validate first: skipped objects must not consume dedup slots
            body: List[str] = []

            if addr_type == "ip-netmask":
                ip, netmask = split_cidr(value)
                if not ip:
                    self._record_failure(addr, "empty ip-netmask value")
                    continue
                body.append(f"        set subnet {ip} {netmask}")
                self._stats["subnet"] += 1

            elif addr_type == "ip-range":
                # Format: "10.0.0.1-10.0.0.10"
                if "-" in value:
                    parts = value.split("-", 1)
                    start_ip = parts[0].strip()
                    end_ip = parts[1].strip()
                else:
                    self._record_failure(addr, f"unrecognized ip-range format: {value}")
                    continue
                body.append("        set type iprange")
                body.append(f"        set start-ip {start_ip}")
                body.append(f"        set end-ip {end_ip}")
                self._stats["iprange"] += 1

            elif addr_type == "fqdn":
                if not value:
                    self._record_failure(addr, "empty fqdn value")
                    continue
                body.append("        set type fqdn")
                body.append(f'        set fqdn "{escape_fg_string(value)}"')
                self._stats["fqdn"] += 1

            else:
                self._record_failure(addr, f"unsupported address type: {addr_type}")
                continue

            # Deduplicate names and record the mapping for reference fixup
            name = dedup_fg_name(orig_name, used_names)
            self._name_map[orig_name] = name

            lines: List[str] = [f'    edit "{name}"'] + body

            if description:
                lines.append(f'        set comment "{escape_fg_string(description)}"')

            lines.append("    next")
            entries.append("\n".join(lines))
            self._stats["total"] += 1
            print(f"  Converted address: {name} ({addr_type})")

        if not entries:
            return ""

        block = "config firewall address\n"
        block += "\n".join(entries)
        block += "\nend\n"
        return block

    def get_statistics(self) -> Dict[str, int]:
        return dict(self._stats)

    def get_name_map(self) -> Dict[str, str]:
        """Return mapping: sanitized original PA name -> final FG name."""
        return dict(self._name_map)

    def get_skipped_names(self) -> Set[str]:
        """Return sanitized names of addresses that were not converted."""
        return set(self._skipped_names)

    def _record_failure(self, addr: Dict, reason: str) -> None:
        name = addr.get("name", "unknown")
        print(f"  Skipped address: {name} ({reason})")
        self.failed_items.append({"name": name, "reason": reason})
        self._skipped_names.add(sanitize_fg_name(name))
        self._stats["skipped"] += 1
