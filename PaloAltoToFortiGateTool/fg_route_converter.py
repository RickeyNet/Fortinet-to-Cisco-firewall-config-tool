#!/usr/bin/env python3
"""PAN-OS Static Route Converter - FortiGate Target
====================================================
Converts PAN-OS static routes to FortiGate ``router static`` CLI config.

PAN-OS routes use CIDR notation; FortiGate uses separate IP + netmask.

FortiGate CLI output format:
    config router static
        edit 1
            set dst 10.0.20.0 255.255.255.0
            set gateway 10.0.222.18
            set device "ethernet1/2"
            set distance 10
            set comment "Branch office route"
        next
    end
"""

from typing import Any, Dict, List, Optional

from fg_common import (
    FG_INTERFACE_NAME_MAX_LENGTH,
    escape_fg_string,
    sanitize_fg_name,
    split_cidr,
)


class FGRouteConverter:
    """Convert PAN-OS static routes to FortiGate router static format."""

    def __init__(
        self,
        pa_config: Dict[str, Any],
        interface_name_map: Optional[Dict[str, str]] = None,
    ) -> None:
        self.pa_config = pa_config
        self._interface_name_map = dict(interface_name_map or {})
        self.failed_items: List[Dict] = []
        self._stats = {
            "total": 0,
            "converted": 0,
            "skipped": 0,
        }

    def convert(self) -> str:
        """Convert all static routes and return FortiGate CLI block.

        Returns:
            A string containing the ``config router static`` block,
            or an empty string if there are no routes.
        """
        routes = self.pa_config.get("static_routes", [])
        if not routes:
            print("  Warning: No static routes found in PAN-OS configuration")
            return ""

        entries: List[str] = []
        route_id = 1

        for route in routes:
            self._stats["total"] += 1

            destination = str(route.get("destination", "")).strip()
            if not destination:
                self._record_failure(route, "no destination")
                continue

            dst_ip, dst_mask = split_cidr(destination)
            if not dst_ip:
                self._record_failure(route, f"invalid destination: {destination}")
                continue

            nexthop: Optional[str] = route.get("nexthop")
            # "0.0.0.0" is not a usable gateway - treat as no nexthop
            if nexthop == "0.0.0.0":
                nexthop = None
            interface = str(route.get("interface", "")).strip()
            metric = route.get("metric", 10)
            description = str(route.get("description", "")).strip()

            if not nexthop and not interface:
                self._record_failure(route, "no nexthop and no interface")
                continue

            lines = [f"    edit {route_id}"]
            lines.append(f"        set dst {dst_ip} {dst_mask}")

            if nexthop:
                lines.append(f"        set gateway {nexthop}")

            if interface:
                sanitized_intf = sanitize_fg_name(interface)
                fg_intf = self._interface_name_map.get(
                    sanitized_intf, sanitized_intf[:FG_INTERFACE_NAME_MAX_LENGTH]
                )
                lines.append(f'        set device "{fg_intf}"')

            try:
                lines.append(f"        set distance {int(metric)}")
            except (ValueError, TypeError):
                lines.append("        set distance 10")

            if description:
                lines.append(f'        set comment "{escape_fg_string(description)}"')

            lines.append("    next")
            entries.append("\n".join(lines))

            self._stats["converted"] += 1
            gw_display = nexthop if nexthop else "interface-only"
            print(
                f"  Converted route: {route_id} -> {destination} "
                f"via {gw_display}"
            )
            route_id += 1

        if not entries:
            return ""

        block = "config router static\n"
        block += "\n".join(entries)
        block += "\nend\n"
        return block

    def get_statistics(self) -> Dict[str, int]:
        return dict(self._stats)

    def _record_failure(self, route: Dict, reason: str) -> None:
        name = route.get("name", "unknown")
        print(f"  Skipped route: {name} ({reason})")
        self.failed_items.append({"name": name, "reason": reason})
        self._stats["skipped"] += 1
