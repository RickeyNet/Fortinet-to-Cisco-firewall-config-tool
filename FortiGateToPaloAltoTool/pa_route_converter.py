#!/usr/bin/env python3
"""
FortiGate Static Route Converter - Palo Alto PAN-OS Target
===========================================================
Converts FortiGate ``router_static`` entries to PAN-OS static routes.

PAN-OS static routes live under a virtual router (default: "default") and
use CIDR notation directly - no separate network object is needed (unlike FTD).

Output JSON:
    {
        "name": "route_10_0_20_0",
        "destination": "10.0.20.0/24",
        "nexthop": "10.0.222.18",
        "interface": "ethernet1/1",
        "metric": 10,
        "description": "Route to branch"
    }
"""

from typing import Any, Dict, List, Optional

from pa_common import sanitize_name, netmask_to_cidr, first_item, dedup_name


class PARouteConverter:
    """Convert FortiGate static routes to PAN-OS static route format."""

    def __init__(
        self,
        fortigate_config: Dict[str, Any],
        interface_name_mapping: Optional[Dict[str, str]] = None,
    ) -> None:
        self.fg_config = fortigate_config
        self.pa_static_routes: List[Dict] = []
        self.failed_items: List[Dict] = []

        # FortiGate interface name -> PAN-OS interface/zone name
        self._interface_name_mapping = interface_name_mapping or {}

        # Statistics
        self._stats = {
            "total_routes": 0,
            "converted": 0,
            "blackhole_skipped": 0,
            "other_skipped": 0,
        }

    def convert(self) -> List[Dict]:
        """Convert all FortiGate static routes to PAN-OS format.

        Returns:
            List of dicts, each representing a PAN-OS static route.
        """
        routes = self.fg_config.get("router_static", [])
        if not routes:
            print("Warning: No static routes found in FortiGate configuration")
            return []

        results: List[Dict] = []
        used_names: Dict[str, int] = {}

        for route_dict in routes:
            item = first_item(route_dict)
            if item is None:
                continue
            route_id, properties = item

            self._stats["total_routes"] += 1

            # --- Skip disabled routes ---
            status = str(properties.get("status", "enable")).strip().lower()
            if status in ("disable", "disabled"):
                self._stats["other_skipped"] += 1
                self.failed_items.append({
                    "name": f"Route_{route_id}",
                    "reason": "route is disabled on the FortiGate (status: disable) "
                              "- not migrated",
                    "config": properties,
                })
                print(f"  Skipped: Route {route_id} (disabled)")
                continue

            # --- Skip blackhole routes ---
            blackhole = str(properties.get("blackhole", "")).strip().lower()
            if blackhole in ("enable", "enabled", "yes"):
                self._stats["blackhole_skipped"] += 1
                print(f"  Skipped: Route {route_id} (blackhole)")
                continue

            # --- Destination ---
            destination = self._extract_destination(properties)
            if not destination and "dst" not in properties and \
                    str(properties.get("gateway", "")).strip() not in ("", "0.0.0.0"):
                # FortiGate omits `set dst` for default routes (0.0.0.0/0 is
                # the field's default value). A gateway with no dst is clearly
                # the default route; anything else stays skipped below.
                destination = "0.0.0.0/0"
            if not destination:
                self._stats["other_skipped"] += 1
                self.failed_items.append({
                    "name": f"Route_{route_id}",
                    "reason": "no destination",
                    "config": properties,
                })
                print(f"  Skipped: Route {route_id} (no destination)")
                continue

            # --- Gateway ---
            gateway = str(properties.get("gateway", "")).strip()
            if not gateway or gateway == "0.0.0.0":
                # Routes without a gateway need an interface at minimum
                if not properties.get("device"):
                    self._stats["other_skipped"] += 1
                    self.failed_items.append({
                        "name": f"Route_{route_id}",
                        "reason": "no gateway and no interface",
                        "config": properties,
                    })
                    print(f"  Skipped: Route {route_id} (no gateway/interface)")
                    continue
                gateway = None  # Interface-only route

            # --- Interface ---
            fg_interface = str(properties.get("device", "")).strip()
            pa_interface = self._map_interface(fg_interface) if fg_interface else None

            # --- Metric ---
            metric = self._parse_metric(properties)

            # --- Route name ---
            comment = str(properties.get("comment", "")).strip()
            route_name = self._build_route_name(destination, route_id, used_names)

            # --- Build route ---
            route: Dict[str, Any] = {
                "name": route_name,
                "destination": destination,
            }

            if gateway:
                route["nexthop"] = gateway
            if pa_interface:
                route["interface"] = pa_interface
            if metric is not None:
                route["metric"] = metric
            if comment:
                route["description"] = comment

            results.append(route)
            self._stats["converted"] += 1

            gw_display = gateway if gateway else "interface-only"
            intf_display = pa_interface if pa_interface else ""
            print(f"  Converted: {route_name} -> {destination} "
                  f"via {gw_display} {intf_display} (metric {metric})")

        self.pa_static_routes = results
        return results

    def get_statistics(self) -> Dict[str, int]:
        return dict(self._stats)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_destination(self, properties: Dict) -> str:
        """Extract destination in CIDR notation from FortiGate route."""
        dst = properties.get("dst")
        if dst is None:
            return ""

        # FortiGate format: [ip, netmask] or "ip netmask" or "ip/cidr"
        if isinstance(dst, list) and len(dst) >= 2:
            ip_addr = str(dst[0]).strip()
            netmask = str(dst[1]).strip()
            if not ip_addr:
                return ""
            cidr = netmask_to_cidr(netmask)
            return f"{ip_addr}/{cidr}"

        dst_str = str(dst).strip()
        if "/" in dst_str:
            return dst_str

        # Space-separated "ip netmask"
        parts = dst_str.split()
        if len(parts) == 2:
            cidr = netmask_to_cidr(parts[1])
            return f"{parts[0]}/{cidr}"

        return dst_str

    def _map_interface(self, fg_interface: str) -> str:
        """Map FortiGate interface name to PAN-OS interface name."""
        if not fg_interface:
            return ""

        # Direct mapping from interface converter
        if fg_interface in self._interface_name_mapping:
            return self._interface_name_mapping[fg_interface]

        # Case-insensitive match
        lower = fg_interface.lower()
        for fg_name, pa_name in self._interface_name_mapping.items():
            if fg_name.lower() == lower:
                return pa_name

        # Fallback: return sanitized name
        return sanitize_name(fg_interface)

    @staticmethod
    def _parse_metric(properties: Dict) -> int:
        """Extract metric/distance value."""
        for key in ("distance", "priority", "metric"):
            val = properties.get(key)
            if val is not None:
                try:
                    return int(val)
                except (ValueError, TypeError):
                    pass
        return 10  # PAN-OS default metric

    def _build_route_name(
        self, destination: str, route_id: str, used_names: Dict[str, int]
    ) -> str:
        """Build a unique, sanitized route name."""
        # Create name from destination
        safe_dest = destination.replace("/", "_").replace(".", "_")
        base_name = f"route_{safe_dest}"
        sanitized = sanitize_name(base_name)

        if not sanitized:
            sanitized = f"route_{route_id}"

        return dedup_name(sanitized, used_names)
