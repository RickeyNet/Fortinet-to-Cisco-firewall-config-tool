#!/usr/bin/env python3
"""
Cisco FTD FDM API Configuration Reader
========================================
Connects to Cisco FTD via the Firepower Device Manager (FDM) REST API and
reads the running configuration into a normalized Python dict.

The dict is passed directly to fg_ftd_converter for conversion to
FortiGate CLI format.
"""

import os
import sys
from typing import Any, Dict, List

import requests

# Allow importing FTDBaseClient from FortiGateToFTDTool
_SELF_DIR = os.path.dirname(os.path.abspath(__file__))
_FTD_DIR = os.path.join(os.path.dirname(_SELF_DIR), "FortiGateToFTDTool")
for _d in (_SELF_DIR, _FTD_DIR):
    if os.path.isdir(_d) and _d not in sys.path:
        sys.path.insert(0, _d)

from ftd_api_base import FTDBaseClient  # noqa: E402


class FTDReader(FTDBaseClient):
    """Reads Cisco FTD configuration via the FDM REST API."""

    # ── Pagination helper ─────────────────────────────────────────────────

    def _fetch_all(self, endpoint: str) -> List[Dict]:
        """Fetch all items from a paginated FDM API endpoint.

        Handles FDM's offset/limit pagination and returns all items as a flat
        list.  Returns an empty list if the endpoint responds with 404 (object
        type not present on this FTD version/feature set).
        """
        items: List[Dict] = []
        offset = 0
        limit = 200

        while True:
            url = f"{self.base_url}{endpoint}"
            params: Dict[str, Any] = {"offset": offset, "limit": limit}
            try:
                response = self.session.get(url, params=params, timeout=60)
            except requests.exceptions.RequestException as exc:
                print(f"  [WARN] Request failed for {endpoint}: {exc}")
                break

            if response.status_code == 404:
                return []
            if response.status_code != 200:
                # Print only the parsed FDM error description - never the raw
                # body, since error replies can echo submitted form fields.
                try:
                    err = response.json().get("error", {}).get("messages", [{}])[0].get("description", "")
                except (ValueError, TypeError, KeyError):
                    err = ""
                print(
                    f"  [WARN] HTTP {response.status_code} for {endpoint}"
                    + (f": {err}" if err else "")
                )
                break

            data = response.json()
            page = data.get("items", [])
            if not page:
                break
            items.extend(page)

            paging = data.get("paging", {})
            total = paging.get("count", len(items))
            if len(items) >= total:
                break
            # Advance by the actual page size (servers may return fewer
            # items than requested, which would otherwise skip objects).
            offset += len(page)

        return items

    # ── Per-section readers ───────────────────────────────────────────────

    def read_network_objects(self) -> List[Dict]:
        print("  Fetching address objects (/object/networks)...")
        result = self._fetch_all("/object/networks")
        print(f"    → {len(result)} objects")
        return result

    def read_network_groups(self) -> List[Dict]:
        print("  Fetching address groups (/object/networkgroups)...")
        result = self._fetch_all("/object/networkgroups")
        print(f"    → {len(result)} groups")
        return result

    def read_tcp_ports(self) -> List[Dict]:
        print("  Fetching TCP port objects (/object/tcpports)...")
        result = self._fetch_all("/object/tcpports")
        print(f"    → {len(result)} objects")
        return result

    def read_udp_ports(self) -> List[Dict]:
        print("  Fetching UDP port objects (/object/udpports)...")
        result = self._fetch_all("/object/udpports")
        print(f"    → {len(result)} objects")
        return result

    def read_icmpv4_ports(self) -> List[Dict]:
        print("  Fetching ICMPv4 port objects (/object/icmpv4ports)...")
        result = self._fetch_all("/object/icmpv4ports")
        print(f"    → {len(result)} objects")
        return result

    def read_icmpv6_ports(self) -> List[Dict]:
        print("  Fetching ICMPv6 port objects (/object/icmpv6ports)...")
        result = self._fetch_all("/object/icmpv6ports")
        print(f"    → {len(result)} objects")
        return result

    def read_port_groups(self) -> List[Dict]:
        print("  Fetching service groups (/object/portgroups)...")
        result = self._fetch_all("/object/portgroups")
        print(f"    → {len(result)} groups")
        return result

    def read_interfaces(self) -> List[Dict]:
        print("  Fetching physical interfaces (/devices/default/interfaces)...")
        result = self._fetch_all("/devices/default/interfaces")
        print(f"    → {len(result)} interfaces")
        return result

    def read_etherchannel_interfaces(self) -> List[Dict]:
        print("  Fetching EtherChannel interfaces...")
        result = self._fetch_all("/devices/default/etherchannelinterfaces")
        print(f"    → {len(result)} EtherChannels")
        return result

    def read_subinterfaces(
        self,
        physical_interfaces: List[Dict],
        etherchannel_interfaces: List[Dict],
    ) -> List[Dict]:
        """Fetch VLAN subinterfaces.

        FDM exposes subinterfaces only under per-parent endpoints:
            /devices/default/interfaces/{parentId}/subinterfaces
            /devices/default/etherchannelinterfaces/{parentId}/subinterfaces
        """
        print("  Fetching VLAN subinterfaces (per-parent endpoints)...")
        subifs: List[Dict] = []
        for base, parents in (
            ("/devices/default/interfaces", physical_interfaces),
            ("/devices/default/etherchannelinterfaces", etherchannel_interfaces),
        ):
            for parent in parents:
                parent_id = parent.get("id", "")
                if not parent_id:
                    continue
                subifs.extend(self._fetch_all(f"{base}/{parent_id}/subinterfaces"))
        print(f"    → {len(subifs)} subinterfaces")
        return subifs

    def read_security_zones(self) -> List[Dict]:
        print("  Fetching security zones (/object/securityzones)...")
        result = self._fetch_all("/object/securityzones")
        print(f"    → {len(result)} zones")
        return result

    def read_static_routes(self) -> List[Dict]:
        """Fetch static routes from all virtual routers."""
        print("  Fetching static routes (/devices/default/routing/virtualrouters)...")
        routes: List[Dict] = []
        vrs = self._fetch_all("/devices/default/routing/virtualrouters")
        for vr in vrs:
            vr_id = vr.get("id", "")
            vr_name = vr.get("name", vr_id)
            if not vr_id:
                continue
            vr_routes = self._fetch_all(
                f"/devices/default/routing/virtualrouters/{vr_id}/staticroutes"
            )
            print(f"    {len(vr_routes)} routes in virtual-router '{vr_name}'")
            routes.extend(vr_routes)
        print(f"    → {len(routes)} static routes total")
        return routes

    def read_access_rules(self) -> List[Dict]:
        print("  Fetching access rules (/policy/accesspolicies/default/accessrules)...")
        result = self._fetch_all("/policy/accesspolicies/default/accessrules")
        print(f"    → {len(result)} rules")
        return result

    # ── Full-config reader ────────────────────────────────────────────────

    def read_all(self) -> Dict[str, Any]:
        """Pull the complete FTD configuration and return a normalized dict."""
        config: Dict[str, Any] = {
            "network_objects":         self.read_network_objects(),
            "network_groups":          self.read_network_groups(),
            "tcp_ports":               self.read_tcp_ports(),
            "udp_ports":               self.read_udp_ports(),
            "icmpv4_ports":            self.read_icmpv4_ports(),
            "icmpv6_ports":            self.read_icmpv6_ports(),
            "port_groups":             self.read_port_groups(),
            "interfaces":              self.read_interfaces(),
            "etherchannel_interfaces": self.read_etherchannel_interfaces(),
            "security_zones":          self.read_security_zones(),
            "static_routes":           self.read_static_routes(),
            "access_rules":            self.read_access_rules(),
        }
        # VLAN subinterfaces live under per-parent endpoints; fold them into
        # the interfaces list so the converter's vlanId branch handles them.
        config["interfaces"] = config["interfaces"] + self.read_subinterfaces(
            config["interfaces"], config["etherchannel_interfaces"]
        )
        return config
