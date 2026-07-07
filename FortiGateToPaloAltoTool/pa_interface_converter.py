#!/usr/bin/env python3
"""
FortiGate Interface Converter - Palo Alto PAN-OS Target
=========================================================
Converts FortiGate ``system_interface`` entries to PAN-OS interface and zone
configurations.

WHAT THIS MODULE DOES:
    - Parses FortiGate 'system_interface' section from YAML
    - Maps FortiGate ports to PAN-OS hardware interfaces
    - Converts physical interfaces with IP/netmask/MTU
    - Converts VLAN interfaces to PAN-OS subinterfaces
    - Converts aggregate interfaces to PAN-OS aggregate-ethernet (LACP)
    - Generates zone definitions from FortiGate zone/role info

FORTIGATE INTERFACE TYPES:
    - type: physical   → PAN-OS ethernet (layer3 with IP)
    - type: aggregate  → PAN-OS aggregate-ethernet (LACP)
    - VLAN (interface + vlanid) → PAN-OS subinterface (ethernet1/X.tag)
    - type: switch (system_switch-interface) → PAN-OS Layer-2 segment:
          member ports become layer2 interfaces grouped in a VLAN object, and
          the switch's IP moves onto a vlan.N interface (SVI) - the L3 analog of
          an FTD bridge group (BVI).
    - type: loopback/tunnel → Skipped

INTERFACE SCALE-UP (mirrors the FortiGate -> FTD tool):
    - Aggregate expansion  : grow an existing aggregate to MORE ethernet members
    - Aggregate promotion  : turn a plain physical port into a NEW aggregate-ethernet
    - Bridge-group expansion: grow a switch's Layer-2 segment with MORE members
    - Bridge-group promotion: turn a plain physical port into a NEW Layer-2 segment
  Port-channel <-> aggregate-ethernet; bridge-group <-> Layer-2 VLAN + vlan.N SVI.

OUTPUT JSON (interfaces):
    {
        "name": "ethernet1/1",
        "type": "physical",
        "ip_address": "10.0.0.1/24",
        "comment": "LAN interface",
        "mtu": 1500,
        "enabled": true,
        "link_speed": "auto"
    }

OUTPUT JSON (zones):
    {
        "name": "trust",
        "interfaces": ["ethernet1/1", "ethernet1/2"]
    }

PA-440 hardware reference:
    - 8x 1G copper: ethernet1/1 through ethernet1/8
    - 1x mgmt port (separate, not in data plane)
"""

import re
from typing import Any, Dict, List, Optional, Set

from pa_common import (
    sanitize_name,
    netmask_to_cidr,
    collect_mgmt_ha_interfaces,
    is_default_fortigate_interface,
)


# PA model definitions
PA_MODELS = {
    "pa-440": {
        "name": "Palo Alto PA-440",
        "total_ports": 8,
        "port_prefix": "ethernet1/",
        "management_port": "mgmt",
        "description": "8-port 1G copper desktop firewall (ethernet1/1 - ethernet1/8)",
    },
    "pa-450": {
        "name": "Palo Alto PA-450",
        "total_ports": 8,
        "port_prefix": "ethernet1/",
        "management_port": "mgmt",
        "description": "8-port desktop firewall (ethernet1/1 - ethernet1/8)",
    },
    "pa-460": {
        "name": "Palo Alto PA-460",
        "total_ports": 12,
        "port_prefix": "ethernet1/",
        "management_port": "mgmt",
        "description": "12-port desktop firewall with PoE",
    },
    "pa-3220": {
        "name": "Palo Alto PA-3220",
        "total_ports": 12,
        "port_prefix": "ethernet1/",
        "management_port": "mgmt",
        "description": "12-port 1U enterprise firewall",
    },
    "pa-3250": {
        "name": "Palo Alto PA-3250",
        "total_ports": 24,
        "port_prefix": "ethernet1/",
        "management_port": "mgmt",
        "description": "24-port 1U enterprise firewall",
    },
    "pa-5220": {
        "name": "Palo Alto PA-5220",
        "total_ports": 24,
        "port_prefix": "ethernet1/",
        "management_port": "mgmt",
        "description": "24-port 2U data center firewall",
    },
}


def get_supported_models() -> list:
    """Return list of supported PA model names."""
    return sorted(PA_MODELS.keys())


def print_supported_models() -> None:
    """Print a table of supported Palo Alto models."""
    print("\nSupported Palo Alto Models:")
    print("=" * 70)
    print(f"{'Model':<15} {'Name':<25} {'Ports':<8} {'Description'}")
    print("-" * 70)
    for model_id, info in sorted(PA_MODELS.items()):
        print(f"{model_id:<15} {info['name']:<25} {info['total_ports']:<8} {info['description']}")
    print("=" * 70)


class PAInterfaceConverter:
    """Convert FortiGate interfaces to PAN-OS interface and zone configs.

    Produces two outputs:
        1. Interface configurations (physical, subinterface, aggregate-ethernet)
        2. Zone definitions (groups of interfaces)

    Also builds mappings consumed by route and policy converters:
        - interface_name_mapping: FortiGate name -> PAN-OS interface name
        - zone_mapping: FortiGate name -> PAN-OS zone name
    """

    # FortiGate interface names to always skip
    _SKIP_NAMES = frozenset([
        "ha", "mgmt", "modem", "naf.root", "l2t.root", "ssl.root",
        "fortilink", "npu0_vlink0", "npu0_vlink1",
    ])

    def __init__(
        self,
        fortigate_config: Dict[str, Any],
        target_model: str = "pa-440",
    ) -> None:
        self.fg_config = fortigate_config
        self.target_model = target_model
        self.model_info = PA_MODELS.get(target_model, PA_MODELS["pa-440"])
        self.total_ports = self.model_info["total_ports"]

        # Dedicated management and HA heartbeat/session-sync interfaces on the
        # FortiGate side (mgmt*/ha* names, `set dedicated-to management`,
        # hbdev/ha-mgmt-interface from `config system ha`). These are
        # infrastructure links with no PAN-OS data-plane equivalent, so they
        # are silently ignored during conversion instead of being reported as
        # failures.
        self._mgmt_ha_interfaces = collect_mgmt_ha_interfaces(fortigate_config)

        # Outputs
        self.pa_interfaces: List[Dict] = []  # Physical + aggregate + subinterface configs
        self.pa_zones: List[Dict] = []
        self.failed_items: List[Dict] = []

        # FortiGate interface name -> PAN-OS interface name (e.g. "port1" -> "ethernet1/1")
        self.interface_name_mapping: Dict[str, str] = {}

        # FortiGate interface name -> PAN-OS zone name (e.g. "port1" -> "trust")
        self.zone_mapping: Dict[str, str] = {}

        # Zone name -> list of PAN-OS interface names
        self._zone_members: Dict[str, List[str]] = {}

        # Zone name -> mode ("layer3" or "layer2"). Layer-2 zones hold the member
        # ports of a converted FortiGate switch; the SVI lives in an L3 zone.
        self._zone_modes: Dict[str, str] = {}

        # Track port assignment
        self._next_port: int = 1
        self._used_ports: Set[int] = set()
        # Ports held for explicitly-requested expansion/promotion specs, kept
        # out of auto-assignment until their owning spec claims them.
        self._held_ports: Set[int] = set()

        # Track aggregate-ethernet IDs
        self._next_ae_id: int = 1

        # Track VLAN IDs used for converted FortiGate switches -> vlan.N SVIs
        self._next_vlan_id: int = 1

        # ------------------------------------------------------------------
        # Interface scale-up config (mirrors FortiGateToFTDTool). All matched
        # case-insensitively by FortiGate name/alias. Empty = 1:1 migration.
        # ------------------------------------------------------------------
        # Grow an existing aggregate to MORE aggregate-ethernet members.
        self.aggregate_expansion: Dict[str, Any] = {}
        # Promote a plain physical port to a NEW aggregate-ethernet.
        self.promote_to_aggregate: Dict[str, Any] = {}
        # Grow a converted switch's Layer-2 segment with MORE members.
        self.bridgegroup_expansion: Dict[str, Any] = {}
        # Promote a plain physical port to a NEW Layer-2 segment (VLAN + SVI).
        self.promote_to_bridgegroup: Dict[str, Any] = {}
        # Straight port assignment: FortiGate name/alias -> PAN-OS port number.
        # Pins an interface to a specific port (no aggregation).
        self.port_map: Dict[str, int] = {}
        # Promote-to-aggregate L3 VLAN tags: FortiGate name/alias -> int tag.
        # When a routed interface is promoted to an aggregate-ethernet, its IP is
        # placed on a subinterface (aeN.tag) instead of directly on the ae.
        self.promotion_pc_vlans: Dict[str, int] = {}

        # Statistics
        self._stats = {
            "total_interfaces": 0,
            "physical_interfaces": 0,
            "subinterfaces": 0,
            "aggregate_interfaces": 0,
            "bridge_groups": 0,
            "layer2_members": 0,
            "zones_created": 0,
            "mapped_interfaces": 0,
            "skipped": 0,
        }

    def convert(self) -> List[Dict]:
        """Convert FortiGate interfaces to PAN-OS zone definitions.

        Also populates self.pa_interfaces with full interface configs.

        Returns:
            List of zone dicts (for backward compatibility).
        """
        interfaces = self.fg_config.get("system_interface", [])
        if not interfaces:
            print("Warning: No interfaces found in FortiGate configuration")
            return []

        # Build FortiGate zone lookup from system_zone
        fg_zones = self.fg_config.get("system_zone", [])
        zone_lookup = self._build_zone_lookup(fg_zones)

        # FortiGate switches: the member list lives in system_switch-interface;
        # the switch's IP lives on the same-named system_interface entry (the
        # SVI source). Collect both so switches convert to a PAN-OS Layer-2
        # segment instead of being dropped.
        switch_interfaces = []  # (switch_name, switch_props) from system_switch-interface
        for sw_dict in self.fg_config.get("system_switch-interface", []) or []:
            if not isinstance(sw_dict, dict) or not sw_dict:
                continue
            sw_name = str(list(sw_dict.keys())[0])
            sw_props = sw_dict[sw_name]
            if isinstance(sw_props, dict):
                switch_interfaces.append((sw_name, sw_props))
        switch_names = {name for name, _ in switch_interfaces}
        switch_svi_props: Dict[str, Dict] = {}  # switch_name -> system_interface props

        # Categorize interfaces by type
        physical_ports = []
        aggregate_ports = []
        vlan_interfaces = []

        for intf_dict in interfaces:
            intf_key = list(intf_dict.keys())[0]
            properties = intf_dict[intf_key]
            intf_name = str(intf_key)
            self._stats["total_interfaces"] += 1

            if not isinstance(properties, dict):
                self._stats["skipped"] += 1
                continue

            # Silently ignore FortiGate factory-default virtual interfaces
            # (ssl.<vdom>, l2t.<vdom>, naf.<vdom>, modem) and other built-in
            # system interfaces - they exist on every appliance and are not
            # meaningful to migrate.
            if intf_name in self._SKIP_NAMES or is_default_fortigate_interface(intf_name):
                print(f"    Ignored: {intf_name} (FortiGate system/virtual interface)")
                continue

            # Silently ignore dedicated management and HA interfaces. These
            # are FortiGate infrastructure links (out-of-band mgmt, HA
            # heartbeat/session-sync) with no PAN-OS data-plane equivalent,
            # so they are not reported as skipped/failed items.
            if intf_name.strip().lower() in self._mgmt_ha_interfaces:
                print(f"    Ignored: {intf_name} (dedicated management/HA interface)")
                continue

            # Skip special FortiGate interfaces
            if intf_name.startswith("vw") or (intf_name.startswith("s") and len(intf_name) <= 2):
                print(f"    Skipped: {intf_name} (special port)")
                self._stats["skipped"] += 1
                continue

            intf_type = str(properties.get("type", "")).strip().lower()

            # Skip loopback and tunnel
            if intf_type in ("loopback", "tunnel"):
                print(f"    Skipped: {intf_name} (type: {intf_type})")
                self._stats["skipped"] += 1
                continue

            # The SVI (IP-bearing) entry of a switch: stash its props for the
            # switch converter; it is not a standalone interface.
            if intf_name in switch_names or intf_type == "switch":
                switch_svi_props[intf_name] = properties
                continue

            # Categorize
            if "interface" in properties and "vlanid" in properties:
                parent_name = str(properties.get("interface", "")).strip().lower()
                if parent_name in self._mgmt_ha_interfaces:
                    print(f"    Ignored: {intf_name} (subinterface of management/HA "
                          f"interface '{properties.get('interface')}')")
                    continue
                vlan_interfaces.append((intf_name, properties))
            elif intf_type == "aggregate":
                aggregate_ports.append((intf_name, properties))
            elif intf_type in ("physical", "hard-switch", "") or not intf_type:
                physical_ports.append((intf_name, properties))
            else:
                print(f"    Skipped: {intf_name} (type: {intf_type})")
                self._stats["skipped"] += 1

        # --- Phase 1: Identify which physical ports are aggregate members ---
        aggregate_member_set: Set[str] = set()
        for _, props in aggregate_ports:
            members = props.get("member", [])
            if isinstance(members, str):
                members = [members]
            for m in members:
                aggregate_member_set.add(str(m).strip())

        # Switch (bridge-group) members must also be excluded from standalone
        # physical conversion - they become Layer-2 members of the VLAN segment.
        switch_member_set: Set[str] = set()
        for _, props in switch_interfaces:
            switch_member_set.update(self._member_list(props.get("member", [])))

        # --- Phase 2: Identify which physical ports have subinterfaces ---
        parent_interface_set: Set[str] = set()
        for _, props in vlan_interfaces:
            parent = str(props.get("interface", "")).strip()
            if parent:
                parent_interface_set.add(parent)

        # Hold user-specified expansion/promotion ports out of the pool before
        # any port is assigned, so greedy standalone assignment can't consume a
        # port the user explicitly requested for an aggregate/Layer-2 segment.
        self._prereserve_explicit_ports()

        # --- Phase 3: Convert aggregate interfaces first (need member ports) ---
        for fg_name, props in aggregate_ports:
            self._convert_aggregate(fg_name, props, zone_lookup)

        # --- Phase 4: Convert switch interfaces -> PAN-OS Layer-2 segments ---
        for sw_name, sw_props in switch_interfaces:
            self._convert_switch(
                sw_name, sw_props, switch_svi_props.get(sw_name, {}), zone_lookup,
            )

        # --- Phase 5: Convert physical interfaces (with optional promotion) ---
        for fg_name, props in physical_ports:
            if fg_name in aggregate_member_set or fg_name in switch_member_set:
                # Already consumed as an aggregate / Layer-2 member.
                continue
            alias = str(props.get("alias", "")).strip()
            ae_spec = self._lookup_spec(self.promote_to_aggregate, fg_name, alias)
            bvi_spec = self._lookup_spec(self.promote_to_bridgegroup, fg_name, alias)
            # Interfaces that carry VLAN subinterfaces are not eligible for
            # promotion (the subinterfaces would have to move onto the new
            # parent). Warn and convert normally, mirroring the FTD tool.
            if (ae_spec is not None or bvi_spec is not None) and fg_name in parent_interface_set:
                kind = "aggregate-ethernet" if ae_spec is not None else "Layer-2 segment"
                print(f"    [WARNING] {fg_name}: cannot promote to {kind} "
                      f"(it has VLAN subinterfaces) - converting as physical")
                ae_spec = bvi_spec = None
            if ae_spec is not None:
                self._promote_physical_to_aggregate(fg_name, props, ae_spec, zone_lookup)
            elif bvi_spec is not None:
                self._promote_physical_to_bridgegroup(fg_name, props, bvi_spec, zone_lookup)
            else:
                self._convert_physical(fg_name, props, zone_lookup)

        # --- Phase 6: Convert VLAN subinterfaces ---
        for fg_name, props in vlan_interfaces:
            self._convert_subinterface(fg_name, props, zone_lookup)

        # --- Phase 7: Build zone output ---
        results: List[Dict] = []
        for zone_name, members in sorted(self._zone_members.items()):
            mode = self._zone_modes.get(zone_name, "layer3")
            zone = {
                "name": zone_name,
                "mode": mode,
                "interfaces": members,
            }
            results.append(zone)
            self._stats["zones_created"] += 1
            print(f"  Zone: {zone_name} [{mode}] ({', '.join(members)})")

        self.pa_zones = results
        return results

    def get_interfaces(self) -> List[Dict]:
        """Return the full interface configuration list."""
        return list(self.pa_interfaces)

    def get_interface_mapping(self) -> Dict[str, str]:
        """Return FortiGate name -> PAN-OS interface name mapping.

        Used by route converter for the 'interface' field in static routes.
        """
        return dict(self.interface_name_mapping)

    def get_zone_mapping(self) -> Dict[str, str]:
        """Return FortiGate name -> PAN-OS zone name mapping.

        Used by policy converter for from_zones/to_zones in security rules.
        """
        return dict(self.zone_mapping)

    def get_statistics(self) -> Dict[str, int]:
        return dict(self._stats)

    # ------------------------------------------------------------------
    # Scale-up configuration (mirrors FortiGateToFTDTool/interface_converter)
    # ------------------------------------------------------------------
    @staticmethod
    def _normalize_specs(specs: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        """Lower-case and strip the keys of a scale-up spec dict."""
        normalized: Dict[str, Any] = {}
        for key, spec in (specs or {}).items():
            if key is None:
                continue
            normalized[str(key).strip().lower()] = spec
        return normalized

    def set_aggregate_expansion(self, expansion: Dict[str, Any]) -> None:
        """Grow an existing FortiGate aggregate to MORE aggregate-ethernet
        members on the PAN-OS side (the port-channel expansion analog).

        Maps a FortiGate aggregate name/alias to either an int (target TOTAL
        member count) or a list of PAN-OS ports (e.g. ['ethernet1/5']) to ADD.
        """
        self.aggregate_expansion = self._normalize_specs(expansion)

    def set_aggregate_promotion(self, promotion: Dict[str, Any]) -> None:
        """Promote a plain FortiGate physical interface into a NEW PAN-OS
        aggregate-ethernet (the port-channel promotion analog).

        Unlike FTD (where the port-channel is left IP-less), the interface's IP
        and MTU stay on the aggregate-ethernet - in PAN-OS the ae IS the L3
        interface. Maps a FortiGate name/alias to an int (TOTAL member count
        incl. the original port) or a list of extra PAN-OS ports to add.
        """
        self.promote_to_aggregate = self._normalize_specs(promotion)

    def set_bridgegroup_expansion(self, expansion: Dict[str, Any]) -> None:
        """Grow a converted FortiGate switch's Layer-2 segment with MORE member
        ports (the bridge-group expansion analog).

        Maps a FortiGate switch name to an int (target TOTAL member count) or a
        list of PAN-OS ports to ADD as layer2 members.
        """
        self.bridgegroup_expansion = self._normalize_specs(expansion)

    def set_bridgegroup_promotion(self, promotion: Dict[str, Any]) -> None:
        """Promote a plain FortiGate physical interface into a NEW PAN-OS
        Layer-2 segment (VLAN object + vlan.N SVI) - the bridge-group promotion
        analog. The interface's IP/MTU move onto the SVI.

        Maps a FortiGate name/alias to an int (TOTAL member count incl. the
        original port) or a list of extra PAN-OS ports to add.
        """
        self.promote_to_bridgegroup = self._normalize_specs(promotion)

    def set_port_mapping(self, mapping: Dict[str, str]) -> None:
        """Straight port assignment: pin a FortiGate interface to a specific
        PAN-OS port (no aggregation). Keys may be the FortiGate name OR alias;
        values are PAN-OS ports (e.g. 'ethernet1/9'). The interface still
        converts as a normal layer3 physical interface.
        """
        for key, pa_port in (mapping or {}).items():
            if key is None:
                continue
            match = re.match(r"^ethernet1/(\d+)$", str(pa_port).strip().lower())
            if not match:
                print(f"  [WARNING] Map {key} -> {pa_port}: expected 'ethernet1/X' "
                      f"- ignored")
                continue
            num = int(match.group(1))
            if num < 1 or num > self.total_ports:
                print(f"  [WARNING] Map {key} -> {pa_port}: out of range for "
                      f"{self.target_model} (1-{self.total_ports}) - ignored")
                continue
            if num in self.port_map.values():
                print(f"  [WARNING] Map {key} -> {pa_port}: port already assigned "
                      f"to another interface - ignored")
                continue
            self.port_map[str(key).strip().lower()] = num

    def set_promotion_subinterface_vlans(self, vlans: Dict[str, Any]) -> None:
        """Set the L3 VLAN tag used when a routed interface promoted to an
        aggregate-ethernet needs its IP placed on a subinterface (aeN.tag).

        Maps a FortiGate name/alias (case-insensitive) to an int VLAN tag.
        """
        normalized: Dict[str, int] = {}
        for key, tag in (vlans or {}).items():
            if key is None:
                continue
            try:
                normalized[str(key).strip().lower()] = int(tag)
            except (TypeError, ValueError):
                print(f"  [WARNING] Ignoring promote VLAN for '{key}': "
                      f"'{tag}' is not a valid VLAN id")
        self.promotion_pc_vlans = normalized

    @staticmethod
    def _lookup_spec(specs: Dict[str, Any], *identifiers: str) -> Any:
        """Return the first matching spec for any of the given identifiers."""
        if not specs:
            return None
        for ident in identifiers:
            if ident and str(ident).strip().lower() in specs:
                return specs[str(ident).strip().lower()]
        return None

    def _reserve_pa_port(self, fg_name: str, pa_port: str, context: str) -> str:
        """Validate and reserve a user-specified PAN-OS port for expansion.

        Returns the normalized port name, or "" (with a warning) if the port is
        malformed, out of range, or already assigned.
        """
        match = re.match(r"^ethernet1/(\d+)$", str(pa_port).strip().lower())
        if not match:
            print(f"      [WARNING] {context} {fg_name}: invalid port "
                  f"'{pa_port}' (expected 'ethernet1/X') - skipped")
            return ""
        port_num = int(match.group(1))
        if port_num < 1 or port_num > self.total_ports:
            print(f"      [WARNING] {context} {fg_name}: port '{pa_port}' out of "
                  f"range for {self.target_model} (1-{self.total_ports}) - skipped")
            return ""
        if port_num in self._used_ports:
            print(f"      [WARNING] {context} {fg_name}: port '{pa_port}' already "
                  f"assigned elsewhere - skipped")
            return ""
        self._used_ports.add(port_num)
        self._held_ports.discard(port_num)
        return f"{self.model_info['port_prefix']}{port_num}"

    # ------------------------------------------------------------------
    # Conversion methods
    # ------------------------------------------------------------------

    def _convert_physical(
        self, fg_name: str, properties: Dict, zone_lookup: Dict[str, str]
    ) -> None:
        """Convert a FortiGate physical interface to PAN-OS layer3 config."""
        alias = str(properties.get("alias", "")).strip()
        pa_interface = self._assign_pa_port(fg_name, alias)
        if not pa_interface:
            return

        # Zone
        zone_name = self._determine_zone(fg_name, properties, zone_lookup)
        self.interface_name_mapping[fg_name] = pa_interface
        self.zone_mapping[fg_name] = zone_name

        # Also map alias if present
        if alias and alias != fg_name:
            self.interface_name_mapping[alias] = pa_interface
            self.zone_mapping[alias] = zone_name

        self._add_to_zone(zone_name, pa_interface)
        self._stats["physical_interfaces"] += 1
        self._stats["mapped_interfaces"] += 1

        # Build interface config
        intf_config: Dict[str, Any] = {
            "name": pa_interface,
            "type": "physical",
            "mode": "layer3",
            "enabled": properties.get("status", "up") != "down",
        }

        # IP address
        ip_cidr = self._extract_ip_cidr(properties)
        if ip_cidr:
            intf_config["ip_address"] = ip_cidr

        # DHCP
        mode = str(properties.get("mode", "")).strip().lower()
        if mode == "dhcp":
            intf_config["dhcp"] = True

        # Comment / description
        desc = properties.get("description") or properties.get("alias") or fg_name
        intf_config["comment"] = str(desc)

        # MTU
        if properties.get("mtu-override") == "enable":
            mtu = self._parse_int(properties.get("mtu"), 1500)
            if mtu > 9216:
                mtu = 9216  # PAN-OS max jumbo frame
            intf_config["mtu"] = mtu

        # Link speed (auto by default on PAN-OS)
        speed = str(properties.get("speed", "")).strip().lower()
        intf_config["link_speed"] = speed if speed else "auto"

        self.pa_interfaces.append(intf_config)
        ip_display = ip_cidr if ip_cidr else ("DHCP" if mode == "dhcp" else "no IP")
        print(f"    Converted: {fg_name} -> {pa_interface} ({ip_display}, zone: {zone_name})")

    def _convert_subinterface(
        self, fg_name: str, properties: Dict, zone_lookup: Dict[str, str]
    ) -> None:
        """Convert a FortiGate VLAN interface to PAN-OS subinterface."""
        parent_fg = str(properties.get("interface", "")).strip()
        vlan_id = properties.get("vlanid")

        if not parent_fg or not vlan_id:
            print(f"    Skipped: {fg_name} (missing parent or VLAN ID)")
            self._stats["skipped"] += 1
            self.failed_items.append({
                "name": fg_name,
                "reason": "missing parent interface or VLAN ID",
                "config": properties,
            })
            return

        vlan_id = self._parse_int(vlan_id, 0)
        if vlan_id <= 0:
            print(f"    Skipped: {fg_name} (invalid VLAN ID: "
                  f"{properties.get('vlanid')!r})")
            self._stats["skipped"] += 1
            self.failed_items.append({
                "name": fg_name,
                "reason": f"invalid VLAN ID: {properties.get('vlanid')!r}",
                "config": properties,
            })
            return

        # Find the PAN-OS parent interface name
        parent_pa = self.interface_name_mapping.get(parent_fg)
        if not parent_pa:
            # Parent hasn't been mapped yet - assign a port for it
            parent_pa = self._assign_pa_port(parent_fg)
            if not parent_pa:
                print(f"    Skipped: {fg_name} (parent {parent_fg} has no available port)")
                self._stats["skipped"] += 1
                self.failed_items.append({
                    "name": fg_name,
                    "reason": f"parent {parent_fg} could not be mapped",
                    "config": properties,
                })
                return
            self.interface_name_mapping[parent_fg] = parent_pa

        # PAN-OS subinterface name: ethernet1/1.100
        pa_name = f"{parent_pa}.{vlan_id}"

        # Zone
        zone_name = self._determine_zone(fg_name, properties, zone_lookup)
        self.interface_name_mapping[fg_name] = pa_name
        self.zone_mapping[fg_name] = zone_name

        alias = str(properties.get("alias", "")).strip()
        if alias and alias != fg_name:
            self.interface_name_mapping[alias] = pa_name
            self.zone_mapping[alias] = zone_name

        self._add_to_zone(zone_name, pa_name)
        self._stats["subinterfaces"] += 1
        self._stats["mapped_interfaces"] += 1

        # Build subinterface config
        intf_config: Dict[str, Any] = {
            "name": pa_name,
            "type": "subinterface",
            "parent": parent_pa,
            "tag": vlan_id,
            "enabled": properties.get("status", "up") != "down",
        }

        ip_cidr = self._extract_ip_cidr(properties)
        if ip_cidr:
            intf_config["ip_address"] = ip_cidr

        mode = str(properties.get("mode", "")).strip().lower()
        if mode == "dhcp":
            intf_config["dhcp"] = True

        desc = properties.get("description") or properties.get("alias") or fg_name
        intf_config["comment"] = str(desc)

        if properties.get("mtu-override") == "enable":
            mtu = self._parse_int(properties.get("mtu"), 1500)
            if mtu > 9216:
                mtu = 9216
            intf_config["mtu"] = mtu

        self.pa_interfaces.append(intf_config)
        ip_display = ip_cidr if ip_cidr else ("DHCP" if mode == "dhcp" else "no IP")
        print(f"    Converted: {fg_name} -> {pa_name} (VLAN {vlan_id}, {ip_display}, zone: {zone_name})")

    def _convert_aggregate(
        self, fg_name: str, properties: Dict, zone_lookup: Dict[str, str]
    ) -> None:
        """Convert a FortiGate aggregate interface to PAN-OS aggregate-ethernet."""
        members_raw = properties.get("member", [])
        if isinstance(members_raw, str):
            members_raw = [members_raw]

        if not members_raw:
            print(f"    Skipped: {fg_name} (aggregate with no members)")
            self._stats["skipped"] += 1
            self.failed_items.append({
                "name": fg_name,
                "reason": "aggregate with no members",
                "config": properties,
            })
            return

        ae_id = self._next_ae_id
        self._next_ae_id += 1
        ae_name = f"ae{ae_id}"

        # Expansion spec, if any. An explicit port LIST means "use exactly these
        # ports as the members" - so the source members are NOT auto-assigned to
        # arbitrary ports first. An int means "grow to this total".
        agg_alias = str(properties.get("alias", "")).strip()
        exp_spec = self._lookup_spec(self.aggregate_expansion, fg_name, agg_alias, ae_name)
        explicit_ports = isinstance(exp_spec, (list, tuple))

        # Assign PAN-OS ports to each source member (skipped for explicit ports).
        member_pa_names = []
        member_configs = []
        if not explicit_ports:
            for member_fg in members_raw:
                member_fg = str(member_fg).strip()
                pa_port = self._assign_pa_port(member_fg)
                if pa_port:
                    member_pa_names.append(pa_port)
                    self.interface_name_mapping[member_fg] = pa_port

                    # Build member physical interface config (set aggregate-group)
                    member_configs.append({
                        "name": pa_port,
                        "type": "aggregate-member",
                        "aggregate_group": ae_name,
                        "enabled": True,
                        "comment": f"Member of {ae_name} (FortiGate: {fg_name})",
                    })
                else:
                    self.failed_items.append({
                        "name": member_fg,
                        "reason": f"no port available for aggregate member of {fg_name}",
                        "config": {},
                    })

        # Aggregate expansion: an explicit list defines the exact members; an int
        # adds MORE aggregate-ethernet members. No-op unless a spec matches this
        # aggregate by FortiGate name, alias, or ae name.
        if exp_spec is not None:
            self._apply_aggregate_expansion(
                fg_name, ae_name, exp_spec, member_pa_names, member_configs,
            )

        if not member_pa_names:
            print(f"    Skipped: {fg_name} (no ports available for members)")
            self._stats["skipped"] += 1
            return

        # Zone
        zone_name = self._determine_zone(fg_name, properties, zone_lookup)
        self.interface_name_mapping[fg_name] = ae_name
        self.zone_mapping[fg_name] = zone_name

        alias = str(properties.get("alias", "")).strip()
        if alias and alias != fg_name:
            self.interface_name_mapping[alias] = ae_name
            self.zone_mapping[alias] = zone_name

        self._add_to_zone(zone_name, ae_name)
        self._stats["aggregate_interfaces"] += 1
        self._stats["mapped_interfaces"] += 1

        # Build aggregate-ethernet config
        intf_config: Dict[str, Any] = {
            "name": ae_name,
            "type": "aggregate-ethernet",
            "mode": "layer3",
            "members": member_pa_names,
            "lacp_mode": "active",
            "enabled": properties.get("status", "up") != "down",
        }

        ip_cidr = self._extract_ip_cidr(properties)
        if ip_cidr:
            intf_config["ip_address"] = ip_cidr

        mode = str(properties.get("mode", "")).strip().lower()
        if mode == "dhcp":
            intf_config["dhcp"] = True

        desc = properties.get("description") or properties.get("alias") or fg_name
        intf_config["comment"] = str(desc)

        if properties.get("mtu-override") == "enable":
            mtu = self._parse_int(properties.get("mtu"), 1500)
            if mtu > 9216:
                mtu = 9216
            intf_config["mtu"] = mtu

        # Add member configs first (they need to be configured before the AE)
        self.pa_interfaces.extend(member_configs)
        self.pa_interfaces.append(intf_config)

        members_display = ", ".join(member_pa_names)
        ip_display = ip_cidr if ip_cidr else ("DHCP" if mode == "dhcp" else "no IP")
        print(f"    Converted: {fg_name} -> {ae_name} (LACP, members: [{members_display}], "
              f"{ip_display}, zone: {zone_name})")

    def _apply_aggregate_expansion(
        self, fg_name: str, ae_name: str, spec: Any,
        member_pa_names: List[str], member_configs: List[Dict],
    ) -> List[str]:
        """Add extra aggregate-ethernet members per the expansion spec.

        ``spec`` is an int (target TOTAL member count) or a list of PAN-OS
        ports to add. ``member_pa_names`` and ``member_configs`` are extended
        in place. Returns the list of ports actually added.
        """
        def add_member(pa_port: str) -> bool:
            if pa_port in member_pa_names:
                return False
            member_pa_names.append(pa_port)
            member_configs.append({
                "name": pa_port,
                "type": "aggregate-member",
                "aggregate_group": ae_name,
                "enabled": True,
                "comment": f"Member of {ae_name} (scale-up of {fg_name})",
            })
            return True

        added: List[str] = []
        if isinstance(spec, int):
            if spec <= len(member_pa_names):
                print(f"      [EXPAND] aggregate {fg_name}: source already has "
                      f"{len(member_pa_names)} member(s) (target {spec}) - no change")
                return added
            while len(member_pa_names) < spec:
                port = self._get_next_port()
                if not port:
                    print(f"      [WARNING] aggregate {fg_name}: not enough free "
                          f"ports to reach {spec} members "
                          f"(stopped at {len(member_pa_names)})")
                    break
                pa_port = f"{self.model_info['port_prefix']}{port}"
                if add_member(pa_port):
                    added.append(pa_port)
        else:
            for raw in spec:
                pa_port = self._reserve_pa_port(fg_name, str(raw), "aggregate")
                if pa_port and add_member(pa_port):
                    added.append(pa_port)

        if added:
            print(f"      [EXPAND] aggregate {fg_name}: added {len(added)} "
                  f"extra member(s): {', '.join(added)}")
        return added

    def _promote_physical_to_aggregate(
        self, fg_name: str, properties: Dict, spec: Any, zone_lookup: Dict[str, str],
    ) -> None:
        """Promote a plain physical interface to a NEW aggregate-ethernet.

        For an int spec the interface's own auto-assigned port becomes member #1
        and the channel grows to that TOTAL count. For an explicit port list the
        listed ports ARE the members (exactly those). The interface's IP/MTU stay
        on the aggregate-ethernet (in PAN-OS the ae is the Layer-3 interface).
        """
        ae_id = self._next_ae_id
        self._next_ae_id += 1
        ae_name = f"ae{ae_id}"

        member_pa_names: List[str] = []
        member_configs: List[Dict] = []
        if isinstance(spec, int):
            orig_port = self._assign_pa_port(fg_name)
            if not orig_port:
                print(f"    Skipped: {fg_name} (no available port to promote)")
                self._stats["skipped"] += 1
                self._next_ae_id -= 1  # reclaim the unused ae id
                return
            member_pa_names.append(orig_port)
            member_configs.append({
                "name": orig_port,
                "type": "aggregate-member",
                "aggregate_group": ae_name,
                "enabled": True,
                "comment": f"Member of {ae_name} (promoted from {fg_name})",
            })
            self._apply_aggregate_expansion(
                fg_name, ae_name, spec, member_pa_names, member_configs,
            )
        else:
            # Explicit ports become the members (held out of the pool earlier).
            self._apply_aggregate_expansion(
                fg_name, ae_name, list(spec), member_pa_names, member_configs,
            )
            if not member_pa_names:
                print(f"    Skipped: {fg_name} (none of the requested ports were available)")
                self._stats["skipped"] += 1
                self._next_ae_id -= 1  # reclaim the unused ae id
                return

        alias = str(properties.get("alias", "")).strip()
        ip_cidr = self._extract_ip_cidr(properties)
        fg_mode = str(properties.get("mode", "")).strip().lower()

        # If an L3 VLAN tag was given AND the interface has an IP, the address
        # goes on a subinterface (aeN.tag); the ae itself stays IP-less. The
        # source interface then resolves to the subinterface (its L3 endpoint).
        vlan_tag = self._lookup_spec(self.promotion_pc_vlans, fg_name, alias) if ip_cidr else None

        zone_name = self._determine_zone(fg_name, properties, zone_lookup)
        l3_name = f"{ae_name}.{vlan_tag}" if vlan_tag is not None else ae_name
        self.interface_name_mapping[fg_name] = l3_name
        self.zone_mapping[fg_name] = zone_name
        if alias and alias != fg_name:
            self.interface_name_mapping[alias] = l3_name
            self.zone_mapping[alias] = zone_name

        self._add_to_zone(zone_name, l3_name)
        self._stats["aggregate_interfaces"] += 1
        self._stats["mapped_interfaces"] += 1

        desc = properties.get("description") or properties.get("alias") or fg_name
        intf_config: Dict[str, Any] = {
            "name": ae_name,
            "type": "aggregate-ethernet",
            "mode": "layer3",
            "members": member_pa_names,
            "lacp_mode": "active",
            "enabled": properties.get("status", "up") != "down",
            "comment": str(desc),
        }
        if properties.get("mtu-override") == "enable":
            mtu = self._parse_int(properties.get("mtu"), 1500)
            intf_config["mtu"] = min(mtu, 9216)

        if vlan_tag is not None:
            # IP lives on the subinterface, not the ae.
            subif = {
                "name": l3_name,
                "type": "subinterface",
                "parent": ae_name,
                "tag": int(vlan_tag),
                "enabled": properties.get("status", "up") != "down",
                "ip_address": ip_cidr,
                "comment": str(desc),
            }
            self.pa_interfaces.extend(member_configs)
            self.pa_interfaces.append(intf_config)
            self.pa_interfaces.append(subif)
            self._stats["subinterfaces"] += 1
            print(f"    Promoted: {fg_name} -> {ae_name} (NEW LACP, members: "
                  f"[{', '.join(member_pa_names)}], IP {ip_cidr} on {l3_name}, "
                  f"zone: {zone_name})")
            return

        if ip_cidr:
            intf_config["ip_address"] = ip_cidr
        if fg_mode == "dhcp":
            intf_config["dhcp"] = True

        self.pa_interfaces.extend(member_configs)
        self.pa_interfaces.append(intf_config)

        ip_display = ip_cidr if ip_cidr else ("DHCP" if fg_mode == "dhcp" else "no IP")
        print(f"    Promoted: {fg_name} -> {ae_name} (NEW LACP, members: "
              f"[{', '.join(member_pa_names)}], {ip_display}, zone: {zone_name})")

    # ------------------------------------------------------------------
    # Switch (bridge group) -> PAN-OS Layer-2 segment
    # ------------------------------------------------------------------
    def _add_layer2_member(
        self, member_fg: str, pa_port: str, vlan_obj: str, l2_zone: str,
        member_configs: List[Dict], member_pa_names: List[str],
        description: str,
    ) -> bool:
        """Append a layer2 member port to the VLAN segment (idempotent)."""
        if pa_port in member_pa_names:
            return False
        member_pa_names.append(pa_port)
        member_configs.append({
            "name": pa_port,
            "type": "layer2-member",
            "vlan_object": vlan_obj,
            "enabled": True,
            "comment": description,
        })
        if member_fg:
            self.interface_name_mapping[member_fg] = pa_port
        self._add_to_zone(l2_zone, pa_port, mode="layer2")
        self._stats["layer2_members"] += 1
        return True

    def _apply_bridgegroup_expansion(
        self, fg_name: str, vlan_obj: str, l2_zone: str, spec: Any,
        member_configs: List[Dict], member_pa_names: List[str],
    ) -> List[str]:
        """Add extra layer2 members to a VLAN segment per the expansion spec."""
        added: List[str] = []
        if isinstance(spec, int):
            if spec <= len(member_pa_names):
                print(f"      [EXPAND] switch {fg_name}: source already has "
                      f"{len(member_pa_names)} member(s) (target {spec}) - no change")
                return added
            while len(member_pa_names) < spec:
                port = self._get_next_port()
                if not port:
                    print(f"      [WARNING] switch {fg_name}: not enough free "
                          f"ports to reach {spec} members "
                          f"(stopped at {len(member_pa_names)})")
                    break
                pa_port = f"{self.model_info['port_prefix']}{port}"
                if self._add_layer2_member(
                    "", pa_port, vlan_obj, l2_zone, member_configs,
                    member_pa_names, f"Layer-2 member of {vlan_obj} (scale-up)",
                ):
                    added.append(pa_port)
        else:
            for raw in spec:
                pa_port = self._reserve_pa_port(fg_name, str(raw), "switch")
                if pa_port and self._add_layer2_member(
                    "", pa_port, vlan_obj, l2_zone, member_configs,
                    member_pa_names, f"Layer-2 member of {vlan_obj} (scale-up)",
                ):
                    added.append(pa_port)
        if added:
            print(f"      [EXPAND] switch {fg_name}: added {len(added)} "
                  f"extra member(s): {', '.join(added)}")
        return added

    def _emit_layer2_segment(
        self, fg_name: str, svi_props: Dict, member_configs: List[Dict],
        member_pa_names: List[str], l3_zone: str, vlan_obj: str,
        description: str, action: str,
    ) -> None:
        """Emit the VLAN object + vlan.N SVI for a Layer-2 segment and wire the
        FortiGate name -> SVI mappings. Shared by switch conversion and
        physical->bridge-group promotion."""
        vlan_unit = self._next_vlan_id
        self._next_vlan_id += 1
        svi_name = f"vlan.{vlan_unit}"

        # VLAN object groups the layer2 members and references the SVI.
        self.pa_interfaces.extend(member_configs)
        self.pa_interfaces.append({
            "name": vlan_obj,
            "type": "vlan-object",
            "members": list(member_pa_names),
            "vlan_interface": svi_name,
            "comment": description,
        })

        # SVI (vlan.N) carries the Layer-3 IP/MTU - the BVI analog.
        svi_config: Dict[str, Any] = {
            "name": svi_name,
            "type": "vlan-interface",
            "vlan_object": vlan_obj,
            "enabled": True,
            "comment": description,
        }
        ip_cidr = self._extract_ip_cidr(svi_props)
        if ip_cidr:
            svi_config["ip_address"] = ip_cidr
        svi_mode = str(svi_props.get("mode", "")).strip().lower()
        if svi_mode == "dhcp":
            svi_config["dhcp"] = True
        if svi_props.get("mtu-override") == "enable":
            mtu = self._parse_int(svi_props.get("mtu"), 1500)
            svi_config["mtu"] = min(mtu, 9216)
        self.pa_interfaces.append(svi_config)

        # The FortiGate switch interface (carrying the IP) maps to the SVI so
        # routes/policies that reference it resolve to the L3 vlan.N interface.
        self.interface_name_mapping[fg_name] = svi_name
        self.zone_mapping[fg_name] = l3_zone
        self._add_to_zone(l3_zone, svi_name, mode="layer3")
        self._stats["bridge_groups"] += 1
        self._stats["mapped_interfaces"] += 1

        ip_display = ip_cidr if ip_cidr else ("DHCP" if svi_mode == "dhcp" else "no IP")
        print(f"    {action}: {fg_name} -> {svi_name} (VLAN segment '{vlan_obj}', "
              f"members: [{', '.join(member_pa_names)}], {ip_display}, "
              f"L3 zone: {l3_zone})")

    def _convert_switch(
        self, fg_name: str, properties: Dict, svi_props: Dict,
        zone_lookup: Dict[str, str],
    ) -> None:
        """Convert a FortiGate switch (system_switch-interface) to a PAN-OS
        Layer-2 segment: member ports become layer2 interfaces in a VLAN object,
        and the switch's IP moves onto a vlan.N SVI."""
        members = self._member_list(properties.get("member", []))
        vlan_obj = sanitize_name(f"{fg_name}_vlan")
        l3_zone = self._determine_zone(fg_name, svi_props or properties, zone_lookup)
        l2_zone = sanitize_name(f"{l3_zone}_l2")
        description = str(
            (svi_props.get("description") if svi_props else None)
            or properties.get("description")
            or (svi_props.get("alias") if svi_props else None)
            or fg_name
        )

        # Expansion spec, if any. An explicit port LIST means "use exactly these
        # ports as the members" - the source switch members are NOT auto-assigned
        # to arbitrary ports. An int means "grow to this total".
        spec = self._lookup_spec(self.bridgegroup_expansion, fg_name, vlan_obj)
        explicit_ports = isinstance(spec, (list, tuple))

        member_configs: List[Dict] = []
        member_pa_names: List[str] = []
        if not explicit_ports:
            for member_fg in members:
                pa_port = self._assign_pa_port(member_fg)
                if not pa_port:
                    self.failed_items.append({
                        "name": member_fg,
                        "reason": f"no port available for switch member of {fg_name}",
                        "config": {},
                    })
                    continue
                m_props = self._get_interface_properties(member_fg)
                m_desc = str(
                    m_props.get("description") or m_props.get("alias")
                    or f"Layer-2 member of {vlan_obj}"
                )
                self._add_layer2_member(
                    member_fg, pa_port, vlan_obj, l2_zone, member_configs,
                    member_pa_names, m_desc,
                )

        # Bridge-group expansion: an explicit list defines the exact members; an
        # int adds MORE layer2 members on the PAN-OS side.
        if spec is not None:
            self._apply_bridgegroup_expansion(
                fg_name, vlan_obj, l2_zone, spec, member_configs, member_pa_names,
            )

        if not member_pa_names:
            print(f"    Skipped: {fg_name} (switch with no available member ports)")
            self._stats["skipped"] += 1
            self.failed_items.append({
                "name": fg_name,
                "reason": "switch with no available member ports",
                "config": properties,
            })
            return

        self._emit_layer2_segment(
            fg_name, svi_props or {}, member_configs, member_pa_names,
            l3_zone, vlan_obj, description, "Converted (switch)",
        )

    def _promote_physical_to_bridgegroup(
        self, fg_name: str, properties: Dict, spec: Any, zone_lookup: Dict[str, str],
    ) -> None:
        """Promote a plain physical interface to a NEW PAN-OS Layer-2 segment.

        For an int spec the interface's own auto-assigned port becomes the first
        layer2 member and the segment grows to that TOTAL count. For an explicit
        port list the listed ports ARE the members (exactly those). The
        interface's IP/MTU move onto the vlan.N SVI."""
        vlan_obj = sanitize_name(f"{fg_name}_vlan")
        l3_zone = self._determine_zone(fg_name, properties, zone_lookup)
        l2_zone = sanitize_name(f"{l3_zone}_l2")
        description = str(
            properties.get("description") or properties.get("alias") or fg_name
        )

        member_configs: List[Dict] = []
        member_pa_names: List[str] = []
        if isinstance(spec, int):
            orig_port = self._assign_pa_port(fg_name)
            if not orig_port:
                print(f"    Skipped: {fg_name} (no available port to promote)")
                self._stats["skipped"] += 1
                return
            self._add_layer2_member(
                fg_name, orig_port, vlan_obj, l2_zone, member_configs,
                member_pa_names,
                f"Layer-2 member of {vlan_obj} (promoted from {fg_name})",
            )
            self._apply_bridgegroup_expansion(
                fg_name, vlan_obj, l2_zone, spec, member_configs, member_pa_names,
            )
        else:
            # Explicit ports become the members (held out of the pool earlier).
            self._apply_bridgegroup_expansion(
                fg_name, vlan_obj, l2_zone, list(spec), member_configs, member_pa_names,
            )
            if not member_pa_names:
                print(f"    Skipped: {fg_name} (none of the requested ports were available)")
                self._stats["skipped"] += 1
                return

        self._emit_layer2_segment(
            fg_name, properties, member_configs, member_pa_names,
            l3_zone, vlan_obj, description, "Promoted",
        )

        # The promoted interface's own alias should also resolve to the SVI.
        alias = str(properties.get("alias", "")).strip()
        if alias and alias != fg_name:
            self.interface_name_mapping[alias] = self.interface_name_mapping[fg_name]
            self.zone_mapping[alias] = l3_zone

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_interface_properties(self, intf_name: str) -> Dict:
        """Look up a port's properties from the system_interface section.

        Returns an empty dict if the interface is not found.
        """
        for intf_dict in self.fg_config.get("system_interface", []) or []:
            if not isinstance(intf_dict, dict) or not intf_dict:
                continue
            name = list(intf_dict.keys())[0]
            if str(name) == str(intf_name):
                props = intf_dict[name]
                return props if isinstance(props, dict) else {}
        return {}

    def _assign_pa_port(self, fg_name: str, alias: str = "") -> str:
        """Assign a PAN-OS port to a FortiGate interface.

        Honors an explicit straight-assignment mapping first (by name or alias),
        otherwise takes the next available port.
        """
        mapped = None
        for key in (fg_name, alias):
            if key and str(key).strip().lower() in self.port_map:
                mapped = self.port_map[str(key).strip().lower()]
                break
        if mapped is not None:
            self._used_ports.add(mapped)
            self._held_ports.discard(mapped)
            return f"{self.model_info['port_prefix']}{mapped}"

        port = self._get_next_port()
        if port:
            return f"{self.model_info['port_prefix']}{port}"
        self.failed_items.append({
            "name": fg_name,
            "reason": f"no available ports on {self.target_model} "
                      f"({self.total_ports} total)",
            "config": {},
        })
        return ""

    def _get_next_port(self) -> int:
        """Get the next available port number on the target model.

        Skips ports held for explicit expansion/promotion specs so they aren't
        auto-assigned to a standalone interface before their owning aggregate /
        bridge group claims them.
        """
        while self._next_port <= self.total_ports:
            port = self._next_port
            self._next_port += 1
            if port not in self._used_ports and port not in self._held_ports:
                self._used_ports.add(port)
                return port
        return 0

    def _prereserve_explicit_ports(self) -> None:
        """Hold every explicitly-named expansion/promotion port out of the
        auto-assignment pool before any interface is assigned a port.

        Mirrors the FortiGate -> FTD tool: without this, a standalone physical
        interface (converted in the same phase, in config order) can grab a port
        the user explicitly requested for an aggregate or Layer-2 segment, and
        the owning spec then skips it as 'already assigned elsewhere'.
        """
        self._held_ports = set()
        # Hold explicitly-mapped (straight-assignment) ports too, so a different
        # standalone interface can't grab a port the user pinned to an interface.
        for num in self.port_map.values():
            if 1 <= num <= self.total_ports and num not in self._used_ports:
                self._held_ports.add(num)
        spec_dicts = (
            self.aggregate_expansion, self.promote_to_aggregate,
            self.bridgegroup_expansion, self.promote_to_bridgegroup,
        )
        for spec_dict in spec_dicts:
            for spec in (spec_dict or {}).values():
                if not isinstance(spec, (list, tuple)):
                    continue
                for raw in spec:
                    match = re.match(r"^ethernet1/(\d+)$", str(raw).strip().lower())
                    if not match:
                        continue
                    num = int(match.group(1))
                    if 1 <= num <= self.total_ports and num not in self._used_ports:
                        self._held_ports.add(num)
        if self._held_ports:
            ports = ", ".join(
                f"{self.model_info['port_prefix']}{n}" for n in sorted(self._held_ports)
            )
            print(f"  Reserved {len(self._held_ports)} port(s) for explicit "
                  f"expansion/promotion: {ports}")

    def _build_zone_lookup(self, fg_zones: List) -> Dict[str, str]:
        """Build interface -> zone name mapping from FortiGate system_zone."""
        lookup: Dict[str, str] = {}
        if not fg_zones:
            return lookup
        for zone_dict in fg_zones:
            zone_name = list(zone_dict.keys())[0]
            properties = zone_dict[zone_name]
            interfaces = properties.get("interface", [])
            if isinstance(interfaces, str):
                interfaces = [interfaces]
            for intf in interfaces:
                lookup[str(intf).strip()] = sanitize_name(zone_name)
        return lookup

    def _determine_zone(
        self, intf_name: str, properties: Dict, zone_lookup: Dict[str, str]
    ) -> str:
        """Determine PAN-OS zone name for a FortiGate interface."""
        # 1. Explicit zone assignment from system_zone
        if intf_name in zone_lookup:
            return zone_lookup[intf_name]

        # 2. Use FortiGate 'alias' or 'description' as zone name
        alias = str(properties.get("alias", "")).strip()
        if alias:
            return sanitize_name(alias)

        # 3. Use FortiGate 'role' hint
        role = str(properties.get("role", "")).strip().lower()
        if role in ("lan", "dmz", "wan"):
            return role
        if role == "undefined":
            return sanitize_name(intf_name)

        # 4. Fallback: use sanitized interface name
        return sanitize_name(intf_name)

    def _add_to_zone(self, zone_name: str, pa_interface: str,
                     mode: str = "layer3") -> None:
        """Add a PAN-OS interface to a zone (tracking the zone's L2/L3 mode)."""
        if zone_name not in self._zone_members:
            self._zone_members[zone_name] = []
            self._zone_modes[zone_name] = mode
        if pa_interface not in self._zone_members[zone_name]:
            self._zone_members[zone_name].append(pa_interface)

    @staticmethod
    def _member_list(value: Any) -> List[str]:
        """Normalize a FortiGate member value to a list of port names.

        FortiGate stores it as a list, a single string, or a space-separated
        string (e.g. 'port5 port6').
        """
        if isinstance(value, str):
            return [v for v in value.split() if v]
        if isinstance(value, list):
            return [str(v).strip() for v in value if str(v).strip()]
        return []

    def _extract_ip_cidr(self, properties: Dict) -> str:
        """Extract IP address in CIDR notation from FortiGate interface properties.

        FortiGate stores IP as: [ip, netmask] e.g. [10.0.0.1, 255.255.255.0]
        PAN-OS uses CIDR: 10.0.0.1/24
        """
        ip_config = properties.get("ip")
        if not ip_config:
            return ""

        if isinstance(ip_config, list) and len(ip_config) >= 2:
            ip_addr = str(ip_config[0]).strip()
            netmask = str(ip_config[1]).strip()
            if ip_addr and ip_addr != "0.0.0.0":
                cidr = netmask_to_cidr(netmask)
                return f"{ip_addr}/{cidr}"

        if isinstance(ip_config, str):
            ip_str = ip_config.strip()
            if "/" in ip_str:
                return ip_str
            parts = ip_str.split()
            if len(parts) == 2 and parts[0] != "0.0.0.0":
                cidr = netmask_to_cidr(parts[1])
                return f"{parts[0]}/{cidr}"

        return ""

    @staticmethod
    def _parse_int(value: Any, default: int = 0) -> int:
        """Safely parse an integer value."""
        try:
            return int(value)
        except (ValueError, TypeError):
            return default
