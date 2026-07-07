#!/usr/bin/env python3
"""PAN-OS Interface and Zone Converter - FortiGate Target
==========================================================
Converts PAN-OS interfaces and zones to FortiGate ``system interface``
and ``system zone`` CLI config.

Physical interfaces CANNOT be created on FortiGate hardware - the port
inventory is fixed by the platform.  Emitting ``edit "ethernet1/1"`` with
``set type physical`` would make the whole CLI paste fail, so physical
PA interfaces are emitted as clearly-commented guidance blocks
(``# MANUAL: ...``) that the administrator applies to the matching real
FortiGate port.  VLAN subinterfaces and loopbacks are emitted as real
config, but VLAN parent-interface references point at the original PA
names and need the same manual re-mapping to real ports.

FortiGate interface names are limited to 15 characters; longer PA names
are truncated (with dedup suffixes), and zone/parent references are
resolved through the resulting name map so they stay consistent.
Secondary interface IPs are emitted via ``set secondary-IP enable`` and a
``config secondaryip`` table.

PAN-OS zones map directly to FortiGate ``config system zone`` entries,
preserving the same zone name and interface membership.

FortiGate CLI output format:
    config system interface
        # MANUAL: map PA interface "ethernet1/1" to a real FortiGate port
        # edit "ethernet1/1"
        #     set ip 10.0.0.1 255.255.255.0
        #     set description "LAN interface"
        # next
        edit "ethernet1/1.100"
            set ip 192.168.100.1 255.255.255.0
            set type vlan
            set interface "ethernet1/1"
            set vlanid 100
        next
    end

    config system zone
        edit "trust"
            set interface "ethernet1/1" "ethernet1/2"
        next
    end
"""

from typing import Any, Dict, List

from fg_common import (
    FG_INTERFACE_NAME_MAX_LENGTH,
    dedup_fg_name,
    escape_fg_string,
    fg_members_str,
    sanitize_fg_name,
    split_cidr,
)


class FGInterfaceConverter:
    """Convert PAN-OS interfaces and zones to FortiGate format."""

    def __init__(self, pa_config: Dict[str, Any]) -> None:
        self.pa_config = pa_config
        self.failed_items: List[Dict] = []
        # Maps sanitized original PA interface name -> final FG name
        self._name_map: Dict[str, str] = {}
        self._stats = {
            "interfaces": 0,
            "zones": 0,
        }

    def convert_interfaces(self) -> str:
        """Convert all interfaces and return FortiGate ``system interface`` block.

        Returns an empty string if no interface data is present (interface
        config is optional - policies can reference zone names instead).
        """
        interfaces = self.pa_config.get("interfaces", [])
        if not interfaces:
            return ""

        entries: List[str] = []
        used_names: Dict[str, int] = {}
        manual_physical: List[str] = []

        for intf in interfaces:
            name = intf.get("name", "").strip()
            if not name:
                continue

            # FortiGate interface names are limited to 15 characters
            fg_name = dedup_fg_name(
                sanitize_fg_name(name), used_names, FG_INTERFACE_NAME_MAX_LENGTH
            )
            self._name_map[sanitize_fg_name(name)] = fg_name
            intf_type = intf.get("type", "physical")
            ip_cidr = intf.get("ip", "").strip()
            secondary_ips = intf.get("secondary_ips", []) or []
            description = intf.get("description", "").strip()
            vlan = intf.get("vlan", "").strip()
            parent = intf.get("parent", "").strip()
            is_physical = intf_type not in ("vlan", "loopback")

            lines = [f'    edit "{fg_name}"']

            if ip_cidr:
                ip, netmask = split_cidr(ip_cidr)
                lines.append(f"        set ip {ip} {netmask}")

            if intf_type == "vlan":
                lines.append("        set type vlan")
                # FortiOS requires the parent interface before the vlanid
                if parent:
                    fg_parent = self._resolve_interface_name(parent)
                    lines.append(f'        set interface "{fg_parent}"')
                if vlan:
                    lines.append(f"        set vlanid {vlan}")
            elif intf_type == "loopback":
                lines.append("        set type loopback")
            # Physical: no "set type physical" - the block below is emitted
            # as commented guidance (see module docstring)

            if secondary_ips:
                lines.append("        set secondary-IP enable")
                lines.append("        config secondaryip")
                for idx, sec_cidr in enumerate(secondary_ips, 1):
                    sec_ip, sec_mask = split_cidr(sec_cidr)
                    lines.append(f"            edit {idx}")
                    lines.append(f"                set ip {sec_ip} {sec_mask}")
                    lines.append("            next")
                lines.append("        end")

            if description:
                lines.append(f'        set description "{escape_fg_string(description)}"')

            lines.append("    next")

            if is_physical:
                manual_physical.append(fg_name)
                guidance = [
                    f'    # MANUAL: map PA interface "{name}" to a real '
                    f"FortiGate port, then apply these settings to it:"
                ]
                guidance.extend(f"    # {line.strip()}" for line in lines)
                entries.append("\n".join(guidance))
            else:
                entries.append("\n".join(lines))

            self._stats["interfaces"] += 1
            print(f"  Converted interface: {fg_name} ({intf_type})")

        if not entries:
            return ""

        if manual_physical:
            print(
                f"  Warning: {len(manual_physical)} physical interface(s) "
                f"emitted as commented guidance - map to real FortiGate "
                f"ports manually: {', '.join(manual_physical)}"
            )

        block = (
            "# NOTE: Physical PA interfaces below are commented out because\n"
            "# physical ports cannot be created on FortiGate hardware.\n"
            "# Apply their settings manually to the matching FortiGate ports.\n"
            "# VLAN subinterfaces are real config, but their parent interface\n"
            "# references must be re-mapped to real FortiGate ports as well.\n"
        )
        block += "config system interface\n"
        block += "\n".join(entries)
        block += "\nend\n"
        return block

    def convert_zones(self) -> str:
        """Convert all zones and return FortiGate ``system zone`` block.

        Returns an empty string if no zone data is present.
        """
        zones = self.pa_config.get("zones", [])
        if not zones:
            return ""

        entries: List[str] = []

        for zone in zones:
            name = zone.get("name", "").strip()
            if not name:
                continue

            fg_name = sanitize_fg_name(name)
            interfaces = [
                self._resolve_interface_name(i)
                for i in zone.get("interfaces", [])
                if i
            ]

            lines = [f'    edit "{fg_name}"']
            if interfaces:
                lines.append(f"        set interface {fg_members_str(interfaces)}")
            lines.append("    next")

            entries.append("\n".join(lines))
            self._stats["zones"] += 1
            members_display = ", ".join(interfaces) if interfaces else "(no interfaces)"
            print(f"  Converted zone: {fg_name} [{members_display}]")

        if not entries:
            return ""

        block = "config system zone\n"
        block += "\n".join(entries)
        block += "\nend\n"
        return block

    def get_statistics(self) -> Dict[str, int]:
        return dict(self._stats)

    def get_interface_name_map(self) -> Dict[str, str]:
        """Return mapping: sanitized original PA name -> final FG name."""
        return dict(self._name_map)

    def _resolve_interface_name(self, name: str) -> str:
        """Resolve an interface reference through the rename map."""
        sanitized = sanitize_fg_name(name)
        return self._name_map.get(
            sanitized, sanitized[:FG_INTERFACE_NAME_MAX_LENGTH]
        )
