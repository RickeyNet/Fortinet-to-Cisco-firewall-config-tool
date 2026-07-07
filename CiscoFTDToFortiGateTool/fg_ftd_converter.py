#!/usr/bin/env python3
"""
Cisco FTD to FortiGate Configuration Converter - Main Script
=============================================================
Connects to a Cisco FTD device via the Firepower Device Manager (FDM)
REST API, reads the running configuration, and converts it to a single
FortiGate CLI .conf file.

OUTPUT FILE:
    {output_base}.conf    - FortiGate CLI configuration

SECTIONS GENERATED (in order):
    1. config system interface    - Physical and EtherChannel interfaces
    2. config system zone         - Security zones (with member interfaces)
    3. config firewall address    - Address objects
    4. config firewall addrgrp    - Address groups
    5. config firewall service custom  - TCP/UDP/ICMP service objects
    6. config firewall service group   - Service groups
    7. config firewall policy     - Security policies (from access rules)
    8. config router static       - Static routes

HOW TO RUN:
    python fg_ftd_converter.py --host 192.168.1.1 --username admin --password P@ss
    python fg_ftd_converter.py --host 192.168.1.1 -o fg_migration --no-ssl-verify

NOTE:
    Direct API import to FortiGate is not currently supported.
    Apply the generated .conf file via the FortiGate CLI or:
        System > Configuration > Restore
"""

import argparse
import os
import re
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Path setup - allow importing from sibling tool directories
# ---------------------------------------------------------------------------
_SELF_DIR = os.path.dirname(os.path.abspath(__file__))
_FTD_DIR = os.path.join(os.path.dirname(_SELF_DIR), "FortiGateToFTDTool")
_PA_FG_DIR = os.path.join(os.path.dirname(_SELF_DIR), "PaloAltoToFortiGateTool")

for _d in (_SELF_DIR, _FTD_DIR, _PA_FG_DIR):
    if os.path.isdir(_d) and _d not in sys.path:
        sys.path.insert(0, _d)

try:
    # NOTE: FTDReader (live FDM API mode) is imported lazily inside main() so
    # that --input-file mode works without the 'requests' package installed.
    from ftd_file_reader import FTDFileReader
    from fg_common import (
        split_cidr,
        sanitize_fg_name,
        fg_members_str,
    )
except ImportError as e:
    print("\n" + "=" * 60)
    print("ERROR: Missing module!")
    print("=" * 60)
    print(f"\nDetails: {e}")
    print("\nMake sure these directories are present:")
    print("  - CiscoFTDToFortiGateTool/ftd_file_reader.py")
    print("  - PaloAltoToFortiGateTool/fg_common.py")
    print("\n" + "=" * 60)
    raise


# ---------------------------------------------------------------------------
# FTD built-in object names that map to FortiGate "all" / "ALL"
# ---------------------------------------------------------------------------
_FTD_ANY_ADDRESSES: frozenset = frozenset({
    "any", "any-ipv4", "any-ipv6", "any_ipv4", "any_ipv6",
    "ipv4-any", "ipv4_any", "ipv4 any",
})
_FTD_ANY_SERVICES: frozenset = frozenset({"any", "any-ipv4"})

# FortiGate object name / comment limits (local so we do not depend on
# fg_common internals beyond its public functions)
_FG_NAME_MAX = 64
_FG_COMMENT_MAX = 255

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# FDM ICMPv4/ICMPv6 type enum → numeric ICMP type (FortiGate 'set icmptype')
_ICMP4_TYPE_NUM: Dict[str, int] = {
    "ECHO_REPLY": 0,
    "DESTINATION_UNREACHABLE": 3,
    "SOURCE_QUENCH": 4,
    "REDIRECT_MESSAGE": 5,
    "ALTERNATE_HOST_ADDRESS": 6,
    "ECHO_REQUEST": 8,
    "ROUTER_ADVERTISEMENT": 9,
    "ROUTER_SOLICITATION": 10,
    "TIME_EXCEEDED": 11,
    "PARAMETER_PROBLEM": 12,
    "TIMESTAMP": 13,
    "TIMESTAMP_REPLY": 14,
    "INFORMATION_REQUEST": 15,
    "INFORMATION_REPLY": 16,
    "ADDRESS_MASK_REQUEST": 17,
    "ADDRESS_MASK_REPLY": 18,
    "TRACEROUTE": 30,
}
_ICMP6_TYPE_NUM: Dict[str, int] = {
    "DESTINATION_UNREACHABLE": 1,
    "PACKET_TOO_BIG": 2,
    "TIME_EXCEEDED": 3,
    "PARAMETER_PROBLEM": 4,
    "ECHO_REQUEST": 128,
    "ECHO_REPLY": 129,
    "ROUTER_SOLICITATION": 133,
    "ROUTER_ADVERTISEMENT": 134,
    "NEIGHBOR_SOLICITATION": 135,
    "NEIGHBOR_ADVERTISEMENT": 136,
}


def _is_ftd_any_addr(name: str) -> bool:
    return name.strip().lower() in _FTD_ANY_ADDRESSES


def _is_ftd_any_svc(name: str) -> bool:
    return name.strip().lower() in _FTD_ANY_SERVICES


def _fg_comment(text: str) -> str:
    """Return text safe for use inside a double-quoted FortiGate comment.

    Unlike sanitize_fg_name (64-char object-name limit), comments allow up
    to 255 characters; quotes/backslashes/control chars are replaced so the
    CLI line stays parseable.
    """
    if not text:
        return ""
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", str(text).strip())
    cleaned = cleaned.replace("\\", "/").replace('"', "'")
    return cleaned[:_FG_COMMENT_MAX]


def _unique_fg_name(base: str, used: Set[str]) -> str:
    """Return base, or base with a numeric suffix when it is already used.

    Prevents silent merges when sanitization/truncation or _TCP/_UDP pair
    merging produces the same FortiGate name for two different objects.
    """
    name = base
    n = 1
    while name in used:
        n += 1
        suffix = f"_{n}"
        name = base[: _FG_NAME_MAX - len(suffix)] + suffix
    used.add(name)
    return name


def _fg_intf_name(ftd_hw_name: str, ftd_ifname: str) -> str:
    """Return the FortiGate interface name for an FTD interface.

    Prefers the logical name (ifname / nameif equivalent) when available,
    falling back to a sanitized hardware name.
    """
    if ftd_ifname:
        return sanitize_fg_name(ftd_ifname)
    # Replace characters that are invalid in FG interface names
    sanitized = ftd_hw_name.replace("/", "_").replace(".", "_")
    return sanitize_fg_name(sanitized)


def _ftd_port_str(raw: Any) -> str:
    """Normalize an FTD port value for use in FortiGate portrange syntax.

    FTD uses '80' or '80-443'.  FortiGate uses the same format.  JSON
    snapshots may store the port as an integer, so coerce to str first.
    """
    if raw is None:
        return ""
    return str(raw).strip()


def _topo_sort_groups(groups: List[Dict]) -> List[Dict]:
    """Order groups so nested (member) groups come before referencing groups.

    FortiGate rejects a group member that does not exist yet, so groups must
    be emitted dependency-first.  Cycles are broken with a warning.
    """
    by_name: Dict[str, Dict] = {}
    for grp in groups:
        n = grp.get("name", "")
        if n and n not in by_name:
            by_name[n] = grp

    ordered: List[Dict] = []
    state: Dict[str, int] = {}  # 1 = visiting, 2 = done

    def _visit(n: str) -> None:
        if state.get(n) == 2:
            return
        if state.get(n) == 1:
            print(f"  [WARN] Circular group reference involving '{n}' - cycle broken")
            return
        state[n] = 1
        for ref in by_name[n].get("objects", []) or []:
            ref_name = ref.get("name", "")
            if ref_name and ref_name != n and ref_name in by_name:
                _visit(ref_name)
        state[n] = 2
        ordered.append(by_name[n])

    for n in by_name:
        _visit(n)

    # Keep unnamed/duplicate entries so downstream skip logic still sees them
    ordered.extend(g for g in groups if by_name.get(g.get("name", "")) is not g)
    return ordered


# ===========================================================================
# Phase 1: Interfaces
# ===========================================================================

def _convert_interfaces(
    interfaces: List[Dict],
    etherchannel_interfaces: List[Dict],
) -> Tuple[str, Dict[str, List[str]], Dict[str, str]]:
    """Convert FTD interfaces to a FortiGate 'config system interface' block.

    Returns:
        cli_block          - The FortiGate CLI text
        zone_to_intfs      - Mapping of zone name → [fg_intf_name, ...]
        hw_to_fg           - Mapping of FTD hardware name → fg_intf_name
                             (used when resolving static-route interface names)
    """
    lines = ["config system interface"]
    count = 0
    zone_to_intfs: Dict[str, List[str]] = {}
    hw_to_fg: Dict[str, str] = {}

    def _process_intf(obj: Dict, intf_type: str) -> None:
        nonlocal count
        hw_name = obj.get("hardwareName") or obj.get("name", "")
        ifname = obj.get("ifname", "")
        fg_name = _fg_intf_name(hw_name, ifname)
        if not fg_name:
            return

        hw_to_fg[hw_name] = fg_name

        lines.append(f'    edit "{fg_name}"')

        # Type
        if intf_type == "etherchannel":
            lines.append("        set type aggregate")
            member_names: List[str] = []
            for member in obj.get("memberInterfaces") or []:
                m_hw = member.get("hardwareName") or member.get("name", "")
                if not m_hw:
                    continue
                member_names.append(
                    hw_to_fg.get(m_hw)
                    or sanitize_fg_name(m_hw.replace("/", "_").replace(".", "_"))
                )
            if member_names:
                lines.append(f"        set member {fg_members_str(member_names)}")
        elif obj.get("vlanId"):
            vlan_id = obj["vlanId"]
            parent = obj.get("parentInterface") or {}
            parent_hw = parent.get("hardwareName") or parent.get("name", "")
            parent_fg = hw_to_fg.get(parent_hw) or sanitize_fg_name(
                parent_hw.replace("/", "_").replace(".", "_")
            )
            lines.append("        set type vlan")
            lines.append(f"        set vlanid {vlan_id}")
            if parent_fg:
                lines.append(f'        set interface "{parent_fg}"')

        # Alias (logical name, if different from the fg_name we used)
        if ifname and ifname != fg_name:
            lines.append(f'        set alias "{sanitize_fg_name(ifname)}"')
        elif hw_name and hw_name != fg_name:
            lines.append(f'        set alias "{sanitize_fg_name(hw_name)}"')

        # IP address
        ipv4 = obj.get("ipv4") or {}
        ip_addr_obj = ipv4.get("ipAddress") or {}
        ip = ip_addr_obj.get("ipAddress", "")
        mask = ip_addr_obj.get("netmask", "")
        if ip and mask:
            lines.append(f"        set ip {ip} {mask}")
        elif ipv4.get("dhcp"):
            lines.append("        set mode dhcp")

        # Admin state
        if not obj.get("enabled", True):
            lines.append("        set status down")

        # Zone membership - record for later zone block generation
        zone_ref = obj.get("securityZone") or {}
        zone_name = zone_ref.get("name", "")
        if zone_name:
            zone_to_intfs.setdefault(zone_name, []).append(fg_name)

        lines.append("    next")
        count += 1
        print(f"    Converted: {hw_name} ({ifname or 'no ifname'}) → \"{fg_name}\"")

    # Process in dependency order: physical parents first, then EtherChannels
    # (whose members are physical), then VLAN subinterfaces (whose parents may
    # be physical or EtherChannel).  This keeps hw_to_fg lookups working for
    # 'set member' and 'set interface' references.
    physical = [i for i in interfaces if not i.get("vlanId")]
    vlan_subifs = [i for i in interfaces if i.get("vlanId")]

    for intf in physical:
        _process_intf(intf, "physical")

    for intf in etherchannel_interfaces:
        _process_intf(intf, "etherchannel")

    for intf in vlan_subifs:
        _process_intf(intf, "physical")

    lines.append("end")
    print(f"  Result: {count} interfaces converted")
    return "\n".join(lines), zone_to_intfs, hw_to_fg


# ===========================================================================
# Phase 2: Zones
# ===========================================================================

def _convert_zones(
    security_zones: List[Dict],
    zone_to_intfs: Dict[str, List[str]],
) -> str:
    """Convert FTD security zones to a FortiGate 'config system zone' block."""
    lines = ["config system zone"]
    count = 0

    # Emit zones that have member interfaces first, then any remaining zones
    emitted: Set[str] = set()

    def _emit_zone(name: str, members: List[str]) -> None:
        nonlocal count
        fg_name = sanitize_fg_name(name)
        lines.append(f'    edit "{fg_name}"')
        if members:
            lines.append(f"        set interface {fg_members_str(members)}")
        lines.append("    next")
        count += 1
        emitted.add(name)

    for zone_name, intfs in zone_to_intfs.items():
        _emit_zone(zone_name, intfs)

    for zone in security_zones:
        name = zone.get("name", "")
        if not name or name in emitted:
            continue
        _emit_zone(name, [])

    lines.append("end")
    print(f"  Result: {count} zones converted")
    return "\n".join(lines)


# ===========================================================================
# Phase 3: Address objects
# ===========================================================================

def _convert_network_objects(network_objects: List[Dict]) -> Tuple[str, Dict[str, str]]:
    """Convert FTD network objects to a FortiGate 'config firewall address' block.

    Returns (cli_block, addr_name_map) where addr_name_map maps the original
    FTD object name → emitted FortiGate address name.  Objects that were
    skipped are NOT in the map, so group/policy converters can detect (and
    drop) dangling references instead of emitting them.
    """
    lines = ["config firewall address"]
    count = 0
    skipped = 0
    addr_name_map: Dict[str, str] = {}
    used_names: Set[str] = set()

    for obj in network_objects:
        name = obj.get("name", "")
        if not name or _is_ftd_any_addr(name):
            continue

        sub_type = obj.get("subType", "").upper()
        value = obj.get("value", "")
        description = obj.get("description", "")

        if sub_type not in ("HOST", "NETWORK", "RANGE", "FQDN"):
            print(f"  Skipped: {name} (unknown subType: '{sub_type}')")
            skipped += 1
            continue
        if sub_type == "RANGE" and "-" not in value:
            print(f"  Skipped: {name} (RANGE with no '-' in value: {value})")
            skipped += 1
            continue

        fg_name = _unique_fg_name(sanitize_fg_name(name), used_names)

        lines.append(f'    edit "{fg_name}"')
        if sub_type == "HOST":
            lines.append(f"        set subnet {value} 255.255.255.255")
        elif sub_type == "NETWORK":
            ip, mask = split_cidr(value)
            lines.append(f"        set subnet {ip} {mask}")
        elif sub_type == "RANGE":
            start, _, end = value.partition("-")
            lines.append("        set type iprange")
            lines.append(f"        set start-ip {start.strip()}")
            lines.append(f"        set end-ip {end.strip()}")
        elif sub_type == "FQDN":
            lines.append("        set type fqdn")
            lines.append(f'        set fqdn "{value}"')
        if description:
            lines.append(f'        set comment "{_fg_comment(description)}"')
        lines.append("    next")
        count += 1
        addr_name_map[name] = fg_name

    lines.append("end")
    print(f"  Result: {count} converted, {skipped} skipped")
    return "\n".join(lines), addr_name_map


# ===========================================================================
# Phase 4: Address groups
# ===========================================================================

def _literal_to_inline_addr(
    lit: Dict,
    inline_objects: List[Dict],
    known_fg_names: Set[str],
) -> Optional[str]:
    """Convert an FTD network literal into an auto-created FG address object.

    Shared by the group and access-rule converters so both handle host,
    subnet, AND range literals identically.  Returns the FG address name,
    or None when the literal has no value.
    """
    value = lit.get("value", "")
    lit_type = str(lit.get("type", "")).lower()
    if not value:
        return None

    # Build a stable name from the value
    safe_val = value.replace("/", "_").replace(".", "_").replace("-", "_")
    fg_name = sanitize_fg_name(f"inline_{safe_val}")

    if fg_name in known_fg_names:
        return fg_name  # Already exists

    known_fg_names.add(fg_name)

    if "-" in value and "/" not in value and lit_type != "host":
        start, _, end = value.partition("-")
        inline_objects.append({
            "fg_name": fg_name,
            "type": "iprange",
            "start": start.strip(),
            "end": end.strip(),
        })
    elif lit_type == "host" or "/" not in value:
        inline_objects.append({
            "fg_name": fg_name,
            "type": "host",
            "ip": value,
            "mask": "255.255.255.255",
        })
    else:
        ip, mask = split_cidr(value)
        inline_objects.append({
            "fg_name": fg_name,
            "type": "subnet",
            "ip": ip,
            "mask": mask,
        })

    return fg_name


def _make_inline_addr_block(inline_objects: List[Dict]) -> str:
    """Build a supplemental address block for literals discovered during group conversion."""
    if not inline_objects:
        return ""
    lines = ["config firewall address"]
    for obj in inline_objects:
        fg_name = obj["fg_name"]
        lines.append(f'    edit "{fg_name}"')
        if obj["type"] == "iprange":
            lines.append("        set type iprange")
            lines.append(f"        set start-ip {obj['start']}")
            lines.append(f"        set end-ip {obj['end']}")
        else:
            lines.append(f"        set subnet {obj['ip']} {obj['mask']}")
        lines.append('        set comment "Auto-created from group literal"')
        lines.append("    next")
    lines.append("end")
    return "\n".join(lines)


def _convert_network_groups(
    network_groups: List[Dict],
    addr_name_map: Dict[str, str],
    known_fg_names: Set[str],
) -> Tuple[str, str]:
    """Convert FTD network groups to a FortiGate 'config firewall addrgrp' block.

    Returns (addrgrp_cli_block, supplemental_address_block).
    The supplemental block contains address objects auto-created from
    inline IP literals found inside groups.  Groups are emitted in
    dependency order (nested groups first) and dangling member references
    are dropped with a message.
    """
    lines = ["config firewall addrgrp"]
    count = 0
    skipped = 0
    inline_objects: List[Dict] = []

    for grp in _topo_sort_groups(network_groups):
        name = grp.get("name", "")
        if not name or _is_ftd_any_addr(name):
            continue

        members: List[str] = []

        for obj_ref in grp.get("objects", []) or []:
            ref_name = obj_ref.get("name", "")
            if not ref_name or _is_ftd_any_addr(ref_name):
                continue
            fg_ref = addr_name_map.get(ref_name, sanitize_fg_name(ref_name))
            if fg_ref in known_fg_names:
                members.append(fg_ref)
            else:
                print(
                    f"    Dropped member '{ref_name}' from group '{name}' "
                    f"(referenced object was not converted)"
                )

        for lit in grp.get("literals", []) or []:
            lit_fg = _literal_to_inline_addr(lit, inline_objects, known_fg_names)
            if lit_fg:
                members.append(lit_fg)

        members = list(dict.fromkeys(members))
        if not members:
            print(f"  Skipped: {name} (no members)")
            skipped += 1
            continue

        fg_name = _unique_fg_name(sanitize_fg_name(name), known_fg_names)
        addr_name_map[name] = fg_name

        lines.append(f'    edit "{fg_name}"')
        lines.append(f"        set member {fg_members_str(members)}")
        lines.append("    next")
        count += 1

    lines.append("end")
    print(f"  Result: {count} converted, {skipped} skipped")
    return "\n".join(lines), _make_inline_addr_block(inline_objects)


# ===========================================================================
# Phase 5: Service objects
# ===========================================================================

def _convert_port_objects(
    tcp_ports: List[Dict],
    udp_ports: List[Dict],
    icmpv4_ports: Optional[List[Dict]] = None,
    icmpv6_ports: Optional[List[Dict]] = None,
) -> Tuple[str, Dict[str, str], Set[str]]:
    """Convert FTD TCP/UDP/ICMP port objects to 'config firewall service custom'.

    Detects _TCP/_UDP suffix pairs (produced by the FG→FTD converter) and
    merges them back into single dual-protocol FortiGate service objects.
    ICMP port objects (e.g. ICMP_Echo_Request/Reply created by this repo's
    FTD writer for PING groups) become FortiGate ICMP services.

    Returns:
        cli_block        - FortiGate CLI text
        service_name_map - Mapping of original FTD port-object name → FG service name
                           (used by group and policy converters)
        emitted          - Set of FG service names actually emitted (used to
                           detect dangling references)
    """
    lines = ["config firewall service custom"]
    count = 0
    skipped = 0
    service_name_map: Dict[str, str] = {}
    used_names: Set[str] = set()

    tcp_map: Dict[str, str] = {}
    udp_map: Dict[str, str] = {}

    for obj in tcp_ports:
        n, p = obj.get("name", ""), _ftd_port_str(obj.get("port", ""))
        if n and p:
            tcp_map[n] = p

    for obj in udp_ports:
        n, p = obj.get("name", ""), _ftd_port_str(obj.get("port", ""))
        if n and p:
            udp_map[n] = p

    # Detect _TCP / _UDP companion pairs (case-insensitive suffix match)
    udp_base_lookup: Dict[str, str] = {}
    for udp_name in sorted(udp_map):
        if udp_name[-4:].lower() == "_udp":
            udp_base_lookup.setdefault(udp_name[:-4].lower(), udp_name)

    merged_pairs: List[Tuple[str, str, str]] = []  # (base, tcp_name, udp_name)
    merged_ftd_names: Set[str] = set()
    for tcp_name in sorted(tcp_map):
        if tcp_name[-4:].lower() != "_tcp":
            continue
        base = tcp_name[:-4]
        matched_udp = udp_base_lookup.get(base.lower())
        if matched_udp and matched_udp not in merged_ftd_names:
            merged_pairs.append((base, tcp_name, matched_udp))
            merged_ftd_names.add(tcp_name)
            merged_ftd_names.add(matched_udp)

    # Reserve names for plain (non-merged) services first so a merged pair
    # can never silently overwrite an existing service; the merged name gets
    # a numeric suffix on collision instead.
    for tcp_name in sorted(tcp_map):
        if tcp_name not in merged_ftd_names:
            service_name_map[tcp_name] = _unique_fg_name(sanitize_fg_name(tcp_name), used_names)
    for udp_name in sorted(udp_map):
        if udp_name not in merged_ftd_names:
            service_name_map[udp_name] = _unique_fg_name(sanitize_fg_name(udp_name), used_names)

    # Emit merged pairs
    for base, tcp_name, udp_name in merged_pairs:
        fg_merged = _unique_fg_name(sanitize_fg_name(base), used_names)
        lines.append(f'    edit "{fg_merged}"')
        lines.append(f"        set tcp-portrange {tcp_map[tcp_name]}")
        lines.append(f"        set udp-portrange {udp_map[udp_name]}")
        lines.append("    next")
        count += 1
        service_name_map[tcp_name] = fg_merged
        service_name_map[udp_name] = fg_merged
        print(f"    Merged: {tcp_name} + {udp_name} → \"{fg_merged}\"")

    # Remaining TCP port objects
    for tcp_name, tcp_port in sorted(tcp_map.items()):
        if tcp_name in merged_ftd_names:
            continue
        lines.append(f'    edit "{service_name_map[tcp_name]}"')
        lines.append(f"        set tcp-portrange {tcp_port}")
        lines.append("    next")
        count += 1

    # Remaining UDP port objects
    for udp_name, udp_port in sorted(udp_map.items()):
        if udp_name in merged_ftd_names:
            continue
        lines.append(f'    edit "{service_name_map[udp_name]}"')
        lines.append(f"        set udp-portrange {udp_port}")
        lines.append("    next")
        count += 1

    # ICMP port objects → FortiGate ICMP services
    for icmp_list, fg_proto, type_key, code_key, type_num_map in (
        (icmpv4_ports or [], "ICMP", "icmpv4Type", "icmpv4Code", _ICMP4_TYPE_NUM),
        (icmpv6_ports or [], "ICMP6", "icmpv6Type", "icmpv6Code", _ICMP6_TYPE_NUM),
    ):
        for obj in icmp_list:
            n = obj.get("name", "")
            if not n:
                continue
            itype = str(obj.get(type_key) or "").upper()
            if itype in ("", "ANY"):
                icmp_num: Optional[int] = None
            elif itype in type_num_map:
                icmp_num = type_num_map[itype]
            else:
                print(f"  Skipped: {n} (unsupported {type_key} '{itype}')")
                skipped += 1
                continue
            fg_name = _unique_fg_name(sanitize_fg_name(n), used_names)
            lines.append(f'    edit "{fg_name}"')
            lines.append(f"        set protocol {fg_proto}")
            if icmp_num is not None:
                lines.append(f"        set icmptype {icmp_num}")
            code = obj.get(code_key)
            if isinstance(code, int) or (isinstance(code, str) and code.isdigit()):
                lines.append(f"        set icmpcode {int(code)}")
            lines.append("    next")
            count += 1
            service_name_map[n] = fg_name

    lines.append("end")
    print(f"  Result: {count} service objects converted, {skipped} skipped")
    return "\n".join(lines), service_name_map, set(service_name_map.values())


# ===========================================================================
# Phase 6: Service groups
# ===========================================================================

def _convert_port_groups(
    port_groups: List[Dict],
    service_name_map: Dict[str, str],
    emitted_services: Set[str],
) -> str:
    """Convert FTD port groups to 'config firewall service group'.

    Groups are emitted in dependency order; member references to objects
    that were not converted are dropped with a message so the output never
    contains dangling names.  Emitted group names are added to
    service_name_map / emitted_services for the policy converter.
    """
    lines = ["config firewall service group"]
    count = 0
    skipped = 0

    for grp in _topo_sort_groups(port_groups):
        name = grp.get("name", "")
        if not name or _is_ftd_any_svc(name):
            continue

        members: List[str] = []

        for obj_ref in grp.get("objects", []) or []:
            ref_name = obj_ref.get("name", "")
            if not ref_name or _is_ftd_any_svc(ref_name):
                continue
            fg_ref = service_name_map.get(ref_name, sanitize_fg_name(ref_name))
            if fg_ref in emitted_services:
                members.append(fg_ref)
            else:
                print(
                    f"    Dropped member '{ref_name}' from group '{name}' "
                    f"(referenced service was not converted)"
                )

        members = list(dict.fromkeys(members))
        if not members:
            print(f"  Skipped: {name} (no members)")
            skipped += 1
            continue

        fg_name = _unique_fg_name(sanitize_fg_name(name), emitted_services)
        service_name_map[name] = fg_name

        lines.append(f'    edit "{fg_name}"')
        lines.append(f"        set member {fg_members_str(members)}")
        lines.append("    next")
        count += 1

    lines.append("end")
    print(f"  Result: {count} converted, {skipped} skipped")
    return "\n".join(lines)


# ===========================================================================
# Phase 7: Security policies (from access rules)
# ===========================================================================

def _resolve_network_refs(
    field: Any,
    inline_addr: List[Dict],
    known_fg_names: Set[str],
    addr_name_map: Dict[str, str],
) -> Tuple[List[str], bool]:
    """Resolve FTD sourceNetworks / destinationNetworks to FG address names.

    FTD GET may return the field as:
      - A list of {name, type} dicts  (older FDM versions)
      - A dict with 'objects' and 'literals' keys  (newer FDM versions)
      - None / empty  (meaning "any")

    Returns (names, fail_closed).  fail_closed is True when the rule HAD
    address restrictions but none could be resolved - the caller must never
    widen such a rule to 'all'.
    """
    if not field:
        return ["all"], False

    objects: List[Dict] = []
    literals: List[Dict] = []

    if isinstance(field, list):
        objects = field
    elif isinstance(field, dict):
        objects = field.get("objects", []) or []
        literals = field.get("literals", []) or []

    result: List[str] = []

    for obj_ref in objects:
        ref_name = obj_ref.get("name", "")
        if not ref_name or _is_ftd_any_addr(ref_name):
            return ["all"], False
        fg_ref = addr_name_map.get(ref_name, sanitize_fg_name(ref_name))
        if fg_ref in known_fg_names:
            result.append(fg_ref)
        else:
            print(f"    Dropped address reference '{ref_name}' (object was not converted)")

    for lit in literals:
        lit_fg = _literal_to_inline_addr(lit, inline_addr, known_fg_names)
        if lit_fg:
            result.append(lit_fg)

    if result:
        return list(dict.fromkeys(result)), False
    if objects or literals:
        return [], True  # had restrictions, nothing resolved → fail closed
    return ["all"], False


def _service_literal_to_fg(
    lit: Dict,
    inline_services: List[Dict],
    emitted_services: Set[str],
) -> Optional[str]:
    """Convert an FTD port literal into an auto-created FG service object.

    Returns the FG service name, or None when the literal cannot be mapped
    (unknown protocol / missing port).
    """
    proto = str(lit.get("protocol", "")).strip().upper()
    port = _ftd_port_str(lit.get("port", ""))
    if proto in ("6", "TCP"):
        kind = "tcp"
    elif proto in ("17", "UDP"):
        kind = "udp"
    else:
        return None
    if not port:
        return None

    fg_name = sanitize_fg_name(f"inline_{kind}_{port.replace('-', '_')}")
    if fg_name not in emitted_services:
        emitted_services.add(fg_name)
        inline_services.append({"fg_name": fg_name, "proto": kind, "port": port})
    return fg_name


def _make_inline_service_block(inline_services: List[Dict]) -> str:
    """Build a supplemental service block for port literals found in rules."""
    if not inline_services:
        return ""
    lines = ["config firewall service custom"]
    for svc in inline_services:
        lines.append(f'    edit "{svc["fg_name"]}"')
        lines.append(f"        set {svc['proto']}-portrange {svc['port']}")
        lines.append('        set comment "Auto-created from rule literal"')
        lines.append("    next")
    lines.append("end")
    return "\n".join(lines)


def _resolve_service_refs(
    field: Any,
    service_name_map: Dict[str, str],
    emitted_services: Set[str],
    inline_services: List[Dict],
) -> Tuple[List[str], bool]:
    """Resolve FTD destinationPorts to FG service names.

    Port literals are converted into auto-created FG services.  Returns
    (names, fail_closed): ["ALL"] when the field is empty or contains "any";
    fail_closed=True when the rule HAD service restrictions but none could
    be resolved (the caller must not widen it to ALL).
    """
    if not field:
        return ["ALL"], False

    objects: List[Dict] = []
    literals: List[Dict] = []

    if isinstance(field, list):
        objects = field
    elif isinstance(field, dict):
        objects = field.get("objects", []) or []
        literals = field.get("literals", []) or []
    else:
        return ["ALL"], False

    result: List[str] = []
    for obj_ref in objects:
        ref_name = obj_ref.get("name", "")
        if not ref_name or _is_ftd_any_svc(ref_name):
            return ["ALL"], False
        fg_ref = service_name_map.get(ref_name, sanitize_fg_name(ref_name))
        if fg_ref in emitted_services:
            result.append(fg_ref)
        else:
            print(f"    Dropped service reference '{ref_name}' (object was not converted)")

    for lit in literals:
        lit_fg = _service_literal_to_fg(lit, inline_services, emitted_services)
        if lit_fg:
            result.append(lit_fg)
        else:
            print(
                f"    Dropped service literal "
                f"{lit.get('protocol', '?')}/{lit.get('port', '?')} (unsupported)"
            )

    if result:
        return list(dict.fromkeys(result)), False
    if objects or literals:
        return [], True  # had restrictions, nothing resolved → fail closed
    return ["ALL"], False


def _convert_access_rules(
    access_rules: List[Dict],
    service_name_map: Dict[str, str],
    emitted_services: Set[str],
    known_fg_names: Set[str],
    addr_name_map: Dict[str, str],
) -> Tuple[str, str, str]:
    """Convert FTD access rules to a FortiGate 'config firewall policy' block.

    Returns (policy_cli_block, supplemental_address_block,
    supplemental_service_block) where the supplemental blocks hold inline
    address/service objects discovered in rule literals.

    Fail-closed guarantee: a rule whose addresses or services were all
    filtered/unresolvable is emitted DISABLED with a review comment instead
    of silently becoming an any/ALL rule.
    """
    lines = ["config firewall policy"]
    count = 0
    fail_closed = 0
    src_port_warnings = 0
    inline_addr: List[Dict] = []
    inline_services: List[Dict] = []
    used_policy_names: Set[str] = set()
    policy_id = 1

    for rule in access_rules:
        name = rule.get("name") or f"rule_{policy_id}"
        action_raw = str(rule.get("ruleAction", "DENY")).upper()
        # PERMIT and TRUST both permit traffic on FTD
        action = "accept" if action_raw in ("PERMIT", "TRUST") else "deny"

        # Source zones → srcintf
        src_zones_raw = rule.get("sourceZones", [])
        if isinstance(src_zones_raw, dict):
            src_zones_raw = src_zones_raw.get("objects", [])
        src_intfs = [
            sanitize_fg_name(z.get("name", ""))
            for z in src_zones_raw
            if z.get("name")
        ]
        if not src_intfs:
            src_intfs = ["any"]

        # Destination zones → dstintf
        dst_zones_raw = rule.get("destinationZones", [])
        if isinstance(dst_zones_raw, dict):
            dst_zones_raw = dst_zones_raw.get("objects", [])
        dst_intfs = [
            sanitize_fg_name(z.get("name", ""))
            for z in dst_zones_raw
            if z.get("name")
        ]
        if not dst_intfs:
            dst_intfs = ["any"]

        # Source networks → srcaddr
        src_addrs, src_failed = _resolve_network_refs(
            rule.get("sourceNetworks"), inline_addr, known_fg_names, addr_name_map
        )

        # Destination networks → dstaddr
        dst_addrs, dst_failed = _resolve_network_refs(
            rule.get("destinationNetworks"), inline_addr, known_fg_names, addr_name_map
        )

        # Destination ports → service
        services, svc_failed = _resolve_service_refs(
            rule.get("destinationPorts"), service_name_map, emitted_services,
            inline_services,
        )

        # Source ports cannot be represented as a plain FortiGate policy
        # service list - warn instead of silently dropping the restriction.
        src_ports = rule.get("sourcePorts")
        if isinstance(src_ports, dict):
            has_src_ports = bool(src_ports.get("objects") or src_ports.get("literals"))
        else:
            has_src_ports = bool(src_ports)
        if has_src_ports:
            print(
                f"    [WARN] {name}: sourcePorts are not supported on FortiGate "
                f"policies - ignored (matching on destination ports only)"
            )
            src_port_warnings += 1

        # Fail closed: never widen an unresolvable restriction to any/ALL
        disable_reasons: List[str] = []
        if src_failed:
            disable_reasons.append("source addresses")
            src_addrs = ["all"]
        if dst_failed:
            disable_reasons.append("destination addresses")
            dst_addrs = ["all"]
        if svc_failed:
            disable_reasons.append("services")
            services = ["ALL"]

        # Logging
        log_action = rule.get("eventLogAction", "")
        log_traffic = "all" if log_action and log_action not in ("LOG_NONE", "") else "disable"

        # Enabled/disabled
        enabled = rule.get("enabled", True)

        fg_rule_name = _unique_fg_name(sanitize_fg_name(name), used_policy_names)

        lines.append(f"    edit {policy_id}")
        lines.append(f'        set name "{fg_rule_name}"')
        lines.append(f"        set srcintf {fg_members_str(src_intfs)}")
        lines.append(f"        set dstintf {fg_members_str(dst_intfs)}")
        lines.append(f"        set srcaddr {fg_members_str(src_addrs)}")
        lines.append(f"        set dstaddr {fg_members_str(dst_addrs)}")
        lines.append(f"        set action {action}")
        lines.append('        set schedule "always"')
        lines.append(f"        set service {fg_members_str(services)}")
        lines.append(f"        set logtraffic {log_traffic}")
        if disable_reasons:
            comment = (
                "MIGRATION-REVIEW: disabled - could not resolve "
                + " and ".join(disable_reasons)
            )
            lines.append(f'        set comments "{_fg_comment(comment)}"')
        if not enabled or disable_reasons:
            lines.append("        set status disable")
        lines.append("    next")

        if disable_reasons:
            fail_closed += 1
            print(
                f"    [FAIL-CLOSED] {name}: could not resolve "
                f"{' and '.join(disable_reasons)} - policy emitted disabled"
            )
        else:
            print(
                f"    Converted: {name} [{action.upper()}] "
                f"({', '.join(src_intfs)} → {', '.join(dst_intfs)})"
            )
        count += 1
        policy_id += 1

    lines.append("end")
    print(
        f"  Result: {count} policies converted, "
        f"{fail_closed} emitted disabled (fail-closed), "
        f"{src_port_warnings} source-port warnings"
    )
    return (
        "\n".join(lines),
        _make_inline_addr_block(inline_addr),
        _make_inline_service_block(inline_services),
    )


# ===========================================================================
# Phase 8: Static routes
# ===========================================================================

def _convert_static_routes(
    static_routes: List[Dict],
    hw_to_fg: Dict[str, str],
    network_objects: List[Dict],
) -> str:
    """Convert FTD static routes to a FortiGate 'config router static' block.

    FDM staticrouteentry stores 'networks' and 'gateway' as object
    REFERENCES ({name, id, type}) and the egress interface under 'iface'.
    References are resolved through the fetched network objects; older
    snapshots that embed 'value' / 'ipAddress' / 'interface' directly are
    still handled.
    """
    lines = ["config router static"]
    count = 0
    skipped = 0
    route_id = 1

    # FTD object name → value (e.g. '10.0.0.0/24' or '192.168.1.254')
    obj_values: Dict[str, str] = {
        o.get("name", ""): str(o.get("value", ""))
        for o in network_objects
        if o.get("name") and o.get("value")
    }

    for route in static_routes:
        networks = route.get("networks") or []
        if not networks:
            continue

        # Gateway: object reference (FDM) or embedded IP (old snapshots)
        gw_obj = route.get("gateway") or {}
        nexthop = gw_obj.get("ipAddress", "")
        if not nexthop and gw_obj:
            gw_name = gw_obj.get("name", "")
            gw_value = obj_values.get(gw_name, "")
            if gw_value:
                nexthop = gw_value.partition("/")[0]
            elif _IPV4_RE.match(gw_name):
                # Gateway objects are commonly named after their IP
                nexthop = gw_name

        if gw_obj and not nexthop:
            print(
                f"  Skipped: route '{route.get('name', route_id)}' "
                f"(could not resolve gateway '{gw_obj.get('name', '')}')"
            )
            skipped += 1
            continue

        # Interface: FDM uses 'iface'; fall back to 'interface' (old snapshots)
        intf_obj = route.get("iface") or route.get("interface") or {}
        ftd_intf = intf_obj.get("hardwareName") or intf_obj.get("name", "")
        fg_intf = hw_to_fg.get(ftd_intf, sanitize_fg_name(ftd_intf))

        metric = route.get("metricValue")
        if metric is None:
            metric = 1

        for net_entry in networks:
            # Network: object reference (FDM) or embedded value (old snapshots)
            dest = net_entry.get("value", "")
            net_name = net_entry.get("name", "")
            if not dest and net_name:
                if _is_ftd_any_addr(net_name):
                    dest = "0.0.0.0/0"
                else:
                    dest = obj_values.get(net_name, "")
            if not dest:
                print(
                    f"  Skipped: route network '{net_name or net_entry}' "
                    f"(could not resolve network object)"
                )
                skipped += 1
                continue

            ip, mask = split_cidr(dest)

            if not nexthop and not fg_intf:
                print(f"  Skipped: {dest} (no nexthop and no interface)")
                skipped += 1
                continue

            lines.append(f"    edit {route_id}")
            lines.append(f"        set dst {ip} {mask}")
            if nexthop:
                lines.append(f"        set gateway {nexthop}")
            if fg_intf:
                lines.append(f'        set device "{fg_intf}"')
            lines.append(f"        set distance {metric}")
            lines.append("    next")
            count += 1
            route_id += 1

    lines.append("end")
    print(f"  Result: {count} static routes converted, {skipped} skipped")
    return "\n".join(lines)


# ===========================================================================
# Output helpers
# ===========================================================================

_HEADER_TEMPLATE = """\
# ============================================================
# FortiGate CLI Configuration
# Generated by Firewall Migration Tool
# Source:    Cisco FTD ({host})
# Generated: {timestamp}
# ============================================================
#
# HOW TO APPLY:
#   Option A - CLI (granular, section by section):
#     Paste each config block into the FortiGate CLI shell.
#
#   Option B - Web UI restore (merges all sections at once):
#     System > Configuration > Restore  (select this .conf file)
#
# IMPORTANT:
#   Review interface names and physical port assignments before
#   applying.  FortiGate port naming (port1, port2, ...) may
#   differ from FTD hardware names.
# ============================================================
"""


def _write_conf(sections: List[str], output_path: str, host: str) -> None:
    """Write the assembled FortiGate .conf file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    header = _HEADER_TEMPLATE.format(host=host, timestamp=timestamp)
    body = "\n\n".join(s for s in sections if s.strip())
    content = header + "\n" + body + "\n"
    with open(output_path, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)


# ===========================================================================
# main()
# ===========================================================================

def main(argv: Optional[List[str]] = None) -> int:
    """Entry point called by the GUI and CLI."""

    parser = argparse.ArgumentParser(
        description="Convert Cisco FTD configuration to FortiGate CLI format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Live FDM API mode:
  python fg_ftd_converter.py --host 192.168.1.1 --username admin --password P@ss
  python fg_ftd_converter.py --host 192.168.1.1 -o fg_migration --no-ssl-verify

  # JSON file mode:
  python fg_ftd_converter.py --input-file ftd_snapshot.json -o fg_migration
        """,
    )
    parser.add_argument(
        "--input-file",
        metavar="FILE",
        help="Path to a JSON config file exported from the FDM API (skips live API connection)",
    )
    parser.add_argument(
        "--host",
        help="FTD management IP address or hostname (required when not using --input-file)",
    )
    parser.add_argument(
        "--username",
        default="admin",
        help="FDM username (default: admin; only used with --host)",
    )
    parser.add_argument(
        "--password",
        help="FDM password (required when not using --input-file)",
    )
    parser.add_argument(
        "-o", "--output",
        default="fg_config",
        help="Base name for output .conf file (default: fg_config)",
    )
    parser.add_argument(
        "--no-ssl-verify",
        action="store_true",
        help="Disable SSL certificate verification (for self-signed certs; only used with --host)",
    )

    args = parser.parse_args(argv)

    # ── Validate arg combinations ─────────────────────────────────────────
    using_file = bool(args.input_file)
    using_api = bool(args.host)

    if using_file and using_api:
        parser.error("--input-file and --host are mutually exclusive.")
    if not using_file and not using_api:
        parser.error("Either --input-file or --host (with --password) must be provided.")
    if using_api and not args.password:
        parser.error("--password is required when using --host.")

    # ── Banner ────────────────────────────────────────────────────────────
    print("=" * 60)
    print("Cisco FTD to FortiGate Configuration Converter")
    print("=" * 60)
    if using_file:
        source_label = os.path.basename(args.input_file)
        print(f"Input File: {args.input_file}")
    else:
        source_label = args.host
        print(f"FTD Host:   {args.host}")
        print(f"Username:   {args.username}")
    print(f"Output:     {args.output}.conf")

    # ── Load FTD configuration ────────────────────────────────────────────
    if using_file:
        print("\n[Loading FTD configuration from file...]")
        try:
            reader = FTDFileReader(args.input_file)
            ftd_config = reader.read_all()
        except (FileNotFoundError, ValueError, OSError) as exc:
            print(f"[ERROR] {exc}")
            return 1
    else:
        print("\n[Connecting to FTD via FDM API...]")
        try:
            # Lazy import: live API mode needs the 'requests' package, but
            # --input-file conversion must work without it.
            from ftd_reader import FTDReader
        except ImportError as exc:
            print(f"[ERROR] Could not load the FDM API client: {exc}")
            print("        Live API mode requires the 'requests' package "
                  "(pip install requests).")
            return 1
        reader = FTDReader(
            host=args.host,
            username=args.username,
            password=args.password,
            verify_ssl=not args.no_ssl_verify,
        )
        if not reader.authenticate():
            print("[ERROR] Authentication failed - check host, username, and password.")
            return 1
        print("\n[Reading FTD configuration...]")
        ftd_config = reader.read_all()

    print(
        f"\n  Inventory: "
        f"{len(ftd_config['network_objects'])} address objects, "
        f"{len(ftd_config['network_groups'])} address groups, "
        f"{len(ftd_config['tcp_ports'])} TCP ports, "
        f"{len(ftd_config['udp_ports'])} UDP ports, "
        f"{len(ftd_config.get('icmpv4_ports', []))} ICMPv4 ports, "
        f"{len(ftd_config.get('icmpv6_ports', []))} ICMPv6 ports, "
        f"{len(ftd_config['port_groups'])} service groups, "
        f"{len(ftd_config['interfaces'])} interfaces, "
        f"{len(ftd_config['security_zones'])} zones, "
        f"{len(ftd_config['static_routes'])} routes, "
        f"{len(ftd_config['access_rules'])} access rules"
    )

    # ── Conversion phases ─────────────────────────────────────────────────
    output_sections: List[str] = []

    # Phase 1: Interfaces
    print("\n[Phase 1/8] Converting interfaces...")
    intf_block, zone_to_intfs, hw_to_fg = _convert_interfaces(
        ftd_config["interfaces"],
        ftd_config["etherchannel_interfaces"],
    )
    if intf_block:
        output_sections.append(intf_block)

    # Phase 2: Zones
    print("\n[Phase 2/8] Converting security zones...")
    zone_block = _convert_zones(ftd_config["security_zones"], zone_to_intfs)
    if zone_block:
        output_sections.append(zone_block)

    # Phase 3: Address objects
    print("\n[Phase 3/8] Converting address objects...")
    addr_block, addr_name_map = _convert_network_objects(ftd_config["network_objects"])
    known_fg_names: Set[str] = set(addr_name_map.values())
    if addr_block:
        output_sections.append(addr_block)

    # Phase 4: Address groups
    print("\n[Phase 4/8] Converting address groups...")
    addrgrp_block, inline_addr_block = _convert_network_groups(
        ftd_config["network_groups"], addr_name_map, known_fg_names
    )
    # Prepend any auto-created inline address objects before the group block
    if inline_addr_block:
        output_sections.append(inline_addr_block)
    if addrgrp_block:
        output_sections.append(addrgrp_block)

    # Phase 5: Service objects
    print("\n[Phase 5/8] Converting service objects...")
    svc_block, service_name_map, emitted_services = _convert_port_objects(
        ftd_config["tcp_ports"],
        ftd_config["udp_ports"],
        ftd_config.get("icmpv4_ports", []),
        ftd_config.get("icmpv6_ports", []),
    )
    if svc_block:
        output_sections.append(svc_block)

    # Phase 6: Service groups
    print("\n[Phase 6/8] Converting service groups...")
    svcgrp_block = _convert_port_groups(
        ftd_config["port_groups"], service_name_map, emitted_services
    )
    if svcgrp_block:
        output_sections.append(svcgrp_block)

    # Phase 7: Policies
    print("\n[Phase 7/8] Converting access rules to policies...")
    policy_block, rule_inline_addr_block, rule_inline_svc_block = _convert_access_rules(
        ftd_config["access_rules"], service_name_map, emitted_services,
        known_fg_names, addr_name_map,
    )
    if rule_inline_addr_block:
        # Insert before the policy block
        output_sections.append(rule_inline_addr_block)
    if rule_inline_svc_block:
        output_sections.append(rule_inline_svc_block)
    if policy_block:
        output_sections.append(policy_block)

    # Phase 8: Static routes
    print("\n[Phase 8/8] Converting static routes...")
    route_block = _convert_static_routes(
        ftd_config["static_routes"], hw_to_fg, ftd_config["network_objects"]
    )
    if route_block:
        output_sections.append(route_block)

    # ── Write output ──────────────────────────────────────────────────────
    output_path = f"{args.output}.conf"
    print(f"\n[Writing output file: {output_path}]")
    try:
        _write_conf(output_sections, output_path, source_label)
    except OSError as exc:
        print(f"[ERROR] Could not write output file: {exc}")
        return 1

    print(f"\n{'='*60}")
    print(f"Conversion complete: {output_path}")
    print(
        f"Sections: {len(output_sections)} | "
        f"Apply via CLI paste or System > Configuration > Restore"
    )
    print("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
