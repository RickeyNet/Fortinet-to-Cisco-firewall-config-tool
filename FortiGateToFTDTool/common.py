#!/usr/bin/env python3
"""Shared utilities for converter modules."""

import re
from typing import Any, Dict, List, Optional, Tuple

_SANITIZE_PATTERN = re.compile(r"[^a-zA-Z0-9_]")


# ---------------------------------------------------------------------------
# FortiGate factory-default objects
# ---------------------------------------------------------------------------
# These objects ship on every FortiGate appliance regardless of customer
# configuration. They are not meaningful to migrate to the target firewall, so
# they are silently ignored during conversion instead of being reported as
# skipped/failed items that need attention. Names are matched case-insensitively.
DEFAULT_FORTIGATE_ADDRESS_OBJECTS = frozenset({
    "all",
    "none",
    "fabric_device",
    "firewall_auth_portal_address",
    "sslvpn_tunnel_addr1",
    "sslvpn_tunnel_ipv6_addr1",
    "ems_all_unmanageable_clients",
    "ems_all_unknown_clients",
})

DEFAULT_FORTIGATE_SERVICE_OBJECTS = frozenset({
    "all",
    "none",
    "all_icmp",
    "all_icmp6",
    "all_icmp_type",
    # Factory-default IP-protocol services (no ports - nothing to migrate).
    "gre",
    "ah",
    "esp",
    "ospf",
})


def is_default_fortigate_address(name: str) -> bool:
    """Return True if *name* is a FortiGate factory-default address object."""
    return name is not None and str(name).strip().lower() in DEFAULT_FORTIGATE_ADDRESS_OBJECTS


def is_default_fortigate_service(name: str) -> bool:
    """Return True if *name* is a FortiGate factory-default service object."""
    return name is not None and str(name).strip().lower() in DEFAULT_FORTIGATE_SERVICE_OBJECTS


# Conventional FortiGate names for the dedicated management and HA interfaces.
MGMT_HA_INTERFACE_NAMES = frozenset({
    "mgmt", "mgmt1", "mgmt2", "management", "ha", "ha1", "ha2",
})

# FortiGate factory-default virtual interfaces. These ship on every appliance
# and have no meaning on the target firewall: the SSL-VPN (ssl.<vdom>),
# L2TP (l2t.<vdom>), and NAF (naf.<vdom>) tunnels exist once per VDOM, plus
# the built-in modem interface.
DEFAULT_FORTIGATE_VIRTUAL_INTERFACES = frozenset({"modem"})
_DEFAULT_VIRTUAL_INTERFACE_PREFIXES = ("ssl.", "l2t.", "naf.")


def is_default_fortigate_interface(name: Any) -> bool:
    """Return True if *name* is a FortiGate factory-default virtual interface."""
    if name is None:
        return False
    nm = str(name).strip().lower()
    return (nm in DEFAULT_FORTIGATE_VIRTUAL_INTERFACES
            or nm.startswith(_DEFAULT_VIRTUAL_INTERFACE_PREFIXES))


def _interface_name_list(value: Any) -> List[str]:
    """Normalize a FortiGate interface-list value to a list of names.

    May be a list, a single string, or a space-separated string (e.g.
    'member' or HA 'hbdev').
    """
    if isinstance(value, str):
        return value.split()
    if isinstance(value, list):
        return [str(m) for m in value]
    return []


def collect_mgmt_ha_interfaces(fg_config: Dict[str, Any]) -> set:
    """Return the lowercase names of dedicated management and HA interfaces.

    These are infrastructure links on the FortiGate side (out-of-band
    management, HA heartbeat/session-sync) that have no meaning on the target
    firewall, so converters silently ignore them instead of reporting them as
    skipped/failed items. Detected from:
      - conventional interface names (mgmt, mgmt1, ha1, ...)
      - ``set dedicated-to management`` on the interface
      - ``config system ha`` fields (hbdev, ha-mgmt-interface, session-sync-dev)
    """
    special: set = set()

    for intf_dict in fg_config.get("system_interface", []) or []:
        if not isinstance(intf_dict, dict) or not intf_dict:
            continue
        name = next(iter(intf_dict))
        props = intf_dict[name]
        nm = str(name).strip().lower()
        if nm in MGMT_HA_INTERFACE_NAMES:
            special.add(nm)
            continue
        if not isinstance(props, dict):
            continue
        dedicated = str(
            props.get("dedicated-to", props.get("dedicated_to", "")),
        ).strip().lower()
        if dedicated == "management":
            special.add(nm)

    # HA heartbeat / HA-management ports from `config system ha`. The YAML
    # parser may emit this section as a plain dict, a list holding the
    # settings dict, or a list of single-key wrapper dicts, so check every
    # dict at both levels. hbdev can interleave interface names with numeric
    # priorities (e.g. "port10 50 port9 50"), so drop pure-number tokens.
    ha_cfg = fg_config.get("system_ha")
    ha_sections: List[Dict[str, Any]] = []
    if isinstance(ha_cfg, dict):
        ha_sections.append(ha_cfg)
    elif isinstance(ha_cfg, list):
        for entry in ha_cfg:
            if not isinstance(entry, dict):
                continue
            ha_sections.append(entry)
            ha_sections.extend(v for v in entry.values() if isinstance(v, dict))
    for section in ha_sections:
        for field in (
            "hbdev", "ha-mgmt-interface", "ha_mgmt_interface", "session-sync-dev",
        ):
            for tok in _interface_name_list(section.get(field, [])):
                t = tok.strip().lower()
                if t and not t.isdigit():
                    special.add(t)

    return special


def sanitize_name(name: str) -> str:
    """Return an FTD-safe name with only alphanumerics/underscores."""
    if name is None:
        return ""
    sanitized = _SANITIZE_PATTERN.sub("_", str(name))
    sanitized = re.sub(r"_+", "_", sanitized).strip("_")
    return sanitized


def first_item(entry: Any) -> Optional[Tuple[Any, Dict[str, Any]]]:
    """Return the (name, properties) pair of a single-key FortiGate YAML entry.

    FortiGate sections parse into lists of ``{NAME: {props}}`` dicts. Empty or
    malformed entries (None, ``{}``, non-dict properties) return None so
    callers can skip them instead of crashing on ``list(d.keys())[0]``.
    """
    if not isinstance(entry, dict) or not entry:
        return None
    name = next(iter(entry))
    props = entry[name]
    if not isinstance(props, dict):
        return None
    return name, props


def dedupe_name(base: str, used_names: Dict[str, int]) -> str:
    """Return a unique name for *base*, appending _2/_3... on collision.

    Generated names are registered in *used_names* too, so a later literal
    source name that matches a generated suffix (e.g. ``X_2``) is itself
    deduplicated instead of colliding.
    """
    if base not in used_names:
        used_names[base] = 1
        return base
    counter = used_names[base] + 1
    while f"{base}_{counter}" in used_names:
        counter += 1
    used_names[base] = counter
    final = f"{base}_{counter}"
    used_names[final] = 1
    return final


def netmask_to_cidr(netmask: str) -> int:
    """Convert a dotted-decimal netmask to a CIDR prefix length.

    Falls back to /32 (single host - the fail-closed choice) with a warning
    when the netmask is invalid.
    """
    try:
        octets = str(netmask).split('.')
        if len(octets) != 4:
            raise ValueError("expected 4 octets")
        binary_str = ''.join(bin(int(octet))[2:].zfill(8) for octet in octets)
        return binary_str.count('1')
    except (ValueError, AttributeError):
        print(f"  Warning: invalid netmask '{netmask}' - defaulting to /32")
        return 32


# ---------------------------------------------------------------------------
# Group-flattening helpers (used by address_group_converter & service_group_converter)
# ---------------------------------------------------------------------------

def build_group_lookup(group_entries: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Build a mapping of sanitized group name -> sanitized member names.

    Args:
        group_entries: List of single-key dicts as produced by the FortiGate
            YAML parser for ``firewall_addrgrp`` or ``firewall_service_group``.

    Returns:
        ``{group_name: [member1, member2, ...]}`` with all names sanitized.
    """
    lookup: Dict[str, List[str]] = {}
    for group_dict in group_entries or []:
        item = first_item(group_dict)
        if item is None:
            continue
        group_name, properties = item

        members_raw = properties.get("member", [])
        if isinstance(members_raw, str):
            members_list = [members_raw]
        elif isinstance(members_raw, list):
            members_list = members_raw
        else:
            members_list = []

        lookup[sanitize_name(group_name)] = [sanitize_name(m) for m in members_list]
    return lookup


def flatten_group_members(
    members: List[str],
    group_lookup: Dict[str, List[str]],
    visited: Optional[set] = None,
) -> List[str]:
    """Recursively flatten *members*, expanding any nested groups.

    Args:
        members: Member names (may include group names).
        group_lookup: Mapping returned by :func:`build_group_lookup`.
        visited: Group names on the CURRENT recursion path (circular-reference
            guard). Entries are removed on the way back up so diamond-shaped
            references (two siblings sharing a nested group) are not falsely
            flagged as circular.

    Returns:
        Deduplicated list of individual object names (order-preserving).
    """
    if visited is None:
        visited = set()

    flattened: List[str] = []

    for member in members:
        if member in group_lookup:
            if member in visited:
                print(f"    Warning: Circular reference detected for group '{member}', skipping")
                continue

            visited.add(member)

            nested_members = group_lookup.get(member, [])
            expanded = flatten_group_members(nested_members, group_lookup, visited)

            visited.discard(member)

            print(f"    Flattening nested group '{member}' -> {len(expanded)} objects")
            flattened.extend(expanded)
        else:
            flattened.append(member)

    # Remove duplicates while preserving order
    seen: set = set()
    unique: List[str] = []
    for item in flattened:
        if item not in seen:
            seen.add(item)
            unique.append(item)

    return unique
