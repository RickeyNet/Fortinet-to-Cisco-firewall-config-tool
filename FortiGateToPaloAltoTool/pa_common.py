#!/usr/bin/env python3
"""Shared utilities for Palo Alto converter modules.

PAN-OS naming rules differ from FTD:
- Max 63 characters
- Allowed: alphanumeric, underscore, hyphen, period
- First character must be alphanumeric or underscore
- Case-sensitive
"""

import re
from typing import Any, Dict, List

# PAN-OS allows alphanumeric, underscore, hyphen, and period
_PA_SANITIZE_PATTERN = re.compile(r"[^a-zA-Z0-9_.\-]")

# Max object name length in PAN-OS
PA_NAME_MAX_LENGTH = 63


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
    """Return a PAN-OS-safe object name.

    Replaces disallowed characters with underscores, collapses runs of
    underscores, ensures the first character is valid, and truncates to
    63 characters.
    """
    if name is None:
        return ""
    sanitized = _PA_SANITIZE_PATTERN.sub("_", str(name))
    # Collapse consecutive underscores
    sanitized = re.sub(r"_+", "_", sanitized).strip("_")
    # First character must be alphanumeric or underscore
    if sanitized and not (sanitized[0].isalnum() or sanitized[0] == "_"):
        sanitized = "_" + sanitized
    # Truncate to max length
    if len(sanitized) > PA_NAME_MAX_LENGTH:
        sanitized = sanitized[:PA_NAME_MAX_LENGTH]
    return sanitized


def netmask_to_cidr(netmask: str) -> int:
    """Convert a dotted-decimal netmask to CIDR prefix length.

    Example: '255.255.255.0' -> 24
    """
    try:
        parts = netmask.split(".")
        binary = "".join(f"{int(p):08b}" for p in parts)
        return binary.count("1")
    except (ValueError, AttributeError):
        return 32


def build_group_lookup(
    group_entries: List[Dict[str, Any]],
) -> Dict[str, List[str]]:
    """Build a mapping of sanitized group name -> sanitized member names.

    Args:
        group_entries: List of single-key dicts from the FortiGate
            YAML parser (``firewall_addrgrp`` or ``firewall_service_group``).

    Returns:
        ``{group_name: [member1, member2, ...]}`` with all names sanitized.
    """
    lookup: Dict[str, List[str]] = {}
    for group_dict in group_entries:
        group_name = list(group_dict.keys())[0]
        properties = group_dict[group_name]

        members_raw = properties.get("member", [])
        if isinstance(members_raw, str):
            members_list = [members_raw]
        elif isinstance(members_raw, list):
            members_list = members_raw
        else:
            members_list = []

        lookup[sanitize_name(group_name)] = [
            sanitize_name(m) for m in members_list
        ]
    return lookup
