#!/usr/bin/env python3
"""Shared utilities for Palo Alto → FortiGate converter modules.

FortiGate CLI naming rules:
- Object names are enclosed in double-quotes in CLI commands
- Double-quotes and backslashes within names must be avoided
- Maximum name length is ~64 characters for most object types
- FortiGate uses the built-in address object "all" where PAN-OS uses "any"
"""

import re
from typing import Dict, List, Tuple, Union

# Max name length for FortiGate objects
FG_NAME_MAX_LENGTH = 64

# Some object types enforce shorter limits than the generic 64 characters
FG_POLICY_NAME_MAX_LENGTH = 35
FG_INTERFACE_NAME_MAX_LENGTH = 15

# PAN-OS "any" translates to FortiGate's built-in "all" address object
PA_ANY_TO_FG_ALL = "all"


def cidr_to_netmask(prefix_len: Union[int, str]) -> str:
    """Convert a CIDR prefix length to a dotted-decimal netmask.

    Example: 24 -> '255.255.255.0'
    """
    try:
        prefix_len = int(prefix_len)
        if prefix_len < 0 or prefix_len > 32:
            print(
                f"  Warning: invalid CIDR prefix length '{prefix_len}' "
                f"- defaulting to /32 (255.255.255.255)"
            )
            return "255.255.255.255"
        if prefix_len == 0:
            return "0.0.0.0"
        bits = 0xFFFFFFFF ^ ((1 << (32 - prefix_len)) - 1)
        return ".".join([str((bits >> (8 * i)) & 0xFF) for i in [3, 2, 1, 0]])
    except (ValueError, TypeError):
        print(
            f"  Warning: invalid CIDR prefix length '{prefix_len}' "
            f"- defaulting to /32 (255.255.255.255)"
        )
        return "255.255.255.255"


def split_cidr(cidr: str) -> Tuple[str, str]:
    """Split CIDR notation into an (ip, netmask) pair.

    Examples:
        '10.0.0.0/24' -> ('10.0.0.0', '255.255.255.0')
        '10.0.0.1/32' -> ('10.0.0.1', '255.255.255.255')
        '10.0.0.1'    -> ('10.0.0.1', '255.255.255.255')
    """
    cidr = str(cidr).strip()
    if "/" in cidr:
        ip, prefix = cidr.split("/", 1)
        return ip.strip(), cidr_to_netmask(prefix.strip())
    return cidr, "255.255.255.255"


def sanitize_fg_name(name: str) -> str:
    """Return a FortiGate-safe object name.

    Strips surrounding whitespace, replaces characters that cause issues
    in FortiGate CLI (double-quotes, backslashes, control characters) with
    underscores, and truncates to the maximum allowed length.
    """
    if not name:
        return ""
    sanitized = re.sub(r'["\\\x00-\x1f\x7f]', "_", str(name).strip())
    return sanitized[:FG_NAME_MAX_LENGTH]


def fg_members_str(members: List[str]) -> str:
    """Format a list of member names as a FortiGate CLI member string.

    Example: ['web1', 'web2'] -> '"web1" "web2"'
    """
    return " ".join(f'"{m}"' for m in members if m)


def map_any_address(name: str) -> str:
    """Map PAN-OS 'any' address to FortiGate's 'all' built-in object."""
    if str(name).strip().lower() == "any":
        return PA_ANY_TO_FG_ALL
    return name


def escape_fg_string(value: str) -> str:
    """Escape a value for safe use inside double quotes in FortiGate CLI.

    Backslashes and double-quotes are escaped with a backslash so an
    embedded quote or a trailing backslash cannot break the CLI quoting.
    """
    if not value:
        return ""
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def dedup_fg_name(
    name: str,
    used_names: Dict[str, int],
    max_length: int = FG_NAME_MAX_LENGTH,
) -> str:
    """Return a unique FortiGate name, tracking usage in *used_names*.

    On collision a ``_N`` suffix is appended; the base name is trimmed so
    the suffixed name still fits within *max_length* and remains unique.
    """
    name = str(name)[:max_length]
    if name not in used_names:
        used_names[name] = 1
        return name
    counter = used_names[name]
    while True:
        counter += 1
        suffix = f"_{counter}"
        candidate = name[: max_length - len(suffix)] + suffix
        if candidate not in used_names:
            used_names[name] = counter
            used_names[candidate] = 1
            return candidate


def topo_sort_groups(groups: List[Dict]) -> List[Dict]:
    """Order group dicts so members appear before groups that reference them.

    FortiGate rejects forward references between nested groups, so groups
    must be emitted after every group they reference.  Each dict needs a
    ``name`` and a ``members`` list.  Cycles are broken with a printed
    warning (the back-reference is dropped from the ordering, not from the
    group's member list).
    """
    by_name = {g.get("name"): g for g in groups if g.get("name")}
    ordered: List[Dict] = []
    visited: set = set()
    in_stack: set = set()

    def _visit(group: Dict) -> None:
        name = group.get("name")
        if name in visited:
            return
        if name in in_stack:
            print(
                f"  Warning: cyclic group reference involving '{name}' "
                f"- breaking cycle"
            )
            return
        in_stack.add(name)
        for member in group.get("members", []) or []:
            child = by_name.get(member)
            if child is not None:
                _visit(child)
        in_stack.discard(name)
        visited.add(name)
        ordered.append(group)

    for group in groups:
        if group.get("name"):
            _visit(group)
    return ordered
