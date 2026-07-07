#!/usr/bin/env python3
"""PAN-OS XML Configuration Parser
===================================
Parses a PAN-OS XML running configuration into Python dict structures
that the converter modules can consume.

Supported XML sources:
    - ``show config running`` piped to a file on the device
    - Exported running config from the PAN-OS web UI (Device > Setup > Operations)
    - PAN-OS XML API ``/api/?type=config&action=show`` response

The parser handles both device-level (NGFW) and Panorama-pushed configs.
"""

import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional


def parse_panos_xml(xml_file: str, vsys_name: Optional[str] = None) -> Dict[str, Any]:
    """Parse a PAN-OS XML configuration file.

    Args:
        xml_file: Path to the PAN-OS XML config file.
        vsys_name: Optional vsys name to parse. When given, the vsys must
            exist (a ``ValueError`` is raised otherwise). When omitted the
            parser prefers ``vsys1``, falling back to the first vsys found.

    Returns:
        Dict with keys: addresses, address_groups, services, service_groups,
        security_rules, zones, static_routes, interfaces, parse_skipped.
        ``parse_skipped`` lists entries dropped because of unsupported types
        (addresses, services, interfaces).
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Handle wrapped API response:
    #   <response><result><config>...</config></result></response>
    # or a bare <config> root element.
    config_root = root
    if root.tag != "config":
        config_node = root.find(".//config")
        if config_node is not None:
            config_root = config_node

    result: Dict[str, Any] = {
        "addresses": [],
        "address_groups": [],
        "services": [],
        "service_groups": [],
        "security_rules": [],
        "zones": [],
        "static_routes": [],
        "interfaces": [],
        "parse_skipped": {"addresses": [], "services": [], "interfaces": []},
    }
    skipped = result["parse_skipped"]

    # ------------------------------------------------------------------ #
    # Shared objects (Panorama-pushed) are parsed first; vsys-level        #
    # objects with the same name override them below.                      #
    # ------------------------------------------------------------------ #
    shared = config_root.find("shared")
    if shared is not None:
        result["addresses"] = _parse_addresses(shared, skipped["addresses"])
        result["address_groups"] = _parse_address_groups(shared)
        result["services"] = _parse_services(shared, skipped["services"])
        result["service_groups"] = _parse_service_groups(shared)

    # ------------------------------------------------------------------ #
    # vsys-level objects (addresses, services, zones, rules)              #
    # ------------------------------------------------------------------ #
    vsys = _find_vsys(config_root, vsys_name)
    if vsys is not None:
        result["addresses"] = _merge_by_name(
            result["addresses"], _parse_addresses(vsys, skipped["addresses"])
        )
        result["address_groups"] = _merge_by_name(
            result["address_groups"], _parse_address_groups(vsys)
        )
        result["services"] = _merge_by_name(
            result["services"], _parse_services(vsys, skipped["services"])
        )
        result["service_groups"] = _merge_by_name(
            result["service_groups"], _parse_service_groups(vsys)
        )
        result["security_rules"] = _parse_security_rules(vsys)
        result["zones"] = _parse_zones(vsys)

    # ------------------------------------------------------------------ #
    # Device / network-level objects (virtual-router routes, interfaces)  #
    # ------------------------------------------------------------------ #
    device_entry = _find_device(config_root)
    if device_entry is not None:
        result["static_routes"] = _parse_static_routes(device_entry)
        result["interfaces"] = _parse_interfaces(device_entry, skipped["interfaces"])

    return result


# ======================================================================== #
# Internal helpers                                                          #
# ======================================================================== #

def _find_vsys(
    root: ET.Element, vsys_name: Optional[str] = None
) -> Optional[ET.Element]:
    """Locate a vsys entry.

    When *vsys_name* is given, only that vsys is accepted and a
    ``ValueError`` is raised if it does not exist.  Otherwise the first
    vsys entry is used, preferring vsys1.
    """
    if vsys_name:
        for path in [
            f'./devices/entry/vsys/entry[@name="{vsys_name}"]',
            f'./vsys/entry[@name="{vsys_name}"]',
        ]:
            node = root.find(path)
            if node is not None:
                return node
        available = [
            e.get("name", "?")
            for e in root.findall("./devices/entry/vsys/entry")
            + root.findall("./vsys/entry")
        ]
        raise ValueError(
            f"vsys '{vsys_name}' not found in configuration "
            f"(available: {', '.join(available) if available else 'none'})"
        )
    for path in [
        './devices/entry/vsys/entry[@name="vsys1"]',
        "./devices/entry/vsys/entry",
        './vsys/entry[@name="vsys1"]',
        "./vsys/entry",
    ]:
        node = root.find(path)
        if node is not None:
            return node
    return None


def _merge_by_name(
    base_items: List[Dict[str, Any]], override_items: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Merge two object lists keyed by name; *override_items* win collisions."""
    merged: Dict[str, Dict[str, Any]] = {item["name"]: item for item in base_items}
    for item in override_items:
        merged[item["name"]] = item
    return list(merged.values())


def _find_device(root: ET.Element) -> Optional[ET.Element]:
    """Locate the device entry node."""
    for path in [
        './devices/entry[@name="localhost.localdomain"]',
        "./devices/entry",
    ]:
        node = root.find(path)
        if node is not None:
            return node
    return None


def _get_members(parent: ET.Element, tag: str = "member") -> List[str]:
    """Collect text from all child elements with the given tag."""
    return [m.text.strip() for m in parent.findall(tag) if m.text and m.text.strip()]


def _text(element: ET.Element, path: str, default: str = "") -> str:
    """Safely get stripped text from a child element found by path."""
    node = element.find(path)
    if node is not None and node.text:
        return node.text.strip()
    return default


# ------------------------------------------------------------------ #
# Address objects                                                      #
# ------------------------------------------------------------------ #

def _parse_addresses(
    vsys: ET.Element, skipped: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """Parse <address> entries.

    Names of entries with unsupported types are appended to *skipped*.
    """
    addresses: List[Dict[str, Any]] = []
    for entry in vsys.findall("./address/entry"):
        name = entry.get("name", "")
        if not name:
            continue

        description = _text(entry, "description")

        ip_netmask = entry.find("ip-netmask")
        ip_range = entry.find("ip-range")
        fqdn = entry.find("fqdn")

        if ip_netmask is not None and ip_netmask.text:
            addr_type = "ip-netmask"
            value = ip_netmask.text.strip()
        elif ip_range is not None and ip_range.text:
            addr_type = "ip-range"
            value = ip_range.text.strip()
        elif fqdn is not None and fqdn.text:
            addr_type = "fqdn"
            value = fqdn.text.strip()
        else:
            if skipped is not None:
                skipped.append(name)
            continue  # Unknown type - skip

        addresses.append({
            "name": name,
            "type": addr_type,
            "value": value,
            "description": description,
        })

    return addresses


# ------------------------------------------------------------------ #
# Address groups                                                       #
# ------------------------------------------------------------------ #

def _parse_address_groups(vsys: ET.Element) -> List[Dict[str, Any]]:
    """Parse <address-group> entries."""
    groups: List[Dict[str, Any]] = []
    for entry in vsys.findall("./address-group/entry"):
        name = entry.get("name", "")
        if not name:
            continue

        members: List[str] = []
        static = entry.find("static")
        if static is not None:
            members = _get_members(static)

        groups.append({
            "name": name,
            "members": members,
            "description": _text(entry, "description"),
            # Dynamic (tag-based) groups cannot be converted; flag them so
            # the converter can report them instead of silently skipping.
            "dynamic": entry.find("dynamic") is not None,
        })

    return groups


# ------------------------------------------------------------------ #
# Service objects                                                      #
# ------------------------------------------------------------------ #

def _parse_services(
    vsys: ET.Element, skipped: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """Parse <service> entries.

    Each PAN-OS service object contains exactly one protocol (tcp or udp).
    Names of entries with unsupported protocols are appended to *skipped*.
    """
    services: List[Dict[str, Any]] = []
    for entry in vsys.findall("./service/entry"):
        name = entry.get("name", "")
        if not name:
            continue

        description = _text(entry, "description")
        protocol_node = entry.find("protocol")
        if protocol_node is None:
            if skipped is not None:
                skipped.append(name)
            continue

        parsed = False
        for proto in ("tcp", "udp"):
            proto_node = protocol_node.find(proto)
            if proto_node is not None:
                port = _text(proto_node, "port")
                source_port = _text(proto_node, "source-port")
                services.append({
                    "name": name,
                    "protocol": proto,
                    "port": port,
                    "source_port": source_port,
                    "description": description,
                })
                parsed = True
                break  # Only one protocol per service entry in PAN-OS

        if not parsed and skipped is not None:
            skipped.append(name)

    return services


# ------------------------------------------------------------------ #
# Service groups                                                       #
# ------------------------------------------------------------------ #

def _parse_service_groups(vsys: ET.Element) -> List[Dict[str, Any]]:
    """Parse <service-group> entries."""
    groups: List[Dict[str, Any]] = []
    for entry in vsys.findall("./service-group/entry"):
        name = entry.get("name", "")
        if not name:
            continue

        members_node = entry.find("members")
        members = _get_members(members_node) if members_node is not None else []

        groups.append({
            "name": name,
            "members": members,
        })

    return groups


# ------------------------------------------------------------------ #
# Security rules                                                       #
# ------------------------------------------------------------------ #

def _parse_security_rules(vsys: ET.Element) -> List[Dict[str, Any]]:
    """Parse security rules from the rulebase."""
    rules: List[Dict[str, Any]] = []

    for entry in vsys.findall("./rulebase/security/rules/entry"):
        name = entry.get("name", "")
        if not name:
            continue

        def _zone_or_addr_members(tag: str) -> List[str]:
            node = entry.find(tag)
            if node is None:
                return ["any"]
            members = _get_members(node)
            return members if members else ["any"]

        action_text = _text(entry, "action", "deny")
        disabled_text = _text(entry, "disabled", "no").lower()
        disabled = disabled_text in ("yes", "true")
        log_end_text = _text(entry, "log-end", "yes").lower()
        log_end = log_end_text != "no"

        rules.append({
            "name": name,
            "from_zones": _zone_or_addr_members("from"),
            "to_zones": _zone_or_addr_members("to"),
            "sources": _zone_or_addr_members("source"),
            "destinations": _zone_or_addr_members("destination"),
            "services": _zone_or_addr_members("service"),
            "applications": _zone_or_addr_members("application"),
            "action": action_text,
            "description": _text(entry, "description"),
            "disabled": disabled,
            "log_end": log_end,
        })

    return rules


# ------------------------------------------------------------------ #
# Zones                                                                #
# ------------------------------------------------------------------ #

def _parse_zones(vsys: ET.Element) -> List[Dict[str, Any]]:
    """Parse <zone> entries."""
    zones: List[Dict[str, Any]] = []
    for entry in vsys.findall("./zone/entry"):
        name = entry.get("name", "")
        if not name:
            continue

        interfaces: List[str] = []
        for layer in ("layer3", "layer2", "virtual-wire", "tap", "tunnel"):
            layer_node = entry.find(f"network/{layer}")
            if layer_node is not None:
                interfaces.extend(_get_members(layer_node))

        zones.append({
            "name": name,
            "interfaces": interfaces,
        })

    return zones


# ------------------------------------------------------------------ #
# Static routes                                                        #
# ------------------------------------------------------------------ #

def _parse_static_routes(device: ET.Element) -> List[Dict[str, Any]]:
    """Parse static routes from all virtual routers."""
    routes: List[Dict[str, Any]] = []
    for vr_entry in device.findall("./network/virtual-router/entry"):
        vr_name = vr_entry.get("name", "default")
        for route_entry in vr_entry.findall(
            "./routing-table/ip/static-route/entry"
        ):
            name = route_entry.get("name", "")
            destination = _text(route_entry, "destination")

            nexthop: Optional[str] = None
            nexthop_ip = route_entry.find("nexthop/ip-address")
            if nexthop_ip is not None and nexthop_ip.text:
                nexthop = nexthop_ip.text.strip()

            interface = _text(route_entry, "interface")
            comment = _text(route_entry, "comment")

            metric = 10
            metric_text = _text(route_entry, "metric")
            if metric_text:
                try:
                    metric = int(metric_text)
                except ValueError:
                    pass

            routes.append({
                "name": name,
                "destination": destination,
                "nexthop": nexthop,
                "interface": interface,
                "metric": metric,
                "description": comment,
                "virtual_router": vr_name,
            })

    return routes


# ------------------------------------------------------------------ #
# Interfaces                                                           #
# ------------------------------------------------------------------ #

def _parse_interfaces(
    device: ET.Element, skipped: Optional[List[str]] = None
) -> List[Dict[str, Any]]:
    """Parse ethernet, sub-interface, and loopback interfaces.

    Aggregate-ethernet, vlan, and tunnel interfaces are not converted;
    their names are appended to *skipped* so they can be reported.
    """
    interfaces: List[Dict[str, Any]] = []

    # Ethernet (physical) interfaces
    for eth_entry in device.findall("./network/interface/ethernet/entry"):
        intf_name = eth_entry.get("name", "")
        if not intf_name:
            continue

        info = _extract_layer3_info(eth_entry)
        info["name"] = intf_name
        info["type"] = "physical"
        interfaces.append(info)

        # Sub-interfaces (units)
        for sub_entry in eth_entry.findall("./layer3/units/entry"):
            sub_name = sub_entry.get("name", "")
            if not sub_name:
                continue
            sub = _extract_layer3_info(sub_entry)
            sub["name"] = sub_name
            sub["type"] = "vlan"
            sub["parent"] = intf_name
            tag_text = _text(sub_entry, "tag")
            if tag_text:
                sub["vlan"] = tag_text
            interfaces.append(sub)

    # Loopback interfaces
    for lo_entry in device.findall("./network/interface/loopback/units/entry"):
        lo_name = lo_entry.get("name", "")
        if not lo_name:
            continue
        lo = _extract_layer3_info(lo_entry)
        lo["name"] = lo_name
        lo["type"] = "loopback"
        interfaces.append(lo)

    # Unsupported interface types - report instead of silently dropping
    if skipped is not None:
        for kind, path in (
            ("aggregate-ethernet", "./network/interface/aggregate-ethernet/entry"),
            ("vlan", "./network/interface/vlan/units/entry"),
            ("tunnel", "./network/interface/tunnel/units/entry"),
        ):
            for entry in device.findall(path):
                entry_name = entry.get("name", "")
                if entry_name:
                    skipped.append(f"{entry_name} ({kind})")

    return interfaces


def _extract_layer3_info(entry: ET.Element) -> Dict[str, Any]:
    """Extract IP addresses and description from an interface entry.

    The first IP becomes the primary; any additional IPs are returned in
    ``secondary_ips``.
    """
    result: Dict[str, Any] = {"ip": "", "description": "", "secondary_ips": []}

    comment = entry.find("comment")
    if comment is not None and comment.text:
        result["description"] = comment.text.strip()

    # Layer3 IPs - try common paths; capture primary and secondaries
    for ip_path in ("./layer3/ip/entry", "./ip/entry"):
        ip_names = [e.get("name", "") for e in entry.findall(ip_path) if e.get("name")]
        if ip_names:
            result["ip"] = ip_names[0]
            result["secondary_ips"] = ip_names[1:]
            break

    return result
