#!/usr/bin/env python3
"""
Cisco ASA to Palo Alto PAN-OS Configuration Converter
=======================================================
Converts a Cisco ASA running-config text file to PAN-OS JSON files that
are compatible with the existing panos_api_importer.

OUTPUT FILES (same schema as the FortiGate->PAN-OS converter):
    {basename}_interfaces.json
    {basename}_address_objects.json
    {basename}_address_groups.json
    {basename}_service_objects.json
    {basename}_service_groups.json
    {basename}_security_rules.json
    {basename}_static_routes.json
    {basename}_zones.json
    {basename}_nat_rules.json        (ASA NAT - for manual review)
    {basename}_metadata.json
    {basename}_summary.json

HOW TO RUN:
    python asa_converter.py Cisco_ASA_config.txt
    python asa_converter.py Cisco_ASA_config.txt -o pa_config --pretty
    python asa_converter.py Cisco_ASA_config.txt --target-model pa-440
"""

import argparse
import json
import sys
import os
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure sibling packages are importable
_SELF_DIR = os.path.dirname(os.path.abspath(__file__))
_PA_DIR = os.path.join(os.path.dirname(_SELF_DIR), "FortiGateToPaloAltoTool")
for _d in (_SELF_DIR, _PA_DIR):
    if os.path.isdir(_d) and _d not in sys.path:
        sys.path.insert(0, _d)

from asa_parser import ASAParser  # noqa: E402
from pa_common import sanitize_name, netmask_to_cidr  # noqa: E402
from pa_interface_converter import PA_MODELS, print_supported_models  # noqa: E402


# ═══════════════════════════════════════════════════════════════════════════
# Helper utilities
# ═══════════════════════════════════════════════════════════════════════════

def write_json_file(path: str, data: object, pretty: bool = False) -> None:
    """Write JSON data to a file."""
    with open(path, "w", encoding="utf-8") as f:
        if pretty:
            json.dump(data, f, indent=2)
        else:
            json.dump(data, f, separators=(",", ":"))


# ═══════════════════════════════════════════════════════════════════════════
# Conversion functions - each mirrors the PAN-OS JSON output schema
# ═══════════════════════════════════════════════════════════════════════════

def convert_interfaces(
    parsed: Dict[str, Any], target_model: str
) -> Tuple[List[Dict], List[Dict], Dict[str, str], Dict[str, str]]:
    """Convert ASA interfaces to PAN-OS interface + zone format.

    Returns:
        (pa_interfaces, pa_zones, interface_name_mapping, zone_mapping)

    interface_name_mapping: ASA nameif -> PAN-OS ethernet name
    zone_mapping:           ASA nameif -> PAN-OS zone name
    """
    model_info = PA_MODELS.get(target_model, PA_MODELS["pa-440"])
    total_ports = model_info["total_ports"]

    pa_interfaces: List[Dict] = []
    zone_to_members: Dict[str, List[str]] = {}
    intf_map: Dict[str, str] = {}   # nameif -> ethernet name
    zone_map: Dict[str, str] = {}   # nameif -> zone name

    port_index = 1

    for intf in parsed["interfaces"]:
        nameif = intf.get("nameif", "")
        if not nameif:
            continue

        # Skip management-only interfaces from data plane assignment
        if intf.get("management_only"):
            print(f"    Skipped data-plane mapping: {intf['hw_id']} "
                  f"(management-only)")
            # Still create a zone for management (an interface-less zone is
            # valid in PAN-OS) so rules bound to it import cleanly
            zone_name = sanitize_name(nameif)
            zone_map[nameif] = zone_name
            zone_to_members.setdefault(zone_name, [])
            continue

        if port_index > total_ports:
            print(f"    WARNING: No more ports on {target_model} for "
                  f"{intf['hw_id']} ({nameif})")
            continue

        pa_name = f"ethernet1/{port_index}"
        port_index += 1

        # Build IP in CIDR format
        ip_cidr = ""
        if intf["ip_address"] and intf["netmask"]:
            cidr = netmask_to_cidr(intf["netmask"])
            ip_cidr = f"{intf['ip_address']}/{cidr}"

        # Preserve the ASA security-level in the comment for reference
        comment = intf.get("description", "")
        sec_note = f"ASA security-level {intf.get('security_level', 0)}"
        comment = f"{comment} [{sec_note}]" if comment else sec_note

        pa_intf: Dict[str, Any] = {
            "name": pa_name,
            "type": "physical",
            "ip_address": ip_cidr,
            "comment": comment,
            "enabled": not intf.get("shutdown", False),
            "link_speed": "auto",
        }
        pa_interfaces.append(pa_intf)

        # Map ASA nameif to PAN-OS interface and zone
        zone_name = sanitize_name(nameif)
        intf_map[nameif] = pa_name
        zone_map[nameif] = zone_name

        zone_to_members.setdefault(zone_name, []).append(pa_name)

        print(f"  Mapped: {intf['hw_id']} ({nameif}) -> {pa_name} "
              f"[zone: {zone_name}] {ip_cidr}")

    # Build zone list
    pa_zones = [
        {"name": z, "interfaces": members}
        for z, members in sorted(zone_to_members.items())
    ]

    return pa_interfaces, pa_zones, intf_map, zone_map


def convert_address_objects(
    parsed: Dict[str, Any],
) -> Tuple[List[Dict], Dict[str, str], Set[str]]:
    """Convert ASA network objects to PAN-OS address objects.

    Returns (pa_address_objects, name_map, used_names) where name_map maps
    the original ASA object name to the emitted PAN-OS name, so renames
    from sanitizing/deduping propagate to every reference. Skipped objects
    have no name_map entry.
    """
    results: List[Dict] = []
    used_names: Set[str] = set()
    name_map: Dict[str, str] = {}

    for obj_name, obj in parsed["network_objects"].items():
        sanitized = sanitize_name(obj_name)
        sanitized = _dedup_name(sanitized, used_names)

        obj_type = obj.get("type", "")
        description = obj.get("description", "")

        if obj_type == "host":
            pa_obj = {
                "name": sanitized,
                "type": "ip-netmask",
                "value": f"{obj['value']}/32",
                "description": description,
            }
        elif obj_type == "subnet":
            cidr = netmask_to_cidr(obj.get("netmask", "255.255.255.255"))
            pa_obj = {
                "name": sanitized,
                "type": "ip-netmask",
                "value": f"{obj['value']}/{cidr}",
                "description": description,
            }
        elif obj_type == "range":
            pa_obj = {
                "name": sanitized,
                "type": "ip-range",
                "value": f"{obj['value']}-{obj.get('end_value', '')}",
                "description": description,
            }
        elif obj_type == "fqdn":
            pa_obj = {
                "name": sanitized,
                "type": "fqdn",
                "value": obj.get("fqdn", ""),
                "description": description,
            }
        else:
            print(f"  Skipped: {obj_name} (unknown type '{obj_type}')")
            continue

        results.append(pa_obj)
        name_map[obj_name] = sanitized
        print(f"  Converted: {obj_name} -> {sanitized} [{pa_obj['type']}] "
              f"({pa_obj['value']})")

    return results, name_map, used_names


def append_inline_address_objects(
    results: List[Dict],
    inline_hosts: Dict[str, str],
    used_names: Set[str],
) -> None:
    """Append ad-hoc address objects created from inline ACL/group refs.

    inline_hosts values are either bare IPs (host refs) or CIDR strings
    (subnet refs) - only bare IPs get a /32 suffix.
    """
    for host_name, ip in inline_hosts.items():
        if host_name in used_names:
            continue
        used_names.add(host_name)
        value = ip if "/" in ip else f"{ip}/32"
        results.append({
            "name": host_name,
            "type": "ip-netmask",
            "value": value,
            "description": "Auto-created from inline reference",
        })
        print(f"  Auto-created: {host_name} -> {value}")


def convert_address_groups(
    parsed: Dict[str, Any],
    inline_hosts: Dict[str, str],
    addr_map: Dict[str, str],
    used_names: Set[str],
    warnings: List[str],
) -> List[Dict]:
    """Convert ASA network object-groups to PAN-OS address groups.

    addr_map (ASA name -> emitted PAN-OS name) is shared with the address
    object converter so renames propagate; groups register themselves too.
    """
    results: List[Dict] = []

    for grp_name, grp in parsed["network_object_groups"].items():
        sanitized = sanitize_name(grp_name)
        sanitized = _dedup_name(sanitized, used_names)

        members: List[str] = []

        for member in grp.get("members", []):
            mtype = member.get("type", "")
            if mtype in ("object", "group"):
                ref = member["name"]
                mapped = addr_map.get(ref)
                if mapped is None:
                    warnings.append(
                        f"Address group '{grp_name}': member '{ref}' was "
                        f"not converted - member dropped, review manually"
                    )
                    print(f"  WARNING: {grp_name}: unresolved member "
                          f"'{ref}' dropped")
                    continue
                members.append(mapped)
            elif mtype == "host":
                # Create an ad-hoc host object
                host_name = f"host_{member['value'].replace('.', '_')}"
                host_name = sanitize_name(host_name)
                inline_hosts[host_name] = member["value"]
                members.append(host_name)
            elif mtype == "subnet":
                ip = member.get("value", "")
                mask = member.get("netmask", "")
                cidr = netmask_to_cidr(mask)
                subnet_name = sanitize_name(
                    f"net_{ip.replace('.', '_')}_{cidr}"
                )
                inline_hosts[subnet_name] = f"{ip}/{cidr}"
                members.append(subnet_name)

        if not members:
            print(f"  Skipped: {grp_name} (no members)")
            continue

        results.append({
            "name": sanitized,
            "members": members,
            "description": "",
        })
        addr_map[grp_name] = sanitized
        print(f"  Converted: {grp_name} -> {sanitized} "
              f"({len(members)} members)")

    return results


def _split_protocol(protocol: str) -> List[str]:
    """Expand ASA 'tcp-udp' into the two valid PAN-OS protocols."""
    if protocol == "tcp-udp":
        return ["tcp", "udp"]
    return [protocol]


def convert_service_objects(
    parsed: Dict[str, Any],
    warnings: List[str],
) -> Tuple[List[Dict], Dict[str, List[str]], Set[str]]:
    """Convert ASA service objects to PAN-OS service objects.

    Returns (pa_service_objects, svc_map, used_names) where svc_map maps the
    original ASA name to the list of emitted PAN-OS service names (tcp-udp
    objects expand to one tcp + one udp service). Skipped services have no
    svc_map entry, so references to them fail closed instead of dangling.
    """
    results: List[Dict] = []
    used_names: Set[str] = set()
    svc_map: Dict[str, List[str]] = {}

    for svc_name, svc in parsed["service_objects"].items():
        protocol = svc.get("protocol", "")
        dst_port = svc.get("dst_port", "")

        if not protocol or protocol.split("-")[0] not in ("tcp", "udp"):
            print(f"  Skipped: {svc_name} (protocol '{protocol}' - "
                  f"no PAN-OS service equivalent)")
            warnings.append(
                f"Service object '{svc_name}' (protocol '{protocol}') has "
                f"no PAN-OS service equivalent - review manually"
            )
            continue

        if not dst_port:
            if svc.get("src_port"):
                # Source-port-only services cannot be expressed by the
                # importer (no <source-port> support) - fail closed.
                print(f"  Skipped: {svc_name} (source-port-only service "
                      f"cannot be expressed)")
                warnings.append(
                    f"Service object '{svc_name}': source-port restriction "
                    f"cannot be migrated - review manually"
                )
            else:
                print(f"  Skipped: {svc_name} (no destination port)")
            continue

        port_value = dst_port
        if svc.get("dst_port_end"):
            port_value = f"{dst_port}-{svc['dst_port_end']}"

        if svc.get("src_port"):
            warnings.append(
                f"Service object '{svc_name}': source-port "
                f"{svc['src_port']} not migrated (destination port kept)"
            )

        base = sanitize_name(svc_name)
        protocols = _split_protocol(protocol)
        emitted: List[str] = []
        for proto in protocols:
            name = base if len(protocols) == 1 else \
                sanitize_name(f"{base}_{proto}")
            name = _dedup_name(name, used_names)
            results.append({
                "name": name,
                "protocol": proto,
                "port": port_value,
            })
            emitted.append(name)
            print(f"  Converted: {svc_name} -> {name} "
                  f"[{proto.upper()}] (port {port_value})")
        svc_map[svc_name] = emitted

    return results, svc_map, used_names


def append_inline_service_objects(
    results: List[Dict],
    inline_services: Dict[str, Dict],
    used_names: Set[str],
) -> None:
    """Append ad-hoc service objects created from inline ACL port specs."""
    for svc_name, svc_info in inline_services.items():
        if svc_name in used_names:
            continue
        used_names.add(svc_name)
        results.append({
            "name": svc_name,
            "protocol": svc_info["protocol"],
            "port": svc_info["port"],
        })
        print(f"  Auto-created: {svc_name} [{svc_info['protocol'].upper()}] "
              f"(port {svc_info['port']})")


def convert_service_groups(
    parsed: Dict[str, Any],
    inline_services: Dict[str, Dict],
    svc_map: Dict[str, List[str]],
    used_names: Set[str],
    warnings: List[str],
) -> List[Dict]:
    """Convert ASA service object-groups to PAN-OS service groups.

    For port-based groups (object-group service <name> tcp), each member
    port becomes an individual PAN-OS service object, and the group
    references them. 'tcp-udp' members split into a tcp and a udp service
    (PAN-OS has no tcp-udp protocol). Members that reference skipped
    services or unsupported group types are dropped with a warning instead
    of emitting dangling references. Groups register themselves in svc_map.
    """
    results: List[Dict] = []

    def _add_inline(proto: str, port_val: str) -> None:
        for p in _split_protocol(proto):
            svc_obj_name = sanitize_name(f"{p}_{port_val}")
            if svc_obj_name not in inline_services:
                inline_services[svc_obj_name] = {
                    "protocol": p,
                    "port": port_val,
                }
            member_names.append(svc_obj_name)

    for grp_name, grp in parsed["service_object_groups"].items():
        sanitized = sanitize_name(grp_name)
        sanitized = _dedup_name(sanitized, used_names)
        protocol = grp.get("protocol") or "tcp"
        port_members = grp.get("members", [])
        svc_refs = grp.get("service_refs", [])

        member_names: List[str] = []

        # Create service objects for each port in the group
        for port_val in port_members:
            _add_inline(protocol, port_val)

        # Handle service-object and group-object references
        for ref in svc_refs:
            if ref["type"] in ("object", "group"):
                ref_name = ref["name"]
                mapped = svc_map.get(ref_name)
                if mapped is None:
                    reason = "was not converted"
                    if ref_name in parsed.get("icmp_type_groups", {}):
                        reason = "is an icmp-type group (unsupported)"
                    elif ref_name in parsed.get("protocol_groups", {}):
                        reason = "is a protocol group (unsupported)"
                    warnings.append(
                        f"Service group '{grp_name}': member '{ref_name}' "
                        f"{reason} - member dropped, review manually"
                    )
                    print(f"  WARNING: {grp_name}: unresolved member "
                          f"'{ref_name}' dropped")
                    continue
                member_names.extend(mapped)
            elif ref["type"] == "inline":
                _add_inline(ref.get("protocol", "tcp"), ref.get("port", ""))
            elif ref["type"] == "protocol":
                # e.g. 'service-object icmp' - no PAN-OS service equivalent
                warnings.append(
                    f"Service group '{grp_name}': protocol-only member "
                    f"'{ref.get('protocol', '')}' dropped - review manually"
                )
                print(f"  WARNING: {grp_name}: protocol-only member "
                      f"'{ref.get('protocol', '')}' dropped")

        if not member_names:
            print(f"  Skipped: {grp_name} (no resolvable members)")
            continue

        results.append({
            "name": sanitized,
            "members": member_names,
        })
        svc_map[grp_name] = [sanitized]
        print(f"  Converted: {grp_name} -> {sanitized} "
              f"({len(member_names)} members)")

    return results


def convert_static_routes(
    parsed: Dict[str, Any],
    intf_map: Dict[str, str],
) -> List[Dict]:
    """Convert ASA static routes to PAN-OS static routes."""
    results: List[Dict] = []
    used_names: Set[str] = set()

    for route in parsed["routes"]:
        dest = route["destination"]
        mask = route["netmask"]
        cidr = netmask_to_cidr(mask)
        dest_cidr = f"{dest}/{cidr}"
        gateway = route["gateway"]
        metric = route.get("metric", 1)

        # Build a descriptive route name
        if dest == "0.0.0.0" and cidr == 0:
            base_name = "default_route"
        else:
            base_name = f"route_{dest.replace('.', '_')}_{cidr}"
        route_name = sanitize_name(base_name)
        route_name = _dedup_name(route_name, used_names)

        # Map ASA interface nameif to PAN-OS interface
        asa_intf = route["interface"]
        pa_intf = intf_map.get(asa_intf, "")

        pa_route: Dict[str, Any] = {
            "name": route_name,
            "destination": dest_cidr,
        }
        if gateway and gateway != "0.0.0.0":
            pa_route["nexthop"] = gateway
        if pa_intf:
            pa_route["interface"] = pa_intf
        pa_route["metric"] = metric

        results.append(pa_route)
        gw_display = gateway if gateway else "connected"
        intf_display = pa_intf if pa_intf else asa_intf
        print(f"  Converted: {route_name} -> {dest_cidr} via {gw_display} "
              f"{intf_display} (metric {metric})")

    return results


def _acl_zone_contexts(
    bindings: List[Dict[str, str]],
    zone_map: Dict[str, str],
) -> List[Tuple[List[str], List[str], str, str]]:
    """Build (from_zones, to_zones, name_suffix, note) contexts for an ACL.

    'in' bindings match traffic entering the interface (from = zone),
    'out' bindings match traffic leaving it (to = zone, zones swapped),
    'global' applies everywhere (from/to any).
    """
    in_zones: List[str] = []
    out_zones: List[str] = []
    has_global = False
    for b in bindings:
        zone = zone_map.get(b.get("interface", ""),
                            sanitize_name(b.get("interface", "")))
        direction = b.get("direction", "in")
        if direction == "global":
            has_global = True
        elif direction == "out":
            out_zones.append(zone)
        else:
            in_zones.append(zone)

    contexts: List[Tuple[List[str], List[str], str, str]] = []
    if in_zones:
        contexts.append((in_zones, ["any"], "", ""))
    if out_zones:
        contexts.append((["any"], out_zones, "_out",
                         "ASA 'out' binding: matched on egress zone"))
    if has_global:
        contexts.append((["any"], ["any"], "_global",
                         "ASA global access-group binding"))
    if not contexts:
        contexts.append((["any"], ["any"], "", ""))
    return contexts


def convert_security_rules(
    parsed: Dict[str, Any],
    zone_map: Dict[str, str],
    inline_hosts: Dict[str, str],
    inline_services: Dict[str, Dict],
    addr_map: Dict[str, str],
    svc_map: Dict[str, List[str]],
    warnings: List[str],
) -> List[Dict]:
    """Convert ASA access-lists to PAN-OS security rules.

    Uses access-group bindings to determine the from/to zones for each ACL.
    Fail-closed policy: an ACE whose service/protocol restriction cannot be
    expressed in PAN-OS is emitted with disabled=yes and a description note
    instead of silently becoming a service=any/application=any rule.
    """
    results: List[Dict] = []
    used_names: Set[str] = set()
    access_groups = parsed.get("access_groups", {})

    for acl_name, aces in parsed.get("access_lists", {}).items():
        contexts = _acl_zone_contexts(
            access_groups.get(acl_name, []), zone_map
        )

        for idx, ace in enumerate(aces, start=1):
            action = ace.get("action", "deny")
            pa_action = "allow" if action == "permit" else "deny"

            # Source / destination
            sources = _resolve_ace_address(
                ace.get("source", {}), inline_hosts, addr_map, warnings
            ) or ["any"]
            destinations = _resolve_ace_address(
                ace.get("destination", {}), inline_hosts, addr_map, warnings
            ) or ["any"]

            # Service / application (may force the rule disabled)
            services, applications, notes, disabled_reason = (
                _resolve_ace_service(ace, parsed, inline_services, svc_map)
            )
            for note in notes:
                warnings.append(f"ACL {acl_name} entry {idx}: {note}")

            disabled = "no"
            if ace.get("inactive"):
                # ASA 'inactive' ACEs stay disabled on PAN-OS
                disabled = "yes"
                notes = notes + ["ASA inactive ACE"]
            if disabled_reason:
                disabled = "yes"
                notes = notes + [f"DISABLED for review: {disabled_reason}"]
                warnings.append(
                    f"ACL {acl_name} entry {idx}: {disabled_reason} - "
                    f"rule emitted disabled"
                )
            if ace.get("time_range"):
                notes = notes + [
                    f"ASA time-range '{ace['time_range']}' not migrated"
                ]
                warnings.append(
                    f"ACL {acl_name} entry {idx}: time-range "
                    f"'{ace['time_range']}' not migrated - review schedule"
                )

            description = " ".join(
                [f"ASA ACL: {acl_name}"] + [f"({n})" for n in notes]
            )

            # ASA logs permits only when 'log' is set; denies are logged
            # by default (syslog 106023)
            log_end = "yes" if (ace.get("log") or pa_action == "deny") \
                else "no"

            for from_zones, to_zones, suffix, ctx_note in contexts:
                base_name = f"{sanitize_name(acl_name)}_rule_{idx}{suffix}"
                rule_name = _dedup_name(base_name, used_names)
                rule_desc = (f"{description} ({ctx_note})" if ctx_note
                             else description)

                rule: Dict[str, Any] = {
                    "name": rule_name,
                    "from_zones": from_zones,
                    "to_zones": to_zones,
                    "sources": sources,
                    "destinations": destinations,
                    "services": services,
                    "application": applications,
                    "action": pa_action,
                    "log_end": log_end,
                    "description": rule_desc,
                    "disabled": disabled,
                }
                results.append(rule)
                print(f"  Converted: {rule_name} [{pa_action.upper()}] "
                      f"({', '.join(from_zones)} -> {', '.join(to_zones)})"
                      + (" [DISABLED]" if disabled == "yes" else ""))

    return results


# ═══════════════════════════════════════════════════════════════════════════
# ACE resolution helpers
# ═══════════════════════════════════════════════════════════════════════════

def _resolve_ace_address(
    addr_spec: Dict[str, str],
    inline_hosts: Dict[str, str],
    addr_map: Dict[str, str],
    warnings: List[str],
) -> List[str]:
    """Resolve an ACE address specifier to PAN-OS address reference(s)."""
    addr_type = addr_spec.get("type", "any")

    if addr_type == "any":
        return ["any"]
    elif addr_type == "host":
        ip = addr_spec.get("value", "")
        host_name = sanitize_name(f"host_{ip.replace('.', '_')}")
        inline_hosts[host_name] = ip
        return [host_name]
    elif addr_type in ("object", "object-group"):
        ref = addr_spec.get("name", "")
        mapped = addr_map.get(ref)
        if mapped is None:
            # Keep a sanitized reference (import fails loudly on a missing
            # object rather than silently matching 'any')
            warnings.append(
                f"Address reference '{ref}' was not converted - rule "
                f"references it anyway, review manually"
            )
            return [sanitize_name(ref)]
        return [mapped]
    elif addr_type == "subnet":
        ip = addr_spec.get("value", "")
        mask = addr_spec.get("netmask", "")
        cidr = netmask_to_cidr(mask)
        net_name = sanitize_name(f"net_{ip.replace('.', '_')}_{cidr}")
        inline_hosts[net_name] = f"{ip}/{cidr}"
        return [net_name]

    return ["any"]


def _resolve_ace_service(
    ace: Dict[str, Any],
    parsed: Dict[str, Any],
    inline_services: Dict[str, Dict],
    svc_map: Dict[str, List[str]],
) -> Tuple[List[str], List[str], List[str], str]:
    """Resolve the service/application for an ACE.

    Returns (services, applications, notes, disabled_reason). A non-empty
    disabled_reason means the restriction cannot be expressed in PAN-OS and
    the rule must be emitted disabled (fail closed) rather than silently
    broadened to service=any/application=any.
    """
    protocol = ace.get("protocol", "")
    notes: List[str] = []

    # Protocol position held a service object / group reference
    if ace.get("protocol_ref_type") in ("object", "object-group"):
        ref = ace.get("protocol_ref_name") or ""
        mapped = svc_map.get(ref)
        if mapped:
            return mapped, ["any"], notes, ""
        if ref in parsed.get("protocol_groups", {}):
            reason = (f"protocol object-group '{ref}' cannot be expressed "
                      f"as a PAN-OS service")
        elif ref in parsed.get("icmp_type_groups", {}):
            reason = (f"icmp-type object-group '{ref}' cannot be expressed "
                      f"as a PAN-OS service")
        else:
            reason = f"service reference '{ref}' was not converted"
        return ["any"], ["any"], notes, reason

    # 'ip' matches any protocol - service any / application any is faithful
    if protocol in ("ip", ""):
        return ["any"], ["any"], notes, ""

    # ICMP: PAN-OS models this with App-IDs, not services. 'icmp' covers
    # non-echo types, 'ping' covers echo request/reply.
    if protocol == "icmp":
        return ["application-default"], ["icmp", "ping"], notes, ""
    if protocol == "icmp6":
        return ["application-default"], ["ipv6-icmp"], notes, ""

    if protocol in ("tcp", "udp"):
        dest_port = ace.get("dest_port")
        if ace.get("source_port"):
            # The importer's service schema has no source-port field
            notes.append("ASA source-port restriction not migrated - "
                         "review manually")
        if dest_port:
            services = _resolve_port_spec(
                dest_port, protocol, inline_services, svc_map
            )
            if services is None:
                return (["any"], ["any"], notes,
                        f"{protocol} port restriction "
                        f"'{dest_port.get('type', '')} "
                        f"{dest_port.get('port', '')}' cannot be expressed")
            return services, ["any"], notes, ""
        # tcp/udp without ports: PAN-OS has no protocol-only service object.
        # Disabling every such rule would be too disruptive, so keep
        # service=any but flag it for review (documented trade-off).
        notes.append(f"ASA restricted protocol to {protocol}; PAN-OS "
                     f"service left 'any' - review manually")
        return ["any"], ["any"], notes, ""

    # Other IP protocols (gre, esp, ospf, protocol numbers, ...) have no
    # service equivalent - fail closed instead of allowing everything.
    return (["any"], ["any"], notes,
            f"IP protocol '{protocol}' cannot be expressed as a "
            f"PAN-OS service")


def _resolve_port_spec(
    port_spec: Dict[str, str],
    protocol: str,
    inline_services: Dict[str, Dict],
    svc_map: Dict[str, List[str]],
) -> Optional[List[str]]:
    """Resolve a port specification to PAN-OS service object name(s).

    Returns None when the specification cannot be expressed (caller emits
    the rule disabled - fail closed).
    """
    ptype = port_spec.get("type", "")

    if ptype == "object-group":
        return svc_map.get(port_spec.get("name", ""))

    if ptype == "eq":
        port_val = port_spec.get("port", "")
        base = f"{protocol}_{port_val}"
    elif ptype == "range":
        start = port_spec.get("start", "")
        end = port_spec.get("end", "")
        port_val = f"{start}-{end}"
        base = f"{protocol}_{start}_{end}"
    elif ptype in ("gt", "lt", "neq"):
        port = port_spec.get("port", "")
        if not port.isdigit():
            return None
        p = int(port)
        if ptype == "gt":
            # gt 65535 matches nothing - inexpressible, fail closed
            if p >= 65535:
                return None
            port_val = f"{p + 1}-65535"
        elif ptype == "lt":
            # lt 0 matches nothing; lt starts at port 0
            if p <= 0:
                return None
            port_val = "0" if p == 1 else f"0-{p - 1}"
        else:
            # neq p = everything except p, as a comma-separated port list
            if p <= 0:
                port_val = "1-65535"
            elif p >= 65535:
                port_val = "0-65534"
            else:
                port_val = f"0-{p - 1},{p + 1}-65535"
        base = f"{protocol}_{ptype}_{port}"
    else:
        return None

    svc_name = sanitize_name(base)
    if svc_name not in inline_services:
        inline_services[svc_name] = {
            "protocol": protocol,
            "port": port_val,
        }
    return [svc_name]


# ═══════════════════════════════════════════════════════════════════════════
# Shared helpers
# ═══════════════════════════════════════════════════════════════════════════

_PA_NAME_MAX = 63


def _dedup_name(name: str, used: Set[str]) -> str:
    """Return a unique name by appending _N if already used.

    The base is trimmed so the suffixed name stays within the PAN-OS
    63-character limit.
    """
    if name not in used:
        used.add(name)
        return name
    counter = 2
    while True:
        suffix = f"_{counter}"
        unique = f"{name[:_PA_NAME_MAX - len(suffix)]}{suffix}"
        if unique not in used:
            used.add(unique)
            return unique
        counter += 1


# ═══════════════════════════════════════════════════════════════════════════
# Main entry point
# ═══════════════════════════════════════════════════════════════════════════

def main(argv: Optional[List[str]] = None) -> int:
    """Main function - parse ASA config and produce PAN-OS JSON files."""

    parser = argparse.ArgumentParser(
        description="Convert Cisco ASA configuration to Palo Alto PAN-OS format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python asa_converter.py Cisco_ASA_config.txt
  python asa_converter.py Cisco_ASA_config.txt -o pa_config --pretty
  python asa_converter.py Cisco_ASA_config.txt --target-model pa-440
  python asa_converter.py Cisco_ASA_config.txt --list-models
        """,
    )

    parser.add_argument(
        "input_file",
        nargs="?",
        help="Path to Cisco ASA configuration file (.txt / .cfg)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Base name for output JSON files (default: pa_config)",
        default="pa_config",
    )
    parser.add_argument(
        "-p", "--pretty",
        action="store_true",
        help="Format JSON output with indentation for readability",
    )
    parser.add_argument(
        "-m", "--target-model",
        default="pa-440",
        help="Target Palo Alto model (default: pa-440). "
             "Use --list-models to see options.",
    )
    parser.add_argument(
        "--list-models",
        action="store_true",
        help="List supported Palo Alto models and exit",
    )

    args = parser.parse_args(argv)

    if args.list_models:
        print_supported_models()
        return 0

    if not args.input_file:
        parser.error("input_file is required (unless using --list-models)")

    # ====================================================================
    # Banner
    # ====================================================================
    print("=" * 60)
    print("Cisco ASA to Palo Alto PAN-OS Configuration Converter")
    print("=" * 60)
    print(f"Target Model: {args.target_model}")

    # ====================================================================
    # Load and parse ASA config
    # ====================================================================
    print(f"\nLoading ASA configuration from: {args.input_file}")

    try:
        with open(args.input_file, "r", encoding="utf-8") as f:
            config_text = f.read()
    except FileNotFoundError:
        print(f"\n[ERROR] Input file '{args.input_file}' not found!")
        return 1
    except UnicodeDecodeError:
        print("  WARNING: input is not valid UTF-8; re-reading with "
              "undecodable bytes replaced")
        try:
            with open(args.input_file, "r", encoding="utf-8",
                      errors="replace") as f:
                config_text = f.read()
        except OSError as e:
            print(f"\n[ERROR] Could not read input file: {e}")
            return 1
    except OSError as e:
        print(f"\n[ERROR] Could not read input file: {e}")
        return 1

    asa_parser = ASAParser()
    parsed = asa_parser.parse(config_text)

    hostname = parsed.get("hostname", "unknown")
    print(f"[OK] Parsed ASA config for hostname: {hostname}")
    print(f"  - Interfaces: {len(parsed['interfaces'])}")
    print(f"  - Network objects: {len(parsed['network_objects'])}")
    print(f"  - Network object-groups: {len(parsed['network_object_groups'])}")
    print(f"  - Service objects: {len(parsed['service_objects'])}")
    print(f"  - Service object-groups: {len(parsed['service_object_groups'])}")
    print(f"  - Access-lists: {len(parsed['access_lists'])} "
          f"({sum(len(v) for v in parsed['access_lists'].values())} ACEs)")
    print(f"  - Access-groups: {len(parsed['access_groups'])}")
    print(f"  - Static routes: {len(parsed['routes'])}")
    print(f"  - NAT rules: {len(parsed['nat_rules'])}")

    # Shared containers for ad-hoc objects created during conversion
    inline_hosts: Dict[str, str] = {}       # name -> IP or CIDR
    inline_services: Dict[str, Dict] = {}   # name -> {protocol, port}
    warnings: List[str] = []                # manual-review notes

    # ====================================================================
    # Convert interfaces & zones
    # ====================================================================
    print("\n" + "=" * 70)
    print("Converting Interfaces & Zones...")
    print("=" * 70)

    pa_interfaces, pa_zones, intf_map, zone_map = convert_interfaces(
        parsed, args.target_model
    )
    print(f"\n[OK] {len(pa_interfaces)} interfaces, "
          f"{len(pa_zones)} zones created")

    # ====================================================================
    # Convert named address / service objects FIRST so their emitted
    # (possibly renamed) names are known to every later reference
    # ====================================================================
    print("\n" + "-" * 60)
    print("Converting Address Objects...")
    print("-" * 60)

    address_objects, addr_map, addr_used = convert_address_objects(parsed)

    print("\n" + "-" * 60)
    print("Converting Service Objects...")
    print("-" * 60)

    service_objects, svc_map, svc_used = convert_service_objects(
        parsed, warnings
    )

    # ====================================================================
    # Convert groups (discover inline objects, register group names)
    # ====================================================================
    print("\n" + "-" * 60)
    print("Converting Address Groups...")
    print("-" * 60)

    address_groups = convert_address_groups(
        parsed, inline_hosts, addr_map, addr_used, warnings
    )
    print(f"[OK] Converted {len(address_groups)} address groups")

    print("\n" + "-" * 60)
    print("Converting Service Groups...")
    print("-" * 60)

    service_groups = convert_service_groups(
        parsed, inline_services, svc_map, svc_used, warnings
    )
    print(f"[OK] Converted {len(service_groups)} service groups")

    # ====================================================================
    # Convert security rules (may create more inline objects)
    # ====================================================================
    print("\n" + "-" * 60)
    print("Converting Security Rules (Access-Lists)...")
    print("-" * 60)

    security_rules = convert_security_rules(
        parsed, zone_map, inline_hosts, inline_services,
        addr_map, svc_map, warnings
    )

    allow_count = sum(1 for r in security_rules if r["action"] == "allow")
    deny_count = len(security_rules) - allow_count
    disabled_count = sum(
        1 for r in security_rules if r["disabled"] == "yes"
    )
    print(f"[OK] Converted {len(security_rules)} security rules "
          f"(allow: {allow_count}, deny: {deny_count}, "
          f"disabled: {disabled_count})")

    # ====================================================================
    # Append inline objects discovered during group / rule conversion
    # ====================================================================
    print("\n" + "-" * 60)
    print("Appending inline objects...")
    print("-" * 60)

    append_inline_address_objects(address_objects, inline_hosts, addr_used)
    print(f"[OK] {len(address_objects)} address objects total")

    append_inline_service_objects(service_objects, inline_services, svc_used)

    tcp_count = sum(1 for s in service_objects if s.get("protocol") == "tcp")
    udp_count = sum(1 for s in service_objects if s.get("protocol") == "udp")
    print(f"[OK] {len(service_objects)} service objects total "
          f"(TCP: {tcp_count}, UDP: {udp_count})")

    # ====================================================================
    # Convert static routes
    # ====================================================================
    print("\n" + "-" * 60)
    print("Converting Static Routes...")
    print("-" * 60)

    static_routes = convert_static_routes(parsed, intf_map)
    print(f"[OK] Converted {len(static_routes)} static routes")

    # ====================================================================
    # Write output files
    # ====================================================================
    print("\n" + "-" * 60)
    print("Saving output files...")
    print("-" * 60)

    base = args.output
    file_map = {
        "interfaces": (f"{base}_interfaces.json", pa_interfaces),
        "zones": (f"{base}_zones.json", pa_zones),
        "address_objects": (f"{base}_address_objects.json", address_objects),
        "address_groups": (f"{base}_address_groups.json", address_groups),
        "service_objects": (f"{base}_service_objects.json", service_objects),
        "service_groups": (f"{base}_service_groups.json", service_groups),
        "security_rules": (f"{base}_security_rules.json", security_rules),
        "static_routes": (f"{base}_static_routes.json", static_routes),
    }

    # Metadata
    metadata = {
        "target_platform": "panos",
        "source_platform": "cisco_asa",
        "source_hostname": hostname,
        "target_model": args.target_model,
        "output_basename": args.output,
        "schema_version": 1,
    }

    try:
        write_json_file(f"{base}_metadata.json", metadata, pretty=args.pretty)
        print(f"[OK] Wrote metadata: {base}_metadata.json")

        for label, (path, data) in file_map.items():
            write_json_file(path, data, args.pretty)
            print(f"[OK] {label}: {path} ({len(data)} items)")

        # NAT rules (for manual review)
        nat_rules = parsed.get("nat_rules", [])
        if nat_rules:
            nat_path = f"{base}_nat_rules.json"
            nat_data = [
                {"original_rule": r, "note": "Manual review required"}
                for r in nat_rules
            ]
            write_json_file(nat_path, nat_data, pretty=True)
            print(f"[OK] NAT rules (manual review): {nat_path} "
                  f"({len(nat_data)} rules)")

        # Summary
        summary = {
            "conversion_summary": {
                "source_platform": "cisco_asa",
                "source_hostname": hostname,
                "target_platform": "panos",
                "target_model": args.target_model,
                "interfaces": len(pa_interfaces),
                "zones": len(pa_zones),
                "address_objects": len(address_objects),
                "address_groups": len(address_groups),
                "service_objects": {
                    "total": len(service_objects),
                    "tcp": tcp_count,
                    "udp": udp_count,
                },
                "service_groups": len(service_groups),
                "security_rules": {
                    "total": len(security_rules),
                    "allow": allow_count,
                    "deny": deny_count,
                    "disabled_for_review": disabled_count,
                },
                "static_routes": len(static_routes),
                "nat_rules_for_review": len(nat_rules),
                "skipped_acl_lines": parsed.get("skipped_acl_lines", []),
            },
            "warnings": warnings,
        }
        write_json_file(f"{base}_summary.json", summary, pretty=True)
        print(f"[OK] Summary: {base}_summary.json")

    except IOError as e:
        print(f"\n[ERROR] Could not write output files: {e}")
        return 1

    # ====================================================================
    # Final summary
    # ====================================================================
    print("\n" + "=" * 60)
    print("CONVERSION COMPLETE")
    print("=" * 60)
    print(f"\nSource: Cisco ASA ({hostname})")
    print(f"Target: Palo Alto {args.target_model}")
    print("\nOutput Files:")
    print(f"  1. {base}_interfaces.json      ({len(pa_interfaces)} interfaces)")
    print(f"  2. {base}_zones.json            ({len(pa_zones)} zones)")
    print(f"  3. {base}_address_objects.json  ({len(address_objects)} objects)")
    print(f"  4. {base}_address_groups.json   ({len(address_groups)} groups)")
    print(f"  5. {base}_service_objects.json  ({len(service_objects)} objects)")
    print(f"  6. {base}_service_groups.json   ({len(service_groups)} groups)")
    print(f"  7. {base}_security_rules.json   ({len(security_rules)} rules)")
    print(f"  8. {base}_static_routes.json    ({len(static_routes)} routes)")

    if nat_rules:
        print(f"\n  NOTE: {len(nat_rules)} NAT rule(s) saved to "
              f"{base}_nat_rules.json")
        print("        NAT requires manual review - PAN-OS NAT differs "
              "significantly from ASA.")

    skipped_acl = parsed.get("skipped_acl_lines", [])
    if warnings or skipped_acl:
        print("\n" + "=" * 60)
        print(f"MANUAL REVIEW REQUIRED "
              f"({len(warnings)} warning(s), "
              f"{len(skipped_acl)} skipped ACL line(s))")
        print("=" * 60)
        for w in warnings:
            print(f"  - {w}")
        for entry in skipped_acl:
            print(f"  - Skipped ACL line ({entry['reason']}): "
                  f"{entry['line']}")
        print(f"  (also saved in {base}_summary.json)")

    print("\n" + "=" * 60)
    print("IMPORT ORDER FOR PAN-OS:")
    print("=" * 60)
    print("  1. Import interfaces first (layer3)")
    print("  2. Import zones")
    print("  3. Import address objects")
    print("  4. Import address groups")
    print("  5. Import service objects")
    print("  6. Import service groups")
    print("  7. Import static routes")
    print("  8. Import security rules last")
    print("  9. Commit configuration")
    print("  10. Configure NAT manually")
    print("\nThis order ensures referenced objects exist before importing")
    print("objects that reference them.")
    print("\n" + "=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
