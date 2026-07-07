#!/usr/bin/env python3
"""
FortiGate to Palo Alto PAN-OS Configuration Converter - Main Script
====================================================================
Orchestrates the conversion of FortiGate YAML configs to PAN-OS JSON format.

This mirrors the structure of FortiGateToFTDTool/fortigate_converter.py
but targets Palo Alto PAN-OS instead of Cisco FTD.

OUTPUT FILES:
    {basename}_interfaces.json        - PAN-OS interface configs (physical, sub, aggregate)
    {basename}_address_objects.json   - PAN-OS address objects
    {basename}_address_groups.json    - PAN-OS address groups
    {basename}_service_objects.json   - PAN-OS service objects
    {basename}_service_groups.json    - PAN-OS service groups
    {basename}_security_rules.json    - PAN-OS security rules
    {basename}_static_routes.json     - PAN-OS static routes
    {basename}_zones.json             - PAN-OS zone definitions
    {basename}_metadata.json          - Conversion metadata
    {basename}_summary.json           - Conversion statistics

HOW TO RUN:
    python pa_converter.py fortigate.yaml
    python pa_converter.py fortigate.yaml -o pa_config --pretty
    python pa_converter.py fortigate.yaml --target-model pa-440
    python pa_converter.py fortigate.yaml --list-models
"""

import yaml
import json
import argparse
import sys
from typing import List, Optional

try:
    from pa_address_converter import PAAddressConverter
    from pa_address_group_converter import PAAddressGroupConverter
    from pa_service_converter import PAServiceConverter
    from pa_service_group_converter import PAServiceGroupConverter
    from pa_policy_converter import PAPolicyConverter
    from pa_route_converter import PARouteConverter
    from pa_interface_converter import PAInterfaceConverter
except ImportError as e:
    print("\n" + "=" * 60)
    print("ERROR: Missing converter module files!")
    print("=" * 60)
    print(f"\nDetails: {e}")
    print("\nMake sure these files are in the same folder as this script:")
    print("  - pa_common.py")
    print("  - pa_address_converter.py")
    print("  - pa_address_group_converter.py")
    print("  - pa_service_converter.py")
    print("  - pa_service_group_converter.py")
    print("  - pa_policy_converter.py")
    print("  - pa_route_converter.py")
    print("  - pa_interface_converter.py")
    print("\n" + "=" * 60)
    raise


def preprocess_yaml_file(input_file: str) -> str:
    """Pre-process YAML file to remove problematic sections before parsing.

    Some FortiGate sections contain characters or formats that cause
    YAML parsing errors. This removes those sections and returns clean content.
    """
    print("  Pre-processing YAML file to remove problematic sections...")

    sections_to_skip = [
        "system_automation-trigger:",
        "dlp_filepattern:",
        "system_automation-action:",
        "dlp_sensor:",
        "dlp_settings:",
    ]

    cleaned_lines = []
    skip_section = False
    current_indent = 0

    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.lstrip()
            indent = len(line) - len(stripped) if stripped else 0

            if any(line.strip().startswith(section) for section in sections_to_skip):
                skip_section = True
                current_indent = indent
                print(f"    Skipping section: {line.strip()}")
                continue

            if skip_section:
                if stripped and indent <= current_indent:
                    skip_section = False
                else:
                    continue

            cleaned_lines.append(line)

    print("  [OK] Pre-processing complete")
    return "".join(cleaned_lines)


def parse_expansion_specs(specs: Optional[List[str]]) -> dict:
    """Parse repeatable ``NAME=SPEC`` scale-up values into a dict.

    SPEC is either an integer total member count or a comma-separated list of
    PAN-OS ports (e.g. 'ethernet1/5,ethernet1/6'). Invalid entries are skipped
    with a warning. Shared by all four interface scale-up flags.
    """
    expansion: dict = {}
    for raw in specs or []:
        if "=" not in raw:
            print(f"[WARNING] Ignoring scale-up '{raw}': expected NAME=SPEC format")
            continue
        key, _, value = raw.partition("=")
        key = key.strip()
        value = value.strip()
        if not key or not value:
            print(f"[WARNING] Ignoring scale-up '{raw}': empty name or spec")
            continue
        if value.isdigit():
            expansion[key] = int(value)
        else:
            ports = [p.strip() for p in value.split(",") if p.strip()]
            if not ports:
                print(f"[WARNING] Ignoring scale-up '{raw}': no valid ports")
                continue
            expansion[key] = ports
    return expansion


def parse_keyvalue_specs(specs: Optional[List[str]], flag: str) -> dict:
    """Parse repeatable ``KEY=VALUE`` values (e.g. --map-port,
    --promote-portchannel-vlan) into a dict. Invalid entries are skipped.
    """
    parsed: dict = {}
    for raw in specs or []:
        if "=" not in raw:
            print(f"[WARNING] Ignoring {flag} '{raw}': expected KEY=VALUE format")
            continue
        key, _, value = raw.partition("=")
        key = key.strip()
        value = value.strip()
        if not key or not value:
            print(f"[WARNING] Ignoring {flag} '{raw}': empty key or value")
            continue
        parsed[key] = value
    return parsed


def build_conversion_metadata(args: argparse.Namespace) -> dict:
    """Build metadata dictionary for downstream tools."""
    return {
        "target_platform": "panos",
        "target_model": str(args.target_model).lower().strip(),
        "output_basename": str(args.output).strip(),
        "schema_version": 1,
    }


def write_json_file(path: str, data: object, pretty: bool = False) -> None:
    """Write JSON data to a file."""
    with open(path, "w", encoding="utf-8") as f:
        if pretty:
            json.dump(data, f, indent=2)
        else:
            json.dump(data, f, separators=(",", ":"))


def main(argv: Optional[List[str]] = None) -> int:
    """Main function that orchestrates the entire conversion process."""
    # ========================================================================
    # STEP 1: Parse command-line arguments
    # ========================================================================
    parser = argparse.ArgumentParser(
        description="Convert FortiGate YAML configuration to Palo Alto PAN-OS format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pa_converter.py fortigate.yaml
  python pa_converter.py fortigate.yaml -o pa_config
  python pa_converter.py fortigate.yaml --pretty
  python pa_converter.py fortigate.yaml --target-model pa-440
  python pa_converter.py fortigate.yaml --list-models
        """,
    )

    parser.add_argument(
        "input_file",
        nargs="?",
        help="Path to FortiGate YAML configuration file",
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
        help="Target Palo Alto model (default: pa-440). Use --list-models to see options.",
    )
    parser.add_argument(
        "--list-models",
        action="store_true",
        help="List supported Palo Alto models and exit",
    )

    # ------------------------------------------------------------------
    # Interface scale-up flags (mirror FortiGateToFTDTool). Port-channel maps
    # to PAN-OS aggregate-ethernet; bridge-group maps to a Layer-2 VLAN + SVI.
    # ------------------------------------------------------------------
    parser.add_argument(
        "--map-port", action="append", default=[], metavar="IFACE=PORT",
        help="Straight port assignment: pin a FortiGate interface to a specific "
             "PAN-OS port (no aggregation). IFACE is the FortiGate name/alias, "
             "PORT is the PAN-OS port (e.g. 'wan1=ethernet1/9'). Repeatable.",
    )
    parser.add_argument(
        "--promote-portchannel-vlan", action="append", default=[], metavar="IFACE=TAG",
        help="When promoting IFACE to an aggregate-ethernet, place its IP on a "
             "subinterface (aeN.TAG) using this L3 VLAN tag (e.g. 'wan1=100') "
             "instead of on the ae directly. Repeatable.",
    )
    parser.add_argument(
        "--expand-portchannel", action="append", default=[], metavar="AGG=SPEC",
        help="Grow a FortiGate aggregate to MORE aggregate-ethernet members. "
             "AGG is the aggregate name/alias. SPEC is a target TOTAL member "
             "count (e.g. 'WAN_LAG=4') or a comma-separated list of PAN-OS "
             "ports to ADD (e.g. 'SRV_LAG=ethernet1/5,ethernet1/6'). Repeatable.",
    )
    parser.add_argument(
        "--promote-portchannel", action="append", default=[], metavar="IFACE=SPEC",
        help="Promote a plain FortiGate physical interface into a NEW PAN-OS "
             "aggregate-ethernet. SPEC is a target TOTAL member count incl. the "
             "original port (e.g. 'wan1=2') or a comma-separated list of extra "
             "PAN-OS ports (e.g. 'wan1=ethernet1/6'). The IP stays on the ae. "
             "Repeatable.",
    )
    parser.add_argument(
        "--expand-bridgegroup", action="append", default=[], metavar="SWITCH=SPEC",
        help="Grow a converted FortiGate switch's Layer-2 segment with MORE "
             "member ports. SWITCH is the system_switch-interface name. SPEC is "
             "a target TOTAL member count or a comma-separated list of PAN-OS "
             "ports to ADD. Repeatable.",
    )
    parser.add_argument(
        "--promote-bridgegroup", action="append", default=[], metavar="IFACE=SPEC",
        help="Promote a plain FortiGate physical interface into a NEW PAN-OS "
             "Layer-2 segment (VLAN + vlan.N SVI). SPEC is a target TOTAL member "
             "count incl. the original port or a comma-separated list of extra "
             "PAN-OS ports. The IP moves onto the SVI. Repeatable.",
    )

    args = parser.parse_args(argv)

    if args.list_models:
        from pa_interface_converter import print_supported_models
        print_supported_models()
        return 0

    if not args.input_file:
        parser.error("input_file is required (unless using --list-models)")

    # ========================================================================
    # STEP 2: Display welcome banner
    # ========================================================================
    print("=" * 60)
    print("FortiGate to Palo Alto PAN-OS Configuration Converter")
    print("=" * 60)
    print(f"Target Model: {args.target_model}")

    # ========================================================================
    # STEP 3: Load FortiGate YAML
    # ========================================================================
    print(f"\nLoading FortiGate configuration from: {args.input_file}")

    try:
        cleaned_yaml = preprocess_yaml_file(args.input_file)
        fg_config = yaml.safe_load(cleaned_yaml)
        if not isinstance(fg_config, dict):
            print(f"\n[ERROR] '{args.input_file}' is empty or not a valid "
                  "FortiGate YAML configuration (expected a top-level mapping)")
            return 1
        print("[OK] YAML file loaded and cleaned successfully")

        # Remove problematic sections from parsed config
        sections_to_remove = [
            "system_automation-trigger",
            "dlp_filepattern",
            "system_automation-action",
            "dlp_sensor",
            "dlp_settings",
        ]
        removed_count = 0
        for section in sections_to_remove:
            if section in fg_config:
                del fg_config[section]
                removed_count += 1

        if removed_count > 0:
            print(f"[OK] Removed {removed_count} non-essential sections")

    except FileNotFoundError:
        print(f"\n[ERROR] Input file '{args.input_file}' not found!")
        return 1
    except yaml.YAMLError as e:
        print(f"\n[ERROR] Could not parse YAML file!\n  Details: {e}")
        return 1
    except Exception as e:
        print(f"\n[ERROR] {e}")
        return 1

    # ========================================================================
    # STEP 4: Initialize converters
    # ========================================================================
    print("\nInitializing converters...")

    address_converter = PAAddressConverter(fg_config)
    address_group_converter = PAAddressGroupConverter(fg_config)
    service_converter = PAServiceConverter(fg_config)
    service_group_converter = PAServiceGroupConverter(fg_config)
    policy_converter = PAPolicyConverter(fg_config)

    # ========================================================================
    # STEP 5: Convert interfaces/zones FIRST (needed for routes and policies)
    # ========================================================================
    print("\n" + "=" * 70)
    print("Converting Interfaces & Zones...")
    print("=" * 70)

    interface_converter = PAInterfaceConverter(fg_config, target_model=args.target_model)

    # Interface scale-up (optional): grow aggregates / Layer-2 segments or
    # promote plain physical ports into them. No-op unless a flag was given.
    agg_expansion = parse_expansion_specs(getattr(args, "expand_portchannel", []))
    if agg_expansion:
        interface_converter.set_aggregate_expansion(agg_expansion)
    agg_promotion = parse_expansion_specs(getattr(args, "promote_portchannel", []))
    if agg_promotion:
        interface_converter.set_aggregate_promotion(agg_promotion)
    bg_expansion = parse_expansion_specs(getattr(args, "expand_bridgegroup", []))
    if bg_expansion:
        interface_converter.set_bridgegroup_expansion(bg_expansion)
    bg_promotion = parse_expansion_specs(getattr(args, "promote_bridgegroup", []))
    if bg_promotion:
        interface_converter.set_bridgegroup_promotion(bg_promotion)
    port_map = parse_keyvalue_specs(getattr(args, "map_port", []), "--map-port")
    if port_map:
        interface_converter.set_port_mapping(port_map)
    pc_vlans = parse_keyvalue_specs(
        getattr(args, "promote_portchannel_vlan", []), "--promote-portchannel-vlan")
    if pc_vlans:
        interface_converter.set_promotion_subinterface_vlans(pc_vlans)

    zones = interface_converter.convert()
    pa_interfaces = interface_converter.get_interfaces()
    interface_name_mapping = interface_converter.get_interface_mapping()
    zone_mapping = interface_converter.get_zone_mapping()

    intf_stats = interface_converter.get_statistics()
    print("\n[OK] Interface/Zone conversion complete:")
    print(f"  - Interfaces mapped: {intf_stats['mapped_interfaces']}")
    print(f"  - Physical interfaces: {intf_stats['physical_interfaces']}")
    print(f"  - Subinterfaces: {intf_stats['subinterfaces']}")
    print(f"  - Aggregate interfaces: {intf_stats['aggregate_interfaces']}")
    print(f"  - Zones created: {intf_stats['zones_created']}")
    if intf_stats["skipped"] > 0:
        print(f"  - Skipped: {intf_stats['skipped']}")

    # ========================================================================
    # STEP 6: Convert address objects
    # ========================================================================
    print("\n" + "-" * 60)
    print("Converting Address Objects...")
    print("-" * 60)

    address_objects = address_converter.convert()
    print(f"[OK] Converted {len(address_objects)} address objects")

    skipped_addresses = address_converter.get_skipped_addresses()
    address_name_map = address_converter.get_name_map()

    # ========================================================================
    # STEP 7: Convert address groups
    # ========================================================================
    print("\n" + "-" * 60)
    print("Converting Address Groups...")
    print("-" * 60)

    address_group_converter.set_address_context(
        skipped_addresses=skipped_addresses,
        address_name_map=address_name_map,
    )
    address_groups = address_group_converter.convert()
    print(f"[OK] Converted {len(address_groups)} address groups")

    address_group_names = {g["name"] for g in address_groups}
    address_group_name_map = address_group_converter.get_name_map()
    # Policy refs to skipped groups are filtered like skipped addresses
    skipped_addresses |= address_group_converter.get_skipped_groups()

    # ========================================================================
    # STEP 8: Convert service objects
    # ========================================================================
    print("\n" + "-" * 60)
    print("Converting Service Objects...")
    print("-" * 60)

    service_objects = service_converter.convert()
    service_stats = service_converter.get_statistics()
    service_name_mapping = service_converter.get_service_name_mapping()
    skipped_services = service_converter.get_skipped_services()
    ping_services = service_converter.get_ping_services()

    print(f"[OK] Converted {service_stats['total_objects']} service objects")
    print(f"  - TCP objects: {service_stats['tcp_objects']}")
    print(f"  - UDP objects: {service_stats['udp_objects']}")
    if service_stats["split_services"] > 0:
        print(f"  - Services split (TCP+UDP): {service_stats['split_services']}")
    if service_stats["icmp_skipped"] > 0:
        print(f"  - Skipped (ICMP/non-port): {service_stats['icmp_skipped']}")
    if service_stats["ping_services"] > 0:
        print(f"  - Ping services (-> application 'ping'): "
              f"{service_stats['ping_services']}")

    # Build split_services set
    split_services = set()
    for fg_name, pa_names in service_name_mapping.items():
        if len(pa_names) > 1:
            split_services.add(fg_name)

    # ========================================================================
    # STEP 9: Convert service groups
    # ========================================================================
    print("\n" + "-" * 60)
    print("Converting Service Groups...")
    print("-" * 60)

    service_group_converter.set_split_services(
        split_services=split_services,
        service_name_mapping=service_name_mapping,
        skipped_services=skipped_services,
    )
    service_groups = service_group_converter.convert()
    print(f"[OK] Converted {len(service_groups)} service groups")

    service_group_names = {g["name"] for g in service_groups}
    service_group_name_map = service_group_converter.get_name_map()
    # Policy refs to skipped groups are filtered like skipped services
    skipped_services = skipped_services | service_group_converter.get_skipped_groups()

    # ========================================================================
    # STEP 10: Convert firewall policies to security rules
    # ========================================================================
    print("\n" + "-" * 60)
    print("Converting Firewall Policies...")
    print("-" * 60)

    policy_converter.set_split_services(
        split_services=split_services,
        service_name_mapping=service_name_mapping,
        skipped_services=skipped_services,
        address_groups=address_group_names,
        service_groups=service_group_names,
        interface_name_mapping=zone_mapping,
        skipped_addresses=skipped_addresses,
        ping_services=ping_services,
        address_name_map=address_name_map,
        address_group_name_map=address_group_name_map,
        service_group_name_map=service_group_name_map,
    )
    security_rules = policy_converter.convert()

    policy_stats = policy_converter.get_statistics()
    print(f"[OK] Converted {policy_stats['total_rules']} security rules")
    print(f"  - Allow rules: {policy_stats['allow_rules']}")
    print(f"  - Deny rules: {policy_stats['deny_rules']}")
    if policy_stats.get("disabled_rules"):
        print(f"  - Disabled rules: {policy_stats['disabled_rules']}")

    # ========================================================================
    # STEP 11: Convert static routes
    # ========================================================================
    print("\n" + "-" * 60)
    print("Converting Static Routes...")
    print("-" * 60)

    route_converter = PARouteConverter(
        fg_config, interface_name_mapping=interface_name_mapping
    )
    static_routes = route_converter.convert()

    route_stats = route_converter.get_statistics()
    print(f"[OK] Converted {route_stats['converted']} static routes")
    if route_stats["blackhole_skipped"] > 0:
        print(f"  - Blackhole routes skipped: {route_stats['blackhole_skipped']}")
    if route_stats["other_skipped"] > 0:
        print(f"  - Other routes skipped: {route_stats['other_skipped']}")

    # ========================================================================
    # STEP 12: Write output files
    # ========================================================================
    print("\n" + "-" * 60)
    print("Saving output files...")
    print("-" * 60)

    interfaces_output = f"{args.output}_interfaces.json"
    address_objects_output = f"{args.output}_address_objects.json"
    address_groups_output = f"{args.output}_address_groups.json"
    service_objects_output = f"{args.output}_service_objects.json"
    service_groups_output = f"{args.output}_service_groups.json"
    security_rules_output = f"{args.output}_security_rules.json"
    static_routes_output = f"{args.output}_static_routes.json"
    zones_output = f"{args.output}_zones.json"
    metadata_output = f"{args.output}_metadata.json"
    summary_output = f"{args.output}_summary.json"

    # Write metadata
    metadata = build_conversion_metadata(args)
    write_json_file(metadata_output, metadata, pretty=args.pretty)
    print(f"[OK] Wrote metadata: {metadata_output}")

    try:
        write_json_file(interfaces_output, pa_interfaces, args.pretty)
        print(f"[OK] Interfaces saved to: {interfaces_output}")

        write_json_file(address_objects_output, address_objects, args.pretty)
        print(f"[OK] Address objects saved to: {address_objects_output}")

        write_json_file(address_groups_output, address_groups, args.pretty)
        print(f"[OK] Address groups saved to: {address_groups_output}")

        write_json_file(service_objects_output, service_objects, args.pretty)
        print(f"[OK] Service objects saved to: {service_objects_output}")

        write_json_file(service_groups_output, service_groups, args.pretty)
        print(f"[OK] Service groups saved to: {service_groups_output}")

        write_json_file(security_rules_output, security_rules, args.pretty)
        print(f"[OK] Security rules saved to: {security_rules_output}")

        write_json_file(static_routes_output, static_routes, args.pretty)
        print(f"[OK] Static routes saved to: {static_routes_output}")

        write_json_file(zones_output, zones, args.pretty)
        print(f"[OK] Zones saved to: {zones_output}")

        # ====================================================================
        # Summary
        # ====================================================================
        conversion_failures = {}
        if interface_converter.failed_items:
            conversion_failures["interfaces"] = interface_converter.failed_items
        if address_converter.failed_items:
            conversion_failures["address_objects"] = address_converter.failed_items
        if address_group_converter.failed_items:
            conversion_failures["address_groups"] = address_group_converter.failed_items
        if service_converter.failed_items:
            conversion_failures["service_objects"] = service_converter.failed_items
        if service_group_converter.failed_items:
            conversion_failures["service_groups"] = service_group_converter.failed_items
        if route_converter.failed_items:
            conversion_failures["static_routes"] = route_converter.failed_items
        if policy_converter.failed_items:
            conversion_failures["security_rules"] = policy_converter.failed_items

        total_failures = sum(len(v) for v in conversion_failures.values())

        summary = {
            "conversion_summary": {
                "target_platform": "panos",
                "target_model": args.target_model,
                "interfaces": {
                    "physical": intf_stats["physical_interfaces"],
                    "subinterfaces": intf_stats["subinterfaces"],
                    "aggregate": intf_stats["aggregate_interfaces"],
                    "total": len(pa_interfaces),
                },
                "zones": intf_stats["zones_created"],
                "address_objects": len(address_objects),
                "address_groups": len(address_groups),
                "service_objects": {
                    "total": service_stats["total_objects"],
                    "tcp": service_stats["tcp_objects"],
                    "udp": service_stats["udp_objects"],
                    "split": service_stats["split_services"],
                },
                "service_groups": len(service_groups),
                "security_rules": {
                    "total": policy_stats["total_rules"],
                    "allow": policy_stats["allow_rules"],
                    "deny": policy_stats["deny_rules"],
                },
                "static_routes": {
                    "total": route_stats["total_routes"],
                    "converted": route_stats["converted"],
                    "blackhole_skipped": route_stats["blackhole_skipped"],
                    "other_skipped": route_stats["other_skipped"],
                },
                "total_failures": total_failures,
            },
            "conversion_failures": conversion_failures,
        }
        write_json_file(summary_output, summary, pretty=True)
        print(f"[OK] Summary saved to: {summary_output}")

        if total_failures > 0:
            print(f"[INFO] {total_failures} item(s) failed/skipped - see summary for details")

    except IOError as e:
        print(f"\n[ERROR] Could not write output files!\n  Details: {e}")
        return 1

    # ========================================================================
    # STEP 13: Final summary
    # ========================================================================
    print("\n" + "=" * 60)
    print("CONVERSION COMPLETE")
    print("=" * 60)
    print("\nOutput Files Created:")
    print(f"  1. {interfaces_output}")
    print(f"     - Interfaces: {len(pa_interfaces)}")
    print(f"       (Physical: {intf_stats['physical_interfaces']}, "
          f"Sub: {intf_stats['subinterfaces']}, "
          f"Aggregate: {intf_stats['aggregate_interfaces']})")
    print(f"\n  2. {zones_output}")
    print(f"     - Zones: {intf_stats['zones_created']}")
    print(f"\n  3. {address_objects_output}")
    print(f"     - Address Objects: {len(address_objects)}")
    print(f"\n  4. {address_groups_output}")
    print(f"     - Address Groups: {len(address_groups)}")
    print(f"\n  5. {service_objects_output}")
    print(f"     - Service Objects: {service_stats['total_objects']}")
    print(f"       (TCP: {service_stats['tcp_objects']}, UDP: {service_stats['udp_objects']})")
    print(f"\n  6. {service_groups_output}")
    print(f"     - Service Groups: {len(service_groups)}")
    print(f"\n  7. {security_rules_output}")
    print(f"     - Security Rules: {policy_stats['total_rules']}")
    print(f"       (Allow: {policy_stats['allow_rules']}, Deny: {policy_stats['deny_rules']})")
    print(f"\n  8. {static_routes_output}")
    print(f"     - Static Routes: {route_stats['converted']}")
    print(f"\n  9. {summary_output}")
    print("     - Conversion statistics")
    print("\n" + "=" * 60)
    print("IMPORT ORDER FOR PAN-OS:")
    print("=" * 60)
    print("  1. Import interfaces first (layer3, subinterfaces, aggregates)")
    print("  2. Import zones")
    print("  3. Import address objects")
    print("  4. Import address groups")
    print("  5. Import service objects")
    print("  6. Import service groups")
    print("  7. Import static routes")
    print("  8. Import security rules last")
    print("  9. Commit configuration")
    print("\nThis order ensures referenced objects exist before importing")
    print("objects that reference them.")
    print("\n" + "=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
