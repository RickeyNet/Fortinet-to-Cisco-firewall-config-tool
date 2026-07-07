# FortiGate to Cisco FTD Configuration Converter - MAIN SCRIPT
# =============================================================
# This is the main script that orchestrates the conversion process.
# It loads the YAML file, calls the converter modules, and saves the output.

# This modular approach keeps the code organized and easier to maintain.

# REQUIREMENTS:
#     - Python 3.6 or higher
#     - PyYAML library (install with: pip install pyyaml)

# FILE STRUCTURE:
#     fortigate_converter.py          <- This main script (run this one!)
#     address_converter.py            <- Handles address object conversion
#     address_group_converter.py      <- Handles address group conversion
#     service_converter.py            <- Handles service port object conversion
#     service_group_converter.py      <- Handles service port group conversion
#     policy_converter.py             <- Handles firewall policy conversion
#     route_converter.py              <- Handles static route conversion
#     your_fortigate_config.yaml      <- Your FortiGate configuration file

# OUTPUT FILES:
#     The script creates SEVEN separate JSON files for easier import:
#     1. {basename}_address_objects.json    <- Network objects only
#     2. {basename}_address_groups.json     <- Network groups only
#     3. {basename}_service_objects.json    <- Port objects only
#     4. {basename}_service_groups.json     <- Port groups only
#     5. {basename}_access_rules.json       <- Firewall access rules
#     6. {basename}_static_routes.json      <- Static routes
#     7. {basename}_summary.json            <- Conversion summary statistics

#     This separation makes it easier to import into FTD in the correct order.

# HOW TO RUN THIS SCRIPT:
#     1. Save ALL THREE Python files in the same folder
#     2. Place your FortiGate YAML file in the SAME FOLDER
#     3. Open terminal/command prompt and navigate to the folder:
#        cd C:\path\to\your\folder
#     4. Run the main script:
#        python fortigate_converter.py your_fortigate_config.yaml

#     EXAMPLES:
#     python fortigate_converter.py fortigate.yaml
#     python fortigate_converter.py fortigate.yaml -o output.json --pretty

# WHAT GETS CONVERTED:
#      Address Objects (firewall_address)
#      Address Groups (firewall_addrgrp)
#      Service Port Objects (firewall_service_custom)
#       - Automatically splits TCP and UDP into separate objects
#      Service Port Groups (firewall_service_group)
#       - Automatically expands split services in groups
#      Firewall Policies (firewall_policy)
#       - Converts to FTD access rules
#       - Maps accept -> PERMIT, deny -> DENY
#       - Handles interfaces as security zones
#       Static Routes (router_static)
#       - Converts to FTD static route entries
#       - Creates network object references for destinations and gateways
#       - Skips blackhole routes



import yaml
import json
import argparse
import sys

from typing import List, Optional

# Import our custom converter modules
# These modules contain the logic for converting specific object types
try:
    from address_converter import AddressConverter
    from address_group_converter import AddressGroupConverter
    from service_converter import ServiceConverter
    from service_group_converter import ServiceGroupConverter
    from policy_converter import PolicyConverter
    from route_converter import RouteConverter
    from interface_converter import InterfaceConverter, FTD_MODELS, get_network_modules
except ImportError as e:
    print("\n" + "="*60)
    print("ERROR: Missing converter module files!")
    print("="*60)
    print(f"\nDetails: {e}")
    print("\nMake sure these files are in the same folder as this script:")
    print("  1. address_converter.py")
    print("  2. address_group_converter.py")
    print("  3. service_converter.py")
    print("  4. service_group_converter.py")
    print("  5. policy_converter.py")
    print("  6. route_converter.py")
    print("  7. interface_converter.py")
    print("  8. fortigate_converter.py (this file)")
    print("\n" + "="*60)
    raise

def preprocess_yaml_file(input_file: str) -> str:
    """
    Pre-process YAML file to remove problematic sections before parsing.

    Some FortiGate sections contain characters or formats that cause
    YAML parsing errors. This function reads the file as text, removes
    those sections, and returns cleaned content.

    Args:
        input_file: Path to the original YAML file

    Returns:
        Cleaned YAML content as string
    """
    print("  Pre-processing YAML file to remove problematic sections...")

    # Sections to completely remove from YAML
    sections_to_skip = [
        'system_automation-trigger:',
        'dlp_filepattern:',
        'system_automation-action:',
        'dlp_sensor:',
        'dlp_settings:'
    ]

    cleaned_lines = []
    skip_section = False
    current_indent = 0

    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            # Get the indentation level of this line
            stripped = line.lstrip()
            if stripped:
                indent = len(line) - len(stripped)
            else:
                indent = 0

            # Check if this line starts a section we want to skip
            if any(line.strip().startswith(section) for section in sections_to_skip):
                skip_section = True
                current_indent = indent
                print(f"    Skipping section: {line.strip()}")
                continue

            # If we're in a skip section, check if we've exited it
            if skip_section:
                # If we encounter a line with same or less indentation, we've exited the section
                if stripped and indent <= current_indent:
                    skip_section = False
                else:
                    # Still in the section, skip this line
                    continue

            # Keep this line
            cleaned_lines.append(line)

    cleaned_yaml = ''.join(cleaned_lines)
    print("  [OK] Pre-processing complete")
    return cleaned_yaml

def parse_keyvalue_specs(specs: Optional[List[str]], flag: str) -> dict:
    """Parse simple 'KEY=VALUE' CLI values into a dict (e.g. --map-port,
    --promote-portchannel-vlan). Invalid entries are skipped with a warning.

    Returns a dict of KEY (interface name/alias) -> VALUE string. Later
    duplicates overwrite earlier ones.
    """
    parsed: dict = {}
    for raw in specs or []:
        if '=' not in raw:
            print(f"[WARNING] Ignoring {flag} '{raw}': expected KEY=VALUE format")
            continue
        key, _, value = raw.partition('=')
        key = key.strip()
        value = value.strip()
        if not key or not value:
            print(f"[WARNING] Ignoring {flag} '{raw}': empty key or value")
            continue
        parsed[key] = value
    return parsed


def parse_expansion_specs(specs: Optional[List[str]]) -> dict:
    """
    Parse --expand-portchannel CLI values into a dict for the InterfaceConverter.

    Each spec is 'PC=VALUE' where VALUE is either an integer total member count
    or a comma-separated list of FTD ports (e.g. 'Ethernet1/5,Ethernet1/6').

    Args:
        specs: List of raw 'PC=VALUE' strings (may be empty/None).

    Returns:
        Dict of port-channel identifier -> int (target count) or list of FTD ports.
        Invalid entries are skipped with a warning.
    """
    expansion = {}
    for raw in specs or []:
        if '=' not in raw:
            print(f"[WARNING] Ignoring --expand-portchannel '{raw}': expected PC=SPEC format")
            continue
        key, _, value = raw.partition('=')
        key = key.strip()
        value = value.strip()
        if not key or not value:
            print(f"[WARNING] Ignoring --expand-portchannel '{raw}': empty name or spec")
            continue
        if value.isdigit():
            expansion[key] = int(value)
        else:
            ports = [p.strip() for p in value.split(',') if p.strip()]
            if not ports:
                print(f"[WARNING] Ignoring --expand-portchannel '{raw}': no valid ports")
                continue
            expansion[key] = ports
    return expansion


def build_conversion_metadata(args: argparse.Namespace) -> dict:
    """
    Build a metadata dictionary describing the conversion context.

    This is exported to a standalone JSON file so downstream scripts
    (importer/cleanup) can automatically apply device-specific behavior.

    Args:
        args: Parsed argparse namespace (must include target_model, output,
              and ha_port)

    Returns:
        Metadata dict with target model, output basename, HA port config,
        and schema version.
    """
    ha_port_val = args.ha_port
    if ha_port_val and ha_port_val.lower() == "none":
        ha_port_val = None  # Explicitly no HA port
    elif not ha_port_val:
        ha_port_val = FTD_MODELS.get(args.target_model, {}).get('ha_port')

    return {
        "target_model": str(args.target_model).lower().strip(),
        "output_basename": str(args.output).strip(),
        "ha_port": ha_port_val,
        "schema_version": 1
    }


def write_json_file(path: str, data: object, pretty: bool = False) -> None:
    """
    Fast JSON writer with optional pretty formatting.

    Args:
        path: Output file path
        data: JSON-serializable object
        pretty: Whether to indent output
    """
    with open(path, "w", encoding="utf-8") as f:
        if pretty:
            json.dump(data, f, indent=2)
        else:
            json.dump(data, f, separators=(",", ":"))

def main(argv: Optional[List[str]] = None) -> int:
    """
    Main function that orchestrates the entire conversion process.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:] when None).

    WORKFLOW:
    1. Parse command-line arguments (input file, output file, formatting)
    2. Load and parse the FortiGate YAML configuration file
    3. Initialize converter modules for each object type
    4. Convert address objects
    5. Convert address groups
    6. Convert service port objects
    7. Convert service port groups
    8. Convert firewall policies
    9. Convert static routes
    10. Save each object type to its own JSON file
    11. Display a summary of what was converted

    Returns:
        0 on success, 1 on error
    """
    # ========================================================================
    # STEP 1: Set up command-line argument parser
    # ========================================================================
    # This allows users to customize how they run the script
    parser = argparse.ArgumentParser(
        description='Convert FortiGate YAML configuration to Cisco FTD FDM API JSON format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python fortigate_converter.py fortigate.yaml
  python fortigate_converter.py fortigate.yaml -o my_config
  python fortigate_converter.py fortigate.yaml --pretty
  python fortigate_converter.py fortigate.yaml --target-model ftd-1010
  python fortigate_converter.py fortigate.yaml --target-model ftd-3120 --pretty
  python fortigate_converter.py fortigate.yaml --list-models

Supported FTD Models:
  ftd-1010   - Cisco Firepower 1010 (8 ports, no HA)
  ftd-1120   - Cisco Firepower 1120 (12 ports)
  ftd-1140   - Cisco Firepower 1140 (12 ports)
  ftd-2110   - Cisco Firepower 2110 (12 ports)
  ftd-2120   - Cisco Firepower 2120 (12 ports)
  ftd-2130   - Cisco Firepower 2130 (16 ports)
  ftd-2140   - Cisco Firepower 2140 (16 ports)
  ftd-3105   - Cisco Secure Firewall 3105 (16 ports, HA on Eth1/2)
  ftd-3110   - Cisco Secure Firewall 3110 (16 ports, HA on Eth1/2)
  ftd-3120   - Cisco Secure Firewall 3120 (16 ports, HA on Eth1/2) [default]
  ftd-3130   - Cisco Secure Firewall 3130 (16 ports, HA on Eth1/2)
  ftd-3140   - Cisco Secure Firewall 3140 (16 ports, HA on Eth1/2)
  ftd-4215   - Cisco Secure Firewall 4215 (24 ports, HA on Eth1/2)
        """
    )

    # REQUIRED argument: The FortiGate YAML file to convert
    parser.add_argument('input_file',
                       nargs='?',  # Make optional so --list-models works
                       help='Path to FortiGate YAML configuration file')

    # OPTIONAL argument: Base name for output files (default: ftd_config)
    parser.add_argument('-o', '--output',
                       help='Base name for output JSON files (default: ftd_config)',
                       default='ftd_config')

    # OPTIONAL flag: Make the JSON output human-readable with indentation
    parser.add_argument('-p', '--pretty',
                       action='store_true',
                       help='Format JSON output with indentation for readability')

    # OPTIONAL: Target FTD firewall model
    parser.add_argument('-m', '--target-model',
                       default='ftd-3120',
                       help='Target FTD firewall model (default: ftd-3120). Use --list-models to see options.')

    parser.add_argument('--ha-port',
                   type=str,
                   default=None,
                   metavar='ETHERNET_PORT',
                   help="Custom HA port(s). Overrides model default. Give one port "
                        "(e.g., 'Ethernet1/5') or several for dual-HA links as a "
                        "comma-separated list (e.g., 'Ethernet1/2,Ethernet1/3'). "
                        "All listed ports are reserved and excluded from conversion. "
                        "Use 'none' to disable HA port reservation entirely. "
                        "Format: 'Ethernet1/X' where X is a valid port number for your model.")

    parser.add_argument('--network-module',
                   type=str,
                   default='none',
                   choices=get_network_modules(),
                   metavar='MODULE',
                   help="Optional network module installed in the model's NM slot "
                        "(models with a slot: 3110/3120/3130/3140, 4215). Adds the "
                        "module's ports (Ethernet2/1..N) to the available pool. "
                        "Choices: " + ", ".join(get_network_modules()) +
                        ". Default: none (fixed ports only).")

    parser.add_argument('--map-port',
                   action='append',
                   default=[],
                   metavar='IFACE=PORT',
                   help="Straight port assignment: pin a FortiGate interface to a "
                        "specific FTD port (no aggregation). IFACE is the FortiGate "
                        "interface name/alias, PORT is the FTD hardware port "
                        "(e.g. 'wan1=Ethernet1/9'). The interface converts as a normal "
                        "routed physical interface. Repeat the flag for multiple ports.")

    parser.add_argument('--promote-portchannel-vlan',
                   action='append',
                   default=[],
                   metavar='IFACE=TAG',
                   help="When promoting IFACE to a port-channel, place its IP on a "
                        "subinterface (Port-channelN.TAG) using this L3 VLAN tag "
                        "(e.g. 'wan1=100'). Without it the IP is applied directly to the "
                        "routed port-channel. Repeat the flag for multiple interfaces.")

    parser.add_argument('--expand-portchannel',
                   action='append',
                   default=[],
                   metavar='PC=SPEC',
                   help="Increase an EtherChannel's 10G member count during migration. "
                        "PC is the FortiGate port-channel name/alias. SPEC is either a "
                        "target TOTAL member count (e.g. 'WAN_LAG=4') or a comma-separated "
                        "list of FTD ports to ADD (e.g. 'SRV_LAG=Ethernet1/5,Ethernet1/6'). "
                        "Repeat the flag for multiple port-channels.")

    parser.add_argument('--promote-portchannel',
                   action='append',
                   default=[],
                   metavar='IFACE=SPEC',
                   help="Promote a plain FortiGate physical interface into a NEW FTD "
                        "EtherChannel so it can carry multiple 10G links. IFACE is the "
                        "FortiGate interface name/alias. SPEC is either a target TOTAL "
                        "member count incl. the original port (e.g. 'wan1=2') or a "
                        "comma-separated list of extra FTD ports to add "
                        "(e.g. 'wan1=Ethernet1/6'). The interface's MTU moves onto the "
                        "port-channel (no IP - put it on a subinterface). Repeat the flag "
                        "for multiple interfaces.")

    parser.add_argument('--expand-bridgegroup',
                   action='append',
                   default=[],
                   metavar='SWITCH=SPEC',
                   help="Increase a bridge group's member count during migration. "
                        "SWITCH is the FortiGate virtual-switch (system_switch-interface) "
                        "name. SPEC is either a target TOTAL member count "
                        "(e.g. 'lan_switch=4') or a comma-separated list of FTD ports to "
                        "ADD (e.g. 'srv_switch=Ethernet1/7,Ethernet1/8'). Repeat the flag "
                        "for multiple switches.")

    parser.add_argument('--promote-bridgegroup',
                   action='append',
                   default=[],
                   metavar='IFACE=SPEC',
                   help="Promote a plain FortiGate physical interface into a NEW FTD "
                        "bridge group (BVI) so its subnet can span several bridged ports. "
                        "IFACE is the FortiGate interface name/alias. SPEC is either a "
                        "target TOTAL member count incl. the original port (e.g. 'lan1=2') "
                        "or a comma-separated list of extra FTD ports to add "
                        "(e.g. 'lan1=Ethernet1/7'). The interface's IP/MTU move onto the "
                        "BVI. Repeat the flag for multiple interfaces.")

    # OPTIONAL flag: verbose debug output (route converter, etc.)
    parser.add_argument('--debug',
                       action='store_true',
                       help='Enable verbose debug output during conversion')

    # OPTIONAL: List supported models and exit
    parser.add_argument('--list-models',
                       action='store_true',
                       help='List supported FTD firewall models and exit')

    # Parse the arguments that the user provided
    args = parser.parse_args(argv)

    # Handle --list-models
    if args.list_models:
        from interface_converter import print_supported_models
        print_supported_models()
        return 0

    # Validate input file is provided
    if not args.input_file:
        parser.error("input_file is required (unless using --list-models)")

    # ========================================================================
    # STEP 2: Display welcome banner
    # ========================================================================
    print("="*60)
    print("FortiGate to Cisco FTD Configuration Converter")
    print("="*60)
    print(f"Target Model: {args.target_model}")

    # ========================================================================
    # STEP 3: Load the FortiGate YAML configuration file
    # ========================================================================
    print(f"\nLoading FortiGate configuration from: {args.input_file}")

    try:
        # Pre-process the YAML file to remove problematic sections
        cleaned_yaml = preprocess_yaml_file(args.input_file)

        # Parse the cleaned YAML content into a Python dictionary
        # yaml.safe_load() safely parses YAML without executing code
        # (safe_load returns None for an empty file - fail with a clear error)
        fg_config = yaml.safe_load(cleaned_yaml)
        if not isinstance(fg_config, dict):
            print(f"\n[ERROR] '{args.input_file}' contains no usable FortiGate "
                  f"configuration (empty or non-mapping YAML)")
            return 1

        print("[OK] YAML file loaded and cleaned successfully")

    except FileNotFoundError:
        # This error occurs if the file doesn't exist at the specified path
        print(f"\n[ERROR] Input file '{args.input_file}' not found!")
        print("\nTroubleshooting:")
        print("  1. Check that the file path is correct")
        print("  2. If the file is in the same folder as this script, just use the filename")
        print("  3. If the file is elsewhere, provide the full path:")
        print("     Windows: C:\\path\\to\\file.yaml")
        print("     Mac/Linux: /path/to/file.yaml")
        return 1

    except yaml.YAMLError as e:
        # This error occurs if the YAML file has syntax errors
        print("\n[ERROR] Could not parse YAML file!")
        print(f"  Details: {e}")
        print("\nMake sure the file is valid YAML format")
        return 1

    except Exception as e:
        # Catch any other unexpected errors
        print(f"\n[ERROR] {e}")
        return 1

    # ========================================================================
    # STEP 4: Initialize converter modules
    # ========================================================================
    # Each converter module is responsible for one type of object
    print("\nInitializing converters...")

    # Create converter instances for address-related objects
    # (the AddressGroupConverter is created in STEP 6, after the address
    # objects are converted, so it can consume the rename map and skip set)
    address_converter = AddressConverter(fg_config)

    # Create converter instances for service-related objects
    service_converter = ServiceConverter(fg_config)
    service_group_converter = ServiceGroupConverter(fg_config)

    # Create converter instance for firewall policies
    policy_converter = PolicyConverter(fg_config)

    # Note: InterfaceConverter is initialized in STEP 4B below (with custom HA port support)

    # Note: Route converter will be initialized later after address objects are converted

    # ========================================================================
    # STEP 4B: Convert interfaces FIRST (needed for routes and policies)
    # ========================================================================
    print("\n" + "="*70)
    print("Converting Interfaces...")
    print("="*70)
    # Pass custom HA port if specified; "none" means no HA port at all
    ha_port_arg = args.ha_port
    if ha_port_arg and ha_port_arg.lower() == "none":
        ha_port_arg = "none"  # Sentinel: explicitly no HA port
    interface_converter = InterfaceConverter(
        fg_config,
        target_model=args.target_model,
        custom_ha_port=ha_port_arg,
        network_module=getattr(args, 'network_module', 'none'),
    )

    # Apply straight port assignments (pin an interface to a specific FTD port)
    map_specs = parse_keyvalue_specs(getattr(args, 'map_port', []), '--map-port')
    if map_specs:
        interface_converter.set_port_mapping(map_specs)
        print(f"  Straight port assignment configured for: {', '.join(map_specs.keys())}")

    # Apply promote-to-port-channel L3 VLAN tags (IP -> subinterface)
    pc_vlan_specs = parse_keyvalue_specs(
        getattr(args, 'promote_portchannel_vlan', []), '--promote-portchannel-vlan')
    if pc_vlan_specs:
        interface_converter.set_promotion_subinterface_vlans(pc_vlan_specs)
        print(f"  Promote-to-port-channel L3 VLAN configured for: {', '.join(pc_vlan_specs.keys())}")

    # Apply EtherChannel expansion (scale up 10G member links) if requested
    expansion_specs = parse_expansion_specs(getattr(args, 'expand_portchannel', []))
    if expansion_specs:
        interface_converter.set_etherchannel_expansion(expansion_specs)
        print(f"  EtherChannel expansion configured for: {', '.join(expansion_specs.keys())}")

    # Apply physical->EtherChannel promotion (turn a plain interface into a LAG)
    promotion_specs = parse_expansion_specs(getattr(args, 'promote_portchannel', []))
    if promotion_specs:
        interface_converter.set_etherchannel_promotion(promotion_specs)
        print(f"  Physical->EtherChannel promotion configured for: {', '.join(promotion_specs.keys())}")

    # Apply bridge group expansion (add members to a virtual switch -> BVI)
    bridgegroup_specs = parse_expansion_specs(getattr(args, 'expand_bridgegroup', []))
    if bridgegroup_specs:
        interface_converter.set_bridgegroup_expansion(bridgegroup_specs)
        print(f"  Bridge group expansion configured for: {', '.join(bridgegroup_specs.keys())}")

    # Apply physical->bridge group promotion (turn a plain interface into a BVI)
    bridge_promotion_specs = parse_expansion_specs(getattr(args, 'promote_bridgegroup', []))
    if bridge_promotion_specs:
        interface_converter.set_bridgegroup_promotion(bridge_promotion_specs)
        print(f"  Physical->bridge group promotion configured for: {', '.join(bridge_promotion_specs.keys())}")

    interface_results = interface_converter.convert()

    # Get the interface name mapping for routes and policies
    interface_name_mapping = interface_converter.get_interface_mapping()

    # Get statistics
    intf_stats = interface_converter.get_statistics()
    print("\n[OK] Interface conversion complete:")
    print(f"  - Physical interfaces to update: {intf_stats['physical_updated']}")
    print(f"  - EtherChannels to create: {intf_stats['etherchannels_created']}")
    print(f"  - Bridge groups to create: {intf_stats['bridge_groups_created']}")
    print(f"  - Subinterfaces to create: {intf_stats['subinterfaces_created']}")
    print(f"  - Security zones to create: {intf_stats['security_zones_created']}")
    if intf_stats.get('vlan_conflicts_remapped', 0) > 0:
        print(f"  - Duplicate VLAN IDs remapped: {intf_stats['vlan_conflicts_remapped']}")
    if intf_stats['skipped'] > 0:
        print(f"  - Skipped: {intf_stats['skipped']}")

    # ========================================================================
    # STEP 5: Convert address objects
    # ========================================================================
    print("\n" + "-"*60)
    print("Converting Address Objects...")
    print("-"*60)

    # Call the convert() method to transform FortiGate addresses to FTD format
    # This returns a list of FTD network object dictionaries
    network_objects = address_converter.convert()

    print(f"[OK] Converted {len(network_objects)} address objects")

    # ========================================================================
    # STEP 5B: Initialize route converter with address objects and interface mapping
    # ========================================================================
    # Now that we have the address objects and interfaces, we can initialize the route converter
    # The route converter needs these to map route destinations/gateways to actual object names
    # and to map interface names to FTD interface names
    # Prepare converted interfaces dictionary for route converter
    converted_interfaces = {
        'physical_interfaces': interface_results.get('physical_interfaces', []),
        'subinterfaces': interface_results.get('subinterfaces', []),
        'etherchannels': interface_results.get('etherchannels', []),
        'bridge_groups': interface_results.get('bridge_groups', [])
    }

    debug_mode = getattr(args, 'debug', False)

    route_converter = RouteConverter(
        fortigate_config=fg_config,
        network_objects=network_objects,
        interface_name_mapping=interface_name_mapping,
        converted_interfaces=converted_interfaces,
        debug=debug_mode
    )

    # ========================================================================
    # STEP 6: Convert address groups
    # ========================================================================
    print("\n" + "-"*60)
    print("Converting Address Groups...")
    print("-"*60)

    # Create the group converter with the address rename map (X -> X_2
    # collision renames) and the set of skipped addresses, so group members
    # follow renames and dangling references are filtered out
    address_group_converter = AddressGroupConverter(
        fg_config,
        address_name_mapping=address_converter.get_address_name_mapping(),
        skipped_addresses=address_converter.get_skipped_addresses(),
    )

    # Call the convert() method to transform FortiGate address groups to FTD format
    # This returns a list of FTD network group dictionaries
    network_groups = address_group_converter.convert()

    print(f"[OK] Converted {len(network_groups)} address groups")

    # Build set of address group names for policy converter
    address_groups = set()
    for group in network_groups:
        address_groups.add(group['name'])

    # ========================================================================
    # STEP 7: Convert service port objects
    # ========================================================================
    print("\n" + "-"*60)
    print("Converting Service Port Objects...")
    print("-"*60)

    # Convert FortiGate services to FTD port objects
    # This handles splitting services with both TCP and UDP into separate objects
    port_objects = service_converter.convert()

    # Get statistics about the conversion
    service_stats = service_converter.get_statistics()
    print(f"[OK] Converted {service_stats['total_objects']} port objects")
    print(f"  - TCP objects: {service_stats['tcp_objects']}")
    print(f"  - UDP objects: {service_stats['udp_objects']}")
    if service_stats.get('icmp_objects', 0) > 0:
        print(f"  - ICMPv4 objects (ping echo): {service_stats['icmp_objects']}")
    print(f"  - Services split into TCP+UDP: {service_stats['split_services']}")
    if service_stats.get('multi_port_services', 0) > 0:
        print(f"  - Services split due to multiple ports: {service_stats['multi_port_services']}")
    if service_stats.get('icmp_skipped', 0) > 0:
        print(f"  - Skipped (ICMP/non-port protocols): {service_stats['icmp_skipped']}")
    if service_stats.get('ping_services', 0) > 0:
        print(f"  - ICMP ping migrated (echo request/reply -> PING group): {service_stats['ping_services']}")
    if service_stats['skipped_services'] > 0:
        print(f"  - Skipped (no ports defined): {service_stats['skipped_services']}")

    # ========================================================================
    # STEP 8: Get service name mapping for group processing
    # ========================================================================
    # Get the mapping of FortiGate service names to FTD object names
    # This is needed so the group converter knows how to expand members
    service_name_mapping = service_converter.get_service_name_mapping()

    # Also build legacy split_services set for backward compatibility
    split_services = set()
    for fg_name, ftd_names in service_name_mapping.items():
        if len(ftd_names) > 1:
            split_services.add(fg_name)

    if split_services:
        print(f"\n  Services that were split: {', '.join(sorted(split_services))}")

    # Get the set of skipped services (ICMP, etc.) to filter from groups
    skipped_services = service_converter.get_skipped_services()
    if skipped_services:
        print(f"  Services skipped (will be filtered from groups): {', '.join(sorted(skipped_services))}")

    # ========================================================================
    # STEP 9: Convert service port groups
    # ========================================================================
    print("\n" + "-"*60)
    print("Converting Service Port Groups...")
    print("-"*60)

    # Update the service group converter with the service name mapping
    service_group_converter.set_split_services(
        split_services=split_services,
        service_name_mapping=service_name_mapping,
        skipped_services=skipped_services
    )

    # Convert FortiGate service groups to FTD port groups
    port_groups = service_group_converter.convert()

    # Append converter-generated groups not derived from a FortiGate service
    # group (currently the "PING" group built for migrated ICMP ping services).
    extra_port_groups = service_converter.get_extra_port_groups()
    if extra_port_groups:
        port_groups.extend(extra_port_groups)
        for grp in extra_port_groups:
            print(f"  Added: {grp['name']} ({len(grp.get('objects', []))} members)")

    print(f"[OK] Converted {len(port_groups)} port groups")

    # Build set of service group names for policy converter
    service_groups = set()
    for group in port_groups:
        service_groups.add(group['name'])

    # ========================================================================
    # STEP 10: Convert firewall policies to access rules
    # ========================================================================
    print("\n" + "-"*60)
    print("Converting Firewall Policies...")
    print("-"*60)

    # Merge the address-object and address-group rename maps so policy
    # references follow collision renames (X -> X_2) for both kinds
    address_ref_mapping = dict(address_converter.get_address_name_mapping())
    address_ref_mapping.update(address_group_converter.get_group_name_mapping())

    # Update the policy converter with service, address, and interface mappings
    policy_converter.set_split_services(
        split_services=split_services,
        service_name_mapping=service_name_mapping,
        skipped_services=skipped_services,
        address_name_mapping=address_ref_mapping,
        skipped_addresses=address_converter.get_skipped_addresses(),
        address_groups=address_groups,
        service_groups=service_groups,
        service_group_name_mapping=service_group_converter.get_group_name_mapping(),
        interface_name_mapping=interface_name_mapping
    )

    # Convert FortiGate policies to FTD access rules
    access_rules = policy_converter.convert()
    disabled_access_rules = policy_converter.disabled_access_rules

    # Get statistics about the conversion
    policy_stats = policy_converter.get_statistics()
    print(f"[OK] Converted {policy_stats['total_rules']} access rules")
    print(f"  - PERMIT rules: {policy_stats['permit_rules']}")
    print(f"  - DENY rules: {policy_stats['deny_rules']}")
    if policy_stats.get('disabled_rules', 0) > 0:
        print(f"  - Converted as disabled (exported separately, not imported): "
              f"{policy_stats['disabled_rules']}")
    if policy_stats.get('fail_closed_skipped', 0) > 0:
        print(f"  - Skipped (all src/dst/services filtered - fail closed): "
              f"{policy_stats['fail_closed_skipped']}")

    # ========================================================================
    # STEP 11: Convert static routes
    # ========================================================================
    print("\n" + "-"*60)
    print("Converting Static Routes...")
    print("-"*60)

    # Convert FortiGate static routes to FTD route entries
    static_routes = route_converter.convert()

    # Get statistics about the conversion
    route_stats = route_converter.get_statistics()
    print(f"[OK] Converted {route_stats['total_routes']} static routes")
    if route_stats['blackhole_skipped'] > 0:
        print(f"  - Blackhole routes skipped: {route_stats['blackhole_skipped']}")
    if route_stats['other_skipped'] > 0:
        print(f"  - Other routes skipped: {route_stats['other_skipped']}")

    # ========================================================================
    # STEP 12: Prepare individual data structures for separate files
    # ========================================================================
    # Each object type gets its own file for easier, sequential import
    # No need to wrap in containers - each file contains just the array

    # ========================================================================
    # STEP 13: Write the output JSON files
    # ========================================================================
    print("\n" + "-"*60)
    print("Saving output files...")
    print("-"*60)

    # Generate output filenames based on the base name provided
    # If user specified "ftd_config", we create separate files for each object type
    address_objects_output = f"{args.output}_address_objects.json"
    address_groups_output = f"{args.output}_address_groups.json"
    service_objects_output = f"{args.output}_service_objects.json"
    service_groups_output = f"{args.output}_service_groups.json"
    access_rules_output = f"{args.output}_access_rules.json"
    disabled_rules_output = f"{args.output}_access_rules_disabled.json"
    static_routes_output = f"{args.output}_static_routes.json"
    physical_interfaces_output = f"{args.output}_physical_interfaces.json"
    subinterfaces_output = f"{args.output}_subinterfaces.json"
    etherchannels_output = f"{args.output}_etherchannels.json"
    bridge_groups_output = f"{args.output}_bridge_groups.json"
    security_zones_output = f"{args.output}_security_zones.json"
    summary_output = f"{args.output}_summary.json"

    # ------------------------------------------------------------------------
    # Export conversion metadata for downstream tools (importer/cleanup)
    # ------------------------------------------------------------------------
    metadata = build_conversion_metadata(args)
    metadata_path = f"{args.output}_metadata.json"
    write_json_file(metadata_path, metadata, pretty=args.pretty)
    print(f"[OK] Wrote metadata: {metadata_path}")


    generated_route_objects = getattr(route_converter, "generated_network_objects", None)
    if generated_route_objects:
        existing_names = {o.get("name") for o in network_objects if isinstance(o, dict)}
        # De-dup by name to keep output stable and avoid API conflicts on import
        for obj in generated_route_objects:
            obj_name = obj.get("name") if isinstance(obj, dict) else None
            if obj_name and obj_name not in existing_names:
                network_objects.append(obj)
                existing_names.add(obj_name)

    try:
        write_json_file(address_objects_output, network_objects, args.pretty)
        print(f"[OK] Address objects saved to: {address_objects_output}")

        write_json_file(address_groups_output, network_groups, args.pretty)
        print(f"[OK] Address groups saved to: {address_groups_output}")

        write_json_file(service_objects_output, port_objects, args.pretty)
        print(f"[OK] Service objects saved to: {service_objects_output}")

        write_json_file(service_groups_output, port_groups, args.pretty)
        print(f"[OK] Service groups saved to: {service_groups_output}")

        write_json_file(access_rules_output, access_rules, args.pretty)
        print(f"[OK] Access rules saved to: {access_rules_output}")

        # Rules disabled in the source config, converted for reference. Kept
        # out of the live import file because FDM cannot disable access rules
        # - importing one would make it ACTIVE.
        if disabled_access_rules:
            write_json_file(disabled_rules_output, disabled_access_rules, args.pretty)
            print(f"[OK] Disabled access rules saved to: {disabled_rules_output} "
                  f"(reference only - NOT imported)")

        write_json_file(static_routes_output, static_routes, args.pretty)
        print(f"[OK] Static routes saved to: {static_routes_output}")

        write_json_file(physical_interfaces_output, interface_results['physical_interfaces'], args.pretty)
        print(f"[OK] Physical interfaces saved to: {physical_interfaces_output}")

        write_json_file(subinterfaces_output, interface_results['subinterfaces'], args.pretty)
        print(f"[OK] Subinterfaces saved to: {subinterfaces_output}")

        write_json_file(etherchannels_output, interface_results['etherchannels'], args.pretty)
        print(f"[OK] EtherChannels saved to: {etherchannels_output}")

        write_json_file(bridge_groups_output, interface_results['bridge_groups'], args.pretty)
        print(f"[OK] Bridge groups saved to: {bridge_groups_output}")

        write_json_file(security_zones_output, interface_results.get('security_zones', []), args.pretty)
        print(f"[OK] Security zones saved to: {security_zones_output}")

        # ====================================================================
        # Save summary statistics
        # ====================================================================
        # Collect conversion failures from all converters
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
            conversion_failures["access_rules"] = policy_converter.failed_items

        total_failures = sum(len(v) for v in conversion_failures.values())

        summary = {
            "conversion_summary": {
                "interfaces": {
                    "physical_updated": intf_stats['physical_updated'],
                    "subinterfaces_created": intf_stats['subinterfaces_created'],
                    "etherchannels_created": intf_stats['etherchannels_created'],
                    "bridge_groups_created": intf_stats['bridge_groups_created'],
                    "security_zones_created": intf_stats['security_zones_created'],
                    "skipped": intf_stats['skipped']
                },
                "address_objects": len(network_objects),
                "address_groups": len(network_groups),
                "service_objects": {
                    "total": service_stats['total_objects'],
                    "tcp": service_stats['tcp_objects'],
                    "udp": service_stats['udp_objects'],
                    "split": service_stats['split_services']
                },
                "service_groups": len(port_groups),
                "access_rules": {
                    "total": policy_stats['total_rules'],
                    "permit": policy_stats['permit_rules'],
                    "deny": policy_stats['deny_rules'],
                    "disabled_exported": policy_stats.get('disabled_rules', 0),
                    "fail_closed_skipped": policy_stats.get('fail_closed_skipped', 0)
                },
                "static_routes": {
                    "total": route_stats['total_routes'],
                    "converted": route_stats['converted'],
                    "blackhole_skipped": route_stats['blackhole_skipped'],
                    "other_skipped": route_stats['other_skipped']
                },
                "total_failures": total_failures
            },
            "conversion_failures": conversion_failures
        }
        write_json_file(summary_output, summary, pretty=True)
        print(f"[OK] Summary saved to: {summary_output}")
        if total_failures > 0:
            print(f"[INFO] {total_failures} item(s) failed/skipped during conversion - see summary for details")

    except IOError as e:
        print("\n[ERROR] Could not write output files!")
        print(f"  Details: {e}")
        return 1

    # ========================================================================
    # STEP 14: Display final summary
    # ========================================================================
    print("\n" + "="*60)
    print("CONVERSION COMPLETE")
    print("="*60)
    print("\nOutput Files Created:")
    print(f"  1. {address_objects_output}")
    print(f"     - Network Objects: {len(network_objects)}")
    print(f"\n  2. {address_groups_output}")
    print(f"     - Network Groups: {len(network_groups)}")
    print(f"\n  3. {service_objects_output}")
    print(f"     - Port Objects: {service_stats['total_objects']}")
    print(f"       (TCP: {service_stats['tcp_objects']}, UDP: {service_stats['udp_objects']})")
    print(f"\n  4. {service_groups_output}")
    print(f"     - Port Groups: {len(port_groups)}")
    print(f"\n  5. {access_rules_output}")
    print(f"     - Access Rules: {policy_stats['total_rules']}")
    print(f"       (PERMIT: {policy_stats['permit_rules']}, DENY: {policy_stats['deny_rules']})")
    print(f"\n  6. {static_routes_output}")
    print(f"     - Static Routes: {route_stats['total_routes']}")
    print(f"       (Converted: {route_stats['converted']}, Skipped: {route_stats['blackhole_skipped'] + route_stats['other_skipped']})")
    print(f"\n  7. {summary_output}")
    print("     - Conversion statistics")
    print("\n" + "="*60)
    print("IMPORT ORDER FOR FTD FDM API:")
    print("="*60)
    print("  1. Import address objects first")
    print("  2. Import address groups second")
    print("  3. Import service objects third")
    print("  4. Import service groups fourth")
    print("  5. Import static routes fifth")
    print("  6. Import access rules last")
    print("\nThis order ensures referenced objects exist before importing")
    print("objects that reference them.")
    print("\n" + "="*60)

    return 0


# =============================================================================
# SCRIPT ENTRY POINT
# =============================================================================

# This is the entry point of the script
# When you run "python fortigate_converter.py", execution starts here
if __name__ == '__main__':
    sys.exit(main())
