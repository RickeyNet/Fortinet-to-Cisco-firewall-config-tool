#!/usr/bin/env python3
""
# FortiGate to Cisco FTD Address Object Converter
# ================================================
# This script parses FortiGate YAML configurations and converts address objects
# to JSON format suitable for Cisco FTD's Firewall Device Manager (FDM) API.

# REQUIREMENTS:
#     - Python 3.6 or higher
#     - PyYAML library (install with: pip install pyyaml)

# HOW TO RUN THIS SCRIPT:
#     1. Save this script as 'fortigate_converter.py'
#     2. Place your FortiGate YAML file in the SAME FOLDER as this script
#        (or note the full path to the file)
#     3. Open a terminal/command prompt
#     4. Navigate to the folder containing this script:
#         cd C:\path\to\your\folder
#     5. Run the script:
#        python fortigate_converter.py your_fortigate_config.yaml
    
#     EXAMPLES:
#     - If YAML file is in the same folder:
#       python fortigate_converter.py fortigate.yaml
    
#     - If YAML file is in a different location:
#       python fortigate_converter.py C:\configs\fortigate.yaml
    
#     - To specify output filename:
#       python fortigate_converter.py fortigate.yaml -o my_output.json
    
#     - To make output more readable (pretty print):
#       python fortigate_converter.py fortigate.yaml --pretty

# EXPECTED YAML FORMAT:
#     The script expects FortiGate configuration in YAML format like:
    
#     firewall_address:
#         - SSLVPN_TUNNEL_ADDR1:
#             uuid: d9a8d716-c01c-51e8-8211-e6f2d6bbbeb6
#             type: iprange
#             start-ip: 10.212.134.200
#             end-ip: 10.212.134.210
#         - LE-LO_IP-KVM:
#             uuid: 8dacf82a-c025-51e8-d369-474978483f63
#             associated-interface: "port2"
#             subnet: [10.0.0.4, 255.255.255.252]
#         - LE-POT_502-Rng:
#             uuid: 8de6f3fe-c025-51e8-2ed9-2728a00114e7
#             subnet: [10.0.2.0, 255.255.255.0]
#         - L_BLOCK_EAST_SVRS:
#             uuid: 9a1f0206-c025-51e8-4276-05657d04ce42
#             comment: "FUN"
#             subnet: [10.0.22.0, 255.255.255.0]
""

import yaml
import json
import argparse
import sys
from typing import Dict, List, Any
from pathlib import Path


class FortiGateToFTDConverter:
    """
    Main converter class that handles the transformation of FortiGate
    address objects into Cisco FTD FDM API compatible JSON format.
    """
    
    def __init__(self, fortigate_config: Dict[str, Any]):
        """
        Initialize the converter with FortiGate configuration data.
        
        Args:
            fortigate_config: Dictionary containing parsed FortiGate YAML config
        """
        self.fg_config = fortigate_config
        # This will store all converted FTD network objects
        self.ftd_network_objects = []
    
    def convert_address_objects(self) -> List[Dict]:
        """
        Convert FortiGate address objects to FTD network objects.
        
        This method processes the 'firewall.address' section of FortiGate config
        and converts each address entry into FTD's network object format.
        
        FortiGate address types supported:
        - subnet: Network address with subnet mask (e.g., "192.168.1.0 255.255.255.0")
        - start-ip/end-ip: IP address range (e.g., "192.168.1.10" to "192.168.1.20")
        - fqdn: Fully qualified domain name (e.g., "www.example.com")
        - Individual host IPs are treated as /32 networks
        
        Returns:
            List of dictionaries, each representing an FTD network object
        """
        # Navigate through the FortiGate config structure to find address objects
        # .get() is used to safely access nested keys without errors if they don't exist
        addresses = self.fg_config.get('firewall_address', {})
        
        # If no addresses found, return empty list
        if not addresses:
            print("Warning: No address objects found in FortiGate configuration")
            print("  Expected key: 'firewall_address'")
            return []
        
        network_objects = []
        
         # Process each FortiGate address object
        # Each 'addr_dict' looks like: {'OBJECT_NAME': {properties}}
        for addr_dict in addresses:
            # Extract the object name (it's the only key in the dictionary)
            # Example: {'SSLVPN_TUNNEL_ADDR1': {uuid: ..., type: ...}}
            object_name = list(addr_dict.keys())[0]

            # Extract the properties (the value associated with the object name)
            properties = addr_dict[object_name]
            
            # Create FTD network object structure
            # FTD FDM API expects objects in this specific format
            ftd_object = {
                "name": object_name,  # The object name from the YAML key
                "description": properties.get('comment', ''),  # Optional description
                "type": "networkobject",  # FTD object type (always 'networkobject' for addresses)
                "subType": self._determine_address_type(properties),  # Specific address type (HOST, NETWORK, RANGE)
                "value": self._extract_address_value(properties)  # The actual IP/network/range value
            }
            
            network_objects.append(ftd_object)
            
            # Print conversion details for user visibility
            print(f"  Converted: {object_name} -> {ftd_object['subType']} ({ftd_object['value']})")
        
        return network_objects
    
    def _determine_address_type(self, properties: Dict) -> str:
        """
        Determine the FTD address subType based on FortiGate address format.
        
        
        - If 'type' field exists and equals 'iprange' -> RANGE
        - If 'subnet' field exists:
            - Check if netmask is 255.255.255.255 -> HOST
            - Otherwise -> NETWORK
        
        FTD supports different address subtypes:
        - HOST: Single IP address (e.g., 192.168.1.10/32)
        - NETWORK: Network with CIDR notation (e.g., 192.168.1.0/24)
        - RANGE: IP address range (e.g., 192.168.1.10-192.168.1.20)
        
        Args:
            properties: Dictionary containing FortiGate address object properties
            
        Returns:
            String representing FTD subType
        """
        # Check if this is explicitly marked as an IP range
        if properties.get('type') == 'iprange':
            return "RANGE"
        
        # Check if subnet field exists
        elif 'subnet' in properties:
            # Subnet is a list: [IP, NETMASK]
            # Example: [10.0.0.4, 255.255.255.252] or [10.0.2.0, 255.255.255.0]
            subnet_list = properties['subnet']
            if len(subnet_list) >= 2:
                netmask = str(subnet_list[1])
                # If netmask is 255.255.255.255, it's a single host
                if netmask == '255.255.255.255':
                    return "HOST"
                else:
                    return "NETWORK"
            else:
                return "NETWORK"
        
        else:
            # Default to HOST if we can't determine type
            return "HOST"
    
    def _extract_address_value(self, properties: Dict) -> str:
        """
        Extract and format the address value from FortiGate format to FTD format.
        
        NEW LOGIC based on actual FortiGate YAML structure:
        - For iprange type: Extract start-ip and end-ip, format as "IP1-IP2"
        - For subnet: Extract from list [IP, NETMASK], convert to "IP/CIDR"
        
        Args:
            properties: Dictionary containing FortiGate address object properties
            
        Returns:
            Formatted string value suitable for FTD
        """
        # Check if this is an IP range type
        if properties.get('type') == 'iprange':
            # Extract start and end IPs
            start_ip = properties.get('start-ip', '')
            end_ip = properties.get('end-ip', '')
            # FTD expects: "192.168.1.10-192.168.1.20"
            return f"{start_ip}-{end_ip}"
        
        # Check if this has a subnet field
        elif 'subnet' in properties:
            # FortiGate subnet format is a list: [IP, NETMASK]
            # Example: [10.0.0.4, 255.255.255.252] or [10.0.2.0, 255.255.255.0]
            subnet_list = properties['subnet']
            
            if len(subnet_list) >= 2:
                ip_addr = str(subnet_list[0])
                netmask = str(subnet_list[1])
                # Convert netmask to CIDR notation
                cidr = self._netmask_to_cidr(netmask)
                # FTD expects: "10.0.0.4/30" or "10.0.2.0/24"
                return f"{ip_addr}/{cidr}"
            else:
                # If format is unexpected, return first element
                return str(subnet_list[0]) if subnet_list else ''
        
        else:
            # Fallback: return empty string if no recognized format
            print(f"  Warning: Could not extract address value from properties: {properties}")
            return ''
    
    def _netmask_to_cidr(self, netmask: str) -> int:
        """
        Convert subnet mask (e.g., 255.255.255.0) to CIDR notation (e.g., 24).
        
        This is necessary because FortiGate uses traditional netmask notation
        while FTD API expects CIDR notation.
        
        Args:
            netmask: Subnet mask in dotted decimal format (e.g., "255.255.255.0")
            
        Returns:
            Integer representing CIDR prefix length (e.g., 24)
        """
        # Convert netmask to binary and count the number of 1s
        # Example: 255.255.255.0 = 11111111.11111111.11111111.00000000 = 24 ones
        try:
            # Split netmask into octets and convert each to binary
            binary_str = ''.join([bin(int(x))[2:].zfill(8) for x in netmask.split('.')])
            # Count the '1' bits
            return binary_str.count('1')
        except:
            # If conversion fails, default to /32 (single host)
            print(f"Warning: Could not convert netmask '{netmask}', defaulting to /32")
            return 32
    
    def convert_all(self) -> Dict[str, Any]:
        """
        Perform the full conversion process.
        
        Currently only converts address objects, but structured to allow
        easy addition of other object types in the future.
        
        Returns:
            Dictionary containing all converted FTD objects in organized format
        """
        print("\nConverting FortiGate address objects...")
        self.ftd_network_objects = self.convert_address_objects()
        
        # Return structured output ready for FTD FDM API
        return {
            "network_objects": self.ftd_network_objects
        }


def main():
    """
    Main function that handles command-line arguments and orchestrates the conversion process.
    
    This function:
    1. Parses command-line arguments
    2. Loads the FortiGate YAML file
    3. Converts the configuration
    4. Saves the output as JSON
    5. Displays a summary
    """
    # Set up command-line argument parser
    # This allows users to specify input file, output file, and formatting options
    parser = argparse.ArgumentParser(
        description='Convert FortiGate YAML address objects to Cisco FTD FDM API JSON format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python fortigate_converter.py fortigate.yaml
  python fortigate_converter.py fortigate.yaml -o output.json
  python fortigate_converter.py fortigate.yaml --pretty
  python fortigate_converter.py C:\\configs\\fortigate.yaml -o C:\\output\\ftd.json --pretty
        """
    )
    
    # Required argument: input YAML file
    parser.add_argument('input_file', 
                       help='Path to FortiGate YAML configuration file')
    
    # Optional argument: output JSON file (defaults to ftd_config.json)
    parser.add_argument('-o', '--output', 
                       help='Output JSON file path (default: ftd_config.json)',
                       default='ftd_config.json')
    
    # Optional flag: pretty print the JSON output (makes it human-readable)
    parser.add_argument('-p', '--pretty', 
                       action='store_true',
                       help='Format JSON output with indentation for readability')
    
    # Parse the command-line arguments
    args = parser.parse_args()
    
    print("="*60)
    print("FortiGate to Cisco FTD Address Object Converter")
    print("="*60)
    
    # STEP 1: Load the FortiGate YAML configuration file
    print(f"\nLoading FortiGate configuration from: {args.input_file}")
    try:
        with open(args.input_file, 'r') as f:
            fg_config = yaml.safe_load(f)
        print("✓ YAML file loaded successfully")
    except FileNotFoundError:
        print(f"\n✗ ERROR: Input file '{args.input_file}' not found!")
        print("\nTroubleshooting:")
        print("  1. Check that the file path is correct")
        print("  2. If the file is in the same folder as this script, just use the filename")
        print("  3. If the file is elsewhere, provide the full path:")
        print("     Windows: C:\\path\\to\\file.yaml")
        print("     Mac/Linux: /path/to/file.yaml")
        return 1
    except yaml.YAMLError as e:
        print(f"\n✗ ERROR: Could not parse YAML file!")
        print(f"  Details: {e}")
        print("\nMake sure the file is valid YAML format")
        return 1
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        return 1
    
    # STEP 2: Convert the configuration
    print("\nInitializing converter...")
    converter = FortiGateToFTDConverter(fg_config)
    ftd_config = converter.convert_all()
    
    # STEP 3: Write the output JSON file
    print(f"\nWriting FTD configuration to: {args.output}")
    try:
        with open(args.output, 'w') as f:
            if args.pretty:
                # Pretty print: indented, readable format
                json.dump(ftd_config, f, indent=2)
            else:
                # Compact format: smaller file size
                json.dump(ftd_config, f)
        print("✓ JSON file created successfully")
    except IOError as e:
        print(f"\n✗ ERROR: Could not write output file!")
        print(f"  Details: {e}")
        return 1
    
    # STEP 4: Display conversion summary
    print("\n" + "="*60)
    print("CONVERSION COMPLETE")
    print("="*60)
    print(f"\nTotal Network Objects Converted: {len(ftd_config['network_objects'])}")
    print(f"\nOutput saved to: {args.output}")
    print("\nNext steps:")
    print("  1. Review the generated JSON file")
    print("  2. Use the JSON file with FTD FDM API to import objects")
    print("  3. Test the configuration in your FTD environment")
    print("\n" + "="*60)
    
    return 0


# This is the entry point of the script
# When you run "python fortigate_converter.py", execution starts here
if __name__ == '__main__':
    sys.exit(main())