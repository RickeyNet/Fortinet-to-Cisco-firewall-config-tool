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
    
#     firewall:
#       address:
#         - name: "Server1"
#           subnet: "192.168.1.10 255.255.255.255"
#           comment: "Production web server"
#         - name: "Network1"
#           subnet: "10.0.0.0 255.255.0.0"
#         - name: "ServerRange"
#           start-ip: "192.168.1.10"
#           end-ip: "192.168.1.20"
#         - name: "WebServer"
#           fqdn: "www.example.com"
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
        addresses = self.fg_config.get('firewall', {}).get('address', [])
        
        # If no addresses found, return empty list
        if not addresses:
            print("Warning: No address objects found in FortiGate configuration")
            return []
        
        network_objects = []
        
        # Process each FortiGate address object
        for addr in addresses:
            # Create FTD network object structure
            # FTD FDM API expects objects in this specific format
            ftd_object = {
                "name": addr.get('name', 'Unnamed'),  # Object name (required by FTD)
                "description": addr.get('comment', ''),  # Optional description
                "type": "networkobject",  # FTD object type (always 'networkobject' for addresses)
                "subType": self._determine_address_type(addr),  # Specific address type (HOST, NETWORK, etc.)
                "value": self._extract_address_value(addr)  # The actual IP/network/FQDN value
            }
            
            network_objects.append(ftd_object)
            
            # Print conversion details for user visibility
            print(f"  Converted: {addr.get('name')} -> {ftd_object['subType']} ({ftd_object['value']})")
        
        return network_objects
    
    def _determine_address_type(self, addr: Dict) -> str:
        """
        Determine the FTD address subType based on FortiGate address format.
        
        FTD supports different address subtypes:
        - HOST: Single IP address (e.g., 192.168.1.10)
        - NETWORK: Network with CIDR notation (e.g., 192.168.1.0/24)
        - RANGE: IP address range (e.g., 192.168.1.10-192.168.1.20)
        - FQDN: Domain name (e.g., www.example.com)
        
        Args:
            addr: Dictionary containing FortiGate address object data
            
        Returns:
            String representing FTD subType
        """
        # Check which format the FortiGate address uses
        if 'subnet' in addr:
            # FortiGate subnet format: "IP NETMASK"
            # We'll convert this to CIDR for FTD
            subnet_value = addr['subnet']
            # Check if it's a host (/32) or actual network
            if '255.255.255.255' in subnet_value:
                return "HOST"
            else:
                return "NETWORK"
        elif 'start-ip' in addr and 'end-ip' in addr:
            # FortiGate IP range format
            return "RANGE"
        elif 'fqdn' in addr:
            # FortiGate FQDN format
            return "FQDN"
        else:
            # Default to HOST if we can't determine type
            return "HOST"
    
    def _extract_address_value(self, addr: Dict) -> str:
        """
        Extract and format the address value from FortiGate format to FTD format.
        
        This method converts FortiGate's address notation to FTD's expected format:
        - FortiGate uses "IP NETMASK" -> FTD uses "IP/CIDR"
        - FortiGate uses separate start-ip/end-ip -> FTD uses "IP1-IP2"
        
        Args:
            addr: Dictionary containing FortiGate address object data
            
        Returns:
            Formatted string value suitable for FTD
        """
        if 'subnet' in addr:
            # FortiGate subnet format: "192.168.1.0 255.255.255.0"
            # We need to convert to CIDR: "192.168.1.0/24"
            subnet_parts = addr['subnet'].split()
            if len(subnet_parts) == 2:
                ip_addr = subnet_parts[0]
                netmask = subnet_parts[1]
                # Convert netmask to CIDR notation
                cidr = self._netmask_to_cidr(netmask)
                return f"{ip_addr}/{cidr}"
            else:
                # If format is unexpected, return as-is
                return addr['subnet']
        
        elif 'start-ip' in addr and 'end-ip' in addr:
            # FortiGate range format: separate start-ip and end-ip fields
            # FTD expects: "192.168.1.10-192.168.1.20"
            return f"{addr['start-ip']}-{addr['end-ip']}"
        
        elif 'fqdn' in addr:
            # FQDN format is the same in both systems
            return addr['fqdn']
        
        else:
            # Fallback: check for generic 'ip' field or return empty string
            return addr.get('ip', '')
    
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