"""
FortiGate Address Object Converter Module
==========================================
This module handles the conversion of FortiGate address objects to 
Cisco FTD network objects.

WHAT THIS MODULE DOES:
    - Parses FortiGate 'firewall_address' section from YAML
    - Extracts address objects (subnets, IP ranges, hosts)
    - Converts subnet masks to CIDR notation
    - Converts to FTD 'networkobject' format

FORTIGATE YAML FORMAT:
    firewall_address:
        - OBJECT_NAME:
            uuid: xxxxx
            type: iprange  # Optional - only for IP ranges
            start-ip: 10.0.0.1  # For iprange type
            end-ip: 10.0.0.10   # For iprange type
            subnet: [10.0.0.0, 255.255.255.0]  # For networks/hosts
            comment: "Description"  # Optional

FTD JSON OUTPUT FORMAT:
    {
        "name": "OBJECT_NAME",
        "description": "Description",
        "type": "networkobject",
        "subType": "NETWORK",  # Can be: HOST, NETWORK, RANGE
        "value": "10.0.0.0/24"
    }
"""
from typing import Dict, List, Any, Set

from common import (
    sanitize_name,
    is_default_fortigate_address,
    first_item,
    dedupe_name,
    netmask_to_cidr,
)


class AddressConverter:
    """
    Converter class for transforming FortiGate address objects to FTD network objects.
    
    This class is responsible for:
    1. Reading the 'firewall_address' section from FortiGate YAML
    2. Identifying the address type (HOST, NETWORK, RANGE)
    3. Converting subnet masks to CIDR notation
    4. Formatting addresses for FTD API compatibility
    """
    
    def __init__(self, fortigate_config: Dict[str, Any]) -> None:
        """
        Initialize the converter with FortiGate configuration data.
        
        Args:
            fortigate_config: Dictionary containing the complete parsed FortiGate YAML
                             Expected to have a 'firewall_address' key with address data
        """
        # Store the entire FortiGate configuration
        # We'll extract what we need from this in the convert() method
        self.fg_config = fortigate_config
        
        # This will store the converted FTD network objects
        # Starts empty and gets populated by the convert() method
        self.ftd_network_objects = []

        # Track items that failed/were skipped during conversion
        self.failed_items = []

        # Mapping of original sanitized name -> final FTD object name
        # (differs when a sanitization collision forced an X_2 rename).
        # Consumed by group/policy converters so references follow renames.
        self.address_name_mapping: Dict[str, str] = {}

        # Sanitized names of addresses that were NOT converted (factory
        # defaults, invalid values, ...). Groups/policies filter these out
        # instead of emitting dangling references.
        self.skipped_addresses: Set[str] = set()

    def convert(self) -> List[Dict]:
        """
        Main conversion method - converts all FortiGate address objects to FTD format.
        
        CONVERSION PROCESS:
        1. Extract the 'firewall_address' list from FortiGate config
        2. Loop through each address entry
        3. Extract the object name (the dictionary key)
        4. Extract the object properties (uuid, type, subnet, etc.)
        5. Determine the address type (HOST, NETWORK, RANGE)
        6. Extract and format the address value
        7. Create FTD networkobject structure
        8. Return the complete list of converted objects
        
        Returns:
            List of dictionaries, each representing an FTD network object
        """
        # ====================================================================
        # STEP 1: Extract address objects from FortiGate configuration
        # ====================================================================
        # The .get() method safely retrieves the key, returning [] if not found
        # This prevents KeyError exceptions if the key doesn't exist
        addresses = self.fg_config.get('firewall_address', [])
        
        # Check if we found any address objects
        if not addresses:
            print("Warning: No address objects found in FortiGate configuration")
            print("  Expected key: 'firewall_address'")
            return []
        
        # This list will accumulate all converted objects
        network_objects = []

        # Track used names to deduplicate (e.g., names that sanitize to the same string)
        used_names: dict[str, int] = {}

        # ====================================================================
        # STEP 2: Process each FortiGate address object
        # ====================================================================
        # Each address in the list looks like: {'OBJECT_NAME': {properties}}
        # Process each FortiGate address object
        # Each address in the list looks like: {'OBJECT_NAME': {properties}}
        for addr_dict in addresses:
            # ================================================================
            # STEP 2A/2B: Extract the object name and properties
            # ================================================================
            # The object name is the only key in the dictionary
            # Example: {'SSLVPN_TUNNEL_ADDR1': {uuid: ..., type: ...}}
            # Properties include: uuid, type, subnet, start-ip, end-ip, comment, etc.
            item = first_item(addr_dict)
            if item is None:
                print("  Skipped: empty/malformed address entry")
                continue
            object_name, properties = item

            # ================================================================
            # STEP 2C: Validate the object name
            # ================================================================
            # Skip objects with invalid names
            
            # Check 0: Silently ignore FortiGate factory-default objects.
            # These exist on every appliance and are not meaningful to migrate,
            # so they are not reported as skipped/failed items.
            if is_default_fortigate_address(object_name):
                print(f"  Ignored: {object_name} (FortiGate default object)")
                self.skipped_addresses.add(sanitize_name(object_name))
                continue

            # Check 1: Skip if name is "none" (case-insensitive)
            if str(object_name).lower() == 'none':
                print(f"  Skipped: {object_name} (name is 'none')")
                self.skipped_addresses.add(sanitize_name(object_name))
                self.failed_items.append({"name": object_name, "reason": "name is 'none'", "config": properties})
                continue
            
            # Note: Objects named with just an IP address are allowed.
            # The IP is kept as the object name.
            
            # ================================================================
            # STEP 2D: Determine the address type (HOST, NETWORK, RANGE)
            # ================================================================
            # This method analyzes the properties to determine what kind of address this is
            address_type = self._determine_address_type(properties)
            
            # ================================================================
            # STEP 2E: Extract and format the address value
            # ================================================================
            # This method extracts the actual IP/network/range and formats it for FTD
            # Examples: "10.0.0.0/24", "192.168.1.10-192.168.1.20", "10.0.0.1/32"
            address_value = self._extract_address_value(properties)
            
            # ================================================================
            # STEP 2F: Validate the address value
            # ================================================================
            # Skip objects with empty or invalid values
            
            # Check 3: Skip if value is empty or just whitespace
            if not address_value or address_value.strip() == '':
                print(f"  Skipped: {object_name} (empty value)")
                self.skipped_addresses.add(sanitize_name(object_name))
                self.failed_items.append({"name": object_name, "reason": "empty value", "config": properties})
                continue

            # Check 4: Skip if value is malformed (no valid IP format)
            # FQDN values are domain names, not IPs - skip IP validation for them
            if address_type != "FQDN" and not self._is_valid_address_value(address_value):
                print(f"  Skipped: {object_name} (invalid value: {address_value})")
                self.skipped_addresses.add(sanitize_name(object_name))
                self.failed_items.append({"name": object_name, "reason": f"invalid value: {address_value}", "config": properties})
                continue
            
            # ================================================================
            # STEP 2G: Create the FTD network object structure
            # ================================================================
            # This is the final format that FTD FDM API expects
            # Sanitize the object name to replace spaces with underscores
            base_name = sanitize_name(object_name)

            # Deduplicate: if this name was already used, append _2, _3, etc.
            # (generated names are registered too, so a literal source object
            # named X_2 cannot collide with a generated X_2)
            sanitized_name = dedupe_name(base_name, used_names)

            # Record the rename so groups/policies referencing the original
            # name can follow it to the final object (first occurrence wins).
            self.address_name_mapping.setdefault(base_name, sanitized_name)

            ftd_object = {
                "name": sanitized_name,                           # Object name from FortiGate
                "description": properties.get('comment', ''),  # Optional description
                "type": "networkobject",                       # Always 'networkobject' for addresses
                "subType": address_type,                       # HOST, NETWORK, or RANGE
                "value": address_value                         # The formatted IP/network/range
            }

            # FDM FQDN objects require a dnsResolution field
            if address_type == "FQDN":
                ftd_object["dnsResolution"] = "IPV4_ONLY"

            # Add the converted object to our result list
            network_objects.append(ftd_object)
            
            # ================================================================
            # STEP 2H: Print conversion details for user feedback
            # ================================================================
            # This helps users see what's being converted in real-time
            if object_name != sanitized_name:
                print(f"  Converted: {object_name} -> {sanitized_name} [{address_type}] ({address_value})")
            else:
                print(f"  Converted: {sanitized_name} -> {address_type} ({address_value})")
        
        # ====================================================================
        # STEP 3: Return all converted objects
        # ====================================================================
        self.ftd_network_objects = network_objects
        return network_objects
    
    def _determine_address_type(self, properties: Dict) -> str:
        """
        Determine the FTD address subType based on FortiGate address format.
        
        LOGIC:
        1. If 'type' field exists and equals 'iprange' -> RANGE
        2. If 'subnet' field exists:
           - Check if netmask is 255.255.255.255 -> HOST (single IP)
           - Otherwise -> NETWORK (subnet)
        3. Default to HOST if we can't determine
        
        FTD ADDRESS SUBTYPES:
        - HOST: Single IP address (e.g., 192.168.1.10/32)
        - NETWORK: Network with CIDR notation (e.g., 192.168.1.0/24)
        - RANGE: IP address range (e.g., 192.168.1.10-192.168.1.20)
        
        Args:
            properties: Dictionary containing FortiGate address object properties
            
        Returns:
            String representing FTD subType ('HOST', 'NETWORK', or 'RANGE')
        """
        # ====================================================================
        # CHECK 1: Is this an explicit IP range?
        # ====================================================================
        # FortiGate marks IP ranges with type: iprange
        if properties.get('type') == 'iprange':
            # Get start and end IPs
            start_ip = str(properties.get('start-ip', ''))
            end_ip = str(properties.get('end-ip', ''))
    
            # If start-ip equals end-ip, this is actually a single host, not a range
            if start_ip and end_ip and start_ip == end_ip:
                print(f"    Note: IP range with same start/end IP ({start_ip}) - converting to HOST")
                return "HOST"
            else:
                return "RANGE"
        
        # ====================================================================
        # CHECK 2: Is this a subnet-based address?
        # ====================================================================
        # FortiGate uses 'subnet' field for both networks and hosts
        elif 'subnet' in properties:
            # Subnet is stored as a list: [IP_ADDRESS, NETMASK]
            # Example: [10.0.0.4, 255.255.255.252] or [10.0.2.0, 255.255.255.0]
            subnet_list = properties['subnet']
            
            # Make sure the subnet list has at least 2 elements
            if len(subnet_list) >= 2:
                # Convert to string in case it's not already
                netmask = str(subnet_list[1])
                
                # Check if this is a host address (/32)
                # A netmask of 255.255.255.255 means it's a single IP
                if netmask == '255.255.255.255':
                    return "HOST"
                else:
                    # Any other netmask means it's a network
                    return "NETWORK"
            else:
                # If subnet format is unexpected, default to NETWORK
                return "NETWORK"
        
        # ====================================================================
        # CHECK 3: Is this an FQDN address?
        # ====================================================================
        # FortiGate marks FQDN addresses with type: fqdn
        elif properties.get('type') == 'fqdn':
            return "FQDN"

        # ====================================================================
        # CHECK 4: Default fallback
        # ====================================================================
        # If we can't determine the type, default to HOST
        else:
            return "HOST"
    
    def _extract_address_value(self, properties: Dict) -> str:
        """
        Extract and format the address value from FortiGate format to FTD format.
        
        CONVERSION RULES:
        - For iprange type: "start-ip" and "end-ip" -> "IP1-IP2"
        - For subnet with /32: [IP, 255.255.255.255] -> "IP" (no /32 suffix for HOST)
        - For subnet with other mask: [IP, NETMASK] -> "IP/CIDR"
        
        EXAMPLES:
        - FortiGate: type: iprange, start-ip: 10.0.0.1, end-ip: 10.0.0.10
          FTD: "10.0.0.1-10.0.0.10"
        
        - FortiGate: subnet: [10.0.0.5, 255.255.255.255]
          FTD: "10.0.0.5" (no /32 for HOST)
        
        - FortiGate: subnet: [10.0.0.0, 255.255.255.0]
          FTD: "10.0.0.0/24"
        
        Args:
            properties: Dictionary containing FortiGate address object properties
            
        Returns:
            Formatted string value suitable for FTD (e.g., "10.0.0.0/24" or "10.0.0.5")
        """
        # ====================================================================
        # CASE 1: IP Range Type
        # ====================================================================
        # Check if this is an IP range (has start-ip and end-ip)
        if properties.get('type') == 'iprange':
            start_ip = str(properties.get('start-ip', ''))
            end_ip = str(properties.get('end-ip', ''))
    
            # If start-ip equals end-ip, return just the single IP (HOST format)
            if start_ip and end_ip and start_ip == end_ip:
                return start_ip
    
            # Otherwise, format for FTD range: "IP1-IP2"
            return f"{start_ip}-{end_ip}"
        
        # ====================================================================
        # CASE 2: Subnet Type (Network or Host)
        # ====================================================================
        # Check if this has a subnet field
        elif 'subnet' in properties:
            # FortiGate subnet format is a list: [IP_ADDRESS, NETMASK]
            # Examples:
            #   [10.0.0.4, 255.255.255.252] - a /30 network
            #   [10.0.2.0, 255.255.255.0]   - a /24 network
            #   [10.0.0.5, 255.255.255.255] - a /32 host
            subnet_list = properties['subnet']
            
            # Make sure we have both IP and netmask
            if len(subnet_list) >= 2:
                # Extract IP address and netmask
                ip_addr = str(subnet_list[0])
                netmask = str(subnet_list[1])
                
                # Convert netmask to CIDR notation
                # Example: 255.255.255.0 -> 24
                cidr = self._netmask_to_cidr(netmask)
                
                # ============================================================
                # IMPORTANT: HOST objects do NOT include /32 notation
                # ============================================================
                # Check if this is a host address (/32 or 255.255.255.255)
                # For HOST type, FTD expects just the IP without /32
                if netmask == '255.255.255.255' or cidr == 32:
                    # Return IP address without CIDR notation
                    # Example: "10.0.0.5" instead of "10.0.0.5/32"
                    return ip_addr
                else:
                    # Return network with CIDR notation
                    # Example: "10.0.2.0/24"
                    return f"{ip_addr}/{cidr}"
            else:
                # If format is unexpected, return just the first element
                return str(subnet_list[0]) if subnet_list else ''
        
        # ====================================================================
        # CASE 3: FQDN Type
        # ====================================================================
        elif properties.get('type') == 'fqdn':
            return str(properties.get('fqdn', ''))

        # ====================================================================
        # CASE 4: Fallback for unexpected formats
        # ====================================================================
        else:
            # This shouldn't happen with valid FortiGate config
            # Print a warning so the user knows something is unusual
            print(f"  Warning: Could not extract address value from properties: {properties}")
            return ''
    
    def _netmask_to_cidr(self, netmask: str) -> int:
        """
        Convert subnet mask to CIDR prefix length.
        
        This is necessary because FortiGate uses traditional dotted decimal
        netmasks (e.g., 255.255.255.0) while FTD API expects CIDR notation
        (e.g., /24).
        
        CONVERSION LOGIC:
        1. Split netmask into 4 octets (e.g., "255.255.255.0" -> [255, 255, 255, 0])
        2. Convert each octet to 8-bit binary
        3. Concatenate all binary strings
        4. Count the number of '1' bits
        
        EXAMPLES:
        - 255.255.255.0 = 11111111.11111111.11111111.00000000 = 24 ones = /24
        - 255.255.255.252 = 11111111.11111111.11111111.11111100 = 30 ones = /30
        - 255.255.255.255 = 11111111.11111111.11111111.11111111 = 32 ones = /32
        - 255.255.0.0 = 11111111.11111111.00000000.00000000 = 16 ones = /16
        
        Args:
            netmask: Subnet mask in dotted decimal format (e.g., "255.255.255.0")

        Returns:
            Integer representing CIDR prefix length (e.g., 24)
        """
        # Shared implementation (warns and defaults to /32 on invalid input)
        return netmask_to_cidr(netmask)
    
    def _is_valid_address_value(self, value: str) -> bool:
        """
        Validate that an address value is properly formatted.
        
        Valid formats:
        - IP with CIDR: "10.0.0.0/24"
        - IP range: "10.0.0.1-10.0.0.10"
        - Single IP with /32: "10.0.0.1/32"
        
        Invalid formats:
        - Empty string: ""
        - Just a slash: "/"
        - Malformed: "/24" or "10.0.0.0/"
        
        Args:
            value: The address value to validate
            
        Returns:
            True if valid, False otherwise
        """
        if not value or value.strip() == '':
            return False
        
        # Check for CIDR notation (IP/prefix)
        if '/' in value:
            parts = value.split('/')
            if len(parts) != 2:
                return False
            
            ip_part = parts[0].strip()
            cidr_part = parts[1].strip()
            
            # IP part should not be empty
            if not ip_part:
                return False
            
            # CIDR part should be a number
            if not cidr_part.isdigit():
                return False
            
            # CIDR should be 0-32 for IPv4
            cidr_num = int(cidr_part)
            if cidr_num < 0 or cidr_num > 32:
                return False
            
            # IP should have at least one dot (IPv4)
            if '.' not in ip_part:
                return False
        
        # Check for range notation (IP1-IP2)
        elif '-' in value:
            parts = value.split('-')
            if len(parts) != 2:
                return False
            
            # Both parts should look like IPs
            for part in parts:
                if not part.strip() or '.' not in part:
                    return False
        
        # Single value should at least have a dot (IPv4)
        else:
            if '.' not in value:
                return False
        
        return True
    
    def get_object_count(self) -> int:
        """
        Get the number of address objects that were converted.

        Returns:
            Integer count of converted objects
        """
        return len(self.ftd_network_objects)

    def get_address_name_mapping(self) -> Dict[str, str]:
        """Return {original sanitized name: final FTD object name}."""
        return self.address_name_mapping

    def get_skipped_addresses(self) -> Set[str]:
        """Return the sanitized names of addresses that were not converted."""
        return self.skipped_addresses


# =============================================================================
# TESTING CODE (for standalone testing of this module)
# =============================================================================

if __name__ == '__main__':
    """
    This code only runs when you execute this file directly.
    It's useful for testing the converter without running the main script.
    
    To test this module standalone:
        python address_converter.py
    """
    
    # Sample FortiGate configuration for testing
    test_config = {
        'firewall_address': [
            {
                'SSLVPN_TUNNEL_ADDR1': {
                    'uuid': 'd9a8d716-c01c-51e8-8211-e6f2d6bbbeb6',
                    'type': 'iprange',
                    'start-ip': '10.212.134.200',
                    'end-ip': '10.212.134.210'
                }
            },
            {
                'LE-AT_IP-KVM': {
                    'uuid': '8dacf82a-c025-51e8-d369-474978483f63',
                    'associated-interface': 'port2',
                    'subnet': ['10.0.0.4', '255.255.255.252']
                }
            },
            {
                'LE-POT_502-Rng': {
                    'uuid': '8de6f3fe-c025-51e8-2ed9-2728a00114e7',
                    'associated-interface': 'port3',
                    'subnet': ['10.0.2.0', '255.255.255.0']
                }
            },
            {
                'L_BLOCK_EAST_SVRS': {
                    'uuid': '9a1f0206-c025-51e8-4276-05657d04ce42',
                    'comment': 'FUN',
                    'color': 13,
                    'subnet': ['10.0.22.0', '255.255.255.0']
                }
            }
        ]
    }
    
    # Create converter instance
    converter = AddressConverter(test_config)
    
    # Run conversion
    print("Testing Address Converter...")
    print("="*60)
    result = converter.convert()
    
    # Display results
    print("\nConversion Results:")
    print("="*60)
    import json
    print(json.dumps(result, indent=2))
    print("\n" + "="*60)
    print(f"Total objects converted: {len(result)}")