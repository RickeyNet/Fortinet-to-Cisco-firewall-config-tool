#!/usr/bin/env python3
"""
FortiGate Address Group Converter Module
=========================================
This module handles the conversion of FortiGate address groups to 
Cisco FTD network object groups.

WHAT THIS MODULE DOES:
    - Parses FortiGate 'firewall_addrgrp' section from YAML
    - Extracts group name and member objects
    - Converts to FTD 'networkobjectgroup' format
    - Handles both single members and lists of members

FORTIGATE YAML FORMAT:
    firewall_addrgrp:
        - GROUP_NAME:
            uuid: xxxxx
            member: ["object1", "object2", "object3"]  # List of members
            color: 13  # Optional
        - ANOTHER_GROUP:
            member: "single_object"  # Single member (string, not list)

FTD JSON OUTPUT FORMAT:
    {
        "name": "GROUP_NAME",
        "isSystemDefined": false,
        "objects": [
            {"name": "object1", "type": "networkobject"},
            {"name": "object2", "type": "networkobject"}
        ],
        "type": "networkobjectgroup"
    }

IMPORTANT NOTES:
    - FortiGate 'member' can be either a STRING or a LIST
      Examples: member: "single_object" OR member: ["obj1", "obj2"]
    - We need to normalize this to always be a list for processing
    - FTD requires each member to be an object with 'name' and 'type' fields
    - The 'type' is always 'networkobject' for address group members
"""

from typing import Dict, List, Any, Optional, Set

from common import sanitize_name, build_group_lookup, flatten_group_members, first_item, dedupe_name


class AddressGroupConverter:
    """
    Converter class for transforming FortiGate address groups to FTD network groups.

    This class is responsible for:
    1. Reading the 'firewall_addrgrp' section from FortiGate YAML
    2. Extracting group names and their member objects
    3. FLATTENING nested groups (FTD doesn't allow groups inside groups)
    4. Converting to FTD's networkobjectgroup format
    5. Handling edge cases (empty groups, single vs multiple members)
    """

    def __init__(self, fortigate_config: Dict[str, Any],
                 address_name_mapping: Optional[Dict[str, str]] = None,
                 skipped_addresses: Optional[Set[str]] = None) -> None:
        """
        Initialize the converter with FortiGate configuration data.

        Args:
            fortigate_config: Dictionary containing the complete parsed FortiGate YAML
                             Expected to have a 'firewall_addrgrp' key with group data
            address_name_mapping: Dict from AddressConverter mapping original
                             sanitized address names to final FTD object names.
                             When provided, members are remapped through it and
                             members without a converted object are dropped.
            skipped_addresses: Sanitized names of addresses the AddressConverter
                             did not convert (defaults, invalid, ...) - these
                             are filtered out of groups.
        """
        # Store the entire FortiGate configuration
        # We'll extract what we need from this in the convert() method
        self.fg_config = fortigate_config

        # Address rename map / skip set from the AddressConverter
        self.address_name_mapping = address_name_mapping or {}
        self.skipped_addresses = skipped_addresses or set()

        # This will store the converted FTD network groups
        # Starts empty and gets populated by the convert() method
        self.ftd_network_groups = []

        # Mapping of original sanitized group name -> final FTD group name
        # (differs when a sanitization collision forced an X_2 rename).
        self.group_name_mapping: Dict[str, str] = {}

        # Track items that failed/were skipped during conversion
        self.failed_items = []

        # Build a lookup of group name -> member list for flattening nested groups
        self.group_members = build_group_lookup(
            self.fg_config.get('firewall_addrgrp', [])
        )
    
    def convert(self) -> List[Dict]:
        """
        Main conversion method - converts all FortiGate address groups to FTD format.
        
        CONVERSION PROCESS:
        1. Extract the 'firewall_addrgrp' list from FortiGate config
        2. Loop through each group entry
        3. Extract the group name (the dictionary key)
        4. Extract the group properties (uuid, member, color, etc.)
        5. Normalize the 'member' field to always be a list
        6. FLATTEN any nested groups (expand group members into individual objects)
        7. Create FTD networkobjectgroup structure
        8. Return the complete list of converted groups
        
        Returns:
            List of dictionaries, each representing an FTD network object group
        """
        # ====================================================================
        # STEP 1: Extract address groups from FortiGate configuration
        # ====================================================================
        address_groups = self.fg_config.get('firewall_addrgrp', [])
        
        if not address_groups:
            print("Warning: No address groups found in FortiGate configuration")
            print("  Expected key: 'firewall_addrgrp'")
            return []
        
        # This list will accumulate all converted groups
        network_groups = []

        # Track used names to deduplicate
        used_names: dict[str, int] = {}

        # ====================================================================
        # STEP 2: Process each FortiGate address group
        # ====================================================================
        for group_dict in address_groups:
            # ================================================================
            # STEP 2A/2B: Extract the group name and properties
            # ================================================================
            item = first_item(group_dict)
            if item is None:
                print("  Skipped: empty/malformed address group entry")
                continue
            group_name, properties = item
            base_group_name = sanitize_name(group_name)

            # Deduplicate: if this name was already used, append _2, _3, etc.
            # (generated names are registered so a literal X_2 can't collide)
            sanitized_group_name = dedupe_name(base_group_name, used_names)

            # ================================================================
            # STEP 2C: Extract and normalize the member list
            # ================================================================
            members_raw = properties.get('member', [])
            
            # Normalize to list format
            if isinstance(members_raw, str):
                members_list = [sanitize_name(members_raw)]
            elif isinstance(members_raw, list):
                members_list = [sanitize_name(m) for m in members_raw]
            else:
                print(f"  Warning: Group '{group_name}' has unexpected member format")
                members_list = []
            
            # ================================================================
            # STEP 2D: FLATTEN nested groups
            # ================================================================
            # FTD does NOT allow groups inside groups, so we need to expand
            # any nested groups into their individual objects
            flattened_members = flatten_group_members(members_list, self.group_members)

            # ================================================================
            # STEP 2E: Convert members to FTD object format
            # ================================================================
            # Filter out members the AddressConverter did not convert (factory
            # defaults, invalid objects) and follow collision renames - a
            # verbatim member would be a dangling reference on FDM import.
            ftd_members = []
            seen_members = set()
            for member_name in flattened_members:
                if member_name in self.skipped_addresses:
                    print(f"    Filtered out: {member_name} (address not migrated)")
                    continue
                if self.address_name_mapping:
                    final_name = self.address_name_mapping.get(member_name)
                    if final_name is None:
                        print(f"    Filtered out: {member_name} (no converted address object)")
                        continue
                else:
                    # No mapping supplied (standalone use) - keep legacy behavior
                    final_name = member_name
                if final_name in seen_members:
                    continue
                seen_members.add(final_name)
                member_obj = {
                    "name": final_name,
                    "type": "networkobject"
                }
                ftd_members.append(member_obj)

            # ================================================================
            # STEP 2F: Create the FTD network group structure
            # ================================================================
            # FDM rejects groups with no members - skip instead of exporting
            if not ftd_members:
                print(f"  Skipped: {group_name} (empty group - no valid members)")
                self.failed_items.append({
                    "name": str(group_name),
                    "reason": "empty group - no members were converted",
                    "config": properties,
                })
                continue

            # Record the rename so policies referencing the original name can
            # follow it to the final group (first occurrence wins).
            self.group_name_mapping.setdefault(base_group_name, sanitized_group_name)

            ftd_group = {
                "name": sanitized_group_name,
                "isSystemDefined": False,
                "objects": ftd_members,
                "type": "networkobjectgroup"
            }

            # Add the converted group to our result list
            network_groups.append(ftd_group)

            # ================================================================
            # STEP 2G: Print conversion details for user feedback
            # ================================================================
            original_count = len(members_list)
            final_count = len(ftd_members)
            
            if group_name != sanitized_group_name:
                print(f"  Converted: {group_name} -> {sanitized_group_name} ({final_count} members)", end="")
            else:
                print(f"  Converted: {sanitized_group_name} ({final_count} members)", end="")
            
            if final_count != original_count:
                print(f" [flattened from {original_count} entries]")
            else:
                print()
        
        # ====================================================================
        # STEP 3: Return all converted groups
        # ====================================================================
        self.ftd_network_groups = network_groups
        return network_groups


    def get_group_count(self) -> int:
        """
        Get the number of address groups that were converted.

        Returns:
            Integer count of converted groups
        """
        return len(self.ftd_network_groups)

    def get_group_name_mapping(self) -> Dict[str, str]:
        """Return {original sanitized group name: final FTD group name}."""
        return self.group_name_mapping
    
    def get_member_count(self, group_name: str) -> int:
        """
        Get the number of members in a specific converted group.
        
        Args:
            group_name: Name of the group to check
            
        Returns:
            Integer count of members, or -1 if group not found
        """
        # Search through converted groups to find the matching name
        for group in self.ftd_network_groups:
            if group['name'] == group_name:
                return len(group['objects'])
        
        # Group not found
        return -1


# =============================================================================
# TESTING CODE (for standalone testing of this module)
# =============================================================================

if __name__ == '__main__':
    """
    This code only runs when you execute this file directly.
    It's useful for testing the converter without running the main script.
    
    To test this module standalone:
        python address_group_converter.py
    """
    
    # Sample FortiGate configuration for testing
    # Includes nested groups to test flattening
    test_config = {
        'firewall_addrgrp': [
            {
                'Blocked IPs': {
                    'uuid': '11111111-2222-3333-8888-000000000005',
                    'member': ["BadIP1", "BadIP2", "BadIP3"]
                }
            },
            {
                'Switches': {
                    'uuid': '11111111-2222-3333-8888-000000000006',
                    'member': ["Switch1", "Switch2", "Switch3"]
                }
            },
            {
                'Servers': {
                    'uuid': '11111111-2222-3333-8888-000000000007',
                    'member': ["Server1", "Server2"]
                }
            },
            {
                'All_Network_Devices': {
                    'uuid': '11111111-2222-3333-8888-000000000008',
                    # This group contains OTHER GROUPS - needs to be flattened!
                    'member': ["Switches", "Servers", "Firewall1"]
                }
            },
            {
                'Everything': {
                    'uuid': '11111111-2222-3333-8888-000000000009',
                    # This group contains a group that contains groups - deep nesting!
                    'member': ["All_Network_Devices", "Blocked IPs", "SingleServer"]
                }
            }
        ]
    }
    
    # Create converter instance
    converter = AddressGroupConverter(test_config)
    
    # Run conversion
    print("Testing Address Group Converter with Nested Groups...")
    print("="*60)
    result = converter.convert()
    
    # Display results
    print("\nConversion Results:")
    print("="*60)
    import json
    print(json.dumps(result, indent=2))
    print("\n" + "="*60)
    print(f"Total groups converted: {len(result)}")
    
    # Show flattening results
    print("\nFlattening Summary:")
    print("-"*60)
    for group in result:
        print(f"  {group['name']}: {len(group['objects'])} members")