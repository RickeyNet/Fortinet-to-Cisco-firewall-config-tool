#!/usr/bin/env python3
"""
FortiGate Service Group Converter Module
=========================================
This module handles the conversion of FortiGate service groups to 
Cisco FTD port object groups.

IMPORTANT CONSIDERATION:
    - When a FortiGate service group references a service that was split
      into TCP and UDP objects (like "DNS" -> "DNS_TCP" and "DNS_UDP"),
      the group must include BOTH the TCP and UDP versions
    - This module assumes all member names are provided as-is from FortiGate
    - The main script should handle resolving split services

WHAT THIS MODULE DOES:
    - Parses FortiGate 'firewall_service_group' section from YAML
    - Extracts group name and member services
    - Converts to FTD 'portobjectgroup' format
    - Handles both single members and lists of members

FORTIGATE YAML FORMAT:
    firewall_service_group:
        - GROUP_NAME:
            uuid: xxxxx
            member: ["HTTP", "HTTPS", "DNS"]  # List of service names
            color: 13  # Optional
        - ANOTHER_GROUP:
            member: "single_service"  # Single member (string, not list)

FTD JSON OUTPUT FORMAT:
    {
        "name": "Web_Access",
        "isSystemDefined": false,
        "objects": [
            {"name": "HTTP_TCP", "type": "tcpportobject"},
            {"name": "HTTPS_TCP", "type": "tcpportobject"},
            {"name": "DNS_TCP", "type": "tcpportobject"},
            {"name": "DNS_UDP", "type": "udpportobject"}
        ],
        "type": "portobjectgroup"
    }

NOTE ON MEMBER TYPES:
    - We don't know in advance if a member is TCP or UDP
    - We include the member name as-is from FortiGate
    - The type field is set generically (could be refined in post-processing)
"""

from typing import Dict, List, Any, Optional, Set

from common import sanitize_name, build_group_lookup, flatten_group_members, first_item, dedupe_name


class ServiceGroupConverter:
    """
    Converter class for transforming FortiGate service groups to FTD port groups.
    
    This class is responsible for:
    1. Reading the 'firewall_service_group' section from FortiGate YAML
    2. Extracting group names and their member services
    3. FLATTENING nested groups (FTD doesn't allow groups inside groups)
    4. Converting to FTD's portobjectgroup format
    5. Handling edge cases (empty groups, single vs multiple members)
    6. Expanding services that were split into multiple FTD objects
    """
    
    def __init__(self, fortigate_config: Dict[str, Any],
                 split_services: Optional[Set[str]] = None,
                 service_name_mapping: Optional[Dict[str, List[str]]] = None,
                 skipped_services: Optional[Set[str]] = None) -> None:
        """
        Initialize the converter with FortiGate configuration data.
        
        Args:
            fortigate_config: Dictionary containing the complete parsed FortiGate YAML
                             Expected to have a 'firewall_service_group' key
            split_services: (DEPRECATED) Set of service names that were split into TCP and UDP
            service_name_mapping: Dict mapping FortiGate service names to list of FTD object names
                                 Example: {"LR_CLUST": ["LR_CLUST_TCP_1", "LR_CLUST_TCP_2", "LR_CLUST_UDP_3"]}
            skipped_services: Set of service names that were skipped (ICMP, etc.) and should be
                            filtered out of groups
        """
        # Store the entire FortiGate configuration
        self.fg_config = fortigate_config
        
        # DEPRECATED: Old way of tracking split services (kept for backward compatibility)
        self.split_services = split_services or set()
        
        # NEW: Mapping of FortiGate service name -> list of FTD object names
        # This handles services split into multiple ports AND TCP/UDP splits
        self.service_name_mapping = service_name_mapping or {}
        
        # Set of services that were skipped (ICMP, etc.) - filter these from groups
        self.skipped_services = skipped_services or set()

        # This will store the converted FTD port groups
        self.ftd_port_groups = []

        # Mapping of original sanitized group name -> final FTD group name
        # (differs when a sanitization collision forced an X_2 rename).
        self.group_name_mapping: Dict[str, str] = {}

        # Track items that failed/were skipped during conversion
        self.failed_items = []

        # Build a lookup of group name -> member list for flattening nested groups
        self.group_members = build_group_lookup(
            self.fg_config.get('firewall_service_group', [])
        )
    
    def convert(self) -> List[Dict]:
        """
        Main conversion method - converts all FortiGate service groups to FTD format.
        
        CONVERSION PROCESS:
        1. Extract the 'firewall_service_group' list from FortiGate config
        2. Loop through each group entry
        3. Extract the group name (the dictionary key)
        4. Extract the group properties (uuid, member, color, etc.)
        5. Normalize the 'member' field to always be a list
        6. Expand members that were split (add both _TCP and _UDP versions)
        7. Create FTD portobjectgroup structure
        8. Return the complete list of converted groups
        
        Returns:
            List of dictionaries, each representing an FTD port object group
        """
        # ====================================================================
        # STEP 1: Extract service groups from FortiGate configuration
        # ====================================================================
        service_groups = self.fg_config.get('firewall_service_group', [])
        
        if not service_groups:
            print("Warning: No service groups found in FortiGate configuration")
            print("  Expected key: 'firewall_service_group'")
            return []
        
        # This list will accumulate all converted groups
        port_groups = []

        # Track used names to deduplicate
        used_names: dict[str, int] = {}

        # ====================================================================
        # STEP 2: Process each FortiGate service group
        # ====================================================================
        for group_dict in service_groups:
            # ================================================================
            # STEP 2A/2B: Extract the group name and properties
            # ================================================================
            item = first_item(group_dict)
            if item is None:
                print("  Skipped: empty/malformed service group entry")
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
            # STEP 2E: Filter out skipped services (ICMP, etc.)
            # ================================================================
            filtered_members = []
            for member_name in flattened_members:
                if member_name in self.skipped_services:
                    print(f"    Filtered out: {member_name} (ICMP/non-port service)")
                else:
                    filtered_members.append(member_name)

            # ================================================================
            # STEP 2F: Expand members that were split into multiple FTD objects
            # ================================================================
            # expanded_members now contains tuples of (name, type)
            expanded_members = []
            
            for member_name in filtered_members:
                # Check if this service was split into multiple FTD objects
                if member_name in self.service_name_mapping:
                    # Use the mapping to get all FTD objects (list of (name, type) tuples)
                    ftd_objects = self.service_name_mapping[member_name]
                    expanded_members.extend(ftd_objects)
                    if len(ftd_objects) > 1:
                        print(f"    Expanded: {member_name} -> {len(ftd_objects)} objects")
                else:
                    # This service was not in our mapping - might be a built-in FTD service
                    # Try to determine type from name, default to TCP
                    if '_UDP' in member_name:
                        expanded_members.append((member_name, "udpportobject"))
                    else:
                        expanded_members.append((member_name, "tcpportobject"))
            
            # ================================================================
            # STEP 2G: Convert members to FTD object format
            # ================================================================
            ftd_members = []
            for member_info in expanded_members:
                # Handle both tuple format (name, type) and legacy string format
                if isinstance(member_info, tuple):
                    member_name, member_type = member_info
                else:
                    # Legacy fallback - shouldn't happen but just in case
                    member_name = member_info
                    if '_TCP' in member_name:
                        member_type = "tcpportobject"
                    elif '_UDP' in member_name:
                        member_type = "udpportobject"
                    else:
                        member_type = "tcpportobject"
                
                member_obj = {
                    "name": member_name,
                    "type": member_type
                }
                ftd_members.append(member_obj)
            
            # ================================================================
            # STEP 2H: Create the FTD port group structure
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
                "type": "portobjectgroup"
            }

            # Add the converted group to our result list
            port_groups.append(ftd_group)

            # ================================================================
            # STEP 2I: Print conversion details for user feedback
            # ================================================================
            original_count = len(members_list)
            final_count = len(ftd_members)
            
            if group_name != sanitized_group_name:
                print(f"  Converted: {group_name} -> {sanitized_group_name} ({final_count} members)", end="")
            else:
                print(f"  Converted: {sanitized_group_name} ({final_count} members)", end="")
            
            if final_count != original_count:
                print(f" [flattened/expanded from {original_count} entries]")
            else:
                print()
        
        # ====================================================================
        # STEP 3: Store results and return
        # ====================================================================
        self.ftd_port_groups = port_groups
        return port_groups
    
    def set_split_services(self, split_services: Optional[Set[str]] = None,
                           service_name_mapping: Optional[Dict[str, List[str]]] = None,
                           skipped_services: Optional[Set[str]] = None) -> None:

        """
        Update the service expansion information.
        
        This should be called by the main script after converting service objects,
        so the group converter knows which members need to be expanded.
        
        Args:
            split_services: (DEPRECATED) Set of service names that have both TCP and UDP versions
            service_name_mapping: Dict mapping FortiGate service names to list of FTD object names
            skipped_services: Set of service names that were skipped (ICMP, etc.) 
        """
        if split_services is not None:
            self.split_services = split_services
        if service_name_mapping is not None:
            self.service_name_mapping = service_name_mapping
        if skipped_services is not None:
            self.skipped_services = skipped_services
    
    def get_group_count(self) -> int:
        """
        Get the number of service groups that were converted.

        Returns:
            Integer count of converted groups
        """
        return len(self.ftd_port_groups)

    def get_group_name_mapping(self) -> Dict[str, str]:
        """Return {original sanitized group name: final FTD group name}."""
        return self.group_name_mapping


# =============================================================================
# TESTING CODE (for standalone testing of this module)
# =============================================================================

if __name__ == '__main__':
    """
    This code only runs when you execute this file directly.
    It's useful for testing the converter without running the main script.
    
    To test this module standalone:
        python service_group_converter.py
    """
    
    # Sample FortiGate configuration for testing
    test_config = {
        'firewall_service_group': [
            {
                'Email Access': {
                    'uuid': '11111111-2222-3333-8888-000000000013',
                    'member': ["DNS", "IMAP", "IMAPS", "POP3", "POP3S", "SMTP"]
                }
            },
            {
                'Web Access': {
                    'uuid': '11111111-2222-3333-8888-000000000013',
                    'member': ["DNS", "HTTP", "HTTPS"]
                }
            },
            {
                'Windows AD': {
                    'uuid': '11111111-2222-3333-8888-000000000013',
                    'member': ["DNS", "Kerberos", "SAMBA", "SMB"]
                }
            }
        ]
    }
    
    # Simulate that DNS and HTTPS were split into TCP and UDP
    split_services = {"DNS", "HTTPS"}
    
    # Create converter instance
    converter = ServiceGroupConverter(test_config, split_services)
    
    # Run conversion
    print("Testing Service Group Converter...")
    print("="*60)
    result = converter.convert()
    
    # Display results
    print("\nConversion Results:")
    print("="*60)
    import json
    print(json.dumps(result, indent=2))
    print("\n" + "="*60)
    print(f"Total groups converted: {len(result)}")