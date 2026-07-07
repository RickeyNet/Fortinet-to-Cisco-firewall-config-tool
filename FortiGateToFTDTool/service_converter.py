#!/usr/bin/env python3
"""
FortiGate Service Port Object Converter Module
===============================================
This module handles the conversion of FortiGate service custom objects to 
Cisco FTD port objects (TCP and UDP).

CRITICAL RULES FOR CISCO FTD:
    1. TCP and UDP must be in SEPARATE objects
    2. Each object can only have ONE port or ONE port range
    3. Multiple ports/ranges must be split into separate objects

WHAT THIS MODULE DOES:
    - Parses FortiGate 'firewall_service_custom' section from YAML
    - Extracts service objects (TCP ports, UDP ports, or both)
    - Splits services with both TCP and UDP into separate objects
    - Splits multiple ports/ranges into separate objects (with _1, _2, etc. suffixes)
    - Converts to FTD 'tcpportobject' and 'udpportobject' formats

FORTIGATE YAML FORMAT:
    firewall_service_custom:
        - SERVICE_NAME:
            uuid: xxxxx
            tcp-portrange: 80  # Single port
            tcp-portrange: 80-443  # Port range
            tcp-portrange: [80, 443, 8080]  # Multiple ports (list)
            tcp-portrange: [80-443, 8080-8090]  # Multiple ranges (list)
            tcp-portrange: 443:1024-65535  # Destination 443 restricted to
                                           # SOURCE ports 1024-65535 (the
                                           # source part cannot be migrated
                                           # to FTD port objects)

CONVERSION EXAMPLES:
    FortiGate: LR_CLUST with tcp-portrange: [8300-8301, 8500-8501, 8086]
    
    FTD Output:
        LR_CLUST_TCP_1: port 8300-8301
        LR_CLUST_TCP_2: port 8500-8501
        LR_CLUST_TCP_3: port 8086

FTD JSON OUTPUT FORMAT:
    {
        "name": "LR_CLUST_TCP_1",
        "isSystemDefined": false,
        "port": "8300-8301",
        "type": "tcpportobject"
    }
"""

from typing import Dict, List, Any, Optional, Set, Tuple

from common import sanitize_name, is_default_fortigate_service, first_item, dedupe_name

# FTD System-Defined Services - these names are reserved and cannot be used
# If a FortiGate service has the same name, we'll add "_Custom" suffix
FTD_BUILTIN_UDP_SERVICES = {
    'DNS': '53',           # DNS over UDP
    'NFSD_UDP': '2049',
    'NTP_UDP': '123',
    'RADIUS': '1645',
    'RIP': '520',
    'SIP': '5060',
    'SNMP': '161',
    'SYSLOG': '514',
    'TFTP': '69',
}

FTD_BUILTIN_TCP_SERVICES = {
    'AOL': '5190',
    'Bittorrent': '6881-6889',
    'DNS': '53',           # DNS over TCP
    'FTP': '21',
    'HTTP': '80',
    'HTTPS': '443',
    'IMAP': '143',
    'LDAP': '389',
    'NFSD_TCP': '2049',
    'NTP_TCP': '123',
    'POP_2': '109',
    'POP_3': '110',
    'SMTP': '25',
    'SMTPS': '465',
    'SSH': '22',
    'TELNET': '23',
}

FTD_BUILTIN_SERVICES = set()
for name in FTD_BUILTIN_UDP_SERVICES.keys():
    FTD_BUILTIN_SERVICES.add(sanitize_name(name))
for name in FTD_BUILTIN_TCP_SERVICES.keys():
    FTD_BUILTIN_SERVICES.add(sanitize_name(name))

# =============================================================================
# ICMP "PING" handling
# =============================================================================
# FortiGate ICMP "ping" services (the predefined PING service, or any custom
# ICMP service with icmptype 8 / echo request) cannot become TCP/UDP port
# objects. Instead of dropping them, we migrate ping to two FTD ICMPv4 port
# objects -- echo request and echo reply -- grouped into a port object group
# called "PING". The group is what policies/groups referencing ping resolve to.
PING_GROUP_NAME = "PING"
PING_ECHO_REQUEST_NAME = "ICMP_Echo_Request"
PING_ECHO_REPLY_NAME = "ICMP_Echo_Reply"

class ServiceConverter:
    """
    Converter class for transforming FortiGate service objects to FTD port objects.
    
    This class is responsible for:
    1. Reading the 'firewall_service_custom' section from FortiGate YAML
    2. Identifying TCP and UDP port ranges
    3. Splitting services with both TCP and UDP into separate objects
    4. Splitting multiple ports/ranges into separate objects
    5. Formatting ports for FTD API compatibility
    6. Handling special protocols (IP, ICMP, etc.)
    """
    
    def __init__(self, fortigate_config: Dict[str, Any]) -> None:
        """
        Initialize the converter with FortiGate configuration data.
        
        Args:
            fortigate_config: Dictionary containing the complete parsed FortiGate YAML
                             Expected to have a 'firewall_service_custom' key
        """
        # Store the entire FortiGate configuration
        self.fg_config = fortigate_config
        
        # This will store the converted FTD port objects
        # Both TCP and UDP objects will be stored here
        self.ftd_port_objects = []
        
        # Track statistics for reporting
        self.tcp_count = 0
        self.udp_count = 0
        self.split_count = 0  # Services that were split into TCP and UDP
        self.multi_port_split_count = 0  # Services split due to multiple ports
        self.skipped_count = 0  # Services that couldn't be converted
        self.icmp_skipped_count = 0 # ICMP/non-port services skipped
        self.ping_service_count = 0 # ICMP ping (echo) services migrated to PING group

        # ICMPv4 port objects (echo request / echo reply) created for ping, plus
        # the "PING" port object group that holds them. Built once, on demand,
        # the first time a ping service is encountered.
        self.icmp_port_objects: List[Dict] = []
        self.ping_group: Dict = {}

        # Mapping of FortiGate service name -> list of (FTD name, type) tuples
        # Used by ServiceGroupConverter to expand group members correctly
        self.service_name_mapping: Dict[str, List[Tuple[str, str]]] = {}
        # Set of service names that were skipped (ICMP, etc.)
        # Used by ServiceGroupConverter to filter these out of groups
        self.skipped_services = set()

        # Track items that failed/were skipped during conversion
        self.failed_items = []
    
    def _parse_port_list(self, port_value: Any, service_name: Optional[str] = None) -> List[str]:
        """
        Parse FortiGate port value into a list of individual ports/ranges.

        FortiGate can specify ports as:
        - Single int: 80
        - Single string: "80" or "80-443"
        - String with source-port restriction: "443:1024-65535"
          (DESTINATION port(s) before the colon, SOURCE port(s) after it)
        - List: [80, 443, 8080] or ["80-90", "443-445"]
        - List of mixed: [8300-8301, 8500-8501, 8086]

        FTD port objects cannot express FortiGate source-port restrictions.
        The destination part before ':' is converted; the source part is
        DROPPED and recorded in failed_items so the loss is visible (dropping
        only the source restriction never broadens the destination match).

        Args:
            port_value: The port value from FortiGate config
            service_name: Original service name (for failed_items reporting)

        Returns:
            List of individual port strings (each suitable for one FTD object)
        """
        if port_value is None:
            return []

        def _dest_only(item_str: str) -> str:
            """Strip a 'dst:src' source-port restriction, keeping the dst part."""
            if ':' not in item_str:
                return item_str
            dst_part, src_part = item_str.split(':', 1)
            dst_part = dst_part.strip()
            src_part = src_part.strip()
            print(f"    Warning: {service_name or 'service'} port range '{item_str}' has a "
                  f"source-port restriction - keeping destination '{dst_part}', "
                  f"dropping source ports '{src_part}'")
            self.failed_items.append({
                "name": service_name or "unknown",
                "reason": f"source-port restriction not migrated "
                          f"(kept destination port(s) '{dst_part}', dropped source port(s) '{src_part}')",
                "config": {"portrange": item_str},
            })
            return dst_part

        # Normalize to a list of raw string tokens
        if isinstance(port_value, list):
            raw_items = [str(item) for item in port_value]
        else:
            raw_items = [str(port_value)]

        ports = [_dest_only(item) for item in raw_items]

        # Clean up each port (strip whitespace)
        ports = [p.strip() for p in ports if p.strip()]

        return ports
    
    def _is_ping_service(self, service_name: str, properties: Dict[str, Any],
                         protocol: str, protocol_number: Any) -> bool:
        """
        Decide whether a FortiGate service is an ICMP "ping" (echo) service.

        A service qualifies as ping only if it actually IS an ICMPv4 service:
        either named PING with an ICMP protocol, or any ICMP service whose
        icmptype is 8 (echo request). FortiGate stores the predefined PING
        service as protocol ICMP with icmptype 8. A TCP/UDP service that merely
        happens to be named "ping" is NOT converted to ICMP objects.

        Args:
            service_name: Original FortiGate service name
            properties: The service's property dict
            protocol: Uppercased 'protocol' value
            protocol_number: Raw 'protocol-number' value (if any)

        Returns:
            True if this service should be migrated as the PING port group.
        """
        # ICMPv4 only (protocol 1). ICMPv6 (58) is left for the normal skip path.
        is_icmpv4 = protocol in ('ICMP', 'PING') or protocol_number in (1, '1')
        if not is_icmpv4:
            return False

        if sanitize_name(service_name).upper() == PING_GROUP_NAME:
            return True

        # icmptype 8 == echo request == ping. Compare loosely (int or string).
        icmptype = properties.get('icmptype', properties.get('icmp-type'))
        return str(icmptype).strip() == '8'

    def _ensure_ping_objects(self) -> List[tuple]:
        """
        Build the two ICMPv4 echo port objects and the PING group, once.

        Returns:
            List of (object name, FTD type) tuples for the echo request/reply
            objects, suitable for use in service_name_mapping so that groups and
            policies referencing a ping service expand to these objects.
        """
        members = [
            (PING_ECHO_REQUEST_NAME, "icmpv4portobject"),
            (PING_ECHO_REPLY_NAME, "icmpv4portobject"),
        ]

        if not self.icmp_port_objects:
            self.icmp_port_objects = [
                {
                    "name": PING_ECHO_REQUEST_NAME,
                    "isSystemDefined": False,
                    "icmpv4Type": "ECHO_REQUEST",
                    "type": "icmpv4portobject",
                },
                {
                    "name": PING_ECHO_REPLY_NAME,
                    "isSystemDefined": False,
                    "icmpv4Type": "ECHO_REPLY",
                    "type": "icmpv4portobject",
                },
            ]
            self.ping_group = {
                "name": PING_GROUP_NAME,
                "isSystemDefined": False,
                "objects": [
                    {"name": name, "type": otype} for name, otype in members
                ],
                "type": "portobjectgroup",
            }

        return members

    def get_icmp_port_objects(self) -> List[Dict]:
        """Return the ICMPv4 echo port objects created for ping (may be empty)."""
        return self.icmp_port_objects

    def get_extra_port_groups(self) -> List[Dict]:
        """
        Return port object groups created by this converter that are not derived
        from a FortiGate service group -- currently just the "PING" group.
        """
        return [self.ping_group] if self.ping_group else []

    def convert(self) -> List[Dict]:
        """
        Main conversion method - converts all FortiGate services to FTD port objects.
        
        CONVERSION PROCESS:
        1. Extract the 'firewall_service_custom' list from FortiGate config
        2. Loop through each service entry
        3. Extract the service name and properties
        4. Parse TCP and UDP port lists
        5. Create separate FTD port objects for EACH port/range
        6. Handle special protocols (IP, ICMP) - skip them
        7. Return the complete list of converted port objects
        
        Returns:
            List of dictionaries, each representing an FTD port object
        """
        # ====================================================================
        # STEP 1: Extract service objects from FortiGate configuration
        # ====================================================================
        services = self.fg_config.get('firewall_service_custom', [])
        
        if not services:
            print("Warning: No service objects found in FortiGate configuration")
            print("  Expected key: 'firewall_service_custom'")
            return []
        
        # This list will accumulate all converted port objects
        port_objects = []

        # Track used names to deduplicate
        used_names: dict[str, int] = {}

        # ====================================================================
        # STEP 2: Process each FortiGate service object
        # ====================================================================
        for service_dict in services:
            # ================================================================
            # STEP 2A: Extract the service name and properties
            # ================================================================
            item = first_item(service_dict)
            if item is None:
                print("  Skipped: empty/malformed service entry")
                continue
            service_name, properties = item
            base_name = sanitize_name(service_name)
            sanitized_name = base_name

            # Silently ignore FortiGate factory-default services (e.g. "ALL").
            # These exist on every appliance and are not meaningful to migrate,
            # so they are not reported as skipped/failed items. They are still
            # registered as skipped so any group referencing them is cleaned up.
            if is_default_fortigate_service(service_name):
                print(f"  Ignored: {service_name} (FortiGate default service)")
                self.skipped_services.add(sanitized_name)
                continue

            # Deduplicate: if this base name was already used, append _2, _3, etc.
            # (generated names are registered so a literal X_2 can't collide)
            sanitized_name = dedupe_name(base_name, used_names)

            # ================================================================
            # STEP 2B: Check the protocol type
            # ================================================================
            protocol = str(properties.get('protocol', '')).upper()
            protocol_number = properties.get('protocol-number', None)

            # ============================================================
            # Migrate ICMP "ping" (echo) services to the PING port group
            # ============================================================
            # Build two ICMPv4 port objects (echo request + echo reply) and a
            # "PING" port object group, then map this service to those objects
            # so any group/policy referencing ping stays valid. This must run
            # before the ICMP skip blocks below.
            if self._is_ping_service(service_name, properties, protocol, protocol_number):
                ping_members = self._ensure_ping_objects()
                self.service_name_mapping[sanitized_name] = ping_members
                if base_name != sanitized_name:
                    # Renamed on collision: keep the original-name lookup working
                    self.service_name_mapping.setdefault(base_name, ping_members)
                self.ping_service_count += 1
                print(f"  Converted: {service_name} -> {PING_GROUP_NAME} group "
                      f"(ICMP echo request + echo reply)")
                continue

            # List of protocols to skip (not port-based services)
            skip_protocols = ['IP', 'ICMP', 'ICMP6', 'ICMPV6', 'IPIP', 'GRE', 'ESP', 'AH']

            if protocol in skip_protocols:
                print(f"  Skipped: {service_name} (Protocol: {protocol} - not a port-based service)")
                self.icmp_skipped_count += 1
                self.skipped_services.add(sanitized_name)
                self.failed_items.append({"name": service_name, "reason": f"Protocol: {protocol} - not a port-based service", "config": properties})
                continue
            
            # Also check for ICMP-specific fields (some FortiGate configs use these)
            if 'icmptype' in properties or 'icmpcode' in properties:
                print(f"  Skipped: {service_name} (ICMP service - not supported in FTD port objects)")
                self.icmp_skipped_count += 1
                self.skipped_services.add(sanitized_name)
                self.failed_items.append({"name": service_name, "reason": "ICMP service - not supported in FTD port objects", "config": properties})
                continue
            
            # Check if protocol-number field indicates ICMP (protocol 1) or ICMPv6 (protocol 58)
            if protocol_number in [1, 58, '1', '58']:
                print(f"  Skipped: {service_name} (ICMP protocol number {protocol_number})")
                self.icmp_skipped_count += 1
                self.skipped_services.add(sanitized_name)
                self.failed_items.append({"name": service_name, "reason": f"ICMP protocol number {protocol_number}", "config": properties})
                continue
            
            # ================================================================
            # STEP 2C: Parse TCP and UDP port lists
            # ================================================================
            tcp_ports = self._parse_port_list(properties.get('tcp-portrange', None), service_name)
            udp_ports = self._parse_port_list(properties.get('udp-portrange', None), service_name)
            
            # ================================================================
            # STEP 2D: Create FTD port objects
            # ================================================================
            has_tcp = len(tcp_ports) > 0
            has_udp = len(udp_ports) > 0
            
            if not has_tcp and not has_udp:
                print(f"  Skipped: {service_name} (No TCP or UDP ports defined)")
                self.skipped_count += 1
                self.skipped_services.add(sanitized_name)
                self.failed_items.append({"name": service_name, "reason": "No TCP or UDP ports defined", "config": properties})
                continue
            
            total_objects = len(tcp_ports) + len(udp_ports)

            if has_tcp and has_udp:
                self.split_count += 1
            
            if total_objects > 1:
                self.multi_port_split_count += 1
            
            # Counter for object numbering - separate counters for TCP and UDP
            tcp_counter = 1
            udp_counter = 1
            
            # Track FTD objects for this service: list of (name, type) tuples
            ftd_object_info = []
            
            # Create TCP objects
            for port in tcp_ports:
                # Determine the object name
                if len(tcp_ports) > 1:
                    # Multiple TCP ports - number them
                    obj_name = f"{sanitized_name}_TCP_{tcp_counter}"
                elif has_udp:
                    # Has both TCP and UDP but only one TCP
                    obj_name = f"{sanitized_name}_TCP"
                else:
                    # Only TCP, single port - use base name
                    obj_name = sanitized_name
                
                # Check if this name conflicts with FTD built-in services
                if obj_name in FTD_BUILTIN_SERVICES:
                    original_name = obj_name
                    obj_name = f"{obj_name}_Custom"
                    print(f"    Renamed: {original_name} -> {obj_name} (conflicts with FTD built-in)")

                obj_type = "tcpportobject"
                port_obj = {
                    "name": obj_name,
                    "isSystemDefined": False,
                    "port": str(port),
                    "type": obj_type
                }
                port_objects.append(port_obj)
                ftd_object_info.append((obj_name, obj_type))
                self.tcp_count += 1
                tcp_counter += 1
            
            # Create UDP objects
            for port in udp_ports:
                # Determine the object name
                if len(udp_ports) > 1:
                    # Multiple UDP ports - number them
                    obj_name = f"{sanitized_name}_UDP_{udp_counter}"
                elif has_tcp:
                    # Has both TCP and UDP but only one UDP
                    obj_name = f"{sanitized_name}_UDP"
                else:
                    # Only UDP, single port - use base name
                    obj_name = sanitized_name
                
                # Check if this name conflicts with FTD built-in services
                if obj_name in FTD_BUILTIN_SERVICES:
                    original_name = obj_name
                    obj_name = f"{obj_name}_Custom"
                    print(f"    Renamed: {original_name} -> {obj_name} (conflicts with FTD built-in)")

                obj_type = "udpportobject"
                port_obj = {
                    "name": obj_name,
                    "isSystemDefined": False,
                    "port": str(port),
                    "type": obj_type
                }
                port_objects.append(port_obj)
                ftd_object_info.append((obj_name, obj_type))
                self.udp_count += 1
                udp_counter += 1
            
            # Store the mapping of FortiGate name -> FTD names
            self.service_name_mapping[sanitized_name] = ftd_object_info
            if base_name != sanitized_name:
                # Renamed on collision: keep the original-name lookup working
                # (first occurrence wins - setdefault won't overwrite it)
                self.service_name_mapping.setdefault(base_name, ftd_object_info)
            
            # ================================================================
            # STEP 2E: Print conversion details
            # ================================================================
            if total_objects == 1:
                proto = "TCP" if has_tcp else "UDP"
                port = tcp_ports[0] if has_tcp else udp_ports[0]
                if service_name != sanitized_name:
                    print(f"  Converted: {service_name} -> {sanitized_name} [{proto} port {port}]")
                else:
                    print(f"  Converted: {sanitized_name} [{proto} port {port}]")
            else:
                print(f"  Converted: {service_name} -> {total_objects} objects:", end="")
                if has_tcp:
                    print(f" {len(tcp_ports)} TCP", end="")
                if has_udp:
                    print(f" {len(udp_ports)} UDP", end="")
                print()
                # Print details for each object
                for port_obj in port_objects[-total_objects:]:
                    print(f"    -> {port_obj['name']}: {port_obj['port']}")
        
        # ====================================================================
        # STEP 3: Store results and return
        # ====================================================================
        # Include any ICMPv4 echo (ping) objects created during conversion so
        # they are imported alongside the TCP/UDP port objects.
        port_objects.extend(self.icmp_port_objects)
        self.ftd_port_objects = port_objects
        return port_objects
    
    def get_statistics(self) -> Dict[str, int]:
        """
        Get conversion statistics for reporting.
        
        Returns:
            Dictionary with counts of TCP, UDP, split, and skipped services
        """
        return {
            # total = tcp + udp + icmp (ping echo objects are counted separately)
            "total_objects": len(self.ftd_port_objects),
            "tcp_objects": self.tcp_count,
            "udp_objects": self.udp_count,
            "icmp_objects": len(self.icmp_port_objects),  # ICMPv4 echo objects for ping
            "split_services": self.split_count,  # Services with both TCP and UDP
            "multi_port_services": self.multi_port_split_count,  # Services with multiple ports
            "skipped_services": self.skipped_count,  # Services with no ports defined
            "icmp_skipped": self.icmp_skipped_count,  # ICMP and other non-port protocols
            "ping_services": self.ping_service_count  # ICMP ping services -> PING group
        }

    def get_service_name_mapping(self) -> Dict[str, List[Tuple[str, str]]]:
        """
        Get a mapping of original FortiGate service names to FTD objects.

        This is used by the ServiceGroupConverter to expand group members
        to the correct FTD object names.

        Returns:
            Dict mapping FortiGate service name -> list of (FTD name, type) tuples
            Example: {"DNS": [("DNS_TCP", "tcpportobject"), ("DNS_UDP", "udpportobject")]}
        """
        return self.service_name_mapping
    
    def get_skipped_services(self) -> Set[str]:
        """
        Get the set of service names that were skipped (ICMP, etc.).
        
        This is used by the ServiceGroupConverter to filter these
        services out of groups.
        
        Returns:
            Set of sanitized service names that were skipped
        """
        return self.skipped_services


# =============================================================================
# TESTING CODE (for standalone testing of this module)
# =============================================================================

if __name__ == '__main__':
    """
    This code only runs when you execute this file directly.
    It's useful for testing the converter without running the main script.
    
    To test this module standalone:
        python service_converter.py
    """
    
    # Sample FortiGate configuration for testing
    # Including the LR_CLUST example with multiple ports
    test_config = {
        'firewall_service_custom': [
            {
                'ALL': {
                    'uuid': '11111111-2222-3333-8888-000000000014',
                    'category': 'General',
                    'protocol': 'IP',
                    'color': 1
                }
            },
            {
                'HTTP': {
                    'uuid': '11111111-2222-3333-8888-000000000013',
                    'category': 'Web Access',
                    'color': 13,
                    'tcp-portrange': 80
                }
            },
            {
                'DNS': {
                    'uuid': '11111111-2222-3333-8888-000000000013',
                    'category': 'Network Services',
                    'color': 13,
                    'tcp-portrange': 53,
                    'udp-portrange': 53
                }
            },
            {
                'LR_CLUST': {
                    'uuid': '11111111-2222-3333-8888-000000000015',
                    'color': 1,
                    'tcp-portrange': ['8300-8301', '8500-8501', '13100-13202', '8086', '8110-8112', '14502-14503', '9200-9400'],
                    'udp-portrange': '8300-8301'
                }
            },
            {
                'Multi_Port_Service': {
                    'uuid': '11111111-2222-3333-8888-000000000016',
                    'tcp-portrange': [80, 443, 8080]
                }
            }
        ]
    }
    
    # Create converter instance
    converter = ServiceConverter(test_config)
    
    # Run conversion
    print("Testing Service Converter with Multiple Ports...")
    print("="*60)
    result = converter.convert()
    
    # Display results
    print("\nConversion Results:")
    print("="*60)
    import json
    print(json.dumps(result, indent=2))
    
    # Display statistics
    print("\nStatistics:")
    print("="*60)
    stats = converter.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")