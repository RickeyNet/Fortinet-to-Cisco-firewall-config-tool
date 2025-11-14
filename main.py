#!/usr/bin/env python3
"""
FortiGate to Cisco FTD Configuration Converter
Parses FortiGate YAML configurations and converts them to FTD FDM API JSON format
"""

import yaml
import json
import argparse
from typing import Dict, List, Any
from pathlib import Path


class FortiGateToFTDConverter:
    """Converts FortiGate configurations to Cisco FTD FDM API format"""
    
    def __init__(self, fortigate_config: Dict[str, Any]):
        self.fg_config = fortigate_config
        self.ftd_config = {
            "network_objects": [],
            "network_groups": [],
            "port_objects": [],
            "port_groups": [],
            "access_policies": [],
            "nat_policies": []
        }
    
    def convert_address_objects(self) -> List[Dict]:
        """Convert FortiGate address objects to FTD network objects"""
        addresses = self.fg_config.get('firewall', {}).get('address', [])
        network_objects = []
        
        for addr in addresses:
            obj = {
                "name": addr.get('name', ''),
                "description": addr.get('comment', ''),
                "type": "networkobject",
                "subType": self._determine_address_type(addr),
                "value": self._extract_address_value(addr)
            }
            network_objects.append(obj)
        
        return network_objects
    
    def _determine_address_type(self, addr: Dict) -> str:
        """Determine FTD address subtype from FortiGate address"""
        if 'subnet' in addr:
            return "NETWORK"
        elif 'start-ip' in addr and 'end-ip' in addr:
            return "RANGE"
        elif 'fqdn' in addr:
            return "FQDN"
        else:
            return "HOST"
    
    def _extract_address_value(self, addr: Dict) -> str:
        """Extract address value from FortiGate format"""
        if 'subnet' in addr:
            return addr['subnet']
        elif 'start-ip' in addr:
            return f"{addr['start-ip']}-{addr['end-ip']}"
        elif 'fqdn' in addr:
            return addr['fqdn']
        else:
            return addr.get('ip', '')
    
    def convert_address_groups(self) -> List[Dict]:
        """Convert FortiGate address groups to FTD network groups"""
        groups = self.fg_config.get('firewall', {}).get('addrgrp', [])
        network_groups = []
        
        for grp in groups:
            obj = {
                "name": grp.get('name', ''),
                "description": grp.get('comment', ''),
                "type": "networkobjectgroup",
                "objects": [{"name": member} for member in grp.get('member', [])]
            }
            network_groups.append(obj)
        
        return network_groups
    
    def convert_service_objects(self) -> List[Dict]:
        """Convert FortiGate service objects to FTD port objects"""
        services = self.fg_config.get('firewall', {}).get('service', {}).get('custom', [])
        port_objects = []
        
        for svc in services:
            protocol = svc.get('protocol', 'TCP').upper()
            
            obj = {
                "name": svc.get('name', ''),
                "description": svc.get('comment', ''),
                "type": "portobject",
                "protocol": protocol,
                "port": self._extract_port_value(svc)
            }
            port_objects.append(obj)
        
        return port_objects
    
    def _extract_port_value(self, svc: Dict) -> str:
        """Extract port value from FortiGate service"""
        if 'tcp-portrange' in svc:
            return svc['tcp-portrange']
        elif 'udp-portrange' in svc:
            return svc['udp-portrange']
        elif 'sctp-portrange' in svc:
            return svc['sctp-portrange']
        else:
            return "any"
    
    def convert_service_groups(self) -> List[Dict]:
        """Convert FortiGate service groups to FTD port groups"""
        groups = self.fg_config.get('firewall', {}).get('service', {}).get('group', [])
        port_groups = []
        
        for grp in groups:
            obj = {
                "name": grp.get('name', ''),
                "description": grp.get('comment', ''),
                "type": "portobjectgroup",
                "objects": [{"name": member} for member in grp.get('member', [])]
            }
            port_groups.append(obj)
        
        return port_groups
    
    def convert_firewall_policies(self) -> List[Dict]:
        """Convert FortiGate firewall policies to FTD access rules"""
        policies = self.fg_config.get('firewall', {}).get('policy', [])
        access_rules = []
        
        for policy in policies:
            rule = {
                "name": policy.get('name', f"Rule_{policy.get('policyid', '')}"),
                "ruleAction": self._map_action(policy.get('action', 'deny')),
                "enabled": policy.get('status', 'enable') == 'enable',
                "sourceZones": [{"name": zone} for zone in policy.get('srcintf', [])],
                "destinationZones": [{"name": zone} for zone in policy.get('dstintf', [])],
                "sourceNetworks": [{"name": addr} for addr in policy.get('srcaddr', [])],
                "destinationNetworks": [{"name": addr} for addr in policy.get('dstaddr', [])],
                "sourcePorts": [{"name": svc} for svc in policy.get('service', [])],
                "logBegin": policy.get('logtraffic', 'disable') != 'disable',
                "logEnd": policy.get('logtraffic', 'disable') != 'disable'
            }
            access_rules.append(rule)
        
        return access_rules
    
    def _map_action(self, fg_action: str) -> str:
        """Map FortiGate action to FTD action"""
        action_map = {
            'accept': 'ALLOW',
            'allow': 'ALLOW',
            'deny': 'BLOCK',
            'reject': 'BLOCK'
        }
        return action_map.get(fg_action.lower(), 'BLOCK')
    
    def convert_nat_policies(self) -> List[Dict]:
        """Convert FortiGate NAT policies to FTD NAT rules"""
        policies = self.fg_config.get('firewall', {}).get('policy', [])
        nat_rules = []
        
        for policy in policies:
            if policy.get('nat') == 'enable':
                rule = {
                    "name": f"NAT_{policy.get('policyid', '')}",
                    "natType": "DYNAMIC" if policy.get('ippool') == 'enable' else "STATIC",
                    "sourceInterface": policy.get('srcintf', [{}])[0] if policy.get('srcintf') else {},
                    "destinationInterface": policy.get('dstintf', [{}])[0] if policy.get('dstintf') else {},
                    "originalSource": [{"name": addr} for addr in policy.get('srcaddr', [])],
                    "originalDestination": [{"name": addr} for addr in policy.get('dstaddr', [])],
                    "translatedSource": policy.get('poolname', 'interface')
                }
                nat_rules.append(rule)
        
        return nat_rules
    
    def convert_all(self) -> Dict[str, Any]:
        """Convert all FortiGate configurations to FTD format"""
        self.ftd_config['network_objects'] = self.convert_address_objects()
        self.ftd_config['network_groups'] = self.convert_address_groups()
        self.ftd_config['port_objects'] = self.convert_service_objects()
        self.ftd_config['port_groups'] = self.convert_service_groups()
        self.ftd_config['access_policies'] = self.convert_firewall_policies()
        self.ftd_config['nat_policies'] = self.convert_nat_policies()
        
        return self.ftd_config


def main():
    parser = argparse.ArgumentParser(
        description='Convert FortiGate YAML configuration to Cisco FTD FDM API JSON format'
    )
    parser.add_argument('input_file', help='Input FortiGate YAML configuration file')
    parser.add_argument('-o', '--output', help='Output JSON file (default: ftd_config.json)',
                       default='ftd_config.json')
    parser.add_argument('-p', '--pretty', action='store_true',
                       help='Pretty print JSON output')
    
    args = parser.parse_args()
    
    # Load FortiGate YAML configuration
    try:
        with open(args.input_file, 'r') as f:
            fg_config = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: Input file '{args.input_file}' not found")
        return 1
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")
        return 1
    
    # Convert configuration
    converter = FortiGateToFTDConverter(fg_config)
    ftd_config = converter.convert_all()
    
    # Write output JSON
    try:
        with open(args.output, 'w') as f:
            if args.pretty:
                json.dump(ftd_config, f, indent=2)
            else:
                json.dump(ftd_config, f)
        print(f"Successfully converted configuration to '{args.output}'")
        
        # Print summary
        print("\nConversion Summary:")
        print(f"  Network Objects: {len(ftd_config['network_objects'])}")
        print(f"  Network Groups: {len(ftd_config['network_groups'])}")
        print(f"  Port Objects: {len(ftd_config['port_objects'])}")
        print(f"  Port Groups: {len(ftd_config['port_groups'])}")
        print(f"  Access Policies: {len(ftd_config['access_policies'])}")
        print(f"  NAT Policies: {len(ftd_config['nat_policies'])}")
        
    except IOError as e:
        print(f"Error writing output file: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())