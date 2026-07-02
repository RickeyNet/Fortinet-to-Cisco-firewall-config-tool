#!/usr/bin/env python3
"""
FortiGate Interface Converter Module
=====================================
This module handles the conversion of FortiGate interfaces to 
Cisco FTD interface configurations.

WHAT THIS MODULE DOES:
    - Parses FortiGate 'system_interface' section from YAML
    - Maps FortiGate ports to FTD hardware interfaces
    - Converts physical interfaces (generates PUT payloads)
    - Converts aggregate interfaces to EtherChannels
    - Converts switch interfaces to Bridge Groups
    - Converts VLAN interfaces to Subinterfaces
    - Ensures all interface names are lowercase (FTD requirement)

FORTIGATE INTERFACE TYPES:
    - type: physical → FTD physicalinterface (PUT to update)
    - type: aggregate → FTD etherchannelinterface (POST to create)
    - type: switch → FTD bridgegroupinterface (POST to create)
    - VLAN (has interface: and vlanid:) → FTD subinterface (POST to create)

FTD INTERFACE NAME RULES:
    - Must be lowercase
    - Only alphanumeric and underscores allowed
    - Cannot start with a number
"""

import re
from typing import Dict, List, Any, Set, Optional

from common import collect_mgmt_ha_interfaces


# =============================================================================
# FIREWALL MODEL DEFINITIONS
# =============================================================================
# Define supported FTD firewall models with their interface configurations

FTD_MODELS = {
    'ftd-1010': {
        'name': 'Cisco Firepower 1010',
        'total_ports': 8,
        'port_prefix': 'Ethernet1/',
        'ha_port': None,  # No dedicated HA port on 1010
        'management_port': 'Management1/1',
        'description': '8-port desktop firewall (Ethernet1/1 - Ethernet1/8)'
    },
    'ftd-1120': {
        'name': 'Cisco Firepower 1120',
        'total_ports': 12,
        'port_prefix': 'Ethernet1/',
        'ha_port': None,
        'management_port': 'Management1/1',
        'description': '12-port firewall (Ethernet1/1 - Ethernet1/12)'
    },
    'ftd-1140': {
        'name': 'Cisco Firepower 1140',
        'total_ports': 12,
        'port_prefix': 'Ethernet1/',
        'ha_port': None,
        'management_port': 'Management1/1',
        'description': '12-port firewall (Ethernet1/1 - Ethernet1/12)'
    },
    'ftd-2110': {
        'name': 'Cisco Firepower 2110',
        'total_ports': 12,
        'port_prefix': 'Ethernet1/',
        'ha_port': None,
        'management_port': 'Management1/1',
        'description': '12-port 1U firewall'
    },
    'ftd-2120': {
        'name': 'Cisco Firepower 2120',
        'total_ports': 12,
        'port_prefix': 'Ethernet1/',
        'ha_port': None,
        'management_port': 'Management1/1',
        'description': '12-port 1U firewall'
    },
    'ftd-2130': {
        'name': 'Cisco Firepower 2130',
        'total_ports': 16,
        'port_prefix': 'Ethernet1/',
        'ha_port': None,
        'management_port': 'Management1/1',
        'description': '16-port 1U firewall'
    },
    'ftd-2140': {
        'name': 'Cisco Firepower 2140',
        'total_ports': 16,
        'port_prefix': 'Ethernet1/',
        'ha_port': None,
        'management_port': 'Management1/1',
        'description': '16-port 1U firewall'
    },
    'ftd-3105': {
        'name': 'Cisco Secure Firewall 3105',
        'total_ports': 16,
        'port_prefix': 'Ethernet1/',
        'ha_port': 'Ethernet1/2',  # Typically port 2 for HA
        'management_port': 'Management1/1',
        # Ethernet1/1-1/8 are 1G RJ45 copper; 1/9-1/16 are 10G SFP+. LACP
        # members must all be the same speed, so EtherChannel scale-up stays
        # within one group (see _speed_group_of_port).
        'port_speed_groups': {
            '1G': [1, 2, 3, 4, 5, 6, 7, 8],
            '10G': [9, 10, 11, 12, 13, 14, 15, 16],
        },
        'description': '16-port firewall (8 RJ45 + 8x 1/10G SFP+) with HA'
    },
    'ftd-3110': {
        'name': 'Cisco Secure Firewall 3110',
        'total_ports': 16,
        'port_prefix': 'Ethernet1/',
        'ha_port': 'Ethernet1/2',
        'management_port': 'Management1/1',
        'module_slots': 1,                   # one optional network-module slot
        'module_port_prefix': 'Ethernet2/',  # module ports = Ethernet2/1..N
        # 1/1-1/8 = 1G RJ45, 1/9-1/16 = 10G SFP+ (EtherChannel members must
        # share a speed - see _speed_group_of_port).
        'port_speed_groups': {
            '1G': [1, 2, 3, 4, 5, 6, 7, 8],
            '10G': [9, 10, 11, 12, 13, 14, 15, 16],
        },
        'description': '16-port firewall (8 RJ45 + 8x 1/10G SFP+) with HA'
    },
    'ftd-3120': {
        'name': 'Cisco Secure Firewall 3120',
        'total_ports': 16,
        'port_prefix': 'Ethernet1/',
        'ha_port': 'Ethernet1/2',
        'management_port': 'Management1/1',
        'module_slots': 1,                   # one optional network-module slot
        'module_port_prefix': 'Ethernet2/',  # module ports = Ethernet2/1..N
        # 1/1-1/8 = 1G RJ45, 1/9-1/16 = 10G SFP+ (EtherChannel members must
        # share a speed - see _speed_group_of_port).
        'port_speed_groups': {
            '1G': [1, 2, 3, 4, 5, 6, 7, 8],
            '10G': [9, 10, 11, 12, 13, 14, 15, 16],
        },
        'description': '16-port firewall (8 RJ45 + 8x 1/10G SFP+) with HA'
    },
    'ftd-3130': {
        'name': 'Cisco Secure Firewall 3130',
        'total_ports': 16,  # 8x RJ45 + 8x SFP+ fixed (plus optional network module)
        'port_prefix': 'Ethernet1/',
        'ha_port': 'Ethernet1/2',
        'management_port': 'Management1/1',
        'module_slots': 1,                   # one optional network-module slot
        'module_port_prefix': 'Ethernet2/',  # module ports = Ethernet2/1..N
        # 1/1-1/8 = 1G RJ45, 1/9-1/16 = 1/10/25G SFP+ (labelled 25G - their max).
        # EtherChannel members must share a speed - see _speed_group_of_port.
        'port_speed_groups': {
            '1G': [1, 2, 3, 4, 5, 6, 7, 8],
            '25G': [9, 10, 11, 12, 13, 14, 15, 16],
        },
        'description': '16-port firewall (8 RJ45 + 8x 1/10/25G SFP+) with HA'
    },
    'ftd-3140': {
        'name': 'Cisco Secure Firewall 3140',
        'total_ports': 16,  # 8x RJ45 + 8x SFP+ fixed (plus optional network module)
        'port_prefix': 'Ethernet1/',
        'ha_port': 'Ethernet1/2',
        'management_port': 'Management1/1',
        'module_slots': 1,                   # one optional network-module slot
        'module_port_prefix': 'Ethernet2/',  # module ports = Ethernet2/1..N
        # 1/1-1/8 = 1G RJ45, 1/9-1/16 = 1/10/25G SFP+ (labelled 25G - their max).
        # EtherChannel members must share a speed - see _speed_group_of_port.
        'port_speed_groups': {
            '1G': [1, 2, 3, 4, 5, 6, 7, 8],
            '25G': [9, 10, 11, 12, 13, 14, 15, 16],
        },
        'description': '16-port firewall (8 RJ45 + 8x 1/10/25G SFP+) with HA'
    },
    'ftd-4215': {
        'name': 'Cisco Secure Firewall 4215',
        'total_ports': 24,
        'port_prefix': 'Ethernet1/',
        'ha_port': 'Ethernet1/2',
        'management_port': 'Management1/1',
        'description': '24-port enterprise firewall with HA'
    }
}

# =============================================================================
# OPTIONAL NETWORK MODULES (NM)
# =============================================================================
# Models with a network-module slot (module_slots >= 1) can carry an add-on
# interface module. Its ports are named with the model's module_port_prefix
# (Ethernet2/1, Ethernet2/2, ... for the first slot) and all run at the module's
# link speed. Selecting a module adds these ports to the available pool so they
# can be assigned, bundled into EtherChannels (same-speed rule still applies),
# or reserved for HA. 'none' is the default (fixed ports only).
FTD_NETWORK_MODULES = {
    'none':   {'label': 'None (fixed ports only)', 'ports': 0, 'speed': None},
    '8x1g':   {'label': '8 x 1G',                  'ports': 8, 'speed': '1G'},
    '8x10g':  {'label': '8 x 10G SFP+',            'ports': 8, 'speed': '10G'},
    '8x25g':  {'label': '8 x 25G SFP+',            'ports': 8, 'speed': '25G'},
    '4x40g':  {'label': '4 x 40G QSFP+',           'ports': 4, 'speed': '40G'},
    '2x100g': {'label': '2 x 100G QSFP28',         'ports': 2, 'speed': '100G'},
}


def get_network_modules() -> list:
    """Return the list of supported network-module identifiers."""
    return list(FTD_NETWORK_MODULES.keys())


def get_supported_models() -> list:
    """Return list of supported firewall model names."""
    return sorted(FTD_MODELS.keys())

def print_supported_models() -> None:
    """Print a table of supported firewall models."""
    print("\nSupported FTD Firewall Models:")
    print("=" * 70)
    print(f"{'Model':<15} {'Name':<30} {'Ports':<8} {'HA Port':<12}")
    print("-" * 70)
    for model_id, info in sorted(FTD_MODELS.items()):
        ha = info['ha_port'] if info['ha_port'] else 'None'
        print(f"{model_id:<15} {info['name']:<30} {info['total_ports']:<8} {ha:<12}")
    print("=" * 70)


def sanitize_interface_name(name: str) -> str:
    """
    Sanitize interface names for FTD compatibility.
    
    FTD interface names must be:
    - Lowercase
    - Alphanumeric and underscores only
    - Cannot start with a number
    
    Args:
        name: Original interface name
        
    Returns:
        Sanitized lowercase name
    """
    if name is None:
        return ""
    
    # Convert to string and lowercase
    name = str(name).lower()
    
    # Replace any non-alphanumeric character (except underscore) with underscore
    sanitized = re.sub(r'[^a-z0-9_]', '_', name)
    
    # Remove consecutive underscores
    sanitized = re.sub(r'_+', '_', sanitized)
    
    # Remove leading/trailing underscores
    sanitized = sanitized.strip('_')
    
    return sanitized


class InterfaceConverter:
    """
    Converter class for transforming FortiGate interfaces to FTD format.
    
    Supports multiple FTD firewall models with automatic port mapping.
    Use set_target_model() to configure for a specific firewall.
    """
    
    def __init__(self, fortigate_config: Dict[str, Any], target_model: str = 'ftd-3120', custom_ha_port: str = None, network_module: str = 'none') -> None: # pyright: ignore[reportArgumentType]
        """
        Initialize the converter with FortiGate configuration data.
        
        Args:
            fortigate_config: Dictionary containing the complete parsed FortiGate YAML
                            Expected to have a 'system_interface' key
            target_model: Target FTD firewall model (e.g., 'ftd-1010', 'ftd-3120')
                        Use get_supported_models() to see available models
            custom_ha_port: Optional custom HA port(s). Accepts a single port
                        (e.g., 'Ethernet1/5'), several ports for dual-HA links
                        as a comma/space-separated string (e.g.,
                        'Ethernet1/2, Ethernet1/3') or a list, or 'none' to
                        reserve no HA port. If None, uses the model's default
                        HA port. Each port must match 'Ethernet1/X' and be a
                        valid port number for the model. All reserved HA ports
                        are excluded from the data-interface conversion.
            network_module: Optional add-on network module installed in the
                        model's NM slot (e.g. '8x10g', '4x40g'); see
                        get_network_modules(). Its ports (Ethernet2/1..N) are
                        added to the available pool. 'none' = fixed ports only.
        """
        self.fg_config = fortigate_config

        # Dedicated management and HA heartbeat/session-sync interfaces on the
        # FortiGate side (mgmt*/ha* names, `set dedicated-to management`,
        # hbdev/ha-mgmt-interface from `config system ha`). These are
        # infrastructure links with no FTD equivalent, so they are silently
        # ignored during conversion instead of being reported as failures.
        self.mgmt_ha_interfaces = collect_mgmt_ha_interfaces(fortigate_config)

        # Set target model (this also sets up port mapping)
        self.target_model = None
        self.model_info = None
        self.total_ports = 16  # Default
        self.ha_port = None      # First reserved HA port (back-compat alias)
        self.ha_ports = []       # All reserved HA ports (supports dual-HA links)
        self.custom_ha_port = custom_ha_port  # Custom HA port preference (str or list)
        self.network_module = (network_module or 'none')  # installed NM, if any
        self.skip_ftd_ports = set()
        self._port_speed = {}    # full port name -> link-speed label (or None)
        self._all_ports = []     # every valid port name (fixed + module)
        self._held_ports = set() # ports reserved up-front for explicit specs

        # Port mapping - will be built dynamically
        self.port_mapping = {}

        # Set the target model (this builds the port mapping)
        self.set_target_model(target_model)
        
        # Store converted interfaces
        self.physical_interfaces = []      # PUT requests
        self.subinterfaces = []            # POST requests
        self.etherchannels = []            # POST requests
        self.bridge_groups = []            # POST requests
        self.security_zones = []           # POST requests - zones for firewall policies
        
        # Interface name mapping: FortiGate name -> FTD name (for routes/policies)
        self.interface_name_mapping = {}
        
        # Track used subinterface names to avoid duplicates
        self.used_subinterface_names = set()
        
        # Track created security zone names to avoid duplicates
        self.created_zone_names = set()
        
        # Track bridge group membership: hardware_name -> bridge_group_name
        # Used to assign physical interfaces to bridge group zones instead of individual zones
        self.bridge_group_members = {}
        
        # Track statistics
        self.stats = {
            'physical_updated': 0,
            'subinterfaces_created': 0,
            'etherchannels_created': 0,
            'bridge_groups_created': 0,
            'security_zones_created': 0,
            'vlan_conflicts_remapped': 0,
            'skipped': 0
        }

        # Track items that failed/were skipped during conversion
        self.failed_items = []

        # EtherChannel expansion config (set via set_etherchannel_expansion()).
        # Lets a source port-channel be grown to MORE member links on the FTD
        # side during migration (e.g. scale a 1-member WAN LAG up to 4x 10G).
        # Maps a lowercased port-channel identifier -> int (target total member
        # count) or list of FTD hardware names to add.
        self.etherchannel_expansion = {}

        # EtherChannel promotion config (set via set_etherchannel_promotion()).
        # Lets a plain (non-aggregate) FortiGate physical interface be migrated
        # as a NEW FTD EtherChannel so it can carry multiple 10G member links
        # (e.g. turn a single physical WAN port into a 2x10G port-channel).
        # Maps a lowercased physical-interface identifier -> int (total member
        # count, incl. the original port) or list of extra FTD ports to add.
        self.promote_to_etherchannel = {}

        # Bridge group expansion config (set via set_bridgegroup_expansion()).
        # Lets a FortiGate virtual switch -> FTD bridge group (BVI) be grown to
        # MORE member links during migration (e.g. add 10G ports to a server
        # bridge group). Maps a lowercased switch-interface identifier -> int
        # (target total member count) or list of FTD hardware names to add.
        self.bridgegroup_expansion = {}

        # Bridge group promotion config (set via set_bridgegroup_promotion()).
        # Lets a plain (non-aggregate) FortiGate physical interface be migrated
        # as a NEW FTD bridge group (BVI) so its subnet can span several bridged
        # ports on the Cisco side. The interface's IP/MTU move onto the BVI.
        # Maps a lowercased physical-interface identifier -> int (total member
        # count, incl. the original port) or list of extra FTD ports to add.
        self.promote_to_bridgegroup = {}

        # Promote-to-port-channel L3 VLAN tags (set via
        # set_promotion_subinterface_vlans()). When a routed physical interface
        # is promoted to a port-channel, its IP cannot live on the channel in
        # the user's design - it is placed on a subinterface (Port-channelN.tag)
        # using the VLAN tag specified here. Maps a lowercased physical-interface
        # identifier -> int VLAN tag.
        self.promotion_pc_vlans = {}
    
    def set_target_model(self, model: str) -> None:
        """
        Set the target FTD firewall model.
        
        This configures the available ports and HA port based on the model.
        Interfaces are assigned starting from the LAST port and working down.
        
        Args:
            model: Model identifier (e.g., 'ftd-1010', 'ftd-3120')
        
        Raises:
            ValueError: If model is not supported
            ValueError: If custom_ha_port is invalid for this model
        """
        if model not in FTD_MODELS:
            raise ValueError(f"Unsupported model: {model}. Use get_supported_models() to see available models.")
        
        self.target_model = model
        self.model_info = FTD_MODELS[model]
        self.total_ports = self.model_info['total_ports']

        # Build the full universe of ports (fixed chassis ports + any installed
        # network-module ports) together with each port's link-speed label. This
        # runs before HA parsing so HA ports can be validated against it.
        self._build_port_universe()

        # Determine the reserved HA port(s). custom_ha_port may be:
        #   - None              -> use the model default (if any)
        #   - "none"            -> reserve no HA port at all
        #   - "Eth.. , Eth.."   -> one OR MORE custom ports (comma/space separated),
        #                          or a list/tuple of port names
        # HA links are often dual (active + standby control/data links), so more
        # than one port can be reserved and excluded from the data conversion.
        if self.custom_ha_port and str(self.custom_ha_port).strip().lower() == "none":
            self.ha_ports = []
        elif self.custom_ha_port:
            # Validate + normalize custom HA port(s); raises ValueError on bad input
            self.ha_ports = self._parse_custom_ha_ports(self.custom_ha_port)
        else:
            default = self.model_info['ha_port']
            self.ha_ports = [default] if default else []

        # Backward-compatible single-port attribute (first HA port, or None).
        self.ha_port = self.ha_ports[0] if self.ha_ports else None

        # Build skip set for reserved ports - every HA port is reserved and
        # cannot be used for data interfaces.
        self.skip_ftd_ports = set(self.ha_ports)

        # Clear existing mapping
        self.port_mapping = {}

        # Build available ports list from the full universe (fixed ports first,
        # highest-numbered first, then any network-module ports), skipping the
        # reserved HA port(s). Assignment pops from the front, so built-in ports
        # are consumed before module ports.
        self.available_ftd_ports = [
            p for p in self._all_ports if p not in self.skip_ftd_ports
        ]

        # Track assigned ports
        self.assigned_ftd_ports = set(self.skip_ftd_ports)

        print(f"  Target model: {self.model_info['name']}")
        print(f"  Available ports: Ethernet1/1 - Ethernet1/{self.total_ports}")
        if self._module_ports:
            mod = FTD_NETWORK_MODULES.get(self.network_module, {})
            print(f"  Network module: {mod.get('label', self.network_module)} "
                  f"({self._module_ports[0]} - {self._module_ports[-1]})")
        if self.ha_ports:
            label = "HA port" if len(self.ha_ports) == 1 else "HA ports"
            print(f"  {label} (skipped): {', '.join(self.ha_ports)}")
        print(f"  Port assignment order: Starting from Ethernet1/{self.total_ports} down to Ethernet1/1")

    def _build_port_universe(self) -> None:
        """Populate self._all_ports and self._port_speed for the current model.

        Includes the fixed chassis ports plus, if a network module is selected
        and the model has a slot, that module's ports. Ordered fixed-first
        (highest-numbered first) then module ports, matching the assignment
        order (built-in ports are consumed before module ports).
        """
        prefix = self.model_info.get('port_prefix', 'Ethernet1/')
        speed_groups = self.model_info.get('port_speed_groups') or {}

        def fixed_speed(num: int):
            for label, nums in speed_groups.items():
                if num in nums:
                    return label
            return None

        self._port_speed = {}
        fixed_ports = []
        for i in range(self.total_ports, 0, -1):
            name = f"{prefix}{i}"
            fixed_ports.append(name)
            self._port_speed[name] = fixed_speed(i)

        # Optional network-module ports (Ethernet2/1..N at the module's speed).
        self._module_ports = []
        module_id = (self.network_module or 'none')
        if module_id != 'none':
            mod = FTD_NETWORK_MODULES.get(module_id)
            if not mod:
                print(f"  [WARNING] Unknown network module '{module_id}' - ignored")
            elif not self.model_info.get('module_slots'):
                print(f"  [WARNING] {self.model_info.get('name', self.target_model)} "
                      f"has no network-module slot - module '{module_id}' ignored")
            else:
                mprefix = self.model_info.get('module_port_prefix', 'Ethernet2/')
                for i in range(1, int(mod['ports']) + 1):
                    name = f"{mprefix}{i}"
                    self._module_ports.append(name)
                    self._port_speed[name] = mod['speed']

        self._all_ports = fixed_ports + self._module_ports

    def set_network_module(self, network_module: str) -> None:
        """Select an optional network module and rebuild the port pool.

        Must be called when no ports have been assigned yet (e.g. right after
        construction). See get_network_modules() for valid identifiers.
        """
        self.network_module = (network_module or 'none')
        self.set_target_model(self.target_model)


    def _validate_custom_ha_port(self, ha_port: str) -> None:
        """
        Validate that the custom HA port is valid for the target model.
        
        Args:
            ha_port: Custom HA port string (e.g., 'Ethernet1/5')
        
        Raises:
            ValueError: If the HA port format is invalid or port number exceeds model capacity
        
        Notes:
            - HA port must match format: 'EthernetS/X' (S = slot, e.g.
              'Ethernet1/5' for a chassis port or 'Ethernet2/1' for a module port)
            - The port must exist on the model (fixed port or installed module)
            - Management ports cannot be used as HA ports
        """
        # Validate format: EthernetS/X (slot/port)
        match = re.match(r'^Ethernet(\d+)/(\d+)$', ha_port)
        if not match:
            raise ValueError(
                f"Invalid HA port format: '{ha_port}'. "
                f"Must be 'Ethernet<slot>/<port>' (e.g., 'Ethernet1/5')"
            )

        # Validate the port actually exists on this model (fixed or module)
        if ha_port not in self._all_ports:
            valid = f"Ethernet1/1 - Ethernet1/{self.total_ports}"
            if self._module_ports:
                valid += f" or {self._module_ports[0]} - {self._module_ports[-1]}"
            raise ValueError(
                f"Invalid HA port: '{ha_port}'. "
                f"Model '{self.target_model}' has ports {valid}."
            )

        # Warn if using port 1 (often used for management/uplink)
        if ha_port == "Ethernet1/1":
            print("\nWARNING: Using Ethernet1/1 as HA port. This is typically the first data port.")
            print("         Ensure this doesn't conflict with your network design.\n")

    def _parse_custom_ha_ports(self, spec: Any) -> List[str]:
        """
        Parse and validate one or more custom HA ports.

        Accepts either a list/tuple of port names or a single string with ports
        separated by commas, semicolons, or whitespace
        (e.g. 'Ethernet1/2, Ethernet1/3'). Each port is validated against the
        target model via _validate_custom_ha_port(); invalid ports raise
        ValueError. Duplicates are removed while preserving order.

        Returns:
            Ordered list of validated HA port hardware names.
        """
        if isinstance(spec, (list, tuple, set)):
            raw_ports = [str(p) for p in spec]
        else:
            # Split on commas, semicolons, or whitespace
            raw_ports = re.split(r'[,;\s]+', str(spec).strip())

        ha_ports: List[str] = []
        for raw in raw_ports:
            port = raw.strip()
            if not port:
                continue
            self._validate_custom_ha_port(port)
            if port not in ha_ports:
                ha_ports.append(port)
        return ha_ports

    def _resolve_fg_port(self, key: str) -> Optional[str]:
        """Resolve a user-supplied interface identifier (FortiGate port name OR
        alias) to the underlying system_interface key (the port name).

        Returns the port name if found, else None. Lets explicit port mappings
        be given by the human-facing alias the GUI displays (e.g. 'wan') and
        still land on the right port (e.g. 'port5')."""
        if not key:
            return None
        target = str(key).strip().lower()
        for intf_dict in self.fg_config.get('system_interface', []) or []:
            if not isinstance(intf_dict, dict) or not intf_dict:
                continue
            name = next(iter(intf_dict))
            props = intf_dict[name]
            if str(name).strip().lower() == target:
                return str(name)
            if isinstance(props, dict):
                alias = str(props.get('alias', '')).strip().lower()
                if alias and alias == target:
                    return str(name)
        return None

    def set_port_mapping(self, mapping: Dict[str, str]) -> None:
        """
        Set explicit (straight) port assignment for specific interfaces.

        Use this to pin a FortiGate interface to a specific FTD port instead of
        letting it be auto-assigned. The interface still converts as a normal
        routed physical interface - no aggregation. Keys may be the FortiGate
        port name OR its alias (the GUI shows the alias).

        Args:
            mapping: Dict of FortiGate port name/alias -> FTD hardware name
        """
        for key, ftd_port in mapping.items():
            ftd_port = str(ftd_port).strip()

            # Validate the FTD port is a real port on this model.
            if self._all_ports and ftd_port not in self._all_ports:
                print(f"  [WARNING] Map {key} -> {ftd_port}: not a valid port for "
                      f"{self.target_model} - ignored")
                continue
            if ftd_port in self.skip_ftd_ports:
                print(f"  [WARNING] Map {key} -> {ftd_port}: reserved (HA/skip) - ignored")
                continue

            # Resolve alias -> port name so _get_ftd_hardware_name() finds it.
            fg_port = self._resolve_fg_port(key) or str(key).strip()

            # Refuse to double-book a port already mapped to a different interface.
            existing = self.port_mapping.get(fg_port)
            if existing and existing != ftd_port:
                print(f"  [WARNING] Map {key}: already mapped to {existing}; "
                      f"keeping that and ignoring {ftd_port}")
                continue
            for other_fg, other_ftd in self.port_mapping.items():
                if other_ftd == ftd_port and other_fg != fg_port:
                    print(f"  [WARNING] Map {key} -> {ftd_port}: port already "
                          f"assigned to {other_fg} - ignored")
                    break
            else:
                self.port_mapping[fg_port] = ftd_port
                self.assigned_ftd_ports.add(ftd_port)
                if ftd_port in self.available_ftd_ports:
                    self.available_ftd_ports.remove(ftd_port)
                print(f"  Mapped (straight assignment): {fg_port} -> {ftd_port}")

    def set_promotion_subinterface_vlans(self, vlans: Dict[str, Any]) -> None:
        """Set the L3 VLAN tag used when a routed interface promoted to a
        port-channel needs its IP placed on a subinterface (Port-channelN.tag).

        Maps a FortiGate physical-interface name/alias (case-insensitive) to an
        int VLAN tag. No-op for interfaces with no IP.
        """
        normalized: Dict[str, int] = {}
        for key, tag in (vlans or {}).items():
            if key is None:
                continue
            try:
                normalized[str(key).strip().lower()] = int(tag)
            except (TypeError, ValueError):
                print(f"  [WARNING] Ignoring promote VLAN for '{key}': "
                      f"'{tag}' is not a valid VLAN id")
        self.promotion_pc_vlans = normalized

    def _get_promotion_pc_vlan(self, fg_name: str, alias: str) -> Optional[int]:
        """Look up the promote-to-port-channel L3 VLAN tag for an interface by
        its FortiGate name or alias (case-insensitive), or None."""
        if not self.promotion_pc_vlans:
            return None
        for key in (fg_name, alias):
            if key and str(key).strip().lower() in self.promotion_pc_vlans:
                return self.promotion_pc_vlans[str(key).strip().lower()]
        return None
    
    def set_skip_ports(self, ports: Set[str]) -> None:
        """
        Set additional FTD ports to skip.
        
        Args:
            ports: Set of FTD hardware names to skip
        """
        self.skip_ftd_ports.update(ports)
        self.assigned_ftd_ports.update(ports)

        # Remove from available list
        self.available_ftd_ports = [p for p in self.available_ftd_ports if p not in ports]

    def set_etherchannel_expansion(self, expansion: Dict[str, Any]) -> None:
        """
        Configure EtherChannel member expansion to scale up link aggregation
        during migration.

        This is for the case where the source FortiGate has a port-channel with
        only a few (or a single) member interface, but the target Cisco firewall
        should carry MORE 10G member links for added bandwidth/redundancy (e.g.
        WAN and server port-channels). Without this, member count is copied 1:1.

        Args:
            expansion: Dict mapping a FortiGate port-channel identifier
                (interface name, alias, or sanitized FTD name) to either:
                  - an int: the desired TOTAL number of member interfaces. If the
                    source already has fewer members, extra ports are
                    auto-assigned from the available FTD port pool until the
                    target count is reached.
                  - a list of FTD hardware names (e.g.
                    ['Ethernet1/5', 'Ethernet1/6']) to ADD as members on top of
                    the source members.

        Matching is case-insensitive. Identifiers that don't match any aggregate
        interface are ignored (a note is printed during conversion).
        """
        normalized = {}
        for key, spec in (expansion or {}).items():
            if key is None:
                continue
            normalized[str(key).strip().lower()] = spec
        self.etherchannel_expansion = normalized

    def _get_expansion_spec(self, fg_name: str, alias: str, ftd_name: str) -> Any:
        """Look up the expansion spec for an aggregate interface by any of its
        identifiers (FortiGate name, alias, or sanitized FTD name)."""
        if not self.etherchannel_expansion:
            return None
        for key in (fg_name, alias, ftd_name):
            if key and str(key).strip().lower() in self.etherchannel_expansion:
                return self.etherchannel_expansion[str(key).strip().lower()]
        return None

    def set_etherchannel_promotion(self, promotion: Dict[str, Any]) -> None:
        """
        Configure promotion of plain physical interfaces to NEW EtherChannels.

        This is for the case where the source FortiGate interface is a regular
        physical port (not an aggregate), but on the target Cisco firewall it
        should become a port-channel so it can carry multiple 10G member links
        (e.g. turn a single physical WAN or server port into a 2x10G LAG).

        The interface's name, MTU, and enabled state move onto the new
        EtherChannel; the original FTD port becomes the first member, and
        additional members are added per the spec. The port-channel itself gets
        NO IP - L3 addresses belong on VLAN subinterfaces riding on the channel.

        Args:
            promotion: Dict mapping a FortiGate physical-interface identifier
                (interface name or alias) to either:
                  - an int: the desired TOTAL member count, INCLUDING the
                    original port. Extra members are auto-assigned from the
                    available FTD port pool.
                  - a list of FTD hardware names (e.g.
                    ['Ethernet1/6']) to ADD as members alongside the original
                    port.

        Matching is case-insensitive. Identifiers that don't match a standalone
        physical interface are ignored (a note is printed during conversion).
        Interfaces that carry VLAN subinterfaces are not eligible (a warning is
        printed and they convert normally).
        """
        normalized = {}
        for key, spec in (promotion or {}).items():
            if key is None:
                continue
            normalized[str(key).strip().lower()] = spec
        self.promote_to_etherchannel = normalized

    def _get_promotion_spec(self, fg_name: str, alias: str) -> Any:
        """Look up the promotion spec for a physical interface by its FortiGate
        name or alias (case-insensitive)."""
        if not self.promote_to_etherchannel:
            return None
        for key in (fg_name, alias):
            if key and str(key).strip().lower() in self.promote_to_etherchannel:
                return self.promote_to_etherchannel[str(key).strip().lower()]
        return None

    def _build_ipv4_config(self, ip_config: Any) -> Optional[Dict]:
        """
        Build an FTD interfaceipv4 block from a FortiGate 'ip' value
        (a [address, netmask] list). Returns None if there is no usable static
        IP (missing, malformed, or 0.0.0.0).
        """
        if not (ip_config and isinstance(ip_config, list) and len(ip_config) >= 2):
            return None
        ip_addr = str(ip_config[0])
        netmask = str(ip_config[1])
        if ip_addr == '0.0.0.0':
            return None
        return {
            "ipType": "STATIC",
            "defaultRouteUsingDHCP": False,
            "ipAddress": {
                "ipAddress": ip_addr,
                "netmask": netmask,
                "type": "haipv4address"
            },
            "dhcp": False,
            "addressNull": False,
            "type": "interfaceipv4"
        }

    def _add_etherchannel_member(self, fg_name: str, ftd_hardware: str,
                                 ftd_members: List[Dict]) -> bool:
        """
        Append an FTD hardware port as an EtherChannel member and create its
        routed-mode physical interface entry (so it is imported and set to
        routed mode before the EtherChannel is created).

        Idempotent: returns False if the port is already a member of this
        EtherChannel.
        """
        # Avoid duplicate membership within the same EtherChannel
        if any(m.get('hardwareName') == ftd_hardware for m in ftd_members):
            return False

        ftd_members.append({
            "hardwareName": ftd_hardware,
            "type": "physicalinterface"
        })

        # Create a physical interface entry for this member.
        # EtherChannel members require: empty name, routed mode, full duplex,
        # autoNegotiation enabled (speed/SFP type is auto-detected at import).
        member_interface = {
            "name": '',  # No name - required for EtherChannel membership
            "hardwareName": ftd_hardware,
            "description": f"EtherChannel {fg_name} member",
            "enabled": True,
            "mode": "ROUTED",
            "duplexType": "FULL",
            "autoNegotiation": True,
            "type": "physicalinterface"
        }
        existing_hardware = [p.get('hardwareName') for p in self.physical_interfaces]
        if ftd_hardware not in existing_hardware:
            self.physical_interfaces.append(member_interface)
        return True

    def _reserve_explicit_port(self, fg_name: str, ftd_hardware: str,
                               context: str = "EtherChannel") -> bool:
        """
        Validate and reserve a user-specified FTD port for EtherChannel or
        bridge group expansion. Returns False (with a warning) if the port is
        invalid, out of range, reserved, or already assigned to another
        interface. ``context`` only affects the wording of warning messages.
        """
        match = re.match(r'^Ethernet(\d+)/(\d+)$', ftd_hardware)
        if not match:
            print(f"      [WARNING] {context} {fg_name}: invalid expansion port "
                  f"'{ftd_hardware}' (expected 'Ethernet<slot>/<port>') - skipped")
            return False

        # Must be a real port on this model (fixed chassis port or module port)
        if ftd_hardware not in self._all_ports:
            print(f"      [WARNING] {context} {fg_name}: expansion port "
                  f"'{ftd_hardware}' is not a valid port for {self.target_model} "
                  f"- skipped")
            return False

        if ftd_hardware in self.skip_ftd_ports:
            print(f"      [WARNING] {context} {fg_name}: expansion port "
                  f"'{ftd_hardware}' is reserved (HA/skip) - skipped")
            return False

        # Already assigned to something else (not just sitting in the free pool)
        if (ftd_hardware in self.assigned_ftd_ports
                and ftd_hardware not in self.available_ftd_ports):
            print(f"      [WARNING] {context} {fg_name}: expansion port "
                  f"'{ftd_hardware}' already assigned elsewhere - skipped")
            return False

        # Reserve it
        self.assigned_ftd_ports.add(ftd_hardware)
        self._held_ports.discard(ftd_hardware)
        if ftd_hardware in self.available_ftd_ports:
            self.available_ftd_ports.remove(ftd_hardware)
        return True

    def _prereserve_explicit_ports(self) -> None:
        """Hold every explicitly-named expansion/promotion port out of the
        auto-assignment pool BEFORE any interface is assigned a port.

        Port assignment is greedy (highest-numbered free port first), and
        promotions/expansions run after standalone interfaces in the priority
        order. Without this pre-pass a standalone interface would grab a port
        the user explicitly requested for a port-channel/bridge group, and the
        owning spec would then skip it as 'already assigned elsewhere'. Holding
        the ports here keeps them out of _get_ftd_hardware_name()'s pool until
        their owning spec claims them via _reserve_explicit_port().
        """
        self._held_ports = set()
        spec_dicts = (
            self.etherchannel_expansion, self.promote_to_etherchannel,
            self.bridgegroup_expansion, self.promote_to_bridgegroup,
        )
        for spec_dict in spec_dicts:
            for spec in (spec_dict or {}).values():
                if not isinstance(spec, (list, tuple)):
                    continue  # int = target count, no specific ports to hold
                for raw in spec:
                    port = str(raw).strip()
                    if not re.match(r'^Ethernet\d+/\d+$', port):
                        continue
                    if port not in self._all_ports or port in self.skip_ftd_ports:
                        continue  # invalid/HA - the owning spec will warn later
                    if port in self.available_ftd_ports:
                        self.available_ftd_ports.remove(port)
                        self._held_ports.add(port)
        if self._held_ports:
            print(f"  Reserved {len(self._held_ports)} port(s) for explicit "
                  f"expansion/promotion: {', '.join(sorted(self._held_ports))}")

    def _speed_group_of_port(self, ftd_hardware: str) -> Optional[str]:
        """Return the link-speed group label (e.g. '1G', '10G') for an FTD
        port on the target model, or None if the model's ports are all the
        same speed (no constraint) or the port can't be classified.

        Used to keep EtherChannel (LACP) members within a single speed group -
        mixing speeds in one channel is invalid on FTD. Covers both fixed
        chassis ports and installed network-module ports.
        """
        return self._port_speed.get(str(ftd_hardware))

    def _pop_available_port(self, speed_group: Optional[str] = None) -> Optional[str]:
        """Pop the next free FTD port from the pool, optionally restricted to a
        given link-speed group. Returns the hardware name, or None if no
        matching port is free."""
        for i, port in enumerate(self.available_ftd_ports):
            if speed_group is None or self._speed_group_of_port(port) == speed_group:
                return self.available_ftd_ports.pop(i)
        return None

    def _apply_etherchannel_expansion(self, fg_name: str, spec: Any,
                                      ftd_members: List[Dict]) -> List[str]:
        """
        Add extra member links to an EtherChannel per the expansion spec.

        Args:
            fg_name: FortiGate interface name (for logging)
            spec: int target total member count, OR list of FTD hardware names
                  to add.
            ftd_members: current member list (modified in place)

        Returns:
            List of FTD hardware names actually added.
        """
        added = []

        # All EtherChannel members must run at the same link speed (LACP rule).
        # On mixed-speed models (e.g. the 3120: 1/1-1/8 = 1G, 1/9-1/16 = 10G)
        # this constrains scale-up to the speed of the existing member(s) so we
        # never bond a 1G port with a 10G port. Returns None on uniform-speed
        # models, which disables the constraint.
        speed_group = (self._speed_group_of_port(ftd_members[0]['hardwareName'])
                       if ftd_members else None)

        if isinstance(spec, int):
            # Target TOTAL member count - auto-assign extra ports from the pool
            target = spec
            if target <= len(ftd_members):
                print(f"      [EXPAND] EtherChannel {fg_name}: source already has "
                      f"{len(ftd_members)} member(s) (target {target}) - no change")
                return added
            while len(ftd_members) < target:
                ftd_hardware = self._pop_available_port(speed_group)
                if not ftd_hardware:
                    if speed_group:
                        print(f"      [WARNING] EtherChannel {fg_name}: not enough free "
                              f"{speed_group} ports to reach {target} members "
                              f"(stopped at {len(ftd_members)}) - EtherChannel members "
                              f"must all be the same speed, so faster/slower ports were "
                              f"not mixed in")
                    else:
                        print(f"      [WARNING] EtherChannel {fg_name}: not enough free "
                              f"ports to reach {target} members "
                              f"(stopped at {len(ftd_members)})")
                    break
                self.assigned_ftd_ports.add(ftd_hardware)
                if self._add_etherchannel_member(fg_name, ftd_hardware, ftd_members):
                    added.append(ftd_hardware)
        else:
            # Explicit list of FTD hardware ports to add
            for ftd_hardware in spec:
                ftd_hardware = str(ftd_hardware).strip()
                if not ftd_hardware:
                    continue
                # Refuse a member whose speed doesn't match the channel - this
                # is checked BEFORE reserving so the port stays in the free pool.
                if speed_group is not None:
                    member_group = self._speed_group_of_port(ftd_hardware)
                    if member_group is not None and member_group != speed_group:
                        print(f"      [WARNING] EtherChannel {fg_name}: port "
                              f"'{ftd_hardware}' is a {member_group} port but the channel "
                              f"uses {speed_group} ports - skipped (LACP members must all "
                              f"be the same speed)")
                        continue
                if not self._reserve_explicit_port(fg_name, ftd_hardware):
                    continue
                if self._add_etherchannel_member(fg_name, ftd_hardware, ftd_members):
                    added.append(ftd_hardware)
                    # If the channel had no speed yet (e.g. a uniform base
                    # member), adopt this member's group for the rest.
                    if speed_group is None:
                        speed_group = self._speed_group_of_port(ftd_hardware)

        if added:
            print(f"      [EXPAND] EtherChannel {fg_name}: added {len(added)} "
                  f"extra member(s): {', '.join(added)}")
        return added

    def set_bridgegroup_expansion(self, expansion: Dict[str, Any]) -> None:
        """
        Configure bridge group (BVI) member expansion to scale up a FortiGate
        virtual switch during migration.

        This is the bridge-group analog of set_etherchannel_expansion(): when a
        FortiGate virtual switch (system_switch-interface) is migrated to an FTD
        bridge group, this lets you ADD more member links on the Cisco side
        (e.g. extra 10G ports on a server bridge group). Without it, member
        count is copied 1:1 from the source switch.

        Args:
            expansion: Dict mapping a FortiGate switch-interface identifier
                (interface name or sanitized FTD name) to either:
                  - an int: the desired TOTAL number of member interfaces. Extra
                    members are auto-assigned from the available FTD port pool.
                  - a list of FTD hardware names (e.g.
                    ['Ethernet1/7', 'Ethernet1/8']) to ADD as members on top of
                    the source members.

        Matching is case-insensitive. Identifiers that don't match any switch
        interface are ignored.
        """
        normalized: Dict[str, Any] = {}
        for key, spec in (expansion or {}).items():
            if key is None:
                continue
            normalized[str(key).strip().lower()] = spec
        self.bridgegroup_expansion = normalized

    def _get_bridgegroup_expansion_spec(self, fg_name: str, ftd_name: str) -> Any:
        """Look up the expansion spec for a switch interface by its FortiGate
        name or sanitized FTD name (case-insensitive)."""
        if not self.bridgegroup_expansion:
            return None
        for key in (fg_name, ftd_name):
            if key and str(key).strip().lower() in self.bridgegroup_expansion:
                return self.bridgegroup_expansion[str(key).strip().lower()]
        return None

    def set_bridgegroup_promotion(self, promotion: Dict[str, Any]) -> None:
        """
        Configure promotion of plain physical interfaces to NEW bridge groups.

        This is the bridge-group analog of set_etherchannel_promotion(): when a
        source FortiGate interface is a regular physical port but on the target
        Cisco firewall its subnet should span several bridged ports, this
        migrates it as a NEW FTD bridge group (BVI). The original FTD port
        becomes the first member; additional members are added per the spec.

        Unlike port-channel promotion (which leaves the channel IP-less), the
        interface's IPv4 address and MTU MOVE ONTO the BVI - a bridge group is
        the Layer-3 interface for the bridged segment.

        Args:
            promotion: Dict mapping a FortiGate physical-interface identifier
                (interface name or alias) to either:
                  - an int: the desired TOTAL member count, INCLUDING the
                    original port. Extra members are auto-assigned from the
                    available FTD port pool.
                  - a list of FTD hardware names to ADD as members alongside the
                    original port.

        Matching is case-insensitive. Interfaces that carry VLAN subinterfaces
        are not eligible (a warning is printed and they convert normally).
        """
        normalized: Dict[str, Any] = {}
        for key, spec in (promotion or {}).items():
            if key is None:
                continue
            normalized[str(key).strip().lower()] = spec
        self.promote_to_bridgegroup = normalized

    def _get_bridgegroup_promotion_spec(self, fg_name: str, alias: str) -> Any:
        """Look up the bridge group promotion spec for a physical interface by
        its FortiGate name or alias (case-insensitive)."""
        if not self.promote_to_bridgegroup:
            return None
        for key in (fg_name, alias):
            if key and str(key).strip().lower() in self.promote_to_bridgegroup:
                return self.promote_to_bridgegroup[str(key).strip().lower()]
        return None

    def _bridgegroup_member_name(self, bridge_ftd_name: str, ftd_hardware: str) -> str:
        """Synthesize a unique, valid FTD interface name for an ADDED bridge
        group member that has no FortiGate source (e.g. 'srv_bridge_e1_7')."""
        suffix = ftd_hardware.replace('Ethernet', 'e').replace('/', '_').lower()
        return sanitize_interface_name(f"{bridge_ftd_name}_{suffix}")

    def _add_bridgegroup_member(self, bridge_fg_name: str, bridge_ftd_name: str,
                                ftd_hardware: str, ftd_members: List[Dict[str, Any]],
                                member_name: str,
                                description: Optional[str] = None) -> bool:
        """
        Append an FTD hardware port as a bridge group (BVI) member and create its
        routed-mode physical interface entry. Tracks the port so its security
        zone is named after the bridge group.

        Idempotent: returns False if the port is already a member.
        """
        if any(m.get('hardwareName') == ftd_hardware for m in ftd_members):
            return False

        ftd_members.append({
            "hardwareName": ftd_hardware,
            "type": "physicalinterface"
        })

        member_interface: Dict[str, Any] = {
            "name": member_name,
            "hardwareName": ftd_hardware,
            "description": description or f"Bridge Group {bridge_fg_name} member",
            "enabled": True,
            "mode": "ROUTED",
            "type": "physicalinterface"
        }
        existing_hardware = [p.get('hardwareName') for p in self.physical_interfaces]
        if ftd_hardware not in existing_hardware:
            self.physical_interfaces.append(member_interface)

        # Track as a bridge group member so its zone is named after the BVI
        self.bridge_group_members[ftd_hardware] = bridge_ftd_name
        return True

    def _apply_bridgegroup_expansion(self, bridge_fg_name: str, bridge_ftd_name: str,
                                     spec: Any,
                                     ftd_members: List[Dict[str, Any]]) -> List[str]:
        """
        Add extra member links to a bridge group (BVI) per the expansion spec.

        Args:
            bridge_fg_name: FortiGate switch interface name (for logging)
            bridge_ftd_name: sanitized FTD bridge group name (used to name members)
            spec: int target total member count, OR list of FTD hardware names
                  to add.
            ftd_members: current member list (modified in place)

        Returns:
            List of FTD hardware names actually added.
        """
        added: List[str] = []

        if isinstance(spec, int):
            target = spec
            if target <= len(ftd_members):
                print(f"      [EXPAND] Bridge group {bridge_fg_name}: source already "
                      f"has {len(ftd_members)} member(s) (target {target}) - no change")
                return added
            while len(ftd_members) < target:
                if not self.available_ftd_ports:
                    print(f"      [WARNING] Bridge group {bridge_fg_name}: not enough "
                          f"free ports to reach {target} members "
                          f"(stopped at {len(ftd_members)})")
                    break
                ftd_hardware = self.available_ftd_ports.pop(0)
                self.assigned_ftd_ports.add(ftd_hardware)
                name = self._bridgegroup_member_name(bridge_ftd_name, ftd_hardware)
                if self._add_bridgegroup_member(bridge_fg_name, bridge_ftd_name,
                                                ftd_hardware, ftd_members, name):
                    added.append(ftd_hardware)
        else:
            for ftd_hardware in spec:
                ftd_hardware = str(ftd_hardware).strip()
                if not ftd_hardware:
                    continue
                if not self._reserve_explicit_port(bridge_fg_name, ftd_hardware,
                                                   context="Bridge group"):
                    continue
                name = self._bridgegroup_member_name(bridge_ftd_name, ftd_hardware)
                if self._add_bridgegroup_member(bridge_fg_name, bridge_ftd_name,
                                                ftd_hardware, ftd_members, name):
                    added.append(ftd_hardware)

        if added:
            print(f"      [EXPAND] Bridge group {bridge_fg_name}: added {len(added)} "
                  f"extra member(s): {', '.join(added)}")
        return added

    def _get_ftd_hardware_name(self, fg_port: str) -> Optional[str]:
        """
        Get the FTD hardware name for a FortiGate port.
        
        Args:
            fg_port: FortiGate port name (e.g., 'port1', 'x1')
            
        Returns:
            FTD hardware name (e.g., 'Ethernet1/1') or None if not available
        """
        # Check explicit mapping first
        if fg_port in self.port_mapping:
            return self.port_mapping[fg_port]
        
        # Auto-assign from available ports
        if self.available_ftd_ports:
            ftd_port = self.available_ftd_ports.pop(0)
            self.port_mapping[fg_port] = ftd_port
            self.assigned_ftd_ports.add(ftd_port)
            return ftd_port
        
        # No ports available
        return None
    
    def _netmask_to_cidr(self, netmask: str) -> int:
        """Convert subnet mask to CIDR prefix length."""
        try:
            octets = netmask.split('.')
            binary_str = ''.join(bin(int(octet))[2:].zfill(8) for octet in octets)
            return binary_str.count('1')
        except (ValueError, AttributeError):
            return 24  # Default for malformed/non-numeric netmask
    
    def convert(self) -> Dict[str, List[Dict]]:
        """
        Main conversion method - converts all FortiGate interfaces to FTD format.
        
        PORT ASSIGNMENT PRIORITY (for limited-port firewalls):
        1. EtherChannels - Need physical member ports
        2. Bridge Groups - Need physical member ports  
        3. Physical interfaces WITH subinterfaces - Can carry multiple VLANs
        4. Standalone physical interfaces - Only if ports available
        
        This priority ensures maximum utilization of limited ports.
        
        Returns:
            Dictionary with keys:
            - 'physical_interfaces': List of PUT payloads for physical interfaces
            - 'subinterfaces': List of POST payloads for subinterfaces
            - 'etherchannels': List of POST payloads for etherchannels
            - 'bridge_groups': List of POST payloads for bridge groups
        """
        interfaces = self.fg_config.get('system_interface', [])
        
        # Get switch interfaces (bridge groups) from separate section
        switch_interfaces = self.fg_config.get('system_switch-interface', [])
        
        if not interfaces:
            print("Warning: No interfaces found in FortiGate configuration")
            print("  Expected key: 'system_interface'")
            return {
                'physical_interfaces': [],
                'subinterfaces': [],
                'etherchannels': [],
                'bridge_groups': []
            }
        
        if switch_interfaces:
            print(f"  Found {len(switch_interfaces)} switch interfaces (bridge groups)")
        
        # ====================================================================
        # PHASE 1: Categorize all interfaces by type
        # ====================================================================
        physical_ports = []
        aggregate_ports = []  # EtherChannels
        switch_ports = []     # Bridge Groups (from system_switch-interface)
        vlan_interfaces = []  # Subinterfaces
        
        # Process system_switch-interface section for bridge groups
        for switch_dict in switch_interfaces:
            switch_name = list(switch_dict.keys())[0]
            switch_props = switch_dict[switch_name]
            
            if isinstance(switch_props, dict):
                switch_ports.append((switch_name, switch_props))
        
        # Process system_interface section
        for intf_dict in interfaces:
            intf_name = list(intf_dict.keys())[0]
            properties = intf_dict[intf_name]

            # Skip non-dict entries
            if not isinstance(properties, dict):
                continue

            # Silently ignore dedicated management and HA interfaces. These
            # are FortiGate infrastructure links (out-of-band mgmt, HA
            # heartbeat/session-sync) with no FTD equivalent, so they are not
            # reported as skipped/failed items that need attention.
            if str(intf_name).strip().lower() in self.mgmt_ha_interfaces:
                print(f"    Ignored: {intf_name} (dedicated management/HA interface)")
                continue

            intf_type = properties.get('type', 'physical')

            # Check if this is a VLAN interface (has 'interface' and 'vlanid')
            if 'interface' in properties and 'vlanid' in properties:
                parent_name = str(properties.get('interface', '')).strip().lower()
                if parent_name in self.mgmt_ha_interfaces:
                    print(f"    Ignored: {intf_name} (subinterface of management/HA "
                          f"interface '{properties.get('interface')}')")
                    continue
                vlan_interfaces.append((intf_name, properties))
            elif intf_type == 'aggregate':
                aggregate_ports.append((intf_name, properties))
            elif intf_type == 'physical':
                physical_ports.append((intf_name, properties))
            # Skip tunnel, loopback, etc.
        
        # ====================================================================
        # PHASE 2: Identify which physical interfaces have subinterfaces
        # ====================================================================
        # These get priority because they can carry multiple VLANs
        parent_interfaces = set()
        for vlan_name, vlan_props in vlan_interfaces:
            parent = vlan_props.get('interface', '')
            if parent:
                parent_interfaces.add(parent)
        
        # ====================================================================
        # PHASE 2B: Identify EtherChannel and Bridge Group members
        # ====================================================================
        # These interfaces should NOT be processed as standalone physical interfaces
        # because they will be configured as members of their parent interface
        etherchannel_members = set()
        for _, props in aggregate_ports:
            members = props.get('member', [])
            if isinstance(members, str):
                members = [members]
            for member in members:
                etherchannel_members.add(member)

        # Bridge group (virtual switch) members must also be excluded - otherwise
        # they get emitted twice: once as a BVI member and again as a standalone
        # physical interface (duplicate payload for the same hardware port).
        bridge_members = set()
        for _, props in switch_ports:
            members = props.get('member', [])
            if isinstance(members, str):
                members = members.split()  # FortiGate may store "port5 port6"
            elif not isinstance(members, list):
                members = []
            for member in members:
                bridge_members.add(member)

        # Combined set of all member interfaces (should not be processed standalone)
        member_interfaces = etherchannel_members | bridge_members
        
        # Separate physical ports into those with and without subinterfaces
        # Also exclude interfaces that are members of EtherChannels
        physical_with_subs = [(n, p) for n, p in physical_ports 
                              if n in parent_interfaces and n not in member_interfaces]
        physical_standalone = [(n, p) for n, p in physical_ports 
                               if n not in parent_interfaces and n not in member_interfaces]
        
        # ====================================================================
        # PHASE 3: Check available ports and warn if insufficient
        # ====================================================================
        # Count ports needed (rough estimate)
        etherch_member_count = 0
        for _, props in aggregate_ports:
            members = props.get('member', [])
            if isinstance(members, str):
                etherch_member_count += 1
            else:
                etherch_member_count += len(members)
        
        bridge_member_count = 0
        for _, props in switch_ports:
            members = props.get('member', [])
            if isinstance(members, str):
                bridge_member_count += 1
            else:
                bridge_member_count += len(members)
        
        # Account for EtherChannel expansion (extra 10G members added on top of
        # the source members for capacity scale-up).
        expansion_extra = 0
        for fg_name, props in aggregate_ports:
            alias = props.get('alias', fg_name)
            spec = self._get_expansion_spec(fg_name, alias, sanitize_interface_name(alias))
            if spec is None:
                continue
            base = props.get('member', [])
            base_n = 1 if isinstance(base, str) else len(base)
            if isinstance(spec, int):
                expansion_extra += max(0, spec - base_n)
            else:
                expansion_extra += len(spec)

        # Account for physical->EtherChannel and physical->bridge group
        # promotion (extra members added alongside the original port when a
        # plain interface becomes a LAG or a bridged segment).
        promotion_extra = 0
        for fg_name, props in physical_standalone:
            alias = props.get('alias', fg_name)
            spec = self._get_promotion_spec(fg_name, alias)
            if spec is None:
                spec = self._get_bridgegroup_promotion_spec(fg_name, alias)
            if spec is None:
                continue
            if isinstance(spec, int):
                promotion_extra += max(0, spec - 1)  # original port is member #1
            else:
                promotion_extra += len(spec)

        # Account for bridge group expansion (extra members added to a virtual
        # switch -> BVI for capacity scale-up).
        bridge_expansion_extra = 0
        for fg_name, props in switch_ports:
            spec = self._get_bridgegroup_expansion_spec(fg_name, sanitize_interface_name(fg_name))
            if spec is None:
                continue
            base = props.get('member', [])
            if isinstance(base, str):
                base_n = len(base.split())
            elif isinstance(base, list):
                base_n = len(base)
            else:
                base_n = 0
            if isinstance(spec, int):
                bridge_expansion_extra += max(0, spec - base_n)
            else:
                bridge_expansion_extra += len(spec)

        total_needed = (etherch_member_count + bridge_member_count +
                       len(physical_with_subs) + len(physical_standalone) +
                       expansion_extra + promotion_extra + bridge_expansion_extra)
        available = len(self.available_ftd_ports)

        print(f"\n  Port Analysis for {self.model_info['name']}:") # pyright: ignore[reportOptionalSubscript]
        print(f"    Available FTD ports: {available}")
        print("    FortiGate interfaces to convert:")
        print(f"      - EtherChannel members: {etherch_member_count}")
        if expansion_extra:
            print(f"      - EtherChannel expansion (extra members): {expansion_extra}")
        if promotion_extra:
            print(f"      - Physical->EtherChannel promotion (extra members): {promotion_extra}")
        print(f"      - Bridge Group members: {bridge_member_count}")
        if bridge_expansion_extra:
            print(f"      - Bridge Group expansion (extra members): {bridge_expansion_extra}")
        print(f"      - Physical with subinterfaces: {len(physical_with_subs)}")
        print(f"      - Standalone physical: {len(physical_standalone)}")
        if member_interfaces:
            print(f"      - Excluded (EC members): {len(member_interfaces)} ({', '.join(sorted(member_interfaces))})")
        print(f"    Total ports needed: {total_needed}")
        
        if total_needed > available:
            print(f"\n  [WARNING] Not enough ports! Need {total_needed}, have {available}")
            print("  [INFO] Using priority-based assignment:")
            print("         1. EtherChannels (aggregate traffic)")
            print("         2. Bridge Groups (switch ports)")
            print("         3. Interfaces with subinterfaces (carry VLANs)")
            print("         4. Standalone interfaces (if ports remain)")
        
        # ====================================================================
        # PHASE 4: Convert in PRIORITY ORDER
        # ====================================================================

        # Hold user-specified expansion/promotion ports out of the pool first,
        # so greedy per-interface assignment below cannot consume a port the
        # user explicitly requested for a port-channel or bridge group.
        self._prereserve_explicit_ports()

        # PRIORITY 1: Convert aggregate interfaces (EtherChannels)
        # These need member ports, so do first
        print("\n  [Priority 1] Converting Aggregate Interfaces (EtherChannels)...")
        for fg_name, properties in aggregate_ports:
            self._convert_aggregate_interface(fg_name, properties)
        
        # PRIORITY 2: Convert switch interfaces (Bridge Groups)
        # These also need member ports
        print("\n  [Priority 2] Converting Switch Interfaces (Bridge Groups)...")
        for fg_name, properties in switch_ports:
            self._convert_switch_interface(fg_name, properties)
        
        # PRIORITY 3: Convert physical interfaces THAT HAVE SUBINTERFACES
        # These are valuable because one port can carry multiple VLANs
        print("\n  [Priority 3] Converting Physical Interfaces with Subinterfaces...")
        for fg_name, properties in physical_with_subs:
            # Promotion of interfaces that carry VLAN subinterfaces is not
            # supported (the subinterfaces would have to move onto the parent).
            alias = properties.get('alias', fg_name)
            if self._get_promotion_spec(fg_name, alias) is not None:
                print(f"    [WARNING] {fg_name}: cannot promote to EtherChannel "
                      f"(it has VLAN subinterfaces) - converting as physical interface")
            elif self._get_bridgegroup_promotion_spec(fg_name, alias) is not None:
                print(f"    [WARNING] {fg_name}: cannot promote to bridge group "
                      f"(it has VLAN subinterfaces) - converting as physical interface")
            self._convert_physical_interface(fg_name, properties)
        
        # PRIORITY 4: Convert standalone physical interfaces
        # Only if we have ports left
        print("\n  [Priority 4] Converting Standalone Physical Interfaces...")
        remaining_ports = len(self.available_ftd_ports)
        if remaining_ports == 0 and len(physical_standalone) > 0:
            print(f"    [WARNING] No ports remaining for {len(physical_standalone)} standalone interfaces")
            for fg_name, props in physical_standalone:
                print(f"      Skipped: {fg_name} (no ports available)")
                self.stats['skipped'] += 1
                self.failed_items.append({"name": fg_name, "reason": "no ports available", "config": props})
        else:
            for fg_name, properties in physical_standalone:
                if len(self.available_ftd_ports) == 0:
                    print(f"    Skipped: {fg_name} (no ports available)")
                    self.stats['skipped'] += 1
                    self.failed_items.append({"name": fg_name, "reason": "no ports available", "config": properties})
                else:
                    # Promote to a new EtherChannel or bridge group if requested,
                    # otherwise convert as a standalone physical interface.
                    alias = properties.get('alias', fg_name)
                    ec_spec = self._get_promotion_spec(fg_name, alias)
                    bvi_spec = self._get_bridgegroup_promotion_spec(fg_name, alias)
                    if ec_spec is not None:
                        self._promote_physical_to_etherchannel(fg_name, properties, ec_spec)
                    elif bvi_spec is not None:
                        self._promote_physical_to_bridgegroup(fg_name, properties, bvi_spec)
                    else:
                        self._convert_physical_interface(fg_name, properties)
        
        # PHASE 5: Convert VLAN interfaces (Subinterfaces)
        # These don't need additional ports - they use parent interfaces
        print("\n  [Phase 5] Converting VLAN Interfaces (Subinterfaces)...")
        for fg_name, properties in vlan_interfaces:
            self._convert_vlan_interface(fg_name, properties)
        
        # PHASE 5B: Resolve duplicate VLAN IDs
        # FortiGate allows the same VLAN ID on different parents; FTD requires
        # device-wide unique VLAN IDs. Must run BEFORE zone generation so
        # zones reference the corrected hardware names.
        self._resolve_vlan_conflicts()

        # PHASE 6: Generate Security Zones for all converted interfaces
        # FTD requires security zones for firewall policies
        print("\n  [Phase 6] Generating Security Zones...")
        self._generate_security_zones()
        
        # Print final port allocation summary
        print("\n  Port Allocation Summary:")
        print(f"    Ports used: {len(self.assigned_ftd_ports) - len(self.skip_ftd_ports)}")
        print(f"    Ports remaining: {len(self.available_ftd_ports)}")
        print(f"    Security zones created: {len(self.security_zones)}")
        
        return {
            'physical_interfaces': self.physical_interfaces,
            'subinterfaces': self.subinterfaces,
            'etherchannels': self.etherchannels,
            'bridge_groups': self.bridge_groups,
            'security_zones': self.security_zones
        }
    
    def _generate_security_zones(self) -> None:
        """
        Generate security zones for all converted interfaces.
        
        FTD requires security zones for firewall policies. Each interface
        that will be used in access rules needs a corresponding security zone.
        
        Zone naming convention:
            - Uses the FTD interface name as the zone name
            - This allows firewall policies to reference zones by interface name
        
        FTD Security Zone API format:
            {
                "name": "zone_name",
                "description": "Auto-generated zone for interface",
                "mode": "ROUTED",
                "interfaces": [
                    {"name": "interface_name", "type": "physicalinterface"}
                ],
                "type": "securityzone"
            }
        """
        # Collect all unique interface names that need zones
        interfaces_needing_zones = []
        
        # Physical interfaces
        # NOTE: If a physical interface is a bridge group member, use the bridge
        # group name as the zone name instead of the physical interface name
        for intf in self.physical_interfaces:
            intf_name = intf.get('name', '')
            hardware_name = intf.get('hardwareName', '')
            
            # Check if this interface is a bridge group member
            bridge_group_name = self.bridge_group_members.get(hardware_name)
            
            if bridge_group_name:
                # Use bridge group name as zone name for member interfaces
                zone_name = bridge_group_name
            else:
                # Use interface name for standalone physical interfaces
                zone_name = intf_name
            
            if zone_name and zone_name not in self.created_zone_names:
                interfaces_needing_zones.append({
                    'name': intf_name,
                    'hardwareName': hardware_name,
                    'type': 'physicalinterface',
                    'zone_name': zone_name  # Store the zone name to use
                })
        
        # Subinterfaces
        for intf in self.subinterfaces:
            intf_name = intf.get('name', '')
            hardware_name = intf.get('hardwareName', '')
            if intf_name and intf_name not in self.created_zone_names:
                interfaces_needing_zones.append({
                    'name': intf_name,
                    'hardwareName': hardware_name,
                    'type': 'subinterface',
                    'zone_name': intf_name  # Zone name matches interface name
                })
        
        # EtherChannels
        for intf in self.etherchannels:
            intf_name = intf.get('name', '')
            hardware_name = intf.get('hardwareName', '')
            if intf_name and intf_name not in self.created_zone_names:
                interfaces_needing_zones.append({
                    'name': intf_name,
                    'hardwareName': hardware_name,
                    'type': 'etherchannelinterface',
                    'zone_name': intf_name  # Zone name matches interface name
                })
        
        # Bridge Groups - SKIP adding to security zones
        # In FTD, bridge group member physical interfaces are added to the zone,
        # NOT the BVI interface itself. The member interfaces above are already
        # assigned to use the bridge group name as their zone name.
        # 
        # FTD Security Zone behavior:
        #   - Physical interfaces that are bridge group members -> added to zone
        #   - The BVI (bridgegroupinterface) itself -> NOT added to zone
        
       # Create security zones for each interface
        # Group interfaces by zone name to support multiple interfaces per zone
        zone_interfaces = {}  # zone_name -> list of interface info dicts
        zone_hardware_seen = {}  # zone_name -> set of hardwareNames already added
        
        for intf_info in interfaces_needing_zones:
            # Use explicit zone_name if provided, otherwise use interface name
            zone_name = intf_info.get('zone_name', intf_info['name'])
            hardware_name = intf_info['hardwareName']
            
            if zone_name not in zone_interfaces:
                zone_interfaces[zone_name] = []
                zone_hardware_seen[zone_name] = set()
            
            # Skip if this hardware interface was already added to this zone
            if hardware_name in zone_hardware_seen[zone_name]:
                continue
            
            zone_interfaces[zone_name].append({
                'name': intf_info['name'],
                'hardwareName': hardware_name,
                'type': intf_info['type']
            })
            zone_hardware_seen[zone_name].add(hardware_name)
        
        # Create security zones
        for zone_name, interfaces in zone_interfaces.items():
            # Skip if zone already created
            if zone_name in self.created_zone_names:
                continue
            
            # Build interface list for zone description
            hardware_names = [intf['hardwareName'] for intf in interfaces]
            desc_interfaces = ', '.join(hardware_names) if len(hardware_names) <= 3 else f"{hardware_names[0]} + {len(hardware_names)-1} more"
            
            # Build security zone payload
            security_zone = {
                "name": zone_name,
                "description": f"Auto-generated zone for interface(s) {desc_interfaces}",
                "mode": "ROUTED",
                "interfaces": interfaces,
                "type": "securityzone"
            }
            
            self.security_zones.append(security_zone)
            self.created_zone_names.add(zone_name)
            self.stats['security_zones_created'] += 1
            
            if len(interfaces) > 1:
                print(f"    Created zone: {zone_name} (interfaces: {', '.join(hardware_names)})")
            else:
                print(f"    Created zone: {zone_name} (interface: {interfaces[0]['hardwareName']})")

    def _convert_physical_interface(self, fg_name: str, properties: Dict) -> None:
        """Convert a FortiGate physical interface to FTD format."""
        
        # Skip certain interfaces
        if fg_name in ['ha', 'mgmt', 'modem', 'naf.root', 'l2t.root', 'ssl.root']:
            print(f"    Skipped: {fg_name} (system/virtual interface)")
            self.stats['skipped'] += 1
            self.failed_items.append({"name": fg_name, "reason": "system/virtual interface", "config": properties})
            return
        
        # Skip interfaces that start with s, vw (special FortiGate ports)
        if fg_name.startswith('s') and len(fg_name) <= 2:
            print(f"    Skipped: {fg_name} (special port - no FTD equivalent)")
            self.stats['skipped'] += 1
            self.failed_items.append({"name": fg_name, "reason": "special port - no FTD equivalent", "config": properties})
            return
        if fg_name.startswith('vw'):
            print(f"    Skipped: {fg_name} (virtual wire port)")
            self.stats['skipped'] += 1
            self.failed_items.append({"name": fg_name, "reason": "virtual wire port", "config": properties})
            return
        
        # Get FTD hardware name
        ftd_hardware = self._get_ftd_hardware_name(fg_name)
        if not ftd_hardware:
            print(f"    Skipped: {fg_name} (no available FTD port)")
            self.stats['skipped'] += 1
            self.failed_items.append({"name": fg_name, "reason": "no available FTD port", "config": properties})
            return
        
        # Check if this FTD port should be skipped
        if ftd_hardware in self.skip_ftd_ports:
            print(f"    Skipped: {fg_name} -> {ftd_hardware} (reserved port)")
            self.stats['skipped'] += 1
            self.failed_items.append({"name": fg_name, "reason": f"reserved port ({ftd_hardware})", "config": properties})
            return
        
       # Get interface name (use alias if available, otherwise port name)
        alias = properties.get('alias', fg_name)
        ftd_name = sanitize_interface_name(alias)
        
        # Reserved names that conflict with FTD built-in interfaces
        # These names cannot be used for user interfaces
        reserved_names = {
            'management',
            'diagnostic',
            'inside',
            'outside'
        }
        
        # If name matches a reserved name, append hardware port number
        if ftd_name.lower() in reserved_names:
            original_reserved = ftd_name
            # Extract port number from hardware name (e.g., "Ethernet1/5" -> "5")
            port_num = ftd_hardware.split('/')[-1] if '/' in ftd_hardware else '1'
            ftd_name = f"{ftd_name}_port{port_num}"
            print(f"      Note: '{original_reserved}' is reserved, renamed to '{ftd_name}'")
        
        # Get description
        description = properties.get('description', alias)
        
        # Store the mapping
        self.interface_name_mapping[fg_name] = ftd_name
        self.interface_name_mapping[alias] = ftd_name
        
        # Build FTD physical interface payload (for PUT)
        ftd_interface = {
            "name": ftd_name,
            "hardwareName": ftd_hardware,
            "description": description,
            "enabled": properties.get('status', 'up') != 'down',
            "mode": "ROUTED",
            "type": "physicalinterface"
        }
        
        # Add IP address if present
        ip_config = properties.get('ip')
        if ip_config and isinstance(ip_config, list) and len(ip_config) >= 2:
            ip_addr = str(ip_config[0])
            netmask = str(ip_config[1])
            
            # Skip if IP is 0.0.0.0
            if ip_addr != '0.0.0.0':
                ftd_interface["ipv4"] = {
                    "ipType": "STATIC",
                    "defaultRouteUsingDHCP": False,
                    "ipAddress": {
                        "ipAddress": ip_addr,
                        "netmask": netmask,
                        "type": "haipv4address"
                    },
                    "dhcp": False,
                    "addressNull": False,
                    "type": "interfaceipv4"
                }
        
        # Add MTU if overridden (cap at 9000 - FTD maximum)
        if properties.get('mtu-override') == 'enable':
            mtu = properties.get('mtu', 1500)
            if mtu > 9000:
                mtu = 9000
            ftd_interface["mtu"] = mtu
        
        self.physical_interfaces.append(ftd_interface)
        self.stats['physical_updated'] += 1

        print(f"    Converted: {fg_name} -> {ftd_name} ({ftd_hardware})")

    def _promote_physical_to_etherchannel(self, fg_name: str, properties: Dict, spec: Any) -> None:
        """
        Promote a plain FortiGate physical interface to a NEW FTD EtherChannel so
        it can carry multiple 10G member links.

        The interface's name, MTU, and enabled state move onto the new
        port-channel; the original FTD port becomes the first member and extra
        members are added per `spec` (an int total member count INCLUDING the
        original port, or a list of FTD ports to add). The port-channel itself
        gets NO IP - in this design L3 addresses belong on VLAN subinterfaces
        riding on the channel, not on the channel.
        """
        alias = properties.get('alias', fg_name)
        ftd_name = sanitize_interface_name(alias)

        # Build the member list. Two spec forms:
        #   int  -> auto-assign the interface's own port as member #1, then grow
        #           to the requested TOTAL count from the free pool.
        #   list -> the listed ports ARE the members (exactly those), so "use
        #           ports 9-10" yields a 2-member channel, not 3.
        ftd_members: List[Dict[str, Any]] = []
        if isinstance(spec, int):
            original_hardware = self._get_ftd_hardware_name(fg_name)
            if not original_hardware:
                print(f"    Skipped promotion: {fg_name} (no available FTD port)")
                self.stats['skipped'] += 1
                self.failed_items.append({"name": fg_name, "reason": "no available FTD port (promotion)", "config": properties})
                return
            if original_hardware in self.skip_ftd_ports:
                print(f"    Skipped promotion: {fg_name} -> {original_hardware} (reserved port)")
                self.stats['skipped'] += 1
                self.failed_items.append({"name": fg_name, "reason": f"reserved port ({original_hardware})", "config": properties})
                return
            name_port = original_hardware
        else:
            # Representative port for the reserved-name rename below.
            name_port = next(
                (str(p).strip() for p in spec
                 if re.match(r'^Ethernet\d+/\d+$', str(p).strip())),
                'Ethernet1/1',
            )

        # Reserved names that conflict with FTD built-ins (same rule as physical)
        reserved_names = {'management', 'diagnostic', 'inside', 'outside'}
        if ftd_name.lower() in reserved_names:
            original_reserved = ftd_name
            port_num = name_port.split('/')[-1] if '/' in name_port else '1'
            ftd_name = f"{ftd_name}_port{port_num}"
            print(f"      Note: '{original_reserved}' is reserved, renamed to '{ftd_name}'")

        if isinstance(spec, int):
            if self._add_etherchannel_member(fg_name, name_port, ftd_members):
                print(f"      Promoted base member: {fg_name} -> {name_port} (routed mode, EC-ready)")
            self._apply_etherchannel_expansion(fg_name, spec, ftd_members)
        else:
            # Explicit ports become the members (held out of the pool earlier).
            self._apply_etherchannel_expansion(fg_name, list(spec), ftd_members)
            if not ftd_members:
                print(f"    Skipped promotion: {fg_name} (none of the requested ports were available)")
                self.stats['skipped'] += 1
                self.failed_items.append({"name": fg_name, "reason": "no requested ports available (promotion)", "config": properties})
                return

        # Store name mapping so routes/policies follow the interface to the EC
        self.interface_name_mapping[fg_name] = ftd_name
        self.interface_name_mapping[alias] = ftd_name

        etherchannel_id = len(self.etherchannels) + 1

        ftd_interface = {
            "name": ftd_name,
            "hardwareName": f"Port-channel{etherchannel_id}",
            "description": properties.get('description', alias),
            "enabled": properties.get('status', 'up') != 'down',
            "mode": "ROUTED",
            "etherChannelID": etherchannel_id,
            "memberInterfaces": ftd_members,
            "lacpMode": "ACTIVE",
            "type": "etherchannelinterface"
        }

        # Add MTU if overridden (cap at 9000 - FTD maximum)
        if properties.get('mtu-override') == 'enable':
            mtu = properties.get('mtu', 1500)
            if mtu > 9000:
                mtu = 9000
            ftd_interface["mtu"] = mtu

        self.etherchannels.append(ftd_interface)
        self.stats['etherchannels_created'] += 1

        member_str = ', '.join([m['hardwareName'] for m in ftd_members])
        print(f"    Promoted: {fg_name} -> {ftd_name} (Port-channel{etherchannel_id}) members: [{member_str}]")

        # Preserve the source interface's IP. A port-channel can't keep the IP
        # on the channel in this design, so:
        #   - if an L3 VLAN tag was given for this interface, place the IP on a
        #     subinterface (Port-channelN.tag) - the configured behavior;
        #   - otherwise apply it directly to the routed port-channel (lossless
        #     fallback so the address is never silently dropped).
        src_ipv4 = self._build_ipv4_config(properties.get('ip'))
        if src_ipv4:
            vlan = self._get_promotion_pc_vlan(fg_name, alias)
            if vlan is not None:
                self._add_promotion_subinterface(
                    fg_name, alias, properties, ftd_name,
                    f"Port-channel{etherchannel_id}", vlan, src_ipv4,
                    parent_class='etherchannel',
                )
            else:
                ftd_interface["ipv4"] = src_ipv4
                print(f"      Note: {fg_name} IP {src_ipv4['ipAddress']['ipAddress']} "
                      f"applied directly to Port-channel{etherchannel_id} "
                      f"(no L3 VLAN tag given for a subinterface)")

    def _add_promotion_subinterface(self, fg_name: str, alias: str,
                                    properties: Dict, parent_ftd_name: str,
                                    parent_hardware: str, vlan_id: int,
                                    ipv4: Dict, parent_class: str) -> None:
        """Create an FTD subinterface that carries the IP of an interface that
        was promoted to a port-channel. Routes/policies that referenced the
        source interface are re-pointed to this subinterface (the L3 endpoint)."""
        base_name = sanitize_interface_name(f"{alias}_vlan{vlan_id}")
        ftd_name = base_name
        counter = 2
        while ftd_name in self.used_subinterface_names:
            ftd_name = f"{base_name}_{counter}"
            counter += 1
        self.used_subinterface_names.add(ftd_name)

        # Re-point the source interface to the subinterface so its IP-bearing
        # endpoint is what routes/policies resolve to.
        self.interface_name_mapping[fg_name] = ftd_name
        if alias:
            self.interface_name_mapping[alias] = ftd_name

        subif = {
            "name": ftd_name,
            "hardwareName": f"{parent_hardware}.{vlan_id}",
            "description": properties.get('description', alias),
            "enabled": properties.get('status', 'up') != 'down',
            "mode": "ROUTED",
            "subIntfId": int(vlan_id),
            "vlanId": int(vlan_id),
            "ipv4": ipv4,
            "type": "subinterface",
            "_vlanParentClass": parent_class,
        }
        if properties.get('mtu-override') == 'enable':
            mtu = properties.get('mtu', 1500)
            subif["mtu"] = min(mtu, 9000)

        self.subinterfaces.append(subif)
        self.stats['subinterfaces_created'] += 1
        print(f"      L3 on subinterface: {fg_name} IP "
              f"{ipv4['ipAddress']['ipAddress']} -> {ftd_name} "
              f"({parent_hardware}.{vlan_id})")

    def _promote_physical_to_bridgegroup(self, fg_name: str, properties: Dict, spec: Any) -> None:
        """
        Promote a plain FortiGate physical interface to a NEW FTD bridge group
        (BVI) so its subnet can span several bridged ports on the Cisco side.

        The original FTD port becomes the first member and extra members are
        added per `spec` (an int total member count INCLUDING the original port,
        or a list of FTD ports to add). Unlike port-channel promotion, the
        interface's IPv4 address and MTU MOVE ONTO the BVI - a bridge group is
        the Layer-3 interface for the bridged segment.
        """
        alias = properties.get('alias', fg_name)
        ftd_name = sanitize_interface_name(alias)

        # Decide the representative port used for the reserved-name rename, and
        # (for an int spec) auto-assign the interface's own port as member #1.
        #   int  -> auto port + grow to the requested TOTAL count.
        #   list -> the listed ports ARE the members (exactly those), so "use
        #           ports 9-10" yields a 2-member bridge group, not 3.
        if isinstance(spec, int):
            original_hardware = self._get_ftd_hardware_name(fg_name)
            if not original_hardware:
                print(f"    Skipped promotion: {fg_name} (no available FTD port)")
                self.stats['skipped'] += 1
                self.failed_items.append({"name": fg_name, "reason": "no available FTD port (bridge promotion)", "config": properties})
                return
            if original_hardware in self.skip_ftd_ports:
                print(f"    Skipped promotion: {fg_name} -> {original_hardware} (reserved port)")
                self.stats['skipped'] += 1
                self.failed_items.append({"name": fg_name, "reason": f"reserved port ({original_hardware})", "config": properties})
                return
            name_port = original_hardware
        else:
            name_port = next(
                (str(p).strip() for p in spec
                 if re.match(r'^Ethernet\d+/\d+$', str(p).strip())),
                'Ethernet1/1',
            )

        # Reserved names that conflict with FTD built-ins (same rule as physical)
        reserved_names = {'management', 'diagnostic', 'inside', 'outside'}
        if ftd_name.lower() in reserved_names:
            original_reserved = ftd_name
            port_num = name_port.split('/')[-1] if '/' in name_port else '1'
            ftd_name = f"{ftd_name}_port{port_num}"
            print(f"      Note: '{original_reserved}' is reserved, renamed to '{ftd_name}'")

        # Build the member list (synthesized member names so they don't collide
        # with the BVI name).
        ftd_members: List[Dict[str, Any]] = []
        if isinstance(spec, int):
            base_member_name = self._bridgegroup_member_name(ftd_name, name_port)
            if self._add_bridgegroup_member(fg_name, ftd_name, name_port,
                                            ftd_members, base_member_name):
                print(f"      Promoted base member: {fg_name} -> {name_port} (routed mode, BVI member)")
            self._apply_bridgegroup_expansion(fg_name, ftd_name, spec, ftd_members)
        else:
            # Explicit ports become the members (held out of the pool earlier).
            self._apply_bridgegroup_expansion(fg_name, ftd_name, list(spec), ftd_members)
            if not ftd_members:
                print(f"    Skipped promotion: {fg_name} (none of the requested ports were available)")
                self.stats['skipped'] += 1
                self.failed_items.append({"name": fg_name, "reason": "no requested ports available (bridge promotion)", "config": properties})
                return

        # Store name mapping so routes/policies follow the interface to the BVI
        self.interface_name_mapping[fg_name] = ftd_name
        self.interface_name_mapping[alias] = ftd_name

        bridge_group_id = len(self.bridge_groups) + 1

        ftd_interface: Dict[str, Any] = {
            "name": ftd_name,
            "bridgeGroupId": bridge_group_id,
            "description": properties.get('description', alias),
            "enabled": properties.get('status', 'up') != 'down',
            "selectedInterfaces": ftd_members,
            "type": "bridgegroupinterface"
        }

        # A bridge group is the L3 interface for the segment, so the source
        # interface's IP moves onto the BVI (unlike port-channel promotion).
        ipv4 = self._build_ipv4_config(properties.get('ip'))
        if ipv4:
            ftd_interface["ipv4"] = ipv4

        # Add MTU if overridden (cap at 9000 - FTD maximum)
        if properties.get('mtu-override') == 'enable':
            mtu = properties.get('mtu', 1500)
            if mtu > 9000:
                mtu = 9000
            ftd_interface["mtu"] = mtu

        self.bridge_groups.append(ftd_interface)
        self.stats['bridge_groups_created'] += 1

        member_str = ', '.join([m['hardwareName'] for m in ftd_members])
        print(f"    Promoted: {fg_name} -> {ftd_name} (BVI{bridge_group_id}) members: [{member_str}]")

    def _convert_aggregate_interface(self, fg_name: str, properties: Dict) -> None:
        """Convert a FortiGate aggregate interface to FTD EtherChannel."""
        
        # Get interface name
        alias = properties.get('alias', fg_name)
        ftd_name = sanitize_interface_name(alias)
        
        # Store the mapping
        self.interface_name_mapping[fg_name] = ftd_name
        self.interface_name_mapping[alias] = ftd_name
        
        # Get member interfaces
        members = properties.get('member', [])
        if isinstance(members, str):
            members = [members]
        
        # Expansion spec, if any. An explicit port LIST means "use exactly these
        # ports as the members" (same as promotion) - so the source members are
        # NOT auto-assigned to arbitrary ports first. An int means "grow to this
        # total", which keeps the source members and adds more.
        spec = self._get_expansion_spec(fg_name, alias, ftd_name)
        explicit_ports = isinstance(spec, (list, tuple))

        # Map member names to FTD hardware names AND create physical interface
        # entries for each member so they get set to routed mode before the
        # EtherChannel is created. EtherChannel members require: empty name,
        # routed mode, full duplex, autoNegotiation enabled (speed/SFP type is
        # auto-detected at import). Skipped when explicit ports were given.
        ftd_members = []
        if not explicit_ports:
            for member in members:
                ftd_hardware = self._get_ftd_hardware_name(member)
                if ftd_hardware:
                    if self._add_etherchannel_member(fg_name, ftd_hardware, ftd_members):
                        print(f"      Added member interface: {member} -> {ftd_hardware} (routed mode, EC-ready)")

        # Apply EtherChannel expansion: an explicit list defines the exact
        # members; an int grows this port-channel to MORE member links on the
        # FTD side. No-op unless an expansion spec matches.
        if spec is not None:
            self._apply_etherchannel_expansion(fg_name, spec, ftd_members)

        if not ftd_members:
            print(f"    Skipped: {fg_name} (no valid member interfaces)")
            self.stats['skipped'] += 1
            self.failed_items.append({"name": fg_name, "reason": "no valid member interfaces", "config": properties})
            return

        # Determine EtherChannel ID (extract from existing or assign new)
        # For simplicity, use 1 for first etherchannel, 2 for second, etc.
        etherchannel_id = len(self.etherchannels) + 1
        
        # Build FTD EtherChannel payload
        ftd_interface = {
            "name": ftd_name,
            "hardwareName": f"Port-channel{etherchannel_id}",
            "description": properties.get('description', alias),
            "enabled": properties.get('status', 'up') != 'down',
            "mode": "ROUTED",
            "etherChannelID": etherchannel_id,
            "memberInterfaces": ftd_members,
            "lacpMode": "ACTIVE",
            "type": "etherchannelinterface"
        }
        
        # Add MTU if overridden (cap at 9000 - FTD maximum)
        if properties.get('mtu-override') == 'enable':
            mtu = properties.get('mtu', 1500)
            if mtu > 9000:
                mtu = 9000
            ftd_interface["mtu"] = mtu
        
        self.etherchannels.append(ftd_interface)
        self.stats['etherchannels_created'] += 1
        
        member_str = ', '.join([m['hardwareName'] for m in ftd_members])
        print(f"    Converted: {fg_name} -> {ftd_name} (Port-channel{etherchannel_id}) members: [{member_str}]")
    
    def _convert_switch_interface(self, fg_name: str, properties: Dict) -> None:
        """Convert a FortiGate switch interface to FTD Bridge Group."""
        
        # Get interface name
        ftd_name = sanitize_interface_name(fg_name)
        
        # Store the mapping
        self.interface_name_mapping[fg_name] = ftd_name
        
        # Get member interfaces from system_switch-interface properties
        # FortiGate can store as: "port5" or "port5 port6" or ["port5", "port6"]
        members_raw = properties.get('member', [])
        if isinstance(members_raw, str):
            # Could be space-separated: "port5 port6"
            members = members_raw.split()
        elif isinstance(members_raw, list):
            members = members_raw
        else:
            members = []
        
        # Expansion spec, if any. An explicit port LIST means "use exactly these
        # ports as the members" - the source switch members are NOT auto-assigned
        # to arbitrary ports. An int means "grow to this total" (keep source
        # members and add more).
        spec = self._get_bridgegroup_expansion_spec(fg_name, ftd_name)
        explicit_ports = isinstance(spec, (list, tuple))

        # Map member names to FTD hardware names AND create physical interface
        # entries for each member (named, routed-mode, tracked as BVI members).
        # Skipped when explicit ports were given.
        ftd_members: List[Dict[str, Any]] = []
        if not explicit_ports:
            for member in members:
                ftd_hardware = self._get_ftd_hardware_name(member)
                if ftd_hardware:
                    # Get the name/description from the physical port's entry in
                    # system_interface (fall back to the raw member name).
                    member_props = self._get_interface_properties(member)
                    member_alias = member_props.get('alias', member) if member_props else member
                    member_name = sanitize_interface_name(member_alias)
                    member_desc = (member_props.get('description', f"Bridge Group {fg_name} member")
                                   if member_props else f"Bridge Group {fg_name} member")
                    if self._add_bridgegroup_member(fg_name, ftd_name, ftd_hardware,
                                                    ftd_members, member_name, member_desc):
                        print(f"      Added member interface: {member} -> {ftd_hardware}")

        # Apply bridge group expansion: an explicit list defines the exact
        # members; an int adds MORE member links on the FTD side. No-op unless
        # an expansion spec matches this switch interface.
        if spec is not None:
            self._apply_bridgegroup_expansion(fg_name, ftd_name, spec, ftd_members)

        if not ftd_members:
            print(f"    Skipped: {fg_name} (no valid member interfaces)")
            self.stats['skipped'] += 1
            self.failed_items.append({"name": fg_name, "reason": "no valid member interfaces", "config": properties})
            return

        # Bridge Group ID
        bridge_group_id = len(self.bridge_groups) + 1
        
        # Look up IP and MTU from system_interface section
        # The switch interface name (fg_name) should have a corresponding entry
        switch_intf_props = self._get_interface_properties(fg_name)
        
        # Build FTD Bridge Group payload
        ftd_interface = {
            "name": ftd_name,
            "bridgeGroupId": bridge_group_id,
            "description": properties.get('description', fg_name),
            "enabled": True,
            "selectedInterfaces": ftd_members,
            "type": "bridgegroupinterface"
        }
        
        # Add IP address if present (from system_interface lookup)
        ip_config = switch_intf_props.get('ip') if switch_intf_props else None
        if ip_config and isinstance(ip_config, list) and len(ip_config) >= 2:
            ip_addr = str(ip_config[0])
            netmask = str(ip_config[1])
            
            if ip_addr != '0.0.0.0':
                ftd_interface["ipv4"] = {
                    "ipType": "STATIC",
                    "defaultRouteUsingDHCP": False,
                    "ipAddress": {
                        "ipAddress": ip_addr,
                        "netmask": netmask,
                        "type": "haipv4address"
                    },
                    "dhcp": False,
                    "addressNull": False,
                    "type": "interfaceipv4"
                }
        
        # Add MTU if overridden (cap at 9000 - FTD maximum)
        mtu_override = switch_intf_props.get('mtu-override') if switch_intf_props else None
        if mtu_override == 'enable':
            mtu = switch_intf_props.get('mtu', 1500)
            if mtu > 9000:
                mtu = 9000
            ftd_interface["mtu"] = mtu
        
        self.bridge_groups.append(ftd_interface)
        self.stats['bridge_groups_created'] += 1
        
        member_str = ', '.join([m['hardwareName'] for m in ftd_members])
        print(f"    Converted: {fg_name} -> {ftd_name} (BVI{bridge_group_id}) members: [{member_str}]")

    def _get_interface_properties(self, intf_name: str) -> Dict:
        """
        Look up interface properties from system_interface section.
        
        Args:
            intf_name: Interface name to look up
            
        Returns:
            Properties dictionary or empty dict if not found
        """
        interfaces = self.fg_config.get('system_interface', [])
        
        for intf_dict in interfaces:
            name = list(intf_dict.keys())[0]
            if name == intf_name:
                return intf_dict[name]
        
        return {}
    
    def _convert_vlan_interface(self, fg_name: str, properties: Dict) -> None:
        """
        Convert a FortiGate VLAN interface to FTD Subinterface.
        
        The FTD subinterface name combines both the alias and the original
        FortiGate interface name for clarity and uniqueness.
        
        Args:
            fg_name: FortiGate interface name (e.g., '551')
            properties: Interface properties from YAML config
        """
        # Get parent interface and VLAN ID
        parent_fg_name = properties.get('interface')
        vlan_id = properties.get('vlanid')
        
        if not parent_fg_name or not vlan_id:
            print(f"    Skipped: {fg_name} (missing parent interface or VLAN ID)")
            self.stats['skipped'] += 1
            self.failed_items.append({"name": fg_name, "reason": "missing parent interface or VLAN ID", "config": properties})
            return
        
        # Build FTD name from both alias and fg_name for clarity
        # Example: alias="L-slap", fg_name="551" -> "l_slap_551"
        alias = properties.get('alias', '')
        
        if alias and alias != fg_name:
            # Combine alias and fg_name: "alias_fgname"
            combined_name = f"{alias}_{fg_name}"
        else:
            # No alias or alias equals fg_name, just use fg_name
            combined_name = fg_name
        
        ftd_name = sanitize_interface_name(combined_name)
        
        # Reserved names that conflict with FTD built-in interfaces
        # These names cannot be used for subinterfaces
        reserved_names = {
            'management',
            'diagnostic',
            'inside',
            'outside'
        }
        
        # If name matches a reserved name, append a suffix
        if ftd_name.lower() in reserved_names:
            original_reserved = ftd_name
            ftd_name = f"{ftd_name}_vlan{vlan_id}"
            print(f"      Note: '{original_reserved}' is reserved, renamed to '{ftd_name}'")
        
        # Check for duplicate names and make unique if needed
        original_name = ftd_name
        counter = 2
        while ftd_name in self.used_subinterface_names:
            ftd_name = f"{original_name}_{counter}"
            counter += 1
        
        # Track this name as used
        self.used_subinterface_names.add(ftd_name)
        
        # Store the mapping for both fg_name and alias (if different)
        self.interface_name_mapping[fg_name] = ftd_name
        if alias and alias != fg_name:
            self.interface_name_mapping[alias] = ftd_name
        
        # Determine parent FTD interface
        # Could be physical or etherchannel
        parent_ftd_name = self.interface_name_mapping.get(parent_fg_name)
        
        # Build set of FortiGate aggregate interface names for efficient lookup
        # This includes the original FortiGate name that maps to each etherchannel
        etherchannel_fg_names = set()
        for ec in self.etherchannels:
            ec_ftd_name = ec.get('name', '')
            # Find all FortiGate names that map to this etherchannel's FTD name
            for fg_name_key, ftd_name_val in self.interface_name_mapping.items():
                if ftd_name_val == ec_ftd_name:
                    etherchannel_fg_names.add(fg_name_key)
        
        # Determine hardware name based on parent type.
        # Also classify the parent for VLAN conflict resolution: subinterfaces
        # on etherchannels and virtual switches (bridge groups) keep their
        # VLAN IDs; physical-parent subinterfaces may be remapped on conflict.
        bridge_group_names = {bg.get('name') for bg in self.bridge_groups}
        if parent_fg_name in etherchannel_fg_names:
            parent_class = 'etherchannel'
            # Parent is an etherchannel - find its hardware name
            for ec in self.etherchannels:
                if parent_ftd_name == ec.get('name'):
                    parent_hardware = ec.get('hardwareName', 'Port-channel1')
                    break
            else:
                parent_hardware = 'Port-channel1'  # Default fallback
        else:
            parent_class = 'bridge' if parent_ftd_name in bridge_group_names else 'physical'
            # Parent is a physical interface
            parent_hardware = self.port_mapping.get(parent_fg_name, "Ethernet1/1")

        hardware_name = f"{parent_hardware}.{vlan_id}"

        # Build FTD Subinterface payload
        # _vlanParentClass is transient - consumed and removed by
        # _resolve_vlan_conflicts() before the payloads are written out.
        ftd_interface = {
            "name": ftd_name,
            "hardwareName": hardware_name,
            "description": properties.get('description', alias),
            "enabled": properties.get('status', 'up') != 'down',
            "mode": "ROUTED",
            "subIntfId": int(vlan_id),
            "vlanId": int(vlan_id),
            "type": "subinterface",
            "_vlanParentClass": parent_class
        }
        
        # Add IP address if present
        ip_config = properties.get('ip')
        if ip_config and isinstance(ip_config, list) and len(ip_config) >= 2:
            ip_addr = str(ip_config[0])
            netmask = str(ip_config[1])
            
            if ip_addr != '0.0.0.0':
                ftd_interface["ipv4"] = {
                    "ipType": "STATIC",
                    "defaultRouteUsingDHCP": False,
                    "ipAddress": {
                        "ipAddress": ip_addr,
                        "netmask": netmask,
                        "type": "haipv4address"
                    },
                    "dhcp": False,
                    "addressNull": False,
                    "type": "interfaceipv4"
                }
        
        # Add MTU if overridden (cap at 9000 - FTD maximum)
        if properties.get('mtu-override') == 'enable':
            mtu = properties.get('mtu', 1500)
            if mtu > 9000:
                mtu = 9000
            ftd_interface["mtu"] = mtu
        
        self.subinterfaces.append(ftd_interface)
        self.stats['subinterfaces_created'] += 1
        
        if ftd_name != original_name:
            print(f"    Converted: {fg_name} -> {ftd_name} ({hardware_name}) VLAN {vlan_id} [renamed from {original_name}]")
        else:
            print(f"    Converted: {fg_name} -> {ftd_name} ({hardware_name}) VLAN {vlan_id}")
    
    @staticmethod
    def _next_free_vlan(start: int, used: Set[int]) -> Optional[int]:
        """
        Find the closest unused VLAN ID, scanning up from ``start`` and
        wrapping around to the bottom of the range (2-4094) if needed.
        """
        for candidate in range(start + 1, 4095):
            if candidate not in used:
                return candidate
        for candidate in range(2, start):
            if candidate not in used:
                return candidate
        return None

    def _resolve_vlan_conflicts(self) -> None:
        """
        Remap duplicate VLAN IDs so every subinterface is unique device-wide.

        FortiGate allows VLAN interfaces on different parents (physical
        ports, port channels, virtual switches) to share a VLAN ID. FTD
        rejects a subinterface whose VLAN ID is already used anywhere on the
        device, so the duplicates would fail to import.

        Priority: subinterfaces parented on EtherChannels and virtual
        switches (bridge groups) keep their original VLAN IDs. Physical-
        interface subinterfaces that conflict are moved to the nearest
        unused VLAN ID. Within the same priority tier, config order wins -
        a later duplicate is remapped even if it is on a priority parent
        (two priority parents cannot both keep the same VLAN ID; this is
        flagged with a warning).

        Only vlanId/subIntfId and the hardwareName suffix change - the
        logical name is untouched, so security zones, routes, and policies
        that reference the interface by name are unaffected.
        """
        # Pop the transient classification tag so it never reaches the
        # JSON output files (default to 'physical' for safety).
        classes = [intf.pop('_vlanParentClass', 'physical') for intf in self.subinterfaces]

        if not self.subinterfaces:
            return

        # Priority parents claim their VLAN IDs first; config order breaks ties
        order = sorted(
            range(len(self.subinterfaces)),
            key=lambda i: (1 if classes[i] == 'physical' else 0, i),
        )

        # Remap targets must avoid every original VLAN ID, not just the ones
        # claimed so far - otherwise a remap could steal the ID of an
        # interface processed later and needlessly displace it too.
        original_vlans = {intf.get('vlanId') for intf in self.subinterfaces}

        used_vlans = set()
        remapped = []
        for i in order:
            intf = self.subinterfaces[i]
            vlan_id = intf.get('vlanId')
            if vlan_id not in used_vlans:
                used_vlans.add(vlan_id)
                continue

            new_vlan = self._next_free_vlan(vlan_id, used_vlans | original_vlans)
            if new_vlan is None:
                print(f"    [WARNING] {intf.get('name')}: no free VLAN ID available to resolve conflict on VLAN {vlan_id}")
                self.stats['skipped'] += 1
                self.failed_items.append({
                    "name": intf.get('name'),
                    "reason": f"duplicate VLAN {vlan_id} and no free VLAN ID available",
                    "config": dict(intf),
                })
                continue

            parent_hardware = str(intf.get('hardwareName', '')).rsplit('.', 1)[0]
            intf['vlanId'] = new_vlan
            intf['subIntfId'] = new_vlan
            intf['hardwareName'] = f"{parent_hardware}.{new_vlan}"
            desc = intf.get('description') or ''
            intf['description'] = f"{desc} [remapped from VLAN {vlan_id}]".strip()
            used_vlans.add(new_vlan)
            remapped.append((intf.get('name'), parent_hardware, vlan_id, new_vlan, classes[i]))

        if remapped:
            print(f"\n  [Phase 5B] Resolved {len(remapped)} duplicate VLAN ID(s):")
            for name, parent_hw, old_vlan, new_vlan, parent_class in remapped:
                note = '' if parent_class == 'physical' else f"  [WARNING: {parent_class}-parented interface had to move]"
                print(f"    {name}: {parent_hw}.{old_vlan} -> {parent_hw}.{new_vlan}{note}")

        self.stats['vlan_conflicts_remapped'] = len(remapped)

    def get_interface_mapping(self) -> Dict[str, str]:
        """
        Get the mapping of FortiGate interface names to FTD interface names.
        
        This is used by route and policy converters to update interface references.
        
        Returns:
            Dict mapping FortiGate names to FTD names
        """
        return self.interface_name_mapping.copy()
    
    def get_statistics(self) -> Dict[str, int]:
        """Get conversion statistics."""
        return self.stats.copy()


# =============================================================================
# TESTING CODE
# =============================================================================

if __name__ == '__main__':
    """Test the interface converter."""
    
    # Sample FortiGate configuration
    test_config = {
        'system_interface': [
            {
                'port2': {
                    'vdom': 'root',
                    'ip': ['10.0.0.6', '255.255.255.252'],
                    'type': 'physical',
                    'alias': 'IP-KVM',
                    'description': 'Connection to KVM'
                }
            },
            {
                'port6': {
                    'vdom': 'root',
                    'ip': ['10.0.0.10', '255.255.255.252'],
                    'type': 'physical',
                    'alias': 'L3_NTP'
                }
            },
            {
                'ether_trunk': {
                    'vdom': 'root',
                    'type': 'aggregate',
                    'member': ['x1', 'x2'],
                    'alias': 'UTB',
                    'mtu-override': 'enable',
                    'mtu': 9216
                }
            },
            {
                'whitebox': {
                    'vdom': 'root',
                    'ip': ['10.10.255.1', '255.255.255.0'],
                    'type': 'switch',
                    'description': 'Bridge Group'
                }
            },
            {
                '551': {
                    'vdom': 'root',
                    'ip': ['10.1.70.1', '255.255.255.0'],
                    'alias': 'L-slap',
                    'interface': 'ether_trunk',
                    'vlanid': 551
                }
            }
        ]
    }
    
    converter = InterfaceConverter(test_config)
    
    print("Testing Interface Converter...")
    print("="*60)
    result = converter.convert()
    
    print("\n" + "="*60)
    print("Results:")
    print("="*60)
    
    import json
    
    print("\nPhysical Interfaces (PUT):")
    print(json.dumps(result['physical_interfaces'], indent=2))
    
    print("\nEtherChannels (POST):")
    print(json.dumps(result['etherchannels'], indent=2))
    
    print("\nBridge Groups (POST):")
    print(json.dumps(result['bridge_groups'], indent=2))
    
    print("\nSubinterfaces (POST):")
    print(json.dumps(result['subinterfaces'], indent=2))
    
    print("\nInterface Name Mapping:")
    print(json.dumps(converter.get_interface_mapping(), indent=2))
    
    print("\nStatistics:")
    print(json.dumps(converter.get_statistics(), indent=2))