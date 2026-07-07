#!/usr/bin/env python3
"""
FTD SNMPv3 Configuration Tool
==============================
Configures SNMPv3 on a locally managed Cisco FTD (FDM) via the REST API.

FDM does not expose SNMPv3 settings in its GUI - configuration must go
through the API (FDM 6.7+). This tool performs the full STIG-compliant
sequence (CASA-ND-001050 / CASA-ND-001070):

1. Create/update an SNMPv3 user (Auth/Priv: SHA auth + AES privacy)
2. Look up the source interface by its logical name
3. For EACH SNMP manager: create/update a network object for the NMS
   host and an SNMP host binding the NMS, user, and interface
4. Optionally set the device-global location/contact (sysLocation /
   sysContact via the SNMPServer settings object)
5. Optionally deploy the pending changes

Multiple SNMP managers are supported - they share the SNMPv3 user and
source interface, and each manager gets its own network object and SNMP
host. Object names are always suffixed with the manager IP, so separate
runs are additive: pushing a different management tool's manager with
its own SNMPv3 user adds alongside the existing config instead of
overwriting it (one user per tool is supported by running once per tool).

All steps are create-or-update (idempotent): re-running with new values
updates the existing objects instead of failing on duplicates.

Verification after deploy (SSH to the FTD):
    show run snmp-server
    show snmp-server user

Usage:
    python ftd_snmp_config.py --host 192.168.1.1 -u admin \
        --nms-ip 10.0.0.50 --snmp-user FWADMIN --interface outside \
        --auth-algorithm SHA --priv-algorithm AES256 --deploy
"""

import argparse
import getpass
import sys
from typing import Dict, List, Optional, Tuple, Union

import requests
import urllib3

from flair import flair
from ftd_api_base import FTDBaseClient

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AUTH_ALGORITHMS = ["SHA", "SHA256"]
PRIV_ALGORITHMS = ["AES128", "AES192", "AES256"]
SECURITY_LEVELS = ["PRIV", "AUTH"]  # NOAUTH intentionally excluded (STIG)

# Device-global trap event types supported by the FDM SNMPServer model.
# (ASA CLI traps like ipsec/ikev2/interface-threshold are NOT exposed by FDM.)
TRAP_EVENTS = [
    "SNMP_AUTHENTICATION", "SNMP_LINKUP", "SNMP_LINKDOWN",
    "SNMP_COLDSTART", "SNMP_WARMSTART", "SYSLOG",
    "CONNECTION_LIMIT_REACHED", "NAT_PACKET_DISCARD",
    "CPU_THRESHOLD_RISING", "MEM_THRESHOLD",
    "FAILOVER", "CLUSTER", "PEER_FLAP",
    "FRU_INSERT", "FRU_REMOVE", "CONFIG_CHANGE",
]

# Read-only FDM bookkeeping that must not be sent back in a PUT body
_META_KEYS = ("links",)


class FTDSNMPConfig(FTDBaseClient):
    """Pushes SNMPv3 configuration objects to an FDM-managed FTD."""

    def __init__(self, host: str, username: str, password: str,
                 verify_ssl: bool = False, debug: bool = False) -> None:
        super().__init__(host, username, password, verify_ssl, debug)

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------
    def _extract_error(self, response: requests.Response) -> str:
        """Best-effort FDM error extraction with safe fallbacks."""
        try:
            messages = response.json().get("error", {}).get("messages", [])
            if messages and isinstance(messages[0], dict):
                return str(messages[0].get("description", f"HTTP {response.status_code}"))
        except (ValueError, TypeError, KeyError):
            pass
        return f"HTTP {response.status_code}"

    def _get_by_name(self, endpoint: str, name: str) -> Optional[Dict]:
        """Find an object by name on a list endpoint (filter + paginated scan).

        Delegates to the shared FTDBaseClient.find_object_by_name helper,
        which advances the scan offset by the actual page size so short
        pages never cause objects to be missed.
        """
        found, obj = self.find_object_by_name(f"{self.base_url}{endpoint}", name)
        if found and isinstance(obj, dict):
            return obj
        return None

    def _upsert(self, endpoint: str, payload: Dict, label: str) -> Tuple[bool, Union[Dict, str]]:
        """
        Create the object, or update it in place if one with the same name
        already exists.

        Returns:
            (True, object_dict) on success, (False, error_message) on failure.
        """
        name = payload.get("name", "")
        existing = self._get_by_name(endpoint, name)

        try:
            if existing and existing.get("id"):
                update = dict(existing)
                update.update(payload)
                update["id"] = existing["id"]
                update["version"] = existing.get("version")
                for key in _META_KEYS:
                    update.pop(key, None)
                response = self.session.put(
                    f"{self.base_url}{endpoint}/{existing['id']}", json=update, timeout=30,
                )
                action = "update"
            else:
                response = self.session.post(
                    f"{self.base_url}{endpoint}", json=payload, timeout=30,
                )
                action = "create"

            if response.status_code in (200, 201, 204):
                if response.content:
                    obj = response.json()
                else:
                    # 204 No Content (e.g. an unchanged PUT) - re-fetch so
                    # callers still get the full object for references
                    obj = self._get_by_name(endpoint, name) or existing or payload
                print(f"  {flair(action, 'OK', f'{label} {name}')}")
                return True, obj

            error_msg = self._extract_error(response)
            print(f"  {flair(action, 'FAIL', f'{label} {name}', error_msg)}")
            return False, error_msg

        except requests.exceptions.RequestException as exc:
            print(f"  {flair('create', 'FAIL', f'{label} {name}', str(exc))}")
            return False, str(exc)

    @staticmethod
    def _ref(obj: Dict) -> Dict:
        """Build an FDM reference block from a full object."""
        ref = {
            "id": obj.get("id"),
            "type": obj.get("type"),
            "name": obj.get("name"),
        }
        if obj.get("version"):
            ref["version"] = obj["version"]
        return ref

    # ------------------------------------------------------------------
    # Interface lookup
    # ------------------------------------------------------------------
    def find_interface(self, name: str) -> Tuple[bool, Union[Dict, str]]:
        """
        Find an interface by logical name across physical interfaces,
        etherchannels, and their subinterfaces.

        Returns:
            (True, interface_dict) or (False, error_message).
        """
        physical_parents = []
        ec_parents = []

        # Pass 1: top-level interfaces (paginated; remember parents for pass 2)
        for endpoint, parents in (
            ("/devices/default/interfaces", physical_parents),
            ("/devices/default/etherchannelinterfaces", ec_parents),
        ):
            ok, items = self.get_paged_items(f"{self.base_url}{endpoint}", page_limit=200)
            if not ok or not isinstance(items, list):
                continue
            for intf in items:
                if intf.get("name") == name:
                    return True, intf
                if intf.get("id"):
                    parents.append(intf["id"])

        # Pass 2: subinterfaces under each parent (paginated)
        for base, parent_ids in (
            ("/devices/default/interfaces", physical_parents),
            ("/devices/default/etherchannelinterfaces", ec_parents),
        ):
            for parent_id in parent_ids:
                ok, items = self.get_paged_items(
                    f"{self.base_url}{base}/{parent_id}/subinterfaces", page_limit=200,
                )
                if not ok or not isinstance(items, list):
                    continue
                for intf in items:
                    if intf.get("name") == name:
                        return True, intf

        return False, (
            f"Interface '{name}' not found. Use the logical name "
            f"(e.g. 'outside'), not the hardware name (e.g. 'Ethernet1/1')."
        )

    # ------------------------------------------------------------------
    # SNMP object builders
    # ------------------------------------------------------------------
    def ensure_network_object(self, name: str, ip: str) -> Tuple[bool, Union[Dict, str]]:
        """Create/update the network object for the NMS host."""
        payload = {
            "name": name,
            "description": "SNMP server (NMS) host",
            "subType": "HOST",
            "value": ip,
            "dnsResolution": "IPV4_ONLY",
            "type": "networkobject",
        }
        return self._upsert("/object/networks", payload, "network object")

    def ensure_snmp_user(
        self,
        name: str,
        security_level: str,
        auth_algorithm: str,
        auth_password: str,
        priv_algorithm: str,
        priv_password: str,
    ) -> Tuple[bool, Union[Dict, str]]:
        """Create/update the SNMPv3 user."""
        payload = {
            "name": name,
            "description": "SNMPv3 user",
            "securityLevel": security_level,
            "authenticationAlgorithm": auth_algorithm,
            "authenticationPassword": auth_password,
            "type": "snmpuser",
        }
        if security_level == "PRIV":
            payload["encryptionAlgorithm"] = priv_algorithm
            payload["encryptionPassword"] = priv_password
        return self._upsert("/object/snmpusers", payload, "SNMP user")

    def ensure_snmp_host(
        self,
        name: str,
        network_object: Dict,
        snmp_user: Dict,
        interface: Dict,
        poll_enabled: bool,
        trap_enabled: bool,
    ) -> Tuple[bool, Union[Dict, str]]:
        """Create/update the SNMP host binding NMS + user + interface."""
        payload = {
            "name": name,
            "managerAddress": self._ref(network_object),
            "pollEnabled": poll_enabled,
            "trapEnabled": trap_enabled,
            "securityConfiguration": {
                "authentication": self._ref(snmp_user),
                "type": "snmpv3securityconfiguration",
            },
            "interface": self._ref(interface),
            "type": "snmphost",
        }
        return self._upsert("/object/snmphosts", payload, "SNMP host")

    def set_server_info(self, location: Optional[str], contact: Optional[str],
                        traps: Optional[List[str]] = None) -> bool:
        """
        Update the device-global SNMPServer settings singleton: location /
        contact (sysLocation / sysContact) and/or the list of enabled trap
        event types. Fields passed as None are left unchanged; traps=[]
        explicitly disables all trap events.
        """
        endpoint = "/devicesettings/default/snmpservers"
        try:
            response = self.session.get(
                f"{self.base_url}{endpoint}", params={"limit": 10}, timeout=30,
            )
            if response.status_code != 200:
                print(f"  {flair('lookup', 'FAIL', 'SNMP server settings', self._extract_error(response))}")
                return False
            items = response.json().get("items", [])
            if not items or not items[0].get("id"):
                print(f"  {flair('lookup', 'FAIL', 'SNMP server settings', 'no SNMPServer object on device')}")
                return False

            server = dict(items[0])
            if location is not None:
                server["location"] = location
            if contact is not None:
                server["contact"] = contact
            if traps is not None:
                server["traps"] = traps
            for key in _META_KEYS:
                server.pop(key, None)

            put_resp = self.session.put(
                f"{self.base_url}{endpoint}/{server['id']}", json=server, timeout=30,
            )
            if put_resp.status_code in (200, 201, 204):
                print(f"  {flair('update', 'OK', 'SNMP server settings')}")
                return True
            print(f"  {flair('update', 'FAIL', 'SNMP server settings', self._extract_error(put_resp))}")
            return False
        except requests.exceptions.RequestException as exc:
            print(f"  {flair('update', 'FAIL', 'SNMP server settings', str(exc))}")
            return False

    # ------------------------------------------------------------------
    # Orchestration
    # ------------------------------------------------------------------
    @staticmethod
    def _per_host_name(base: str, ip: str) -> str:
        """Object name for one NMS: always suffixed with the manager IP so
        every push is additive - separate runs for different managers (e.g.
        one SNMPv3 user per management tool) never overwrite each other."""
        return f"{base}_{ip.replace('.', '_')}"

    def configure(
        self,
        nms_ips: List[str],
        nms_object_name: str,
        snmp_user_name: str,
        security_level: str,
        auth_algorithm: str,
        auth_password: str,
        priv_algorithm: str,
        priv_password: str,
        interface_name: str,
        host_object_name: str,
        poll_enabled: bool = True,
        trap_enabled: bool = True,
        location: Optional[str] = None,
        contact: Optional[str] = None,
        trap_events: Optional[List[str]] = None,
    ) -> bool:
        """
        Run the full SNMPv3 configuration sequence.

        One SNMPv3 user and source interface are shared by all SNMP
        managers; each manager IP gets its own network object and SNMP
        host. Returns True only if every manager was configured.
        """
        print(f"\n{'='*60}")
        print("Configuring SNMPv3")
        print(f"{'='*60}")
        print(f"  SNMP managers:   {', '.join(nms_ips)}")
        print(f"  SNMP user:       {snmp_user_name} ({security_level}, "
              f"{auth_algorithm}"
              f"{' + ' + priv_algorithm if security_level == 'PRIV' else ''})")
        print(f"  Source interface: {interface_name}")
        print(f"  Polling: {'enabled' if poll_enabled else 'disabled'}, "
              f"Traps: {'enabled' if trap_enabled else 'disabled'}")
        if location is not None:
            print(f"  Location: {location}")
        if contact is not None:
            print(f"  Contact:  {contact}")
        if trap_events is not None:
            print(f"  Trap events: {', '.join(trap_events) if trap_events else 'none (all disabled)'}")
        print()

        # Step 1: SNMPv3 user (shared by all managers)
        ok, user_obj = self.ensure_snmp_user(
            snmp_user_name, security_level,
            auth_algorithm, auth_password,
            priv_algorithm, priv_password,
        )
        if not ok or not isinstance(user_obj, dict):
            return False

        # Step 2: source interface (shared by all managers)
        ok, intf_obj = self.find_interface(interface_name)
        if not ok or not isinstance(intf_obj, dict):
            print(f"  {flair('lookup', 'FAIL', f'interface {interface_name}', str(intf_obj))}")
            return False
        hardware_name = intf_obj.get('hardwareName', '?')
        print(f"  {flair('lookup', 'OK', f'interface {interface_name} ({hardware_name})')}")

        # Step 3: per-manager network object + SNMP host
        configured = 0
        failed = 0
        for ip in nms_ips:
            net_name = self._per_host_name(nms_object_name, ip)
            host_name = self._per_host_name(host_object_name, ip)

            ok, net_obj = self.ensure_network_object(net_name, ip)
            if not ok or not isinstance(net_obj, dict):
                failed += 1
                continue

            ok, _ = self.ensure_snmp_host(
                host_name, net_obj, user_obj, intf_obj,
                poll_enabled, trap_enabled,
            )
            if ok:
                configured += 1
            else:
                failed += 1

        # Step 4: device-global location/contact/trap events (optional)
        info_ok = True
        if location is not None or contact is not None or trap_events is not None:
            info_ok = self.set_server_info(location, contact, trap_events)

        print(f"\n  Summary: {configured} of {len(nms_ips)} SNMP manager(s) configured"
              f"{f', {failed} failed' if failed else ''}")
        if configured:
            print(f"  NMS access: UDP 161 (polling){' / UDP 162 (traps)' if trap_enabled else ''}")
            print("  Verify after deploy via SSH: show run snmp-server")
        return failed == 0 and info_ok

    def deploy_changes(self) -> bool:
        """Deploy pending changes and poll the task until completion."""
        print(f"\n{'='*60}")
        print("Deploying configuration changes...")
        print(f"{'='*60}")
        try:
            response = self.session.post(
                f"{self.base_url}/operational/deploy", json={}, timeout=30,
            )
            if response.status_code in (200, 201, 202):
                print(flair("deploy", "OK", "configuration changes initiated"))
                print("  (Deployment may take several minutes)")
                # Poll the deployment task until it finishes (shared poller
                # in FTDBaseClient).
                return self.start_and_wait_deployment(response)
            print(flair("deploy", "FAIL", "configuration changes",
                        f"HTTP {response.status_code}"))
            return False
        except requests.exceptions.RequestException as exc:
            print(flair("deploy", "FAIL", "configuration changes", str(exc)))
            return False


def main(argv: Optional[List[str]] = None) -> int:
    """Main function.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:] when None).
    """
    parser = argparse.ArgumentParser(
        description="Configure SNMPv3 on Cisco FTD via the FDM REST API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full STIG-compliant SNMPv3 setup (prompts for passwords)
  python ftd_snmp_config.py --host 192.168.1.1 -u admin \\
      --nms-ip 10.0.0.50 --snmp-user FWADMIN --interface outside --deploy

  # Multiple SNMP managers (comma-separated or repeated flag)
  python ftd_snmp_config.py --host 192.168.1.1 -u admin \\
      --nms-ip 10.0.0.50,10.0.0.51 --nms-ip 10.1.0.50 --nms-ip 10.2.0.50 \\
      --snmp-user FWADMIN --interface outside --deploy

  # Explicit algorithms, traps disabled (polling only)
  python ftd_snmp_config.py --host 192.168.1.1 -u admin \\
      --nms-ip 10.0.0.50 --snmp-user FWADMIN --interface management_net \\
      --auth-algorithm SHA256 --priv-algorithm AES256 --no-trap
        """,
    )

    parser.add_argument('--host', required=True, help='FTD management IP')
    parser.add_argument('-u', '--username', required=True, help='FDM username')
    parser.add_argument('-p', '--password', help='FDM password (prompted if omitted)')
    parser.add_argument('--verify-ssl', action='store_true', default=False,
                        help='Verify the FTD management SSL certificate '
                             '(default: disabled - mgmt certs are usually self-signed)')
    parser.add_argument('--skip-verify', action='store_true', default=False,
                        help='(DEPRECATED, ignored) SSL verification is already '
                             'disabled by default; use --verify-ssl to enable it')
    parser.add_argument('--nms-ip', required=True, action='append',
                        help='IP address of an SNMP manager / NMS (e.g. SolarWinds). '
                             'Repeat the flag or comma-separate for multiple managers '
                             '(e.g. --nms-ip 10.0.0.50,10.0.0.51)')
    parser.add_argument('--nms-object-name', default='snmpHost',
                        help='Base name for the NMS network object(s) (default: snmpHost). '
                             'Each object name is suffixed with its manager IP.')
    parser.add_argument('--snmp-user', required=True,
                        help='SNMPv3 user name (e.g. FWADMIN)')
    parser.add_argument('--security-level', choices=SECURITY_LEVELS, default='PRIV',
                        help='SNMPv3 security level (default: PRIV; STIG requires Auth/Priv)')
    parser.add_argument('--auth-algorithm', choices=AUTH_ALGORITHMS, default='SHA',
                        help='Authentication algorithm (default: SHA)')
    parser.add_argument('--auth-password',
                        help='Authentication password (prompted if omitted)')
    parser.add_argument('--priv-algorithm', choices=PRIV_ALGORITHMS, default='AES256',
                        help='Privacy/encryption algorithm (default: AES256; AES128 is the STIG minimum)')
    parser.add_argument('--priv-password',
                        help='Privacy/encryption password (prompted if omitted)')
    parser.add_argument('--interface', required=True,
                        help='Logical name of the interface that sources SNMP traffic (e.g. outside)')
    parser.add_argument('--host-object-name', default='snmpv3-host',
                        help='Base name for the SNMP host object(s) (default: snmpv3-host). '
                             'Each object name is suffixed with its manager IP.')
    parser.add_argument('--location',
                        help='SNMP system location (sysLocation), e.g. a site or rack '
                             'identifier. Max 233 characters, no semicolons.')
    parser.add_argument('--contact',
                        help='SNMP system contact (sysContact), e.g. an administrator '
                             'name or email. Max 234 characters, no semicolons.')
    parser.add_argument('--trap-events', action='append',
                        help='Device-global SNMP trap event types to enable (sets the '
                             'SNMPServer traps list). Comma-separate or repeat the flag. '
                             'Use "none" to disable all trap events. Omitted = unchanged. '
                             'Choices: ' + ', '.join(TRAP_EVENTS))
    parser.add_argument('--no-poll', action='store_true', help='Disable SNMP polling')
    parser.add_argument('--no-trap', action='store_true', help='Disable SNMP traps')
    parser.add_argument('--deploy', action='store_true', help='Deploy after configuring')
    parser.add_argument('--debug', action='store_true', help='Enable debug output')

    args = parser.parse_args(argv)

    # Flatten repeated/comma-separated --nms-ip values, dedupe preserving order
    nms_ips = []
    for chunk in args.nms_ip:
        for ip in chunk.split(','):
            ip = ip.strip()
            if ip and ip not in nms_ips:
                nms_ips.append(ip)
    if not nms_ips:
        print("[ERROR] No valid SNMP manager IPs given via --nms-ip.")
        return 1

    if not args.password:
        args.password = getpass.getpass(f"Enter FDM password for {args.username}: ")
    if not args.auth_password:
        args.auth_password = getpass.getpass("Enter SNMPv3 authentication password: ")
    if args.security_level == 'PRIV' and not args.priv_password:
        args.priv_password = getpass.getpass("Enter SNMPv3 privacy (encryption) password: ")

    if len(args.auth_password) < 8:
        print("[ERROR] Authentication password must be at least 8 characters (FDM requirement).")
        return 1
    if args.security_level == 'PRIV' and len(args.priv_password) < 8:
        print("[ERROR] Privacy password must be at least 8 characters (FDM requirement).")
        return 1
    if args.security_level != 'PRIV':
        print("[WARNING] Security level AUTH (no privacy) is NOT STIG-compliant "
              "(CASA-ND-001070 requires AES encryption). Use PRIV for compliance.")

    # Flatten/validate --trap-events; "none" alone means an explicit empty list
    trap_events = None
    if args.trap_events:
        trap_events = []
        for chunk in args.trap_events:
            for event in chunk.split(','):
                event = event.strip().upper()
                if not event:
                    continue
                if event == "NONE":
                    continue
                if event not in TRAP_EVENTS:
                    print(f"[ERROR] Unknown trap event '{event}'. "
                          f"Choices: {', '.join(TRAP_EVENTS)} (or 'none').")
                    return 1
                if event not in trap_events:
                    trap_events.append(event)

    # FDM limits: location <= 233 chars, contact <= 234 chars, no semicolons
    for flag, value, limit in (("--location", args.location, 233),
                               ("--contact", args.contact, 234)):
        if value is not None:
            if ';' in value:
                print(f"[ERROR] {flag} must not contain semicolons (FDM restriction).")
                return 1
            if len(value) > limit:
                print(f"[ERROR] {flag} must be at most {limit} characters (FDM restriction).")
                return 1

    if args.skip_verify:
        print("[DEPRECATED] --skip-verify is ignored: SSL verification is "
              "already disabled by default. Use --verify-ssl to enable it.")

    client = FTDSNMPConfig(
        host=args.host,
        username=args.username,
        password=args.password,
        verify_ssl=args.verify_ssl,
        debug=args.debug,
    )

    if not client.authenticate():
        return 1

    success = client.configure(
        nms_ips=nms_ips,
        nms_object_name=args.nms_object_name,
        snmp_user_name=args.snmp_user,
        security_level=args.security_level,
        auth_algorithm=args.auth_algorithm,
        auth_password=args.auth_password,
        priv_algorithm=args.priv_algorithm,
        priv_password=args.priv_password,
        interface_name=args.interface,
        host_object_name=args.host_object_name,
        poll_enabled=not args.no_poll,
        trap_enabled=not args.no_trap,
        location=args.location,
        contact=args.contact,
        trap_events=trap_events,
    )

    if not success:
        print("\n[ERROR] SNMPv3 configuration failed - see messages above.")
        return 1

    if args.deploy:
        if not client.deploy_changes():
            return 1
    else:
        print("\n[INFO] Changes are staged but NOT deployed.")
        print("       Deploy from FDM or re-run with --deploy to activate.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
