#!/usr/bin/env python3
"""
Palo Alto PAN-OS API Importer
================================
Imports converted FortiGate configuration into a PAN-OS firewall
using the XML API.

IMPORT ORDER:
    1. Zones
    2. Address objects
    3. Address groups
    4. Service objects
    5. Service groups
    6. Static routes
    7. Security rules
    8. Commit

HOW TO RUN:
    python panos_api_importer.py --host 10.0.0.1 --username admin
    python panos_api_importer.py --host 10.0.0.1 --username admin --dry-run
    python panos_api_importer.py --host 10.0.0.1 --username admin --input pa_config --commit
"""

import json
import argparse
import re
import sys
import getpass
from typing import Any, Callable, Dict, List, Optional
from xml.sax.saxutils import escape, quoteattr

from panos_api_base import PANOSBaseClient, XPATHS


def _x(value: Any) -> str:
    """Escape a value for use as XML text content."""
    return escape(str(value))


def _attr(value: Any) -> str:
    """Quote and escape a value for use as an XML attribute (adds quotes)."""
    return quoteattr(str(value))


class PANOSImporter(PANOSBaseClient):
    """Import converted configuration into PAN-OS via XML API."""

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        verify_ssl: bool = False,
        debug: bool = False,
        dry_run: bool = False,
    ) -> None:
        super().__init__(host, username, password, verify_ssl, debug)
        self.dry_run = dry_run

        self.stats = {
            "interfaces_configured": 0,
            "zones_created": 0,
            "address_objects_created": 0,
            "address_groups_created": 0,
            "service_objects_created": 0,
            "service_groups_created": 0,
            "static_routes_created": 0,
            "security_rules_created": 0,
            "failed": 0,
        }
        self.failed_items: List[Dict[str, str]] = []

    # ------------------------------------------------------------------
    # XML Element Builders
    # ------------------------------------------------------------------
    @staticmethod
    def _build_address_xml(obj: Dict) -> str:
        """Build XML element for a PAN-OS address object."""
        name = obj["name"]
        pa_type = obj["type"]  # ip-netmask, ip-range, fqdn
        value = obj["value"]
        desc = obj.get("description", "")

        xml = f"<entry name={_attr(name)}>"
        xml += f"<{pa_type}>{_x(value)}</{pa_type}>"
        if desc:
            xml += f"<description>{_x(desc)}</description>"
        xml += "</entry>"
        return xml

    @staticmethod
    def _build_address_group_xml(obj: Dict) -> str:
        """Build XML element for a PAN-OS address group."""
        name = obj["name"]
        members = obj.get("members", [])
        desc = obj.get("description", "")

        xml = f"<entry name={_attr(name)}><static>"
        for m in members:
            xml += f"<member>{_x(m)}</member>"
        xml += "</static>"
        if desc:
            xml += f"<description>{_x(desc)}</description>"
        xml += "</entry>"
        return xml

    @staticmethod
    def _build_service_xml(obj: Dict) -> str:
        """Build XML element for a PAN-OS service object."""
        name = obj["name"]
        protocol = obj["protocol"]  # tcp or udp
        port = obj["port"]

        xml = f"<entry name={_attr(name)}><protocol>"
        xml += f"<{protocol}><port>{_x(port)}</port></{protocol}>"
        xml += "</protocol></entry>"
        return xml

    @staticmethod
    def _build_service_group_xml(obj: Dict) -> str:
        """Build XML element for a PAN-OS service group."""
        name = obj["name"]
        members = obj.get("members", [])

        xml = f"<entry name={_attr(name)}><members>"
        for m in members:
            xml += f"<member>{_x(m)}</member>"
        xml += "</members></entry>"
        return xml

    @staticmethod
    def _build_security_rule_xml(obj: Dict) -> str:
        """Build XML element for a PAN-OS security rule."""
        name = obj["name"]

        xml = f"<entry name={_attr(name)}>"

        # From zones
        xml += "<from>"
        for z in obj.get("from_zones", ["any"]):
            xml += f"<member>{_x(z)}</member>"
        xml += "</from>"

        # To zones
        xml += "<to>"
        for z in obj.get("to_zones", ["any"]):
            xml += f"<member>{_x(z)}</member>"
        xml += "</to>"

        # Sources
        xml += "<source>"
        for s in obj.get("sources", ["any"]):
            xml += f"<member>{_x(s)}</member>"
        xml += "</source>"

        # Destinations
        xml += "<destination>"
        for d in obj.get("destinations", ["any"]):
            xml += f"<member>{_x(d)}</member>"
        xml += "</destination>"

        # Services
        xml += "<service>"
        for s in obj.get("services", ["any"]):
            xml += f"<member>{_x(s)}</member>"
        xml += "</service>"

        # Application
        xml += "<application>"
        for a in obj.get("application", ["any"]):
            xml += f"<member>{_x(a)}</member>"
        xml += "</application>"

        # Action
        xml += f"<action>{_x(obj.get('action', 'deny'))}</action>"

        # Log
        xml += f"<log-end>{_x(obj.get('log_end', 'yes'))}</log-end>"

        # Description
        desc = obj.get("description", "")
        if desc:
            xml += f"<description>{_x(desc)}</description>"

        # Disabled
        disabled = obj.get("disabled", "no")
        if disabled == "yes":
            xml += "<disabled>yes</disabled>"

        xml += "</entry>"
        return xml

    @staticmethod
    def _build_static_route_xml(obj: Dict) -> str:
        """Build XML element for a PAN-OS static route."""
        name = obj["name"]

        xml = f"<entry name={_attr(name)}>"
        xml += f"<destination>{_x(obj['destination'])}</destination>"

        if "nexthop" in obj:
            xml += f"<nexthop><ip-address>{_x(obj['nexthop'])}</ip-address></nexthop>"

        if "interface" in obj:
            xml += f"<interface>{_x(obj['interface'])}</interface>"

        if "metric" in obj:
            xml += f"<metric>{_x(obj['metric'])}</metric>"

        xml += "</entry>"
        return xml

    @staticmethod
    def _build_zone_xml(obj: Dict) -> str:
        """Build XML element for a PAN-OS zone.

        Honors the zone's mode: 'layer2' zones hold the member ports of a
        converted FortiGate switch; everything else is a layer3 zone.
        """
        name = obj["name"]
        interfaces = obj.get("interfaces", [])
        mode = obj.get("mode", "layer3")
        section = "layer2" if mode == "layer2" else "layer3"

        xml = f"<entry name={_attr(name)}><network><{section}>"
        for intf in interfaces:
            xml += f"<member>{_x(intf)}</member>"
        xml += f"</{section}></network></entry>"
        return xml

    # ------------------------------------------------------------------
    # Interface XML Builders
    # ------------------------------------------------------------------
    @staticmethod
    def _build_physical_interface_xml(obj: Dict) -> str:
        """Build XML element for a PAN-OS ethernet interface (layer3 mode)."""
        name = obj["name"]
        xml = f"<entry name={_attr(name)}><layer3>"

        # IP address
        ip_addr = obj.get("ip_address")
        if ip_addr:
            xml += f"<ip><entry name={_attr(ip_addr)}/></ip>"

        # DHCP
        if obj.get("dhcp"):
            xml += "<dhcp-client><enable>yes</enable></dhcp-client>"

        # MTU
        mtu = obj.get("mtu")
        if mtu:
            xml += f"<mtu>{_x(mtu)}</mtu>"

        xml += "</layer3>"

        # Comment
        comment = obj.get("comment", "")
        if comment:
            xml += f"<comment>{_x(comment)}</comment>"

        # Link speed
        link_speed = obj.get("link_speed", "auto")
        if link_speed and link_speed != "auto":
            xml += f"<link-speed>{_x(link_speed)}</link-speed>"

        # Administratively disabled on the FortiGate -> force link down
        if obj.get("enabled") is False:
            xml += "<link-state>down</link-state>"

        xml += "</entry>"
        return xml

    @staticmethod
    def _build_subinterface_xml(obj: Dict) -> str:
        """Build XML element for a PAN-OS subinterface (layer3 unit)."""
        name = obj["name"]
        tag = obj["tag"]

        xml = f"<entry name={_attr(name)}>"
        xml += f"<tag>{_x(tag)}</tag>"

        # IP address
        ip_addr = obj.get("ip_address")
        if ip_addr:
            xml += f"<ip><entry name={_attr(ip_addr)}/></ip>"

        # DHCP
        if obj.get("dhcp"):
            xml += "<dhcp-client><enable>yes</enable></dhcp-client>"

        # MTU
        mtu = obj.get("mtu")
        if mtu:
            xml += f"<mtu>{_x(mtu)}</mtu>"

        # Comment
        comment = obj.get("comment", "")
        if comment:
            xml += f"<comment>{_x(comment)}</comment>"

        xml += "</entry>"
        return xml

    @staticmethod
    def _build_aggregate_ethernet_xml(obj: Dict) -> str:
        """Build XML element for a PAN-OS aggregate-ethernet interface."""
        name = obj["name"]
        xml = f"<entry name={_attr(name)}><layer3>"

        # IP address
        ip_addr = obj.get("ip_address")
        if ip_addr:
            xml += f"<ip><entry name={_attr(ip_addr)}/></ip>"

        # DHCP
        if obj.get("dhcp"):
            xml += "<dhcp-client><enable>yes</enable></dhcp-client>"

        # MTU
        mtu = obj.get("mtu")
        if mtu:
            xml += f"<mtu>{_x(mtu)}</mtu>"

        xml += "</layer3>"

        # LACP
        lacp_mode = obj.get("lacp_mode", "active")
        xml += f"<lacp><mode>{_x(lacp_mode)}</mode></lacp>"

        # Comment
        comment = obj.get("comment", "")
        if comment:
            xml += f"<comment>{_x(comment)}</comment>"

        xml += "</entry>"
        return xml

    @staticmethod
    def _build_aggregate_member_xml(obj: Dict) -> str:
        """Build XML element to assign a physical interface to an aggregate group."""
        name = obj["name"]
        ae_group = obj["aggregate_group"]
        xml = f"<entry name={_attr(name)}>"
        xml += f"<aggregate-group>{_x(ae_group)}</aggregate-group>"

        comment = obj.get("comment", "")
        if comment:
            xml += f"<comment>{_x(comment)}</comment>"

        # Administratively disabled on the FortiGate -> force link down
        if obj.get("enabled") is False:
            xml += "<link-state>down</link-state>"

        xml += "</entry>"
        return xml

    @staticmethod
    def _build_layer2_member_xml(obj: Dict) -> str:
        """Build XML to set an ethernet interface to Layer-2 mode.

        The VLAN membership itself is configured on the vlan object (see
        ``_build_vlan_object_xml``); the ethernet entry just declares layer2.
        """
        name = obj["name"]
        xml = f"<entry name={_attr(name)}><layer2/>"
        comment = obj.get("comment", "")
        if comment:
            xml += f"<comment>{_x(comment)}</comment>"
        # Administratively disabled on the FortiGate -> force link down
        if obj.get("enabled") is False:
            xml += "<link-state>down</link-state>"
        xml += "</entry>"
        return xml

    @staticmethod
    def _build_vlan_object_xml(obj: Dict) -> str:
        """Build XML for a PAN-OS VLAN object grouping Layer-2 members.

        References the vlan.N SVI as the VLAN's virtual interface so the bridged
        segment has a Layer-3 presence (the FortiGate switch IP).
        """
        name = obj["name"]
        members = obj.get("members", [])
        svi = obj.get("vlan_interface")

        xml = f"<entry name={_attr(name)}>"
        if svi:
            xml += f"<virtual-interface><interface>{_x(svi)}</interface></virtual-interface>"
        if members:
            xml += "<interface>"
            for m in members:
                xml += f"<member>{_x(m)}</member>"
            xml += "</interface>"
        xml += "</entry>"
        return xml

    @staticmethod
    def _build_vlan_interface_xml(obj: Dict) -> str:
        """Build XML for a PAN-OS vlan.N interface (the Layer-3 SVI)."""
        name = obj["name"]
        xml = f"<entry name={_attr(name)}>"

        ip_addr = obj.get("ip_address")
        if ip_addr:
            xml += f"<ip><entry name={_attr(ip_addr)}/></ip>"

        if obj.get("dhcp"):
            xml += "<dhcp-client><enable>yes</enable></dhcp-client>"

        mtu = obj.get("mtu")
        if mtu:
            xml += f"<mtu>{_x(mtu)}</mtu>"

        comment = obj.get("comment", "")
        if comment:
            xml += f"<comment>{_x(comment)}</comment>"

        xml += "</entry>"
        return xml

    # ------------------------------------------------------------------
    # Import methods
    # ------------------------------------------------------------------
    def _import_interfaces(self, interfaces: List[Dict]) -> bool:
        """Import interface configurations to PAN-OS.

        Handles different interface types with their specific XPaths:
        - physical: ethernet entries (layer3 config)
        - aggregate-member: physical interfaces assigned to aggregate groups
        - aggregate-ethernet: aggregate-ethernet entries
        - layer2-member: ethernet entries set to Layer-2 mode (switch members)
        - vlan-object: VLAN objects grouping Layer-2 members
        - vlan-interface: vlan.N SVIs (the Layer-3 interface of a switch)
        - subinterface: units under parent ethernet interface
        """
        total = len(interfaces)
        success_count = 0
        fail_count = 0

        for idx, obj in enumerate(interfaces, start=1):
            name = obj.get("name", f"intf_{idx}")
            intf_type = obj.get("type", "physical")

            try:
                if intf_type == "aggregate-member":
                    xpath = XPATHS["ethernet"]
                    xml_element = self._build_aggregate_member_xml(obj)
                elif intf_type == "aggregate-ethernet":
                    xpath = XPATHS["aggregate_ethernet"]
                    xml_element = self._build_aggregate_ethernet_xml(obj)
                elif intf_type == "layer2-member":
                    xpath = XPATHS["ethernet"]
                    xml_element = self._build_layer2_member_xml(obj)
                elif intf_type == "vlan-object":
                    xpath = XPATHS["vlan"]
                    xml_element = self._build_vlan_object_xml(obj)
                elif intf_type == "vlan-interface":
                    xpath = XPATHS["vlan_interface"]
                    xml_element = self._build_vlan_interface_xml(obj)
                elif intf_type == "subinterface":
                    parent = str(obj["parent"]).strip()
                    # Subinterfaces of an aggregate-ethernet (aeN) live under
                    # the aggregate-ethernet XPath, not ethernet.
                    if re.match(r"^ae\d+$", parent):
                        parent_base = XPATHS["aggregate_ethernet"]
                    else:
                        parent_base = XPATHS["ethernet"]
                    xpath = (
                        f"{parent_base}/entry[@name='{parent}']"
                        "/layer3/units"
                    )
                    xml_element = self._build_subinterface_xml(obj)
                else:
                    # physical
                    xpath = XPATHS["ethernet"]
                    xml_element = self._build_physical_interface_xml(obj)
            except (KeyError, TypeError) as e:
                print(f"  [{idx}/{total}] [FAIL] {name}: XML build error: {e}")
                self._record_failure(name, "interfaces", f"XML build error: {e}")
                fail_count += 1
                continue

            if self.dry_run:
                print(f"  [{idx}/{total}] [DRY-RUN] Would configure: {name} ({intf_type})")
                if self.debug:
                    print(f"    XPath: {xpath}")
                    print(f"    Element: {xml_element[:200]}")
                success_count += 1
                continue

            ok, msg = self.config_set(xpath, xml_element)
            if ok:
                print(f"  [{idx}/{total}] [OK] {name} ({intf_type})")
                success_count += 1
            else:
                print(f"  [{idx}/{total}] [FAIL] {name}: {msg}")
                self._record_failure(name, "interfaces", msg)
                fail_count += 1

        self.stats["interfaces_configured"] += success_count
        self.stats["failed"] += fail_count

        print(f"\n  interfaces: {success_count}/{total} succeeded"
              + (f", {fail_count} failed" if fail_count else ""))

        return fail_count == 0

    def import_all(
        self,
        input_basename: str,
        auto_commit: bool = False,
        force_commit: bool = False,
    ) -> bool:
        """Import all object types from JSON files.

        Args:
            input_basename: Base name of JSON files (e.g., "pa_config")
            auto_commit: Whether to commit after import. The commit is skipped
                if any import failed, unless force_commit is set.
            force_commit: Commit even when some imports failed.

        Returns:
            True if all imports succeeded.
        """
        all_ok = True

        # --- Step 0: Import interfaces (special handling per type) ---
        intf_file = f"{input_basename}_interfaces.json"
        print(f"\n{'=' * 60}")
        print("Importing interfaces...")
        print(f"{'=' * 60}")
        try:
            with open(intf_file, "r", encoding="utf-8") as f:
                interfaces = json.load(f)
            if interfaces:
                ok = self._import_interfaces(interfaces)
                if not ok:
                    all_ok = False
            else:
                print("  [SKIP] No interfaces to import")
        except FileNotFoundError:
            print(f"  [SKIP] File not found: {intf_file}")
        except json.JSONDecodeError as e:
            print(f"  [ERROR] Invalid JSON in {intf_file}: {e}")
            all_ok = False

        # Import order matters: dependencies first
        steps = [
            ("zones", f"{input_basename}_zones.json",
             self._import_objects, XPATHS["zone"], self._build_zone_xml, "zones_created"),
            ("address objects", f"{input_basename}_address_objects.json",
             self._import_objects, XPATHS["address"], self._build_address_xml, "address_objects_created"),
            ("address groups", f"{input_basename}_address_groups.json",
             self._import_objects, XPATHS["address_group"], self._build_address_group_xml, "address_groups_created"),
            ("service objects", f"{input_basename}_service_objects.json",
             self._import_objects, XPATHS["service"], self._build_service_xml, "service_objects_created"),
            ("service groups", f"{input_basename}_service_groups.json",
             self._import_objects, XPATHS["service_group"], self._build_service_group_xml, "service_groups_created"),
            ("static routes", f"{input_basename}_static_routes.json",
             self._import_objects, XPATHS["static_route"], self._build_static_route_xml, "static_routes_created"),
            ("security rules", f"{input_basename}_security_rules.json",
             self._import_objects, XPATHS["security_rule"], self._build_security_rule_xml, "security_rules_created"),
        ]

        for label, filepath, import_fn, xpath, builder, stat_key in steps:
            print(f"\n{'=' * 60}")
            print(f"Importing {label}...")
            print(f"{'=' * 60}")

            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    objects = json.load(f)
            except FileNotFoundError:
                print(f"  [SKIP] File not found: {filepath}")
                continue
            except json.JSONDecodeError as e:
                print(f"  [ERROR] Invalid JSON in {filepath}: {e}")
                all_ok = False
                continue

            if not objects:
                print(f"  [SKIP] No {label} to import")
                continue

            ok = import_fn(objects, xpath, builder, stat_key, label)
            if not ok:
                all_ok = False

        # Commit if requested - but never auto-commit a partially failed
        # import unless the user explicitly forces it.
        if auto_commit and not self.dry_run:
            if all_ok or force_commit:
                success, msg = self.commit()
                if not success:
                    print(f"[FAIL] Commit failed: {msg}")
                    all_ok = False
            else:
                print("\n[SKIP] Commit skipped: some imports failed "
                      "(re-run with --force-commit to commit anyway)")

        return all_ok

    def _import_objects(
        self,
        objects: List[Dict],
        xpath: str,
        xml_builder: Callable[[Dict], str],
        stat_key: str,
        label: str,
    ) -> bool:
        """Import a list of objects to PAN-OS.

        Each object is pushed individually via config_set. PAN-OS config_set
        with action=set is idempotent (creates or merges).
        """
        total = len(objects)
        success_count = 0
        fail_count = 0

        for idx, obj in enumerate(objects, start=1):
            name = obj.get("name", f"item_{idx}")

            try:
                xml_element = xml_builder(obj)
            except (KeyError, TypeError) as e:
                print(f"  [{idx}/{total}] [FAIL] {name}: XML build error: {e}")
                self._record_failure(name, label, f"XML build error: {e}")
                fail_count += 1
                continue

            if self.dry_run:
                print(f"  [{idx}/{total}] [DRY-RUN] Would set: {name}")
                if self.debug:
                    print(f"    XPath: {xpath}")
                    print(f"    Element: {xml_element[:200]}")
                success_count += 1
                continue

            ok, msg = self.config_set(xpath, xml_element)
            if ok:
                print(f"  [{idx}/{total}] [OK] {name}")
                success_count += 1
            else:
                print(f"  [{idx}/{total}] [FAIL] {name}: {msg}")
                self._record_failure(name, label, msg)
                fail_count += 1

        self.stats[stat_key] += success_count
        self.stats["failed"] += fail_count

        print(f"\n  {label}: {success_count}/{total} succeeded"
              + (f", {fail_count} failed" if fail_count else ""))

        return fail_count == 0

    def _record_failure(self, name: str, category: str, reason: str) -> None:
        """Record a failed import item."""
        self.failed_items.append({
            "name": name,
            "category": category,
            "reason": reason,
        })

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    def print_summary(self) -> None:
        """Print import summary."""
        print(f"\n{'=' * 60}")
        print("IMPORT SUMMARY")
        print(f"{'=' * 60}")
        mode = "[DRY-RUN] " if self.dry_run else ""
        print(f"  {mode}Interfaces configured:  {self.stats['interfaces_configured']}")
        print(f"  {mode}Zones created:          {self.stats['zones_created']}")
        print(f"  {mode}Address objects created: {self.stats['address_objects_created']}")
        print(f"  {mode}Address groups created:  {self.stats['address_groups_created']}")
        print(f"  {mode}Service objects created: {self.stats['service_objects_created']}")
        print(f"  {mode}Service groups created:  {self.stats['service_groups_created']}")
        print(f"  {mode}Static routes created:   {self.stats['static_routes_created']}")
        print(f"  {mode}Security rules created:  {self.stats['security_rules_created']}")
        if self.stats["failed"] > 0:
            print(f"  FAILED: {self.stats['failed']}")
        print(f"{'=' * 60}")

        if self.failed_items:
            print("\nFailed Items:")
            for item in self.failed_items:
                print(f"  - [{item['category']}] {item['name']}: {item['reason']}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Import converted FortiGate config to Palo Alto PAN-OS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python panos_api_importer.py --host 10.0.0.1 --username admin
  python panos_api_importer.py --host 10.0.0.1 --username admin --dry-run
  python panos_api_importer.py --host 10.0.0.1 --username admin --input pa_config --commit
        """,
    )

    parser.add_argument("--host", required=True, help="PAN-OS management IP/hostname")
    parser.add_argument("--username", required=True, help="PAN-OS admin username")
    parser.add_argument("--password", default=None, help="PAN-OS admin password (prompts if omitted)")
    parser.add_argument("--input", default="pa_config", help="Base name of input JSON files (default: pa_config)")
    parser.add_argument("--dry-run", action="store_true", help="Preview what would be imported without making changes")
    parser.add_argument("--commit", action="store_true",
                        help="Automatically commit after import (skipped if any import failed)")
    parser.add_argument("--force-commit", action="store_true",
                        help="With --commit: commit even if some imports failed")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificate (default: disabled)")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args(argv)

    # Prompt for password if not provided
    password = args.password
    if not password:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    # Create client
    client = PANOSImporter(
        host=args.host,
        username=args.username,
        password=password,
        verify_ssl=args.verify_ssl,
        debug=args.debug,
        dry_run=args.dry_run,
    )

    if args.dry_run:
        print("\n*** DRY-RUN MODE - no changes will be made ***\n")
        # In dry-run, we don't need to authenticate
        success = client.import_all(args.input, auto_commit=False)
        client.print_summary()
        return 0 if success else 1

    # Authenticate
    if not client.authenticate():
        print("\n[FATAL] Authentication failed. Aborting.")
        return 1

    # Validate connection
    client.validate_connection()

    # Import
    success = client.import_all(
        args.input, auto_commit=args.commit, force_commit=args.force_commit
    )
    client.print_summary()

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
