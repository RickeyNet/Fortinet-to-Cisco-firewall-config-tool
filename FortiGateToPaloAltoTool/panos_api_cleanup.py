#!/usr/bin/env python3
"""
Palo Alto PAN-OS API Bulk Cleanup
====================================
Deletes custom objects of specified types from a PAN-OS firewall.

WARNING: This deletes configuration objects! Always backup first.

SAFETY FEATURES:
    - Dry-run mode (preview without deleting)
    - Interactive confirmation required
    - Detailed logging of what's being deleted

DELETION ORDER (reverse of import):
    1. Security rules (reference services/addresses)
    2. Service groups (reference services)
    3. Service objects
    4. Address groups (reference addresses)
    5. Address objects
    6. Static routes
    7. Zones
    8. VLAN interfaces (vlan.N SVIs) and VLAN objects
    9. Aggregate-ethernet interfaces and ethernet resets (incl. layer2)

HOW TO RUN:
    python panos_api_cleanup.py --host 10.0.0.1 --username admin --delete-all
    python panos_api_cleanup.py --host 10.0.0.1 --username admin --delete-security-rules --dry-run
    python panos_api_cleanup.py --host 10.0.0.1 --username admin --delete-address-objects --commit
"""

import argparse
import sys
import getpass
import xml.etree.ElementTree as ET
from typing import List, Optional, Tuple

from panos_api_base import PANOSBaseClient, XPATHS


class PANOSBulkDelete(PANOSBaseClient):
    """Bulk delete objects from PAN-OS via XML API."""

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
            "total_found": 0,
            "deleted": 0,
            "failed": 0,
        }

    def delete_objects_by_type(self, object_type: str) -> Tuple[bool, int]:
        """Delete all custom objects of a given type.

        Args:
            object_type: Key from XPATHS dict (e.g., "address", "service", "security_rule")

        Returns:
            (success, count_deleted)
        """
        xpath = XPATHS.get(object_type)
        if not xpath:
            print(f"  [ERROR] Unknown object type: {object_type}")
            return False, 0

        print(f"\n{'=' * 60}")
        print(f"Deleting {object_type.replace('_', ' ')}s...")
        print(f"{'=' * 60}")

        # Get current objects
        names = self._get_object_names(xpath)
        if not names:
            print(f"  No {object_type} objects found.")
            return True, 0

        self.stats["total_found"] += len(names)
        print(f"  Found {len(names)} object(s)")

        deleted = 0
        failed = 0

        for idx, name in enumerate(names, start=1):
            entry_xpath = f"{xpath}/entry[@name='{name}']"

            if self.dry_run:
                print(f"  [{idx}/{len(names)}] [DRY-RUN] Would delete: {name}")
                deleted += 1
                continue

            ok, msg = self.config_delete(entry_xpath)
            if ok:
                print(f"  [{idx}/{len(names)}] [OK] Deleted: {name}")
                deleted += 1
            else:
                print(f"  [{idx}/{len(names)}] [FAIL] {name}: {msg}")
                failed += 1

        self.stats["deleted"] += deleted
        self.stats["failed"] += failed

        print(f"\n  {object_type}: {deleted}/{len(names)} deleted"
              + (f", {failed} failed" if failed else ""))

        return failed == 0, deleted

    def _get_object_names(self, xpath: str) -> List[str]:
        """Retrieve the top-level entry names at the given XPath.

        Only direct entries of the queried container are returned - nested
        <entry> elements (e.g. IP entries under an ethernet interface's
        <layer3><ip>) must not be mistaken for objects.
        """
        ok, response = self.config_get_xml(xpath)
        if not ok:
            if self.debug:
                print(f"  [DEBUG] config_get_xml failed: {response}")
            return []

        try:
            root = ET.fromstring(response)
        except ET.ParseError as e:
            if self.debug:
                print(f"  [DEBUG] could not parse config response: {e}")
            return []

        result = root.find(".//result")
        if result is None:
            return []

        # PAN-OS usually wraps the entries in a container element named after
        # the last XPath node (<result><address><entry .../></address></result>)
        # but some versions/paths return the entries directly under <result>.
        entries = result.findall("entry")
        if not entries:
            entries = [
                entry
                for container in result
                for entry in container.findall("entry")
            ]

        names = []
        for entry in entries:
            name = entry.attrib.get("name")
            if name:
                names.append(name)
        return names

    def delete_all(self, commit: bool = False) -> bool:
        """Delete all custom objects in reverse dependency order.

        Returns:
            True if all deletions succeeded.
        """
        all_ok = True

        # Delete in reverse import order (dependents first). vlan.N SVIs and
        # vlan objects must go before the interface resets that reference them.
        delete_order = [
            "security_rule",
            "service_group",
            "service",
            "address_group",
            "address",
            "static_route",
            "zone",
            "vlan_interface",
            "vlan",
            "aggregate_ethernet",
        ]

        for obj_type in delete_order:
            ok, _ = self.delete_objects_by_type(obj_type)
            if not ok:
                all_ok = False

        # Reset physical ethernet interfaces (can't delete, only clear config)
        print(f"\n{'=' * 60}")
        print("Resetting ethernet interface configs...")
        print(f"{'=' * 60}")
        if not self._reset_ethernet_interfaces():
            all_ok = False

        if commit and not self.dry_run:
            success, msg = self.commit()
            if not success:
                print(f"[FAIL] Commit failed: {msg}")
                all_ok = False

        return all_ok

    # Subtrees removed from each ethernet entry when resetting it. layer2 is
    # included so converted switch member ports are cleaned up too.
    _ETHERNET_RESET_NODES = ("layer3", "layer2", "comment", "aggregate-group")

    # Error fragments meaning "nothing to delete" - not a real failure when
    # clearing config nodes that may simply not exist on an interface.
    _BENIGN_DELETE_ERRORS = ("no object", "not present", "does not exist")

    def _reset_ethernet_interfaces(self) -> bool:
        """Reset ethernet interfaces by removing layer3/layer2 config and comments.

        Physical ethernet interfaces can't be deleted on PAN-OS - they're
        hardware entries. Instead we remove the layer3/layer2 config (IP, MTU,
        etc.) and any comments/aggregate-group assignments.

        Returns:
            True if every interface was reset successfully.
        """
        xpath = XPATHS.get("ethernet", "")
        if not xpath:
            return True

        names = self._get_object_names(xpath)
        if not names:
            print("  No ethernet interfaces with config found.")
            return True

        reset_count = 0
        fail_count = 0
        for name in names:
            if self.dry_run:
                print(f"  [DRY-RUN] Would reset: {name}")
                reset_count += 1
                continue

            errors = []
            for node in self._ETHERNET_RESET_NODES:
                ok, msg = self.config_delete(f"{xpath}/entry[@name='{name}']/{node}")
                if not ok and not any(
                    b in str(msg).lower() for b in self._BENIGN_DELETE_ERRORS
                ):
                    errors.append(f"{node}: {msg}")

            if errors:
                print(f"  [FAIL] Reset {name}: {'; '.join(errors)}")
                fail_count += 1
            else:
                print(f"  [OK] Reset: {name}")
                reset_count += 1

        self.stats["deleted"] += reset_count
        self.stats["failed"] += fail_count
        print(f"\n  ethernet interfaces reset: {reset_count}"
              + (f", {fail_count} failed" if fail_count else ""))
        return fail_count == 0

    def print_summary(self) -> None:
        """Print cleanup summary."""
        print(f"\n{'=' * 60}")
        print("CLEANUP SUMMARY")
        print(f"{'=' * 60}")
        mode = "[DRY-RUN] " if self.dry_run else ""
        print(f"  {mode}Total objects found: {self.stats['total_found']}")
        print(f"  {mode}Successfully deleted: {self.stats['deleted']}")
        if self.stats["failed"] > 0:
            print(f"  FAILED: {self.stats['failed']}")
        print(f"{'=' * 60}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Bulk delete objects from Palo Alto PAN-OS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python panos_api_cleanup.py --host 10.0.0.1 --username admin --delete-all
  python panos_api_cleanup.py --host 10.0.0.1 --username admin --delete-all --dry-run
  python panos_api_cleanup.py --host 10.0.0.1 --username admin --delete-security-rules
  python panos_api_cleanup.py --host 10.0.0.1 --username admin --delete-address-objects --commit
        """,
    )

    parser.add_argument("--host", required=True, help="PAN-OS management IP/hostname")
    parser.add_argument("--username", required=True, help="PAN-OS admin username")
    parser.add_argument("--password", default=None, help="PAN-OS admin password (prompts if omitted)")
    parser.add_argument("--dry-run", action="store_true", help="Preview what would be deleted")
    parser.add_argument("--commit", action="store_true", help="Commit after deletion")
    parser.add_argument("--verify-ssl", action="store_true", help="Verify SSL certificate")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")

    # Delete flags
    parser.add_argument("--delete-all", action="store_true", help="Delete ALL custom objects")
    parser.add_argument("--delete-address-objects", action="store_true", help="Delete address objects")
    parser.add_argument("--delete-address-groups", action="store_true", help="Delete address groups")
    parser.add_argument("--delete-service-objects", action="store_true", help="Delete service objects")
    parser.add_argument("--delete-service-groups", action="store_true", help="Delete service groups")
    parser.add_argument("--delete-security-rules", action="store_true", help="Delete security rules")
    parser.add_argument("--delete-static-routes", action="store_true", help="Delete static routes")
    parser.add_argument("--delete-zones", action="store_true", help="Delete zones")
    parser.add_argument("--delete-interfaces", action="store_true",
                        help="Reset ethernet interfaces and delete aggregate-ethernet configs")

    args = parser.parse_args(argv)

    # Validate at least one delete flag
    has_delete = (
        args.delete_all
        or args.delete_address_objects
        or args.delete_address_groups
        or args.delete_service_objects
        or args.delete_service_groups
        or args.delete_security_rules
        or args.delete_static_routes
        or args.delete_zones
        or args.delete_interfaces
    )
    if not has_delete:
        parser.error("Specify at least one --delete-* flag. Use --delete-all for everything.")

    # Prompt for password
    password = args.password
    if not password:
        password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    client = PANOSBulkDelete(
        host=args.host,
        username=args.username,
        password=password,
        verify_ssl=args.verify_ssl,
        debug=args.debug,
        dry_run=args.dry_run,
    )

    if args.dry_run:
        print("\n*** DRY-RUN MODE - no changes will be made ***\n")

    # Authenticate (even for dry-run, we need to read existing objects)
    if not client.authenticate():
        print("\n[FATAL] Authentication failed. Aborting.")
        return 1

    # Confirmation prompt (unless dry-run)
    if not args.dry_run:
        print("\nWARNING: This will DELETE objects from PAN-OS!")
        confirm = input("Type 'YES' to confirm: ").strip()
        if confirm != "YES":
            print("Aborted.")
            return 0

    all_ok = True

    if args.delete_all:
        all_ok = client.delete_all(commit=args.commit)
    else:
        # Delete in reverse dependency order
        if args.delete_security_rules:
            ok, _ = client.delete_objects_by_type("security_rule")
            all_ok = all_ok and ok
        if args.delete_service_groups:
            ok, _ = client.delete_objects_by_type("service_group")
            all_ok = all_ok and ok
        if args.delete_service_objects:
            ok, _ = client.delete_objects_by_type("service")
            all_ok = all_ok and ok
        if args.delete_address_groups:
            ok, _ = client.delete_objects_by_type("address_group")
            all_ok = all_ok and ok
        if args.delete_address_objects:
            ok, _ = client.delete_objects_by_type("address")
            all_ok = all_ok and ok
        if args.delete_static_routes:
            ok, _ = client.delete_objects_by_type("static_route")
            all_ok = all_ok and ok
        if args.delete_zones:
            ok, _ = client.delete_objects_by_type("zone")
            all_ok = all_ok and ok
        if args.delete_interfaces:
            for obj_type in ("vlan_interface", "vlan", "aggregate_ethernet"):
                ok, _ = client.delete_objects_by_type(obj_type)
                all_ok = all_ok and ok
            if not client._reset_ethernet_interfaces():
                all_ok = False

        if args.commit and not args.dry_run:
            success, msg = client.commit()
            if not success:
                print(f"[FAIL] Commit failed: {msg}")
                all_ok = False

    client.print_summary()
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
