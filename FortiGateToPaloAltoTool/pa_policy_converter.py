#!/usr/bin/env python3
"""
FortiGate Policy Converter - Palo Alto PAN-OS Target
=====================================================
Converts FortiGate ``firewall_policy`` entries to PAN-OS security rules.

PAN-OS security rule fields:
    - from/to       : source/destination zones
    - source/dest   : address objects or groups
    - service       : service objects, groups, "any", or "application-default"
    - application   : "any" for migration, or "ping" for ICMP-echo-only rules
    - action        : allow / deny / drop / reset-*
    - log-end       : yes/no

Fail-closed rule: if every service (or address) a policy references was
filtered/unresolvable, the rule is still emitted but with ``disabled: yes``
and a description note, and it is recorded in ``failed_items``. It is never
silently widened to service/any.

FortiGate policies with ``status: disable`` are converted with
``disabled: yes``.

Output JSON:
    {
        "name": "Allow_Web",
        "from_zones": ["untrust"],
        "to_zones": ["trust"],
        "sources": ["any"],
        "destinations": ["webserver"],
        "services": ["tcp_80", "tcp_443"],
        "application": ["any"],
        "action": "allow",
        "log_end": "yes",
        "description": "Allow web traffic",
        "disabled": "no"
    }
"""

from typing import Any, Dict, List, Optional, Set, Tuple

from pa_common import sanitize_name, first_item, dedup_name


class PAPolicyConverter:
    """Convert FortiGate firewall policies to PAN-OS security rules."""

    def __init__(self, fortigate_config: Dict[str, Any]) -> None:
        self.fg_config = fortigate_config
        self.pa_security_rules: List[Dict] = []
        self.failed_items: List[Dict] = []

        # Set by the orchestrator after service/address conversion
        self._split_services: Set[str] = set()
        self._service_name_mapping: Dict[str, List[Tuple[str, str]]] = {}
        self._skipped_services: Set[str] = set()
        self._address_groups: Set[str] = set()
        self._service_groups: Set[str] = set()
        self._interface_name_mapping: Dict[str, str] = {}
        # Addresses (and address groups) that were skipped/dropped - refs to
        # these are filtered from rules (raw and sanitized names).
        self._skipped_addresses: Set[str] = set()
        # ICMP echo ("ping") services - a rule whose services were all ping
        # gets application ["ping"] instead of a service object.
        self._ping_services: Set[str] = set()
        # Dedup rename maps (FortiGate name, raw and sanitized -> final name).
        self._address_name_map: Dict[str, str] = {}
        self._address_group_name_map: Dict[str, str] = {}
        self._service_group_name_map: Dict[str, str] = {}

        # Interfaces for which no zone mapping existed and a zone name was
        # fabricated - tracked so each is reported only once.
        self._fabricated_zones: Set[str] = set()

        # Statistics
        self._stats = {
            "total_rules": 0,
            "allow_rules": 0,
            "deny_rules": 0,
            "disabled_rules": 0,
        }

    def set_split_services(
        self,
        split_services: Set[str],
        service_name_mapping: Dict[str, List[Tuple[str, str]]],
        skipped_services: Set[str],
        address_groups: Set[str],
        service_groups: Set[str],
        interface_name_mapping: Dict[str, str],
        skipped_addresses: Optional[Set[str]] = None,
        ping_services: Optional[Set[str]] = None,
        address_name_map: Optional[Dict[str, str]] = None,
        address_group_name_map: Optional[Dict[str, str]] = None,
        service_group_name_map: Optional[Dict[str, str]] = None,
    ) -> None:
        """Provide context from prior converters (called before convert)."""
        self._split_services = split_services
        self._service_name_mapping = service_name_mapping
        self._skipped_services = skipped_services
        self._address_groups = address_groups
        self._service_groups = service_groups
        self._interface_name_mapping = interface_name_mapping
        self._skipped_addresses = set(skipped_addresses or set())
        self._ping_services = set(ping_services or set())
        self._address_name_map = dict(address_name_map or {})
        self._address_group_name_map = dict(address_group_name_map or {})
        self._service_group_name_map = dict(service_group_name_map or {})

    def convert(self) -> List[Dict]:
        """Convert all FortiGate policies to PAN-OS security rules.

        Returns:
            List of dicts, each representing a PAN-OS security rule.
        """
        policies = self.fg_config.get("firewall_policy", [])
        if not policies:
            print("Warning: No firewall policies found in FortiGate configuration")
            return []

        results: List[Dict] = []
        used_names: Dict[str, int] = {}

        for policy_dict in policies:
            item = first_item(policy_dict)
            if item is None:
                continue
            policy_id, properties = item

            # Build rule name from policy name or ID
            rule_name = str(properties.get("name", f"Policy_{policy_id}")).strip()
            if not rule_name or rule_name.lower() == "none":
                rule_name = f"Policy_{policy_id}"

            sanitized = sanitize_name(rule_name)
            if not sanitized:
                sanitized = f"Policy_{policy_id}"

            sanitized = dedup_name(sanitized, used_names)

            # --- Action ---
            fg_action = str(properties.get("action", "deny")).strip().lower()
            if fg_action in ("accept", "allow"):
                pa_action = "allow"
            else:
                pa_action = "deny"

            # --- Disabled state (FortiGate `set status disable`) ---
            fg_status = str(properties.get("status", "enable")).strip().lower()
            disabled = fg_status in ("disable", "disabled")

            # Reasons that force the rule to be emitted disabled (fail closed)
            fail_reasons: List[str] = []

            # --- Zones ---
            from_zones = self._resolve_zones(properties.get("srcintf", []))
            to_zones = self._resolve_zones(properties.get("dstintf", []))

            # PAN-OS requires at least one zone; use "any" as fallback
            if not from_zones:
                from_zones = ["any"]
            if not to_zones:
                to_zones = ["any"]

            # --- Source addresses (fail closed if all refs were filtered) ---
            sources, src_filtered = self._resolve_addresses(
                properties.get("srcaddr", [])
            )
            if not sources:
                if src_filtered:
                    fail_reasons.append(
                        "all source addresses were skipped during conversion: "
                        + ", ".join(src_filtered)
                    )
                sources = ["any"]

            # --- Destination addresses ---
            destinations, dst_filtered = self._resolve_addresses(
                properties.get("dstaddr", [])
            )
            if not destinations:
                if dst_filtered:
                    fail_reasons.append(
                        "all destination addresses were skipped during conversion: "
                        + ", ".join(dst_filtered)
                    )
                destinations = ["any"]

            # --- Services (ping-aware, fail closed if all refs filtered) ---
            services, svc_filtered, ping_refs = self._resolve_services(
                properties.get("service", [])
            )
            application = ["any"]
            if not services:
                if ping_refs and not svc_filtered:
                    # All referenced services were ICMP echo ("ping") - PAN-OS
                    # models ICMP as an application, not a service.
                    application = ["ping"]
                    services = ["application-default"]
                elif svc_filtered or ping_refs:
                    fail_reasons.append(
                        "all services were skipped during conversion: "
                        + ", ".join(svc_filtered + ping_refs)
                    )
                    services = ["any"]
                else:
                    services = ["any"]
            elif ping_refs:
                # Mixed rule: real services plus ping. PAN-OS cannot express
                # both in one rule (application would restrict the services),
                # so keep the port-based services and note the dropped ping.
                self.failed_items.append({
                    "name": sanitized,
                    "reason": "ping service(s) dropped from rule with other "
                              "services: " + ", ".join(ping_refs),
                    "config": properties,
                })

            # --- Description ---
            description = str(properties.get("comments", "")).strip()
            if not description:
                description = str(properties.get("name", "")).strip()

            if fail_reasons:
                disabled = True
                note = "DISABLED by migration: " + "; ".join(fail_reasons)
                description = f"{description} | {note}" if description else note
                self.failed_items.append({
                    "name": sanitized,
                    "reason": "; ".join(fail_reasons),
                    "config": properties,
                })

            # --- Build rule ---
            rule = {
                "name": sanitized,
                "from_zones": from_zones,
                "to_zones": to_zones,
                "sources": sources,
                "destinations": destinations,
                "services": services,
                "application": application,
                "action": pa_action,
                "log_end": "yes",
                "description": description,
                "disabled": "yes" if disabled else "no",
            }
            results.append(rule)

            # Update stats
            if pa_action == "allow":
                self._stats["allow_rules"] += 1
            else:
                self._stats["deny_rules"] += 1
            if disabled:
                self._stats["disabled_rules"] += 1

            state = " [DISABLED]" if disabled else ""
            print(f"  Converted: {sanitized} [{pa_action.upper()}]{state} "
                  f"({', '.join(from_zones)} -> {', '.join(to_zones)})")

        self._stats["total_rules"] = len(results)
        self.pa_security_rules = results
        return results

    def get_statistics(self) -> Dict[str, int]:
        return dict(self._stats)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_zones(self, raw: Any) -> List[str]:
        """Map FortiGate interface names to PAN-OS zone names."""
        items = _to_list(raw)
        zones: List[str] = []
        for item in items:
            item_str = str(item).strip()
            if item_str.lower() in ("any", "all", ""):
                continue

            # Try interface mapping first
            zone_name = self._find_zone(item_str)
            if zone_name and zone_name not in zones:
                zones.append(zone_name)

        return zones

    def _find_zone(self, interface_name: str) -> str:
        """Look up zone name for a FortiGate interface (deterministic).

        Match order: exact, case-insensitive exact, then suffix match (only
        used when it is unambiguous; an ambiguous suffix match falls back to
        the alphabetically-first zone with a warning). If nothing matches, a
        zone name is fabricated from the interface name with a warning and a
        failed_items entry (recorded once per interface).
        """
        # Direct match
        if interface_name in self._interface_name_mapping:
            return self._interface_name_mapping[interface_name]

        # Case-insensitive match (deterministic: sorted iteration)
        lower = interface_name.lower()
        for fg_name, pa_zone in sorted(self._interface_name_mapping.items()):
            if fg_name.lower() == lower:
                return pa_zone

        # VLAN ID suffix match (e.g., "551" matches zone for VLAN 551).
        # Only trust it when it resolves to a single zone.
        candidates = sorted({
            pa_zone
            for fg_name, pa_zone in self._interface_name_mapping.items()
            if fg_name.endswith(interface_name) or interface_name.endswith(fg_name)
        })
        if len(candidates) == 1:
            return candidates[0]
        if candidates:
            print(f"    [WARNING] Interface '{interface_name}' matches multiple "
                  f"zones ({', '.join(candidates)}) - using '{candidates[0]}'")
            return candidates[0]

        # No match at all: fabricate a zone name from the interface name.
        fabricated = sanitize_name(interface_name)
        if interface_name not in self._fabricated_zones:
            self._fabricated_zones.add(interface_name)
            print(f"    [WARNING] No zone mapping for interface "
                  f"'{interface_name}' - using fabricated zone '{fabricated}' "
                  f"(verify it exists on the firewall)")
            self.failed_items.append({
                "name": interface_name,
                "reason": f"no zone mapping found; fabricated zone name "
                          f"'{fabricated}' used in rules",
                "config": {},
            })
        return fabricated

    def _resolve_addresses(self, raw: Any) -> Tuple[List[str], List[str]]:
        """Resolve FortiGate address references to PAN-OS names.

        Returns:
            (resolved_names, filtered_names) - filtered_names are references
            to addresses/groups that were skipped during conversion.
        """
        items = _to_list(raw)
        addresses: List[str] = []
        filtered: List[str] = []
        for item in items:
            item_str = str(item).strip()
            if item_str.lower() in ("any", "all", ""):
                # "any" is explicit in PAN-OS
                if "any" not in addresses:
                    addresses.append("any")
                continue

            sanitized = sanitize_name(item_str)

            # References to skipped addresses/groups are filtered out
            if (item_str in self._skipped_addresses
                    or sanitized in self._skipped_addresses):
                filtered.append(item_str)
                continue

            # Follow dedup renames (address objects, then address groups)
            resolved = self._address_name_map.get(
                item_str,
                self._address_name_map.get(sanitized),
            )
            if resolved is None:
                resolved = self._address_group_name_map.get(
                    item_str,
                    self._address_group_name_map.get(sanitized, sanitized),
                )
            if resolved and resolved not in addresses:
                addresses.append(resolved)

        return addresses, filtered

    def _resolve_services(
        self, raw: Any
    ) -> Tuple[List[str], List[str], List[str]]:
        """Resolve FortiGate service references to PAN-OS service names.

        Returns:
            (resolved_names, filtered_names, ping_names) - filtered_names are
            references to services/groups skipped during conversion (excluding
            ping); ping_names are references to ICMP echo services which map
            to application "ping" instead of a service object.
        """
        items = _to_list(raw)
        services: List[str] = []
        filtered: List[str] = []
        ping_refs: List[str] = []

        for item in items:
            item_str = str(item).strip()
            if item_str.lower() in ("all", "any", ""):
                if "any" not in services:
                    services.append("any")
                continue

            sanitized = sanitize_name(item_str)

            # ICMP echo ("ping") services map to the ping application
            if sanitized in self._ping_services:
                if item_str not in ping_refs:
                    ping_refs.append(item_str)
                continue

            # Skip protocols/groups that have no PAN-OS equivalent
            if sanitized in self._skipped_services:
                filtered.append(item_str)
                continue

            # If this service was split into multiple PAN-OS objects
            if sanitized in self._service_name_mapping:
                for pa_name, _proto in self._service_name_mapping[sanitized]:
                    if pa_name not in services:
                        services.append(pa_name)
                continue

            # Service group reference (following dedup renames)
            group_resolved = self._service_group_name_map.get(
                item_str,
                self._service_group_name_map.get(sanitized),
            )
            if group_resolved is None and sanitized in self._service_groups:
                group_resolved = sanitized
            if group_resolved is not None:
                if group_resolved not in services:
                    services.append(group_resolved)
                continue

            # Direct service reference
            if sanitized not in services:
                services.append(sanitized)

        return services, filtered, ping_refs


def _to_list(raw: Any) -> List:
    """Normalize raw value to a list."""
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return raw
    return [raw]
