#!/usr/bin/env python3
"""
FortiGate Service Object Converter - Palo Alto PAN-OS Target
=============================================================
Converts FortiGate ``firewall_service_custom`` entries to PAN-OS service objects.

PAN-OS rules:
    - Each service object supports ONE protocol (tcp OR udp, not both)
    - A single service can have a port range (e.g., 8000-8999) or comma-
      separated ports are NOT supported - must use port range or multiple objects
    - FortiGate services with both TCP and UDP → two PAN-OS objects
    - FortiGate services with multiple disjoint port entries → separate objects

Output JSON:
    {
        "name": "tcp_8080",
        "protocol": "tcp",
        "port": "8080",
        "description": "Custom HTTP"
    }
"""

from typing import Any, Dict, List, Set, Tuple

from pa_common import (
    PA_NAME_MAX_LENGTH,
    sanitize_name,
    is_default_fortigate_service,
    first_item,
    dedup_name,
)


# Protocols we skip (no equivalent PAN-OS service object)
_SKIP_PROTOCOLS = {"icmp", "icmp6", "icmpv6", "ip", "ipip", "gre", "esp", "ah"}

# PAN-OS predefined service names that should not be overwritten
_PA_BUILTIN_SERVICES = {
    "service-http", "service-https", "service-dns-udp", "service-dns-tcp",
}


class PAServiceConverter:
    """Convert FortiGate service custom objects to PAN-OS service format."""

    def __init__(self, fortigate_config: Dict[str, Any]) -> None:
        self.fg_config = fortigate_config
        self.pa_service_objects: List[Dict] = []
        self.failed_items: List[Dict] = []

        # Mapping: FortiGate service name -> list of (pa_name, protocol) tuples
        # Used by groups and policies to resolve references
        self._service_name_mapping: Dict[str, List[Tuple[str, str]]] = {}
        self._skipped_services: Set[str] = set()

        # FortiGate ICMP echo ("ping") services. No PAN-OS service object is
        # created for these; rules referencing them get application "ping"
        # instead (PAN-OS models ICMP as an application, not a service).
        self._ping_services: Set[str] = set()

        # Statistics
        self._stats = {
            "total_objects": 0,
            "tcp_objects": 0,
            "udp_objects": 0,
            "split_services": 0,
            "multi_port_services": 0,
            "icmp_skipped": 0,
            "skipped_services": 0,
            "ping_services": 0,
        }

    def convert(self) -> List[Dict]:
        """Convert all FortiGate service objects to PAN-OS format.

        Returns:
            List of dicts, each representing a PAN-OS service object.
        """
        services = self.fg_config.get("firewall_service_custom", [])
        if not services:
            print("Warning: No service objects found in FortiGate configuration")
            return []

        results: List[Dict] = []
        used_names: Dict[str, int] = {}

        for svc_dict in services:
            item = first_item(svc_dict)
            if item is None:
                continue
            svc_name, properties = item
            protocol = str(properties.get("protocol", "")).strip().lower()

            # Silently ignore FortiGate factory-default services (e.g. "ALL").
            # These exist on every appliance and are not meaningful to migrate.
            # Register as skipped so any group referencing them is cleaned up.
            if is_default_fortigate_service(svc_name):
                print(f"  Ignored: {svc_name} (FortiGate default service)")
                self._skipped_services.add(sanitize_name(svc_name))
                continue

            # ICMP echo ("ping") services: no PAN-OS service object exists for
            # ICMP, but rules referencing them can use application "ping".
            # Track them separately (also as skipped, so groups filter them).
            if self._is_ping_service(svc_name, properties, protocol):
                print(f"  Converted: {svc_name} -> application 'ping' "
                      f"(ICMP echo service)")
                self._ping_services.add(sanitize_name(svc_name))
                self._skipped_services.add(sanitize_name(svc_name))
                self._stats["ping_services"] += 1
                continue

            # Skip non-port protocols
            if protocol in _SKIP_PROTOCOLS:
                self._skipped_services.add(sanitize_name(svc_name))
                self._stats["icmp_skipped"] += 1
                continue

            sanitized_base = sanitize_name(svc_name)

            # Avoid collision with PAN-OS built-in services
            if sanitized_base.lower() in _PA_BUILTIN_SERVICES:
                sanitized_base = f"{sanitized_base}_custom"

            # Extract TCP and UDP port entries
            tcp_ports = self._parse_ports(properties.get("tcp-portrange"), svc_name)
            udp_ports = self._parse_ports(properties.get("udp-portrange"), svc_name)

            if not tcp_ports and not udp_ports:
                # Attempt fallback for generic "portrange" key
                generic = self._parse_ports(properties.get("portrange"), svc_name)
                if generic and protocol in ("tcp", "6"):
                    tcp_ports = generic
                elif generic and protocol in ("udp", "17"):
                    udp_ports = generic

            if not tcp_ports and not udp_ports:
                self._stats["skipped_services"] += 1
                self._skipped_services.add(sanitized_base)
                self.failed_items.append({
                    "name": svc_name,
                    "reason": "no TCP or UDP ports defined",
                    "config": properties,
                })
                continue

            # Track if this service was split
            is_split = bool(tcp_ports) and bool(udp_ports)
            if is_split:
                self._stats["split_services"] += 1

            pa_names: List[Tuple[str, str]] = []

            # Create TCP objects
            tcp_objs = self._build_port_objects(
                sanitized_base, "tcp", tcp_ports, is_split, used_names
            )
            for obj in tcp_objs:
                results.append(obj)
                pa_names.append((obj["name"], "tcp"))
                self._stats["tcp_objects"] += 1

            # Create UDP objects
            udp_objs = self._build_port_objects(
                sanitized_base, "udp", udp_ports, is_split, used_names
            )
            for obj in udp_objs:
                results.append(obj)
                pa_names.append((obj["name"], "udp"))
                self._stats["udp_objects"] += 1

            if len(tcp_objs) + len(udp_objs) > 1:
                self._stats["multi_port_services"] += 1

            self._service_name_mapping[sanitized_base] = pa_names

        self._stats["total_objects"] = len(results)
        self.pa_service_objects = results
        return results

    # ------------------------------------------------------------------
    # Public accessors (mirror FTD converter interface)
    # ------------------------------------------------------------------

    def get_service_name_mapping(self) -> Dict[str, List[Tuple[str, str]]]:
        return self._service_name_mapping

    def get_skipped_services(self) -> Set[str]:
        return self._skipped_services

    def get_ping_services(self) -> Set[str]:
        """Sanitized names of ICMP echo services mapped to application 'ping'."""
        return set(self._ping_services)

    def get_statistics(self) -> Dict[str, int]:
        return dict(self._stats)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_port_objects(
        self,
        base_name: str,
        protocol: str,
        ports: List[str],
        is_split: bool,
        used_names: Dict[str, int],
    ) -> List[Dict]:
        """Build one or more PAN-OS service objects for a given protocol."""
        if not ports:
            return []

        objects: List[Dict] = []
        needs_suffix = is_split or len(ports) > 1
        proto_tag = protocol.upper()

        for idx, port_val in enumerate(ports, start=1):
            if needs_suffix:
                # Trim the base so the protocol/index suffix keeps the name
                # within the PAN-OS 63-char limit.
                suffix = f"_{proto_tag}_{idx}"
                name = base_name[:PA_NAME_MAX_LENGTH - len(suffix)] + suffix
            else:
                name = base_name

            # Deduplicate (re-trims to the PAN-OS 63-char limit)
            name = dedup_name(name, used_names)

            obj = {
                "name": name,
                "protocol": protocol,
                "port": port_val,
            }
            objects.append(obj)
            print(f"  Converted: {name} [{protocol.upper()}] (port {port_val})")

        return objects

    @staticmethod
    def _is_ping_service(
        svc_name: str, properties: Dict, protocol: str
    ) -> bool:
        """Return True if this is an ICMP echo ("ping") service.

        Matches the predefined PING service (by name) or any custom ICMPv4
        service with icmptype 8 (echo request).
        """
        if str(svc_name).strip().lower() == "ping":
            return True
        if protocol not in ("icmp", "1"):
            return False
        icmptype = properties.get("icmptype", properties.get("icmp-type"))
        return str(icmptype).strip() == "8"

    def _parse_ports(self, raw: Any, svc_name: str = "") -> List[str]:
        """Parse FortiGate port definitions into a list of PAN-OS port strings.

        FortiGate formats:
            - 80           (int or str)
            - "80"
            - "80-443"     (destination-port range)
            - "443:1024-65535"  (colon separates dst:src - the source-port
                                 restriction is dropped with a failed_items note)
            - [80, "443", "8000-8999"]  (list)

        PAN-OS port format:
            - "80"         (single port)
            - "80-443"     (range with hyphen)
            - "80,443"     (NOT supported in a single object - each becomes separate)
        """
        if raw is None:
            return []

        if isinstance(raw, (int, float)):
            return [str(int(raw))]

        if isinstance(raw, str):
            raw = raw.strip()
            if not raw:
                return []
            # In FortiGate portranges a colon ALWAYS separates the destination
            # ports from a source-port restriction ("dst[:src]"). PAN-OS
            # service objects have no source-port field, so keep the
            # destination part and record that the restriction was dropped.
            if ":" in raw:
                dst_part, _, src_part = raw.partition(":")
                dst_part = dst_part.strip()
                src_part = src_part.strip()
                if src_part:
                    self.failed_items.append({
                        "name": svc_name,
                        "reason": (
                            f"source-port restriction '{src_part}' not "
                            f"migrated (kept destination ports '{dst_part}')"
                        ),
                        "config": {"portrange": raw},
                    })
                return [dst_part] if dst_part else []
            return [raw]

        if isinstance(raw, list):
            ports: List[str] = []
            for item in raw:
                ports.extend(self._parse_ports(item, svc_name))
            return ports

        return []
