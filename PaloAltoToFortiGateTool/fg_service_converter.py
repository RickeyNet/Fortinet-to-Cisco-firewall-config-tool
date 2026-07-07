#!/usr/bin/env python3
"""PAN-OS Service Object Converter - FortiGate Target
======================================================
Converts PAN-OS service objects to FortiGate ``firewall service custom``
CLI config.

PAN-OS has one protocol (tcp OR udp) per service object.  FortiGate can
combine both protocols in a single service object with separate
``tcp-portrange`` and ``udp-portrange`` directives.  This converter
detects companion objects that share a base name and differ only by a
``_TCP`` / ``_UDP`` suffix (the pattern produced by the reverse FG→PA
converter) and emits a merged TCP+UDP object for them.

To avoid broadening rules that referenced only ONE half of a companion
pair, the individual ``_TCP`` / ``_UDP`` objects are ALSO emitted, and the
name map keeps each original name pointing at its own individual object.
The merged object is only used when a rule/group referenced BOTH halves
(the policy and service-group converters collapse such pairs via
``get_merged_pairs()``).

Services with a PAN-OS source-port are emitted using FortiGate's
``<dst>:<src>`` portrange syntax.

FortiGate CLI output format:
    config firewall service custom
        edit "HTTP"
            set tcp-portrange 80
        next
        edit "DNS"
            set tcp-portrange 53
            set udp-portrange 53
            set comment "DNS service"
        next
    end

PAN-OS port formats supported:
    "80"          -> single port
    "8000-8999"   -> range
    "80,8080"     -> multi-port (written as FG space-separated range list)
    port "80" + source-port "1024-65535" -> "80:1024-65535"
"""

from typing import Any, Dict, List, Optional, Set, Tuple

from fg_common import dedup_fg_name, escape_fg_string, sanitize_fg_name


# PAN-OS suffixes applied by the reverse converter when splitting TCP+UDP
_SPLIT_SUFFIXES = ("_TCP", "_UDP", "_tcp", "_udp")


def _strip_split_suffix(name: str) -> Tuple[Optional[str], Optional[str]]:
    """If *name* ends in a TCP/UDP split suffix, return (base, proto).

    Returns (None, None) if the name does not end in a known suffix or if
    stripping the suffix would leave an empty base name (e.g. a service
    named exactly "_TCP" is kept as-is, unmerged).
    """
    for suffix in _SPLIT_SUFFIXES:
        if name.endswith(suffix):
            base = name[: -len(suffix)]
            if not base:
                return None, None
            return base, suffix.lstrip("_").lower()
    return None, None


def _convert_pa_ports(port_str: str, source_port_str: str = "") -> str:
    """Convert PAN-OS port strings to FortiGate portrange format.

    PAN-OS uses comma-separated and hyphenated notation.  FortiGate uses
    space-separated entries (each entry is a single port or range), with an
    optional ``:<source>`` suffix per entry for source-port restrictions.

    Examples:
        "80"                    -> "80"
        "8000-8999"             -> "8000-8999"
        "80,8080"               -> "80 8080"
        "80" + source "1024-65535" -> "80:1024-65535"
    """
    if not port_str:
        return ""
    dst_entries = [p.strip() for p in port_str.split(",") if p.strip()]
    if not source_port_str:
        return " ".join(dst_entries)
    src_entries = [p.strip() for p in source_port_str.split(",") if p.strip()]
    if not src_entries:
        return " ".join(dst_entries)
    return " ".join(f"{d}:{s}" for d in dst_entries for s in src_entries)


def collapse_merged_pairs(
    members: List[str], merged_pairs: Dict[str, List[str]]
) -> List[str]:
    """Replace TCP/UDP companion halves with their merged service when
    BOTH halves are present in *members*; otherwise leave them alone.
    """
    if not merged_pairs:
        return members
    result = list(members)
    for merged_name, halves in merged_pairs.items():
        if len(halves) == 2 and all(h in result for h in halves):
            collapsed: List[str] = []
            replaced = False
            for m in result:
                if m in halves:
                    if not replaced:
                        collapsed.append(merged_name)
                        replaced = True
                    continue
                collapsed.append(m)
            result = collapsed
    return result


class FGServiceConverter:
    """Convert PAN-OS service objects to FortiGate service custom format."""

    def __init__(self, pa_config: Dict[str, Any]) -> None:
        self.pa_config = pa_config
        self.failed_items: List[Dict] = []

        # Maps the original PA service name -> FG service name
        # Used by the policy and group converters to resolve references
        self._name_map: Dict[str, str] = {}

        # merged FG name -> [final FG names of the tcp and udp halves]
        self._merged_pairs: Dict[str, List[str]] = {}

        # Sanitized PA names of services that could not be converted
        self._skipped_names: Set[str] = set()

        self._stats = {
            "total": 0,
            "tcp_only": 0,
            "udp_only": 0,
            "merged_tcp_udp": 0,
            "skipped": 0,
        }

    def convert(self) -> str:
        """Convert all service objects and return FortiGate CLI block.

        Returns:
            A string containing the ``config firewall service custom`` block,
            or an empty string if there are no service objects.
        """
        services = self.pa_config.get("services", [])
        if not services:
            return ""

        # ------------------------------------------------------------------
        # Pass 1: Group by base name to detect TCP+UDP companion pairs
        # ------------------------------------------------------------------
        # base_name -> {proto: service record}
        merged: Dict[str, Dict[str, Dict[str, str]]] = {}
        standalone: List[Dict[str, str]] = []

        for svc in services:
            pa_name = sanitize_fg_name(svc.get("name", ""))
            if not pa_name:
                continue
            record = {
                "name": pa_name,
                "protocol": svc.get("protocol", "").lower(),
                "port": svc.get("port", ""),
                "source_port": svc.get("source_port", ""),
                "description": svc.get("description", ""),
            }

            base, split_proto = _strip_split_suffix(pa_name)
            if base is not None and split_proto is not None:
                # Candidate for merging
                merged.setdefault(base, {})[split_proto] = record
            else:
                standalone.append(record)

        # ------------------------------------------------------------------
        # Pass 2: Decide what becomes merged vs standalone
        # ------------------------------------------------------------------
        # Groups with BOTH tcp and udp entries → merged object PLUS the two
        # individual halves (so single-half references keep original scope).
        # Groups missing one side → treat remaining as standalone.
        fg_services: List[Dict[str, Any]] = []
        merged_defs: List[Dict[str, Any]] = []
        for base, protos in merged.items():
            if "tcp" in protos and "udp" in protos:
                tcp = protos["tcp"]
                udp = protos["udp"]
                merged_defs.append({
                    "fg_name": base,
                    "tcp_port": _convert_pa_ports(tcp["port"], tcp["source_port"]),
                    "udp_port": _convert_pa_ports(udp["port"], udp["source_port"]),
                    "description": tcp["description"],
                    "merged": True,
                    "pa_names": [],
                    "merged_from": [tcp["name"], udp["name"]],
                })
                # Also emit the individual halves (see module docstring)
                standalone.append(tcp)
                standalone.append(udp)
            else:
                # Only one protocol - treat as standalone
                standalone.extend(protos.values())

        # Standalone objects (original pa_name preserved)
        for svc in standalone:
            proto = svc["protocol"]
            port = _convert_pa_ports(svc["port"], svc.get("source_port", ""))
            fg_services.append({
                "fg_name": svc["name"],
                "tcp_port": port if proto == "tcp" else "",
                "udp_port": port if proto == "udp" else "",
                "description": svc["description"],
                "merged": False,
                "pa_names": [svc["name"]],
                "merged_from": [],
            })
        # Merged objects last so their halves' final names are known
        fg_services.extend(merged_defs)

        # ------------------------------------------------------------------
        # Pass 3: Build name mapping and CLI entries
        # ------------------------------------------------------------------
        entries: List[str] = []
        used_names: Dict[str, int] = {}

        for fg_svc in fg_services:
            base_name = fg_svc["fg_name"]
            if not base_name:
                continue

            tcp_port = fg_svc["tcp_port"]
            udp_port = fg_svc["udp_port"]
            description = fg_svc.get("description", "")

            if not tcp_port and not udp_port:
                # Skipped services must not register a name mapping;
                # downstream converters filter them out (fail closed).
                print(f"  Skipped service: {base_name} (no ports)")
                self.failed_items.append({"name": base_name, "reason": "no ports"})
                for pa_name in fg_svc["pa_names"]:
                    self._skipped_names.add(pa_name)
                self._stats["skipped"] += 1
                continue

            fg_name = dedup_fg_name(base_name, used_names)

            # Register name mapping for all original PA names
            for pa_name in fg_svc["pa_names"]:
                self._name_map[pa_name] = fg_name
            if fg_svc["merged"]:
                self._merged_pairs[fg_name] = [
                    self._name_map.get(n, n) for n in fg_svc["merged_from"]
                ]

            lines = [f'    edit "{fg_name}"']
            if tcp_port:
                lines.append(f"        set tcp-portrange {tcp_port}")
            if udp_port:
                lines.append(f"        set udp-portrange {udp_port}")
            if description:
                lines.append(f'        set comment "{escape_fg_string(description)}"')
            lines.append("    next")

            entries.append("\n".join(lines))
            self._stats["total"] += 1

            if fg_svc["merged"]:
                self._stats["merged_tcp_udp"] += 1
                print(f"  Converted service: {fg_name} (tcp+udp merged)")
            elif tcp_port:
                self._stats["tcp_only"] += 1
                print(f"  Converted service: {fg_name} (tcp)")
            else:
                self._stats["udp_only"] += 1
                print(f"  Converted service: {fg_name} (udp)")

        if not entries:
            return ""

        block = "config firewall service custom\n"
        block += "\n".join(entries)
        block += "\nend\n"
        return block

    def get_name_map(self) -> Dict[str, str]:
        """Return mapping: original PA service name -> FG service name."""
        return dict(self._name_map)

    def get_merged_pairs(self) -> Dict[str, List[str]]:
        """Return mapping: merged FG name -> [tcp half, udp half] FG names."""
        return {k: list(v) for k, v in self._merged_pairs.items()}

    def get_skipped_names(self) -> Set[str]:
        """Return sanitized PA names of services that were not converted."""
        return set(self._skipped_names)

    def get_statistics(self) -> Dict[str, int]:
        return dict(self._stats)
