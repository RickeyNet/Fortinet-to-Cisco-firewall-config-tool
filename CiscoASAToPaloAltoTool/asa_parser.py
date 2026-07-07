#!/usr/bin/env python3
"""
Cisco ASA Configuration Parser
================================
Parses a Cisco ASA running-config text file into structured data suitable
for conversion to Palo Alto PAN-OS format.

Supported ASA config sections:
    - hostname
    - interface blocks (nameif, security-level, ip address)
    - static routes
    - network objects (host, subnet, range, fqdn)
    - network object-groups
    - service objects
    - service object-groups
    - access-lists (extended ACEs)
    - access-groups (ACL-to-interface bindings)
    - NAT rules (parsed for reference, not auto-converted)
"""

from typing import Any, Dict, List, Optional, Set, Tuple


# ── Well-known ASA port name -> number mapping ─────────────────────────────
ASA_PORT_NAMES: Dict[str, str] = {
    "ftp-data": "20", "ftp": "21", "ssh": "22", "telnet": "23",
    "smtp": "25", "time": "37", "whois": "43", "tacacs": "49",
    "domain": "53", "dns": "53", "bootps": "67", "bootpc": "68",
    "tftp": "69", "gopher": "70", "finger": "79",
    "http": "80", "www": "80", "kerberos": "750",  # ASA literal (IANA 88)
    "pop2": "109", "pop3": "110", "sunrpc": "111",
    "ident": "113", "nntp": "119", "ntp": "123",
    "netbios-ns": "137", "netbios-dgm": "138", "netbios-ssn": "139",
    "imap4": "143", "snmp": "161", "snmptrap": "162",
    "bgp": "179", "ldap": "389", "https": "443",
    "cmd": "514", "syslog": "514", "lpd": "515",
    "isakmp": "500", "login": "513", "rsh": "514",
    "rtsp": "554", "ldaps": "636",
    # ASA literals that differ from IANA: kerberos (IANA 88) -> 750,
    # sqlnet (IANA 1521) -> 1522, radius (IANA 1812) -> 1645,
    # radius-acct (IANA 1813) -> 1646.
    "sqlnet": "1522", "h323": "1720", "pptp": "1723",
    "radius": "1645", "radius-acct": "1646",
    "nfs": "2049", "mysql": "3306", "rdp": "3389",
    "sip": "5060", "aol": "5190",
    "pcanywhere-data": "5631", "pcanywhere-status": "5632",
    "citrix-ica": "1494", "lotusnotes": "1352",
    "imap4s": "993", "pop3s": "995",
    "echo": "7", "discard": "9", "daytime": "13", "chargen": "19",
}


def _resolve_port(port_token: str) -> str:
    """Resolve an ASA port name or number to a numeric string."""
    if port_token.isdigit():
        return port_token
    return ASA_PORT_NAMES.get(port_token.lower(), port_token)


class ASAParser:
    """Parse a Cisco ASA running-config into structured data."""

    def parse(self, config_text: str) -> Dict[str, Any]:
        """Parse the full ASA configuration text.

        Returns a dict with keys:
            hostname, interfaces, routes, network_objects,
            network_object_groups, service_objects, service_object_groups,
            icmp_type_groups, protocol_groups, access_lists, access_groups,
            nat_rules, skipped_acl_lines
        """
        lines = config_text.splitlines()
        result: Dict[str, Any] = {
            "hostname": "",
            "interfaces": [],
            "routes": [],
            "network_objects": {},
            "network_object_groups": {},
            "service_objects": {},
            "service_object_groups": {},
            # Parsed-but-unsupported group types (recorded so the converter
            # can report references to them instead of emitting dangling refs)
            "icmp_type_groups": {},
            "protocol_groups": {},
            "access_lists": {},
            # ACL name -> LIST of bindings (an ACL can be bound to multiple
            # interfaces and/or globally)
            "access_groups": {},
            "nat_rules": [],
            # ACL lines that could not be parsed (reported, never silent)
            "skipped_acl_lines": [],
        }

        i = 0
        while i < len(lines):
            line = lines[i].rstrip()
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("!"):
                i += 1
                continue

            if stripped.startswith("hostname "):
                parts = stripped.split(None, 1)
                if len(parts) == 2:
                    result["hostname"] = parts[1]

            elif stripped.startswith("interface "):
                block, i = self._collect_block(lines, i)
                self._parse_interface(stripped, block, result)
                continue

            elif stripped.startswith("object network "):
                block, i = self._collect_block(lines, i)
                self._parse_network_object(stripped, block, result)
                continue

            elif stripped.startswith("object service "):
                block, i = self._collect_block(lines, i)
                self._parse_service_object(stripped, block, result)
                continue

            elif stripped.startswith("object-group network "):
                block, i = self._collect_block(lines, i)
                self._parse_network_object_group(stripped, block, result)
                continue

            elif stripped.startswith("object-group service "):
                block, i = self._collect_block(lines, i)
                self._parse_service_object_group(stripped, block, result)
                continue

            elif stripped.startswith("object-group icmp-type "):
                block, i = self._collect_block(lines, i)
                self._parse_unsupported_group(
                    stripped, block, result, "icmp_type_groups"
                )
                continue

            elif stripped.startswith("object-group protocol "):
                block, i = self._collect_block(lines, i)
                self._parse_unsupported_group(
                    stripped, block, result, "protocol_groups"
                )
                continue

            elif stripped.startswith("route "):
                self._parse_route(stripped, result)

            elif stripped.startswith("access-list "):
                self._parse_access_list_entry(stripped, result)

            elif stripped.startswith("access-group "):
                self._parse_access_group(stripped, result)

            elif stripped.startswith("nat "):
                self._parse_nat_rule(stripped, result)

            i += 1

        if result["skipped_acl_lines"]:
            print(f"  WARNING: {len(result['skipped_acl_lines'])} access-list "
                  f"line(s) could not be converted (see warnings above)")

        return result

    # ── Block collector ────────────────────────────────────────────────
    def _collect_block(
        self, lines: List[str], start: int
    ) -> Tuple[List[str], int]:
        """Collect indented lines belonging to a block.

        Returns (block_body_lines, next_line_index).
        """
        body: List[str] = []
        i = start + 1
        while i < len(lines):
            raw = lines[i].rstrip()
            if not raw:
                i += 1
                continue
            stripped = raw.strip()
            if stripped.startswith("!"):
                i += 1
                continue
            # Indented lines belong to the block
            if raw[0] in (" ", "\t"):
                body.append(stripped)
                i += 1
            else:
                break
        return body, i

    # ── Interface parsing ──────────────────────────────────────────────
    def _parse_interface(
        self, header: str, body: List[str], result: Dict
    ) -> None:
        parts = header.split()
        hw_id = parts[1] if len(parts) >= 2 else ""

        intf: Dict[str, Any] = {
            "hw_id": hw_id,
            "description": "",
            "nameif": "",
            "security_level": 0,
            "ip_address": "",
            "netmask": "",
            # 'show run' omits 'no shutdown' for enabled interfaces, so an
            # interface is enabled unless an explicit 'shutdown' line appears.
            "shutdown": False,
            "management_only": False,
        }

        for line in body:
            if line.startswith("description "):
                intf["description"] = line.split(None, 1)[1]
            elif line.startswith("nameif "):
                intf["nameif"] = line.split(None, 1)[1]
            elif line.startswith("security-level "):
                try:
                    intf["security_level"] = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
            elif line.startswith("ip address "):
                tokens = line.split()
                if len(tokens) >= 4:
                    intf["ip_address"] = tokens[2]
                    intf["netmask"] = tokens[3]
            elif line == "no shutdown":
                intf["shutdown"] = False
            elif line == "shutdown":
                intf["shutdown"] = True
            elif line == "management-only":
                intf["management_only"] = True

        result["interfaces"].append(intf)

    # ── Network object parsing ─────────────────────────────────────────
    def _parse_network_object(
        self, header: str, body: List[str], result: Dict
    ) -> None:
        tokens = header.split()
        name = tokens[2] if len(tokens) >= 3 else ""
        if not name:
            return

        # ASA re-declares 'object network <name>' blocks for object-NAT.
        # Merge into any existing object instead of overwriting it, so the
        # NAT block does not wipe out the address definition.
        obj: Dict[str, Any] = result["network_objects"].get(
            name, {"type": "", "value": "", "netmask": "", "fqdn": ""}
        )

        for line in body:
            if line.startswith("subnet "):
                parts = line.split()
                obj["type"] = "subnet"
                obj["value"] = parts[1] if len(parts) >= 2 else ""
                obj["netmask"] = parts[2] if len(parts) >= 3 else ""
            elif line.startswith("host "):
                obj["type"] = "host"
                obj["value"] = line.split()[1] if len(line.split()) >= 2 else ""
            elif line.startswith("range "):
                parts = line.split()
                obj["type"] = "range"
                obj["value"] = parts[1] if len(parts) >= 2 else ""
                obj["end_value"] = parts[2] if len(parts) >= 3 else ""
            elif line.startswith("fqdn "):
                parts = line.split()
                obj["type"] = "fqdn"
                obj["fqdn"] = parts[2] if len(parts) >= 3 else parts[1]
            elif line.startswith("description "):
                obj["description"] = line.split(None, 1)[1]
            elif line.startswith("nat "):
                # Object-NAT: record for the manual-review NAT output
                result["nat_rules"].append(f"object network {name}: {line}")

        result["network_objects"][name] = obj

    # ── Service object parsing ─────────────────────────────────────────
    def _parse_service_object(
        self, header: str, body: List[str], result: Dict
    ) -> None:
        tokens = header.split()
        name = tokens[2] if len(tokens) >= 3 else ""
        if not name:
            return

        obj: Dict[str, Any] = {
            "protocol": "",
            "dst_port": "",
            "dst_port_end": "",
            "src_port": "",
        }

        for line in body:
            if line.startswith("service "):
                self._parse_service_line(line, obj)

        result["service_objects"][name] = obj

    @staticmethod
    def _parse_service_line(line: str, obj: Dict) -> None:
        """Parse 'service tcp destination eq 443' and similar lines."""
        tokens = line.split()
        # service <protocol> [source|destination] <operator> <port> [<port>]
        if len(tokens) < 2:
            return
        obj["protocol"] = tokens[1].lower()

        i = 2
        while i < len(tokens):
            if tokens[i] == "destination":
                i += 1
                if i < len(tokens) and tokens[i] == "eq":
                    i += 1
                    if i < len(tokens):
                        obj["dst_port"] = _resolve_port(tokens[i])
                elif i < len(tokens) and tokens[i] == "range":
                    i += 1
                    if i + 1 < len(tokens):
                        obj["dst_port"] = _resolve_port(tokens[i])
                        obj["dst_port_end"] = _resolve_port(tokens[i + 1])
                        i += 1
                elif i < len(tokens) and tokens[i] in ("gt", "lt", "neq"):
                    i += 1
                    if i < len(tokens):
                        obj["dst_port"] = _resolve_port(tokens[i])
            elif tokens[i] == "source":
                i += 1
                if i < len(tokens) and tokens[i] == "eq":
                    i += 1
                    if i < len(tokens):
                        obj["src_port"] = _resolve_port(tokens[i])
            elif tokens[i] == "eq":
                # No direction keyword -> assume destination
                i += 1
                if i < len(tokens):
                    obj["dst_port"] = _resolve_port(tokens[i])
            elif tokens[i] == "range":
                i += 1
                if i + 1 < len(tokens):
                    obj["dst_port"] = _resolve_port(tokens[i])
                    obj["dst_port_end"] = _resolve_port(tokens[i + 1])
                    i += 1
            i += 1

    # ── Network object-group parsing ───────────────────────────────────
    def _parse_network_object_group(
        self, header: str, body: List[str], result: Dict
    ) -> None:
        tokens = header.split()
        name = tokens[2] if len(tokens) >= 3 else ""
        if not name:
            return

        members: List[Dict[str, str]] = []

        for line in body:
            if line.startswith("network-object object "):
                ref_name = line.split()[2] if len(line.split()) >= 3 else ""
                if ref_name:
                    members.append({"type": "object", "name": ref_name})
            elif line.startswith("network-object host "):
                ip = line.split()[2] if len(line.split()) >= 3 else ""
                if ip:
                    members.append({"type": "host", "value": ip})
            elif line.startswith("network-object "):
                parts = line.split()
                if len(parts) >= 3:
                    members.append({
                        "type": "subnet",
                        "value": parts[1],
                        "netmask": parts[2],
                    })
            elif line.startswith("group-object "):
                ref = line.split()[1] if len(line.split()) >= 2 else ""
                if ref:
                    members.append({"type": "group", "name": ref})

        result["network_object_groups"][name] = {"members": members}

    # ── Service object-group parsing ───────────────────────────────────
    def _parse_service_object_group(
        self, header: str, body: List[str], result: Dict
    ) -> None:
        tokens = header.split()
        # object-group service <name> [tcp|udp|tcp-udp]
        name = tokens[2] if len(tokens) >= 3 else ""
        protocol = tokens[3].lower() if len(tokens) >= 4 else ""
        if not name:
            return

        members: List[str] = []
        service_refs: List[Dict[str, str]] = []

        for line in body:
            if line.startswith("port-object eq "):
                port = line.split()[2] if len(line.split()) >= 3 else ""
                if port:
                    members.append(_resolve_port(port))
            elif line.startswith("port-object range "):
                parts = line.split()
                if len(parts) >= 4:
                    start = _resolve_port(parts[2])
                    end = _resolve_port(parts[3])
                    members.append(f"{start}-{end}")
            elif line.startswith("service-object object "):
                ref = line.split()[2] if len(line.split()) >= 3 else ""
                if ref:
                    service_refs.append({"type": "object", "name": ref})
            elif line.startswith("service-object "):
                # service-object tcp destination eq 80
                parts = line.split()
                if len(parts) >= 2:
                    proto = parts[1].lower()
                    port_str = ""
                    j = 2
                    while j < len(parts):
                        if parts[j] in ("destination", "source"):
                            j += 1
                            if j < len(parts) and parts[j] == "eq":
                                j += 1
                                if j < len(parts):
                                    port_str = _resolve_port(parts[j])
                            elif j < len(parts) and parts[j] == "range":
                                j += 1
                                if j + 1 < len(parts):
                                    port_str = (
                                        f"{_resolve_port(parts[j])}"
                                        f"-{_resolve_port(parts[j + 1])}"
                                    )
                                    j += 1
                        elif parts[j] == "eq":
                            j += 1
                            if j < len(parts):
                                port_str = _resolve_port(parts[j])
                        elif parts[j] == "range":
                            j += 1
                            if j + 1 < len(parts):
                                port_str = (
                                    f"{_resolve_port(parts[j])}"
                                    f"-{_resolve_port(parts[j + 1])}"
                                )
                                j += 1
                        j += 1
                    if port_str:
                        service_refs.append({
                            "type": "inline",
                            "protocol": proto,
                            "port": port_str,
                        })
                    else:
                        # Protocol-only member (e.g. 'service-object icmp'):
                        # record it so the converter can report it instead of
                        # dropping it silently.
                        service_refs.append({
                            "type": "protocol",
                            "protocol": proto,
                        })
            elif line.startswith("group-object "):
                ref = line.split()[1] if len(line.split()) >= 2 else ""
                if ref:
                    service_refs.append({"type": "group", "name": ref})

        result["service_object_groups"][name] = {
            "protocol": protocol,
            "members": members,
            "service_refs": service_refs,
        }

    # ── Unsupported object-group types (icmp-type / protocol) ──────────
    def _parse_unsupported_group(
        self, header: str, body: List[str], result: Dict, key: str
    ) -> None:
        """Record an icmp-type / protocol object-group.

        These have no PAN-OS service equivalent; they are stored so that
        references to them can be reported instead of silently dropped.
        """
        tokens = header.split()
        name = tokens[2] if len(tokens) >= 3 else ""
        if not name:
            return
        result[key][name] = {"members": list(body)}

    # ── Static route parsing ───────────────────────────────────────────
    def _parse_route(self, line: str, result: Dict) -> None:
        """Parse: route <nameif> <dest> <mask> <gateway> [<metric>]"""
        tokens = line.split()
        if len(tokens) < 5:
            return

        route: Dict[str, Any] = {
            "interface": tokens[1],
            "destination": tokens[2],
            "netmask": tokens[3],
            "gateway": tokens[4],
            "metric": 1,
        }
        if len(tokens) >= 6:
            try:
                route["metric"] = int(tokens[5])
            except ValueError:
                pass

        result["routes"].append(route)

    # ── Access-list entry parsing ──────────────────────────────────────
    def _parse_access_list_entry(self, line: str, result: Dict) -> None:
        """Parse an extended or standard ACE line into structured data.

        Unparseable lines are recorded in result['skipped_acl_lines'] and
        reported - never dropped silently.
        """
        tokens = line.split()
        acl_name = tokens[1] if len(tokens) >= 2 else ""

        # Remarks carry no policy - ignore without warning
        if len(tokens) >= 3 and tokens[2] == "remark":
            return

        ace: Optional[Dict[str, Any]] = None
        if len(tokens) >= 5 and tokens[2] == "extended":
            ace = self._parse_ace_tokens(
                tokens[4:], tokens[3], set(result["service_object_groups"])
            )
        elif len(tokens) >= 5 and tokens[2] == "standard":
            ace = self._parse_standard_ace(tokens[3], tokens[4:])
        else:
            self._skip_acl_line(line, result, "unsupported ACL form")
            return

        if ace is None:
            self._skip_acl_line(line, result, "could not parse ACE")
            return
        if ace.get("skip_reason"):
            self._skip_acl_line(line, result, ace["skip_reason"])
            return

        if acl_name not in result["access_lists"]:
            result["access_lists"][acl_name] = []
        result["access_lists"][acl_name].append(ace)

    @staticmethod
    def _skip_acl_line(line: str, result: Dict, reason: str) -> None:
        result["skipped_acl_lines"].append({"line": line, "reason": reason})
        print(f"  WARNING: skipped ACL line ({reason}): {line}")

    def _parse_standard_ace(
        self, action: str, tokens: List[str]
    ) -> Optional[Dict[str, Any]]:
        """Parse a standard ACE (source-only match, any protocol)."""
        stream = _TokenStream(tokens)
        src = self._parse_address_spec(stream)
        if src is None:
            return None
        ace = self._new_ace(action)
        ace["protocol"] = "ip"
        ace["source"] = src
        ace["destination"] = {"type": "any"}
        if src.get("type") in ("any6", "interface"):
            ace["skip_reason"] = self._address_skip_reason(src)
        return ace

    @staticmethod
    def _new_ace(action: str) -> Dict[str, Any]:
        return {
            "action": action,
            "protocol": "",
            "protocol_ref_type": None,  # "object" or "object-group"
            "protocol_ref_name": None,
            "source": {},
            "source_port": None,
            "destination": {},
            "dest_port": None,
            "log": False,
            "inactive": False,
            "time_range": None,
        }

    @staticmethod
    def _address_skip_reason(spec: Dict[str, str]) -> str:
        if spec.get("type") == "any6":
            return "IPv6 (any6) not supported"
        return (f"'interface {spec.get('name', '')}' address "
                f"not supported")

    def _parse_ace_tokens(
        self, tokens: List[str], action: str,
        service_group_names: Set[str],
    ) -> Optional[Dict[str, Any]]:
        """Parse the token stream after 'access-list <name> extended <action>'.

        Returns a structured ACE dict or None if parsing fails. ACEs that
        parsed but cannot be converted carry a 'skip_reason' key.
        """
        ace = self._new_ace(action)

        stream = _TokenStream(tokens)

        # ── Protocol ──
        proto_token = stream.consume()
        if proto_token is None:
            return None

        if proto_token in ("object", "object-group"):
            ref_name = stream.consume()
            if ref_name is None:
                return None
            ace["protocol_ref_type"] = proto_token
            ace["protocol_ref_name"] = ref_name
            ace["protocol"] = ""
        else:
            ace["protocol"] = proto_token.lower()

        # ── Source address ──
        src = self._parse_address_spec(stream)
        if src is None:
            return None
        ace["source"] = src

        # ── Source port (only for tcp/udp with explicit protocol) ──
        has_ports = ace["protocol"] in ("tcp", "udp", "tcp-udp")
        if has_ports:
            port_spec = self._try_parse_port_spec(stream, service_group_names)
            if port_spec is not None:
                ace["source_port"] = port_spec

        # ── Destination address ──
        dst = self._parse_address_spec(stream)
        if dst is None:
            return None
        ace["destination"] = dst

        # ── Destination port (only for tcp/udp with explicit protocol) ──
        if has_ports:
            port_spec = self._try_parse_port_spec(stream, service_group_names)
            if port_spec is not None:
                ace["dest_port"] = port_spec

        # ── Trailing keywords ──
        while stream.has_more():
            tok = stream.consume()
            if tok == "log":
                ace["log"] = True
            elif tok == "inactive":
                ace["inactive"] = True
            elif tok == "time-range":
                ace["time_range"] = stream.consume() or ""

        # Unconvertible address specifiers (IPv6 / interface keyword)
        for spec in (ace["source"], ace["destination"]):
            if spec.get("type") in ("any6", "interface"):
                ace["skip_reason"] = self._address_skip_reason(spec)
                break

        return ace

    def _parse_address_spec(
        self, stream: "_TokenStream"
    ) -> Optional[Dict[str, str]]:
        """Parse an address specifier from the token stream."""
        token = stream.consume()
        if token is None:
            return None

        if token in ("any", "any4"):
            return {"type": "any"}
        elif token == "any6":
            # IPv6 - recorded so the ACE can be skipped with a warning
            return {"type": "any6"}
        elif token == "interface":
            # 'interface <nameif>' - recorded so the ACE can be skipped
            nameif = stream.consume()
            return {"type": "interface", "name": nameif or ""}
        elif token == "host":
            ip = stream.consume()
            return {"type": "host", "value": ip or ""}
        elif token == "object":
            name = stream.consume()
            return {"type": "object", "name": name or ""}
        elif token == "object-group":
            name = stream.consume()
            return {"type": "object-group", "name": name or ""}
        else:
            # Bare IP + mask
            mask = stream.consume()
            return {"type": "subnet", "value": token, "netmask": mask or ""}

    def _try_parse_port_spec(
        self, stream: "_TokenStream",
        service_group_names: Set[str],
    ) -> Optional[Dict[str, str]]:
        """Try to parse a port operator from the token stream.

        Returns None (and doesn't consume tokens) if the next token is
        not a port operator.
        """
        token = stream.peek()
        if token is None:
            return None

        if token == "eq":
            stream.consume()
            port = stream.consume()
            return {"type": "eq", "port": _resolve_port(port or "")}
        elif token == "range":
            stream.consume()
            start = stream.consume()
            end = stream.consume()
            return {
                "type": "range",
                "start": _resolve_port(start or ""),
                "end": _resolve_port(end or ""),
            }
        elif token == "gt":
            stream.consume()
            port = stream.consume()
            return {"type": "gt", "port": _resolve_port(port or "")}
        elif token == "lt":
            stream.consume()
            port = stream.consume()
            return {"type": "lt", "port": _resolve_port(port or "")}
        elif token == "neq":
            stream.consume()
            port = stream.consume()
            return {"type": "neq", "port": _resolve_port(port or "")}
        elif token == "object-group":
            # Only a SERVICE group here is a port spec; a network group in
            # this position is the destination address - don't consume it.
            name = stream.peek_at(1)
            if name is not None and name in service_group_names:
                stream.consume()
                stream.consume()
                return {"type": "object-group", "name": name}

        return None

    # ── Access-group parsing ───────────────────────────────────────────
    def _parse_access_group(self, line: str, result: Dict) -> None:
        """Parse: access-group <acl> in|out interface <nameif>
                  access-group <acl> global

        An ACL may be bound multiple times, so bindings are kept as a list.
        """
        tokens = line.split()
        if len(tokens) < 3:
            return

        acl_name = tokens[1]
        if tokens[2] == "global":
            binding = {"direction": "global", "interface": ""}
        elif len(tokens) >= 5:
            binding = {"direction": tokens[2], "interface": tokens[4]}
        else:
            return

        result["access_groups"].setdefault(acl_name, []).append(binding)

    # ── NAT rule parsing ──────────────────────────────────────────────
    def _parse_nat_rule(self, line: str, result: Dict) -> None:
        """Parse NAT rule as raw text (manual review needed for PAN-OS)."""
        result["nat_rules"].append(line.strip())


class _TokenStream:
    """Simple forward-only token stream for ACE parsing."""

    def __init__(self, tokens: List[str]) -> None:
        self._tokens = tokens
        self._pos = 0

    def peek(self) -> Optional[str]:
        if self._pos < len(self._tokens):
            return self._tokens[self._pos]
        return None

    def peek_at(self, offset: int) -> Optional[str]:
        """Peek at the token 'offset' positions ahead without consuming."""
        idx = self._pos + offset
        if idx < len(self._tokens):
            return self._tokens[idx]
        return None

    def consume(self) -> Optional[str]:
        if self._pos < len(self._tokens):
            t = self._tokens[self._pos]
            self._pos += 1
            return t
        return None

    def has_more(self) -> bool:
        return self._pos < len(self._tokens)
