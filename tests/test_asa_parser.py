"""Tests for the Cisco ASA -> PAN-OS parser and converter.

Covers the code-review findings: C1 (dest object-group vs port spec),
C2 (inline subnet /32 double-suffix), C3 (object-NAT re-declaration),
H1 (inactive ACEs), H2 (ICMP / portless / unknown-protocol handling),
H3 (tcp-udp service group split), H4 (neq port inversion), H5 (interface
shutdown default), H6 (standard / unparseable ACL lines), plus assorted
M/L findings.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _sub in ("CiscoASAToPaloAltoTool", "FortiGateToPaloAltoTool"):
    _p = str(ROOT / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from asa_parser import ASAParser, ASA_PORT_NAMES  # noqa: E402
import asa_converter  # noqa: E402


def parse(text):
    return ASAParser().parse(text)


def convert(text):
    """Run the same conversion pipeline as asa_converter.main()."""
    parsed = parse(text)
    inline_hosts, inline_services, warnings = {}, {}, []
    interfaces, zones, intf_map, zone_map = asa_converter.convert_interfaces(
        parsed, "pa-440"
    )
    addr_objs, addr_map, addr_used = asa_converter.convert_address_objects(
        parsed
    )
    svc_objs, svc_map, svc_used = asa_converter.convert_service_objects(
        parsed, warnings
    )
    addr_groups = asa_converter.convert_address_groups(
        parsed, inline_hosts, addr_map, addr_used, warnings
    )
    svc_groups = asa_converter.convert_service_groups(
        parsed, inline_services, svc_map, svc_used, warnings
    )
    rules = asa_converter.convert_security_rules(
        parsed, zone_map, inline_hosts, inline_services,
        addr_map, svc_map, warnings
    )
    asa_converter.append_inline_address_objects(
        addr_objs, inline_hosts, addr_used
    )
    asa_converter.append_inline_service_objects(
        svc_objs, inline_services, svc_used
    )
    return {
        "parsed": parsed,
        "interfaces": interfaces,
        "zones": zones,
        "address_objects": addr_objs,
        "address_groups": addr_groups,
        "service_objects": svc_objs,
        "service_groups": svc_groups,
        "rules": rules,
        "warnings": warnings,
    }


def svc_by_name(out, name):
    return {s["name"]: s for s in out["service_objects"]}[name]


# ── C1: destination object-group must not be eaten as a port spec ──────


def test_c1_dest_network_group_not_consumed_as_ports():
    cfg = """
object-group network WEB_SERVERS
 network-object host 10.1.1.10
access-list ACL1 extended permit tcp any object-group WEB_SERVERS
"""
    parsed = parse(cfg)
    aces = parsed["access_lists"]["ACL1"]
    assert len(aces) == 1
    ace = aces[0]
    assert ace["source"] == {"type": "any"}
    assert ace["destination"] == {"type": "object-group",
                                  "name": "WEB_SERVERS"}
    assert ace["source_port"] is None
    assert ace["dest_port"] is None


def test_c1_dest_network_group_with_port():
    cfg = """
object-group network WEB_SERVERS
 network-object host 10.1.1.10
access-list ACL1 extended permit tcp any object-group WEB_SERVERS eq 443
"""
    ace = parse(cfg)["access_lists"]["ACL1"][0]
    assert ace["destination"]["name"] == "WEB_SERVERS"
    assert ace["dest_port"] == {"type": "eq", "port": "443"}
    assert ace["source_port"] is None


def test_c1_src_and_dst_network_groups_with_port():
    cfg = """
object-group network SRC
 network-object host 10.1.1.1
object-group network DST
 network-object host 10.2.2.2
access-list ACL1 extended permit tcp object-group SRC object-group DST eq 80
"""
    ace = parse(cfg)["access_lists"]["ACL1"][0]
    assert ace["source"] == {"type": "object-group", "name": "SRC"}
    assert ace["destination"] == {"type": "object-group", "name": "DST"}
    assert ace["dest_port"] == {"type": "eq", "port": "80"}


def test_c1_service_group_still_parsed_as_port_spec():
    cfg = """
object-group service WEB_PORTS tcp
 port-object eq 80
 port-object eq 443
access-list ACL1 extended permit tcp any host 10.1.1.1 object-group WEB_PORTS
"""
    ace = parse(cfg)["access_lists"]["ACL1"][0]
    assert ace["destination"] == {"type": "host", "value": "10.1.1.1"}
    assert ace["dest_port"] == {"type": "object-group", "name": "WEB_PORTS"}


# ── C2: inline subnet objects must not get a second suffix ─────────────


def test_c2_inline_subnet_no_double_suffix():
    cfg = """
object-group network NETS
 network-object 10.0.0.0 255.255.255.0
 network-object host 10.9.9.9
access-list ACL1 extended permit ip 172.16.0.0 255.255.0.0 any
"""
    out = convert(cfg)
    values = {o["name"]: o["value"] for o in out["address_objects"]}
    assert values["net_10_0_0_0_24"] == "10.0.0.0/24"
    assert values["host_10_9_9_9"] == "10.9.9.9/32"
    assert values["net_172_16_0_0_16"] == "172.16.0.0/16"
    assert not any("/32/32" in v or v.count("/") > 1 for v in values.values())


# ── C3: object-NAT re-declaration must not wipe the address object ─────


def test_c3_object_nat_redeclaration_merges():
    cfg = """
object network OBJ_WEB
 host 192.168.1.10
object network OBJ_WEB
 nat (inside,outside) static 203.0.113.10
"""
    parsed = parse(cfg)
    obj = parsed["network_objects"]["OBJ_WEB"]
    assert obj["type"] == "host"
    assert obj["value"] == "192.168.1.10"
    # NAT line lands in the manual-review NAT list
    assert any("OBJ_WEB" in r and "nat (inside,outside)" in r
               for r in parsed["nat_rules"])


# ── H1: inactive ACEs convert disabled; time-range recorded ────────────


def test_h1_inactive_ace_disabled():
    cfg = """
access-list ACL1 extended permit tcp any any eq 80 inactive
access-list ACL1 extended permit tcp any any eq 443
"""
    out = convert(cfg)
    rules = {r["name"]: r for r in out["rules"]}
    assert rules["ACL1_rule_1"]["disabled"] == "yes"
    assert "inactive" in rules["ACL1_rule_1"]["description"]
    assert rules["ACL1_rule_2"]["disabled"] == "no"


def test_h1_time_range_recorded():
    cfg = "access-list ACL1 extended permit tcp any any eq 80 time-range WORK\n"
    parsed = parse(cfg)
    ace = parsed["access_lists"]["ACL1"][0]
    assert ace["time_range"] == "WORK"
    out = convert(cfg)
    assert "WORK" in out["rules"][0]["description"]
    assert any("time-range" in w for w in out["warnings"])


# ── H2: ICMP / portless tcp / unknown protocols ────────────────────────


def test_h2_icmp_uses_applications():
    cfg = "access-list ACL1 extended permit icmp any any\n"
    rule = convert(cfg)["rules"][0]
    assert rule["application"] == ["icmp", "ping"]
    assert rule["services"] == ["application-default"]
    assert rule["disabled"] == "no"


def test_h2_portless_tcp_kept_with_note():
    cfg = "access-list ACL1 extended permit tcp any any\n"
    out = convert(cfg)
    rule = out["rules"][0]
    assert rule["services"] == ["any"]
    assert rule["disabled"] == "no"  # documented trade-off: not disabled
    assert "review" in rule["description"]
    assert any("tcp" in w for w in out["warnings"])


def test_h2_unknown_protocol_fails_closed():
    cfg = "access-list ACL1 extended permit gre any any\n"
    rule = convert(cfg)["rules"][0]
    assert rule["disabled"] == "yes"
    assert "gre" in rule["description"]


def test_h2_permit_ip_any_any_unchanged():
    cfg = "access-list ACL1 extended permit ip any any\n"
    rule = convert(cfg)["rules"][0]
    assert rule["services"] == ["any"]
    assert rule["application"] == ["any"]
    assert rule["disabled"] == "no"


# ── H3: tcp-udp service groups split into tcp + udp services ───────────


def test_h3_tcp_udp_group_split():
    cfg = """
object-group service DNS_SVCS tcp-udp
 port-object eq 53
"""
    out = convert(cfg)
    grp = out["service_groups"][0]
    assert set(grp["members"]) == {"tcp_53", "udp_53"}
    assert svc_by_name(out, "tcp_53")["protocol"] == "tcp"
    assert svc_by_name(out, "udp_53")["protocol"] == "udp"
    assert not any(s["protocol"] == "tcp-udp"
                   for s in out["service_objects"])


def test_h3_inline_tcp_udp_member_split():
    cfg = """
object-group service MIXED
 service-object tcp-udp destination eq 88
"""
    out = convert(cfg)
    grp = out["service_groups"][0]
    assert set(grp["members"]) == {"tcp_88", "udp_88"}


# ── H4: neq expressed as two ranges, with boundary handling ────────────


def test_h4_neq_two_ranges():
    cfg = "access-list ACL1 extended permit tcp any any neq 80\n"
    out = convert(cfg)
    rule = out["rules"][0]
    assert rule["disabled"] == "no"
    svc = svc_by_name(out, rule["services"][0])
    assert svc["port"] == "0-79,81-65535"


def test_h4_neq_boundaries():
    assert asa_converter._resolve_port_spec(
        {"type": "neq", "port": "0"}, "tcp", {}, {}
    ) is not None
    inline = {}
    asa_converter._resolve_port_spec(
        {"type": "neq", "port": "0"}, "tcp", inline, {}
    )
    assert inline["tcp_neq_0"]["port"] == "1-65535"
    inline = {}
    asa_converter._resolve_port_spec(
        {"type": "neq", "port": "65535"}, "udp", inline, {}
    )
    assert inline["udp_neq_65535"]["port"] == "0-65534"


# ── H5: interfaces enabled unless explicit shutdown ────────────────────


def test_h5_shutdown_default():
    cfg = """
interface GigabitEthernet1/1
 nameif outside
 security-level 0
 ip address 1.1.1.1 255.255.255.0
interface GigabitEthernet1/2
 shutdown
 nameif inside
 security-level 100
 ip address 10.0.0.1 255.255.255.0
"""
    parsed = parse(cfg)
    assert parsed["interfaces"][0]["shutdown"] is False
    assert parsed["interfaces"][1]["shutdown"] is True
    out = convert(cfg)
    enabled = {i["name"]: i["enabled"] for i in out["interfaces"]}
    assert enabled["ethernet1/1"] is True
    assert enabled["ethernet1/2"] is False


# ── H6: standard ACLs parsed; unparseable lines counted ────────────────


def test_h6_standard_acl_parsed():
    cfg = "access-list STD1 standard permit 10.0.0.0 255.0.0.0\n"
    parsed = parse(cfg)
    ace = parsed["access_lists"]["STD1"][0]
    assert ace["protocol"] == "ip"
    assert ace["source"] == {"type": "subnet", "value": "10.0.0.0",
                             "netmask": "255.0.0.0"}
    assert ace["destination"] == {"type": "any"}
    assert parsed["skipped_acl_lines"] == []


def test_h6_unparseable_lines_recorded(capsys):
    cfg = """
access-list ACL1 remark this is a remark
access-list ETHER ethertype permit ipx
"""
    parsed = parse(cfg)
    assert len(parsed["skipped_acl_lines"]) == 1
    assert "ethertype" in parsed["skipped_acl_lines"][0]["line"]
    assert "WARNING" in capsys.readouterr().out


# ── M-level findings ───────────────────────────────────────────────────


def test_m1_management_zone_emitted():
    cfg = """
interface Management1/1
 management-only
 nameif management
 security-level 100
 ip address 192.168.100.1 255.255.255.0
"""
    out = convert(cfg)
    zones = {z["name"]: z["interfaces"] for z in out["zones"]}
    assert zones["management"] == []


def test_m2_dedup_respects_63_char_limit():
    used = set()
    long_name = "x" * 63
    first = asa_converter._dedup_name(long_name, used)
    second = asa_converter._dedup_name(long_name, used)
    assert first == long_name
    assert second != first
    assert len(second) <= 63


def test_m2_renames_propagate_to_rules():
    # Two ASA object names that sanitize to the same PAN-OS name
    # ('SRV/A' sanitizes to 'SRV_A', clashing with the real 'SRV_A')
    cfg = """
object network SRV/A
 host 10.1.1.1
object network SRV_A
 host 10.2.2.2
access-list ACL1 extended permit ip object SRV_A any
"""
    out = convert(cfg)
    names = [o["name"] for o in out["address_objects"]]
    assert "SRV_A" in names and "SRV_A_2" in names
    assert out["rules"][0]["sources"] == ["SRV_A_2"]


def test_m3_unsupported_group_types_not_dangling():
    cfg = """
object-group icmp-type ICMP_TYPES
 icmp-object echo
object-group service MIXED
 service-object object NOSUCH
 group-object ICMP_TYPES
 service-object tcp destination eq 22
 service-object icmp
"""
    out = convert(cfg)
    grp = out["service_groups"][0]
    assert grp["members"] == ["tcp_22"]
    assert any("ICMP_TYPES" in w for w in out["warnings"])
    assert any("NOSUCH" in w for w in out["warnings"])
    assert any("protocol-only" in w for w in out["warnings"])


def test_m3_protocol_group_in_ace_fails_closed():
    cfg = """
object-group protocol PROTOS
 protocol-object tcp
access-list ACL1 extended permit object-group PROTOS any any
"""
    rule = convert(cfg)["rules"][0]
    assert rule["disabled"] == "yes"
    assert "PROTOS" in rule["description"]


def test_m5_multiple_bindings_and_out_direction():
    cfg = """
interface GigabitEthernet1/1
 nameif outside
 ip address 1.1.1.1 255.255.255.0
interface GigabitEthernet1/2
 nameif inside
 ip address 10.0.0.1 255.255.255.0
access-list ACL1 extended permit ip any any
access-group ACL1 in interface outside
access-group ACL1 out interface inside
access-group ACL1 global
"""
    parsed = parse(cfg)
    assert len(parsed["access_groups"]["ACL1"]) == 3
    out = convert(cfg)
    rules = {r["name"]: r for r in out["rules"]}
    assert rules["ACL1_rule_1"]["from_zones"] == ["outside"]
    assert rules["ACL1_rule_1"]["to_zones"] == ["any"]
    # 'out' binding swaps to the egress zone
    assert rules["ACL1_rule_1_out"]["from_zones"] == ["any"]
    assert rules["ACL1_rule_1_out"]["to_zones"] == ["inside"]
    assert rules["ACL1_rule_1_global"]["from_zones"] == ["any"]
    assert "global" in rules["ACL1_rule_1_global"]["description"]


def test_m6_source_port_noted():
    cfg = "access-list ACL1 extended permit tcp any eq 1024 any eq 80\n"
    out = convert(cfg)
    ace = out["parsed"]["access_lists"]["ACL1"][0]
    assert ace["source_port"] == {"type": "eq", "port": "1024"}
    rule = out["rules"][0]
    assert "source-port" in rule["description"]
    assert any("source-port" in w for w in out["warnings"])
    # destination port still enforced
    assert rule["services"] == ["tcp_80"]


def test_m7_any6_and_interface_skipped():
    cfg = """
access-list ACL1 extended permit tcp any6 any eq 80
access-list ACL1 extended permit ip any interface outside
access-list ACL1 extended permit ip any any
"""
    parsed = parse(cfg)
    assert len(parsed["access_lists"]["ACL1"]) == 1
    reasons = [e["reason"] for e in parsed["skipped_acl_lines"]]
    assert any("IPv6" in r for r in reasons)
    assert any("interface" in r for r in reasons)


# ── L-level findings ───────────────────────────────────────────────────


def test_l1_gt_lt_boundaries():
    inline = {}
    asa_converter._resolve_port_spec(
        {"type": "lt", "port": "1"}, "tcp", inline, {}
    )
    assert inline["tcp_lt_1"]["port"] == "0"
    inline = {}
    asa_converter._resolve_port_spec(
        {"type": "lt", "port": "100"}, "tcp", inline, {}
    )
    assert inline["tcp_lt_100"]["port"] == "0-99"
    inline = {}
    asa_converter._resolve_port_spec(
        {"type": "gt", "port": "100"}, "tcp", inline, {}
    )
    assert inline["tcp_gt_100"]["port"] == "101-65535"
    # inexpressible boundaries fail closed (None -> disabled rule)
    assert asa_converter._resolve_port_spec(
        {"type": "gt", "port": "65535"}, "tcp", {}, {}
    ) is None
    assert asa_converter._resolve_port_spec(
        {"type": "lt", "port": "0"}, "tcp", {}, {}
    ) is None


def test_l2_asa_port_literals():
    assert ASA_PORT_NAMES["kerberos"] == "750"
    assert ASA_PORT_NAMES["sqlnet"] == "1522"
    assert ASA_PORT_NAMES["radius"] == "1645"
    assert ASA_PORT_NAMES["radius-acct"] == "1646"


def test_l4_log_keyword_wired():
    cfg = """
access-list ACL1 extended permit tcp any any eq 80 log
access-list ACL1 extended permit tcp any any eq 443
access-list ACL1 extended deny ip any any
"""
    out = convert(cfg)
    rules = {r["name"]: r for r in out["rules"]}
    assert rules["ACL1_rule_1"]["log_end"] == "yes"
    assert rules["ACL1_rule_2"]["log_end"] == "no"
    # ASA logs denies by default
    assert rules["ACL1_rule_3"]["log_end"] == "yes"


def test_l4_source_only_service_object_fails_closed():
    cfg = """
object service SVC_SRC
 service tcp source eq 123
access-list ACL1 extended permit object SVC_SRC any any
"""
    out = convert(cfg)
    assert out["service_objects"] == []
    assert any("source-port" in w for w in out["warnings"])
    # Rule referencing the skipped service fails closed
    assert out["rules"][0]["disabled"] == "yes"
