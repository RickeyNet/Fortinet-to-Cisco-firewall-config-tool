"""Unit tests for the Cisco FTD → FortiGate converter (fg_ftd_converter).

Pure conversion-function tests using dict fixtures - no live device needed.
Covers code-review findings C1 (static-route reference resolution),
H1 (TRUST action), H2 (integer port values), H3 (ICMP port objects),
H4 (service literals / fail-closed) and M6 (unified literal handling).
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for _sub in ("CiscoFTDToFortiGateTool", "PaloAltoToFortiGateTool"):
    _p = str(ROOT / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

import fg_ftd_converter as conv  # noqa: E402


# ---------------------------------------------------------------------------
# C1: static routes - FDM object references, 'iface' key, null metric
# ---------------------------------------------------------------------------

def test_static_route_resolves_fdm_object_references():
    network_objects = [
        {"name": "net-10.0.0.0", "subType": "NETWORK", "value": "10.0.0.0/24"},
        {"name": "gw-192.168.1.254", "subType": "HOST", "value": "192.168.1.254"},
    ]
    routes = [{
        "name": "route1",
        "iface": {
            "name": "outside",
            "hardwareName": "GigabitEthernet0/0",
            "type": "physicalinterface",
        },
        "networks": [{"name": "net-10.0.0.0", "type": "networkobject"}],
        "gateway": {"name": "gw-192.168.1.254", "type": "networkobject"},
        "metricValue": None,
        "ipType": "IPv4",
        "type": "staticrouteentry",
    }]

    out = conv._convert_static_routes(
        routes, {"GigabitEthernet0/0": "outside"}, network_objects
    )

    assert "edit 1" in out
    assert "set dst 10.0.0.0 255.255.255.0" in out
    assert "set gateway 192.168.1.254" in out
    assert 'set device "outside"' in out
    # L2: metricValue null must default to 1, never emit 'None'
    assert "set distance 1" in out
    assert "None" not in out


def test_static_route_legacy_embedded_values_still_work():
    routes = [{
        "networks": [{"value": "172.16.0.0/16"}],
        "gateway": {"ipAddress": "10.1.1.1"},
        "interface": {"hardwareName": "GigabitEthernet0/1"},
        "metricValue": 5,
    }]
    out = conv._convert_static_routes(routes, {"GigabitEthernet0/1": "inside"}, [])
    assert "set dst 172.16.0.0 255.255.0.0" in out
    assert "set gateway 10.1.1.1" in out
    assert 'set device "inside"' in out
    assert "set distance 5" in out


def test_static_route_unresolvable_gateway_skipped_with_message(capsys):
    routes = [{
        "name": "broken",
        "iface": {"name": "outside"},
        "networks": [{"name": "some-net", "type": "networkobject"}],
        "gateway": {"name": "ghost-gw", "type": "networkobject"},
    }]
    out = conv._convert_static_routes(routes, {}, [])
    assert "edit 1" not in out
    captured = capsys.readouterr().out
    assert "could not resolve gateway" in captured.lower()


def test_static_route_gateway_named_by_ip_resolves():
    routes = [{
        "iface": {"name": "outside"},
        "networks": [{"name": "any-ipv4", "type": "networkobject"}],
        "gateway": {"name": "192.168.99.1", "type": "networkobject"},
    }]
    out = conv._convert_static_routes(routes, {}, [])
    assert "set dst 0.0.0.0 0.0.0.0" in out
    assert "set gateway 192.168.99.1" in out


# ---------------------------------------------------------------------------
# H2: _ftd_port_str must handle integer port values from JSON snapshots
# ---------------------------------------------------------------------------

def test_ftd_port_str_coerces_types():
    assert conv._ftd_port_str(80) == "80"
    assert conv._ftd_port_str("80") == "80"
    assert conv._ftd_port_str(" 80-443 ") == "80-443"
    assert conv._ftd_port_str(None) == ""
    assert conv._ftd_port_str("") == ""


def test_convert_port_objects_with_integer_ports():
    tcp = [{"name": "web", "port": 80}]
    udp = [{"name": "dns", "port": 53}]
    block, name_map, emitted = conv._convert_port_objects(tcp, udp, [], [])
    assert "set tcp-portrange 80" in block
    assert "set udp-portrange 53" in block
    assert name_map["web"] == "web"
    assert "dns" in emitted


# ---------------------------------------------------------------------------
# H1: TRUST rule action must permit (accept), not deny
# ---------------------------------------------------------------------------

def test_trust_action_maps_to_accept():
    rules = [{"name": "trusted", "ruleAction": "TRUST"}]
    policy, _, _ = conv._convert_access_rules(rules, {}, set(), set(), {})
    assert "set action accept" in policy


def test_deny_action_maps_to_deny():
    rules = [{"name": "blocked", "ruleAction": "DENY"}]
    policy, _, _ = conv._convert_access_rules(rules, {}, set(), set(), {})
    assert "set action deny" in policy


# ---------------------------------------------------------------------------
# H3: ICMP port objects become FortiGate ICMP services
# ---------------------------------------------------------------------------

def test_icmp_port_objects_convert_to_icmp_services():
    icmpv4 = [
        {"name": "ICMP_Echo_Request", "icmpv4Type": "ECHO_REQUEST",
         "type": "icmpv4portobject"},
        {"name": "ICMP_Echo_Reply", "icmpv4Type": "ECHO_REPLY",
         "type": "icmpv4portobject"},
    ]
    block, name_map, emitted = conv._convert_port_objects([], [], icmpv4, [])
    assert 'edit "ICMP_Echo_Request"' in block
    assert "set protocol ICMP" in block
    assert "set icmptype 8" in block
    assert "set icmptype 0" in block
    assert name_map["ICMP_Echo_Reply"] == "ICMP_Echo_Reply"
    assert "ICMP_Echo_Request" in emitted


def test_unsupported_icmp_type_skipped_and_excluded(capsys):
    icmpv4 = [{"name": "weird", "icmpv4Type": "NOT_A_REAL_TYPE"}]
    block, name_map, emitted = conv._convert_port_objects([], [], icmpv4, [])
    assert "weird" not in name_map
    assert "weird" not in emitted
    assert "Skipped: weird" in capsys.readouterr().out
    # The PING-style group referencing it must drop the member and be skipped
    groups = [{"name": "PING", "objects": [{"name": "weird"}]}]
    grp_block = conv._convert_port_groups(groups, name_map, emitted)
    assert 'edit "PING"' not in grp_block


def test_ping_group_round_trips():
    icmpv4 = [
        {"name": "ICMP_Echo_Request", "icmpv4Type": "ECHO_REQUEST"},
        {"name": "ICMP_Echo_Reply", "icmpv4Type": "ECHO_REPLY"},
    ]
    _, name_map, emitted = conv._convert_port_objects([], [], icmpv4, [])
    groups = [{
        "name": "PING",
        "objects": [
            {"name": "ICMP_Echo_Request", "type": "icmpv4portobject"},
            {"name": "ICMP_Echo_Reply", "type": "icmpv4portobject"},
        ],
    }]
    grp_block = conv._convert_port_groups(groups, name_map, emitted)
    assert 'edit "PING"' in grp_block
    assert 'set member "ICMP_Echo_Request" "ICMP_Echo_Reply"' in grp_block


# ---------------------------------------------------------------------------
# H4: service literals in rules; fail closed when nothing resolves
# ---------------------------------------------------------------------------

def test_service_literal_generates_inline_service():
    rules = [{
        "name": "web-literal",
        "ruleAction": "PERMIT",
        "destinationPorts": {
            "literals": [{"type": "portliteral", "protocol": "6", "port": 8080}],
        },
    }]
    policy, _, svc_block = conv._convert_access_rules(rules, {}, set(), set(), {})
    assert 'set service "inline_tcp_8080"' in policy
    assert "set status disable" not in policy
    assert 'edit "inline_tcp_8080"' in svc_block
    assert "set tcp-portrange 8080" in svc_block


def test_rule_with_only_unresolvable_services_fails_closed():
    rules = [{
        "name": "broken-svc",
        "ruleAction": "PERMIT",
        "destinationPorts": {"objects": [{"name": "ghost-svc"}]},
    }]
    policy, _, _ = conv._convert_access_rules(rules, {}, set(), set(), {})
    # Must NOT silently become an enabled service-ALL rule
    assert "set status disable" in policy
    assert "MIGRATION-REVIEW" in policy


def test_rule_with_only_unresolvable_addresses_fails_closed():
    rules = [{
        "name": "broken-addr",
        "ruleAction": "PERMIT",
        "sourceNetworks": {"objects": [{"name": "ghost-net"}]},
    }]
    policy, _, _ = conv._convert_access_rules(rules, {}, set(), set(), {})
    assert "set status disable" in policy
    assert "MIGRATION-REVIEW" in policy


def test_rule_with_empty_service_field_is_all_and_enabled():
    rules = [{"name": "open", "ruleAction": "PERMIT"}]
    policy, _, _ = conv._convert_access_rules(rules, {}, set(), set(), {})
    assert 'set service "ALL"' in policy
    assert "set status disable" not in policy


# ---------------------------------------------------------------------------
# M6: rule network literals use the same converter as group literals
# ---------------------------------------------------------------------------

def test_rule_range_literal_emits_iprange_address():
    rules = [{
        "name": "range-rule",
        "ruleAction": "PERMIT",
        "sourceNetworks": {
            "literals": [
                {"type": "networkobjectliteral", "value": "10.1.1.5-10.1.1.9"},
            ],
        },
    }]
    policy, addr_block, _ = conv._convert_access_rules(rules, {}, set(), set(), {})
    assert "set type iprange" in addr_block
    assert "set start-ip 10.1.1.5" in addr_block
    assert "set end-ip 10.1.1.9" in addr_block
    # The old bug emitted an invalid 'set subnet 10.1.1.5-10.1.1.9 <mask>'
    assert "set subnet" not in addr_block
    assert 'set srcaddr "inline_10_1_1_5_10_1_1_9"' in policy


def test_rule_and_group_literals_share_one_helper():
    inline: list = []
    known: set = set()
    name1 = conv._literal_to_inline_addr({"value": "10.0.0.0/24"}, inline, known)
    name2 = conv._literal_to_inline_addr({"value": "10.0.0.0/24"}, inline, known)
    assert name1 == name2
    assert len(inline) == 1  # deduplicated
    assert inline[0]["type"] == "subnet"
    assert inline[0]["mask"] == "255.255.255.0"


# ---------------------------------------------------------------------------
# M1/L4: merged service names must not collide with existing services
# ---------------------------------------------------------------------------

def test_merged_pair_does_not_overwrite_plain_service():
    tcp = [
        {"name": "web_TCP", "port": "80"},
        {"name": "web", "port": "8080"},
    ]
    udp = [{"name": "web_UDP", "port": "80"}]
    block, name_map, _ = conv._convert_port_objects(tcp, udp, [], [])
    assert name_map["web"] == "web"
    merged = name_map["web_TCP"]
    assert merged == name_map["web_UDP"]
    assert merged != "web"
    assert block.count('edit "web"') == 1


def test_mixed_case_suffix_pairs_merge():
    tcp = [{"name": "FOO_Tcp", "port": "10"}]
    udp = [{"name": "FOO_udp", "port": "10"}]
    _, name_map, _ = conv._convert_port_objects(tcp, udp, [], [])
    assert name_map["FOO_Tcp"] == name_map["FOO_udp"] == "FOO"


# ---------------------------------------------------------------------------
# L5: empty rule names default to rule_<n> and duplicates are deduped
# ---------------------------------------------------------------------------

def test_empty_and_duplicate_rule_names():
    rules = [
        {"name": "", "ruleAction": "PERMIT"},
        {"name": "dup", "ruleAction": "PERMIT"},
        {"name": "dup", "ruleAction": "PERMIT"},
    ]
    policy, _, _ = conv._convert_access_rules(rules, {}, set(), set(), {})
    assert 'set name ""' not in policy
    assert 'set name "rule_1"' in policy
    assert 'set name "dup"' in policy
    assert 'set name "dup_2"' in policy
