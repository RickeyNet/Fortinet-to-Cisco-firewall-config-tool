"""Unit tests for the FortiGate -> FTD policy converter (TODO P3).

Covers action mapping, zone lookup strategies, service expansion,
address group type detection, and "any"/"all" filtering. Fail-closed
and disabled-rule routing are covered in test_converter_fixes.py.
"""
from typing import Any, Dict, List, Optional

from policy_converter import PolicyConverter  # noqa: E402


def _convert(policies: List[Dict[str, Any]], **mappings):
    conv = PolicyConverter({"firewall_policy": policies}, **mappings)
    return conv, conv.convert()


def _rule(action: str = "accept", **fields) -> Dict[int, Dict[str, Any]]:
    props = {
        "name": fields.pop("name", "Rule1"),
        "srcintf": "any",
        "dstintf": "any",
        "srcaddr": "all",
        "dstaddr": "all",
        "service": "ALL",
        "action": action,
    }
    props.update(fields)
    return {1: props}


# ---------------------------------------------------------------------------
# Action mapping
# ---------------------------------------------------------------------------

def test_accept_and_allow_map_to_permit():
    for action in ("accept", "allow", "ACCEPT"):
        _, rules = _convert([_rule(action)])
        assert rules[0]["ruleAction"] == "PERMIT"


def test_deny_and_reject_map_to_deny():
    for action in ("deny", "reject", "DENY"):
        _, rules = _convert([_rule(action)])
        assert rules[0]["ruleAction"] == "DENY"


def test_unknown_action_fails_closed_to_deny():
    _, rules = _convert([_rule("mystery")])
    assert rules[0]["ruleAction"] == "DENY"


def test_missing_action_defaults_to_deny():
    policy = _rule()
    del policy[1]["action"]
    _, rules = _convert([policy])
    assert rules[0]["ruleAction"] == "DENY"


# ---------------------------------------------------------------------------
# "any"/"all" filtering -> empty match lists (no restriction)
# ---------------------------------------------------------------------------

def test_any_and_all_produce_unrestricted_rule():
    _, rules = _convert([_rule()])
    rule = rules[0]
    assert rule["sourceZones"] == []
    assert rule["destinationZones"] == []
    assert rule["sourceNetworks"] == []
    assert rule["destinationNetworks"] == []
    assert rule["destinationPorts"] == []


def test_any_mixed_with_specific_zone_keeps_only_specific():
    _, rules = _convert(
        [_rule(srcintf=["any", "wan1"])],
        interface_name_mapping={"wan1": "wan_primary"},
    )
    assert rules[0]["sourceZones"] == [{"name": "wan_primary", "type": "securityzone"}]


def test_rule_ids_assigned_sequentially():
    _, rules = _convert([_rule(name="A"), _rule(name="B")])
    assert [r["ruleId"] for r in rules] == [1, 2]


# ---------------------------------------------------------------------------
# Zone lookup strategies
# ---------------------------------------------------------------------------

def test_zone_direct_lookup():
    _, rules = _convert(
        [_rule(srcintf="wan1", dstintf="lan")],
        interface_name_mapping={"wan1": "wan_primary", "lan": "lan"},
    )
    assert rules[0]["sourceZones"] == [{"name": "wan_primary", "type": "securityzone"}]
    assert rules[0]["destinationZones"] == [{"name": "lan", "type": "securityzone"}]


def test_zone_lowercase_lookup():
    _, rules = _convert(
        [_rule(srcintf="WAN1")],
        interface_name_mapping={"wan1": "wan_primary"},
    )
    assert rules[0]["sourceZones"] == [{"name": "wan_primary", "type": "securityzone"}]


def test_zone_numeric_vlan_suffix_match():
    # FortiGate policies can reference a VLAN interface by its bare ID; the
    # converter matches it against FTD names ending in "_<id>".
    _, rules = _convert(
        [_rule(srcintf=551)],
        interface_name_mapping={"551_intf": "l_slap_551"},
    )
    assert rules[0]["sourceZones"] == [{"name": "l_slap_551", "type": "securityzone"}]


def test_zone_ambiguous_suffix_uses_sorted_first():
    _, rules = _convert(
        [_rule(srcintf="551")],
        interface_name_mapping={"a": "zeta_551", "b": "alpha_551"},
    )
    assert rules[0]["sourceZones"] == [{"name": "alpha_551", "type": "securityzone"}]


def test_zone_unmapped_falls_back_to_sanitized_lowercase_name():
    _, rules = _convert(
        [_rule(srcintf="Unknown Intf")],
        interface_name_mapping={"other": "other"},
    )
    assert rules[0]["sourceZones"] == [{"name": "unknown_intf", "type": "securityzone"}]


# ---------------------------------------------------------------------------
# Address handling: renames, groups, member expansion, dedup
# ---------------------------------------------------------------------------

def test_addresses_follow_collision_renames():
    _, rules = _convert(
        [_rule(srcaddr="HostA")],
        address_name_mapping={"HostA": "HostA_2"},
    )
    assert rules[0]["sourceNetworks"] == [{"name": "HostA_2", "type": "networkobject"}]


def test_address_group_reference_typed_as_group():
    _, rules = _convert(
        [_rule(dstaddr="SrvGrp")],
        address_name_mapping={"SrvGrp": "SrvGrp"},
        address_groups={"SrvGrp"},
    )
    assert rules[0]["destinationNetworks"] == [
        {"name": "SrvGrp", "type": "networkobjectgroup"}
    ]


def test_flattened_group_expands_to_individual_members():
    _, rules = _convert(
        [_rule(srcaddr="FlatGrp")],
        address_group_members={"FlatGrp": ["m1", "m2"]},
    )
    assert rules[0]["sourceNetworks"] == [
        {"name": "m1", "type": "networkobject"},
        {"name": "m2", "type": "networkobject"},
    ]


def test_duplicate_address_references_deduped():
    _, rules = _convert(
        [_rule(srcaddr=["A", "A dup"])],
        address_name_mapping={"A": "A", "A_dup": "A"},
    )
    assert rules[0]["sourceNetworks"] == [{"name": "A", "type": "networkobject"}]


def test_skipped_address_filtered_from_rule():
    _, rules = _convert(
        [_rule(srcaddr=["Gone", "Kept"])],
        address_name_mapping={"Kept": "Kept"},
        skipped_addresses={"Gone"},
    )
    assert rules[0]["sourceNetworks"] == [{"name": "Kept", "type": "networkobject"}]


def test_unmapped_address_dropped_when_mapping_supplied():
    # Fail closed: with a mapping present, references without a converted
    # object are dropped instead of emitted as dangling names.
    _, rules = _convert(
        [_rule(dstaddr=["Ghost", "Real"])],
        address_name_mapping={"Real": "Real"},
    )
    assert rules[0]["destinationNetworks"] == [{"name": "Real", "type": "networkobject"}]


# ---------------------------------------------------------------------------
# Service expansion
# ---------------------------------------------------------------------------

def test_split_service_expands_to_all_ftd_objects():
    _, rules = _convert(
        [_rule(service="DNS")],
        service_name_mapping={
            "DNS": [("DNS_TCP", "tcpportobject"), ("DNS_UDP", "udpportobject")]
        },
    )
    assert rules[0]["destinationPorts"] == [
        {"name": "DNS_TCP", "type": "tcpportobject"},
        {"name": "DNS_UDP", "type": "udpportobject"},
    ]


def test_service_group_reference_typed_as_port_group():
    _, rules = _convert(
        [_rule(service="Web Access")],
        service_groups={"Web_Access"},
    )
    assert rules[0]["destinationPorts"] == [
        {"name": "Web_Access", "type": "portobjectgroup"}
    ]


def test_service_group_follows_collision_rename():
    _, rules = _convert(
        [_rule(service="Grp")],
        service_groups={"Grp_2"},
        service_group_name_mapping={"Grp": "Grp_2"},
    )
    assert rules[0]["destinationPorts"] == [
        {"name": "Grp_2", "type": "portobjectgroup"}
    ]


def test_skipped_service_filtered_from_rule():
    _, rules = _convert(
        [_rule(service=["PING_ICMP", "Web"])],
        service_name_mapping={"Web": [("Web", "tcpportobject")]},
        skipped_services={"PING_ICMP"},
    )
    assert rules[0]["destinationPorts"] == [{"name": "Web", "type": "tcpportobject"}]


def test_unmapped_service_type_guessed_from_udp_suffix():
    _, rules = _convert([_rule(service=["FOO_UDP", "BAR"])])
    assert rules[0]["destinationPorts"] == [
        {"name": "FOO_UDP", "type": "udpportobject"},
        {"name": "BAR", "type": "tcpportobject"},
    ]


def test_duplicate_service_references_deduped():
    _, rules = _convert(
        [_rule(service=["SvcA", "SvcB"])],
        service_name_mapping={
            "SvcA": [("Shared", "tcpportobject")],
            "SvcB": [("Shared", "tcpportobject")],
        },
    )
    assert rules[0]["destinationPorts"] == [{"name": "Shared", "type": "tcpportobject"}]


# ---------------------------------------------------------------------------
# Names and statistics
# ---------------------------------------------------------------------------

def test_missing_policy_name_falls_back_to_policy_id():
    policy = _rule()
    del policy[1]["name"]
    _, rules = _convert([policy])
    assert rules[0]["name"] == "Policy_1"


def test_duplicate_policy_names_deduped():
    _, rules = _convert([_rule(name="Same"), _rule(name="Same")])
    assert [r["name"] for r in rules] == ["Same", "Same_2"]


def test_statistics_count_permit_and_deny():
    conv, _ = _convert([_rule("accept"), _rule("deny"), _rule("accept")])
    stats = conv.get_statistics()
    assert stats["total_rules"] == 3
    assert stats["permit_rules"] == 2
    assert stats["deny_rules"] == 1
