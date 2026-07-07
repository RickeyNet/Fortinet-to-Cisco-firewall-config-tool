"""Unit tests for group flattening (TODO P3): the shared helpers in
common.py plus the address and service group converters.

Covers circular reference detection, deep nesting, duplicate removal,
single-member normalization, and empty group handling.
"""
from typing import Any, Dict, List

from address_group_converter import AddressGroupConverter  # noqa: E402
from common import build_group_lookup, flatten_group_members  # noqa: E402
from service_group_converter import ServiceGroupConverter  # noqa: E402


# ---------------------------------------------------------------------------
# flatten_group_members / build_group_lookup (shared helpers)
# ---------------------------------------------------------------------------

def test_deep_nesting_flattens_to_leaf_objects():
    lookup = {
        "top": ["mid", "leaf1"],
        "mid": ["bottom", "leaf2"],
        "bottom": ["leaf3"],
    }
    assert flatten_group_members(["top"], lookup) == ["leaf3", "leaf2", "leaf1"]


def test_circular_reference_skipped_not_infinite():
    lookup = {"A": ["B"], "B": ["A", "x"]}
    assert flatten_group_members(["A"], lookup) == ["x"]


def test_self_referencing_group_skipped():
    lookup = {"A": ["A", "x"]}
    assert flatten_group_members(["A"], lookup) == ["x"]


def test_diamond_reference_is_not_flagged_as_circular():
    # Two siblings share a nested group - the shared group must expand for
    # both paths (deduped), not be treated as a cycle.
    lookup = {
        "top": ["g1", "g2"],
        "g1": ["shared"],
        "g2": ["shared", "y"],
    }
    assert flatten_group_members(["top"], lookup) == ["shared", "y"]


def test_duplicates_removed_preserving_first_occurrence_order():
    lookup = {"g": ["b", "a"]}
    assert flatten_group_members(["a", "g", "b"], lookup) == ["a", "b"]


def test_build_group_lookup_normalizes_string_member_and_sanitizes():
    entries = [
        {"My Group": {"member": "single obj"}},
        {"Other": {"member": ["a b", "c"]}},
        {"Weird": {"member": 42}},  # unexpected type -> empty list
        None,                        # malformed entry skipped
    ]
    lookup = build_group_lookup(entries)
    assert lookup == {
        "My_Group": ["single_obj"],
        "Other": ["a_b", "c"],
        "Weird": [],
    }


# ---------------------------------------------------------------------------
# AddressGroupConverter
# ---------------------------------------------------------------------------

def _addr_groups(groups: List[Dict[str, Any]], **kwargs):
    conv = AddressGroupConverter({"firewall_addrgrp": groups}, **kwargs)
    return conv, conv.convert()


def test_address_group_single_string_member_normalized():
    _, result = _addr_groups([{"G1": {"member": "obj one"}}])
    assert result == [{
        "name": "G1",
        "isSystemDefined": False,
        "objects": [{"name": "obj_one", "type": "networkobject"}],
        "type": "networkobjectgroup",
    }]


def test_address_group_nested_groups_flattened():
    _, result = _addr_groups([
        {"Inner": {"member": ["a", "b"]}},
        {"Outer": {"member": ["Inner", "c"]}},
    ])
    outer = [g for g in result if g["name"] == "Outer"][0]
    assert [m["name"] for m in outer["objects"]] == ["a", "b", "c"]


def test_address_group_duplicate_members_removed():
    _, result = _addr_groups([
        {"Inner": {"member": ["a"]}},
        {"Outer": {"member": ["Inner", "a", "b"]}},
    ])
    outer = [g for g in result if g["name"] == "Outer"][0]
    assert [m["name"] for m in outer["objects"]] == ["a", "b"]


def test_empty_address_group_skipped_and_reported():
    conv, result = _addr_groups([{"Empty": {"member": []}}])
    assert result == []
    assert len(conv.failed_items) == 1
    assert "empty group" in conv.failed_items[0]["reason"]


def test_address_group_emptied_by_filtering_is_skipped():
    conv, result = _addr_groups(
        [{"OnlySkipped": {"member": ["gone"]}}],
        address_name_mapping={"other": "other"},
        skipped_addresses={"gone"},
    )
    assert result == []
    assert len(conv.failed_items) == 1


def test_address_group_unexpected_member_type_yields_empty_group_skip():
    conv, result = _addr_groups([{"Bad": {"member": 42}}])
    assert result == []
    assert len(conv.failed_items) == 1


def test_circular_address_groups_convert_without_hanging():
    _, result = _addr_groups([
        {"A": {"member": ["B", "a1"]}},
        {"B": {"member": ["A", "b1"]}},
    ])
    by_name = {g["name"]: sorted(m["name"] for m in g["objects"]) for g in result}
    # Each group expands the other one level; the cycle back to itself is cut.
    assert by_name == {"A": ["a1", "b1"], "B": ["a1", "b1"]}


# ---------------------------------------------------------------------------
# ServiceGroupConverter
# ---------------------------------------------------------------------------

def _svc_groups(groups: List[Dict[str, Any]], **kwargs):
    conv = ServiceGroupConverter({"firewall_service_group": groups}, **kwargs)
    return conv, conv.convert()


def test_service_group_single_string_member_normalized():
    _, result = _svc_groups([{"G1": {"member": "svc one"}}])
    assert result[0]["objects"] == [{"name": "svc_one", "type": "tcpportobject"}]
    assert result[0]["type"] == "portobjectgroup"


def test_service_group_expands_split_members():
    _, result = _svc_groups(
        [{"Web": {"member": ["DNS", "HTTP"]}}],
        service_name_mapping={
            "DNS": [("DNS_TCP", "tcpportobject"), ("DNS_UDP", "udpportobject")],
            "HTTP": [("HTTP_Custom", "tcpportobject")],
        },
    )
    assert result[0]["objects"] == [
        {"name": "DNS_TCP", "type": "tcpportobject"},
        {"name": "DNS_UDP", "type": "udpportobject"},
        {"name": "HTTP_Custom", "type": "tcpportobject"},
    ]


def test_service_group_nested_groups_flattened_before_expansion():
    _, result = _svc_groups(
        [
            {"Inner": {"member": ["SvcA"]}},
            {"Outer": {"member": ["Inner", "SvcB"]}},
        ],
        service_name_mapping={
            "SvcA": [("SvcA", "tcpportobject")],
            "SvcB": [("SvcB", "udpportobject")],
        },
    )
    outer = [g for g in result if g["name"] == "Outer"][0]
    assert [m["name"] for m in outer["objects"]] == ["SvcA", "SvcB"]


def test_service_group_filters_skipped_members():
    _, result = _svc_groups(
        [{"Mixed": {"member": ["PING_ICMP", "Web"]}}],
        service_name_mapping={"Web": [("Web", "tcpportobject")]},
        skipped_services={"PING_ICMP"},
    )
    assert result[0]["objects"] == [{"name": "Web", "type": "tcpportobject"}]


def test_service_group_emptied_by_filtering_is_skipped():
    conv, result = _svc_groups(
        [{"OnlyICMP": {"member": ["ping"]}}],
        skipped_services={"ping"},
    )
    assert result == []
    assert len(conv.failed_items) == 1
    assert "empty group" in conv.failed_items[0]["reason"]


def test_service_group_unmapped_member_type_guessed_from_name():
    _, result = _svc_groups([{"G": {"member": ["Custom_UDP", "Custom"]}}])
    assert result[0]["objects"] == [
        {"name": "Custom_UDP", "type": "udpportobject"},
        {"name": "Custom", "type": "tcpportobject"},
    ]


def test_group_name_collision_renames_tracked_in_mapping():
    conv, result = _svc_groups([
        {"Grp One": {"member": ["a"]}},
        {"Grp@One": {"member": ["b"]}},
    ])
    assert [g["name"] for g in result] == ["Grp_One", "Grp_One_2"]
    assert conv.get_group_name_mapping()["Grp_One"] == "Grp_One"
