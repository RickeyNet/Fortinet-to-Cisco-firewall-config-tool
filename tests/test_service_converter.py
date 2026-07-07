"""Unit tests for the FortiGate -> FTD service converter (TODO P3).

Covers TCP/UDP splitting, multi-port expansion, ICMP skipping, FTD
built-in name collisions, colon-separated (source-restricted) port
parsing, and the name mapping consumed by group/policy converters.
"""
from typing import Any, Dict, List

from service_converter import ServiceConverter  # noqa: E402


def _convert(services: List[Dict[str, Any]]):
    conv = ServiceConverter({"firewall_service_custom": services})
    return conv, conv.convert()


# ---------------------------------------------------------------------------
# Basic conversion and TCP/UDP splitting
# ---------------------------------------------------------------------------

def test_single_tcp_port_keeps_base_name():
    conv, result = _convert([{"Web8080": {"tcp-portrange": 8080}}])
    assert result == [{
        "name": "Web8080",
        "isSystemDefined": False,
        "port": "8080",
        "type": "tcpportobject",
    }]
    assert conv.get_service_name_mapping()["Web8080"] == [("Web8080", "tcpportobject")]


def test_single_udp_port_keeps_base_name():
    _, result = _convert([{"MyUDP": {"udp-portrange": "5000"}}])
    assert result == [{
        "name": "MyUDP",
        "isSystemDefined": False,
        "port": "5000",
        "type": "udpportobject",
    }]


def test_tcp_and_udp_split_into_suffixed_objects():
    conv, result = _convert([{"NameSvc": {"tcp-portrange": 53, "udp-portrange": 53}}])
    assert [(o["name"], o["type"]) for o in result] == [
        ("NameSvc_TCP", "tcpportobject"),
        ("NameSvc_UDP", "udpportobject"),
    ]
    stats = conv.get_statistics()
    assert stats["split_services"] == 1
    assert stats["tcp_objects"] == 1
    assert stats["udp_objects"] == 1
    # Mapping lets groups/policies expand the original name to both halves.
    assert conv.get_service_name_mapping()["NameSvc"] == [
        ("NameSvc_TCP", "tcpportobject"),
        ("NameSvc_UDP", "udpportobject"),
    ]


def test_port_range_preserved_as_string():
    _, result = _convert([{"RangeSvc": {"tcp-portrange": "8300-8301"}}])
    assert result[0]["port"] == "8300-8301"


# ---------------------------------------------------------------------------
# Multi-port expansion
# ---------------------------------------------------------------------------

def test_multiple_tcp_ports_expand_to_numbered_objects():
    conv, result = _convert([{"Cluster": {"tcp-portrange": [80, 443, "8000-8080"]}}])
    assert [(o["name"], o["port"]) for o in result] == [
        ("Cluster_TCP_1", "80"),
        ("Cluster_TCP_2", "443"),
        ("Cluster_TCP_3", "8000-8080"),
    ]
    assert conv.get_statistics()["multi_port_services"] == 1


def test_multiple_tcp_with_single_udp_uses_mixed_suffixes():
    _, result = _convert([{
        "Mix": {"tcp-portrange": [80, 443], "udp-portrange": 500}
    }])
    assert [o["name"] for o in result] == ["Mix_TCP_1", "Mix_TCP_2", "Mix_UDP"]


# ---------------------------------------------------------------------------
# FTD built-in name collisions
# ---------------------------------------------------------------------------

def test_builtin_name_collision_gets_custom_suffix():
    _, result = _convert([{"HTTP": {"tcp-portrange": 80}}])
    assert result[0]["name"] == "HTTP_Custom"


def test_builtin_collision_mapping_points_at_renamed_object():
    conv, _ = _convert([{"SSH": {"tcp-portrange": 22}}])
    assert conv.get_service_name_mapping()["SSH"] == [("SSH_Custom", "tcpportobject")]


def test_non_builtin_name_not_renamed():
    _, result = _convert([{"HTTP_ALT": {"tcp-portrange": 8080}}])
    assert result[0]["name"] == "HTTP_ALT"


# ---------------------------------------------------------------------------
# ICMP / non-port protocol skipping
# ---------------------------------------------------------------------------

def test_non_ping_icmp_service_skipped():
    conv, result = _convert([{
        "DestUnreach": {"protocol": "ICMP", "icmptype": 3}
    }])
    assert result == []
    assert "DestUnreach" in conv.get_skipped_services()
    assert conv.get_statistics()["icmp_skipped"] == 1
    assert len(conv.failed_items) == 1


def test_ip_protocol_service_skipped():
    conv, result = _convert([{"MyGRE": {"protocol": "IP", "protocol-number": 47}}])
    assert result == []
    assert "MyGRE" in conv.get_skipped_services()


def test_icmpv6_protocol_number_skipped():
    conv, result = _convert([{"Ping6": {"protocol-number": 58}}])
    assert result == []
    assert "Ping6" in conv.get_skipped_services()


def test_icmptype_field_alone_causes_skip():
    conv, result = _convert([{"OddICMP": {"icmptype": 11}}])
    assert result == []
    assert "OddICMP" in conv.get_skipped_services()


def test_service_with_no_ports_skipped():
    conv, result = _convert([{"NoPorts": {"category": "General"}}])
    assert result == []
    assert conv.get_statistics()["skipped_services"] == 1
    assert "NoPorts" in conv.get_skipped_services()


def test_factory_default_service_ignored_without_failure_report():
    conv, result = _convert([
        {"ALL": {"protocol": "IP"}},
        {"GRE": {"protocol": "IP", "protocol-number": 47}},
        {"Keep": {"tcp-portrange": 1234}},
    ])
    assert [o["name"] for o in result] == ["Keep"]
    # Registered as skipped so group references are cleaned up...
    assert {"ALL", "GRE"} <= conv.get_skipped_services()
    # ...but not reported as failures.
    assert conv.failed_items == []


# ---------------------------------------------------------------------------
# Colon-separated (destination:source) port parsing
# ---------------------------------------------------------------------------

def test_colon_portrange_keeps_destination_and_reports_dropped_source():
    conv, result = _convert([{"SrcRestricted": {"tcp-portrange": "443:1024-65535"}}])
    assert result[0]["port"] == "443"
    assert len(conv.failed_items) == 1
    reason = conv.failed_items[0]["reason"]
    assert "source-port restriction" in reason
    assert "443" in reason and "1024-65535" in reason


def test_colon_portrange_inside_list_items():
    _, result = _convert([{
        "Multi": {"tcp-portrange": ["80:1024-65535", "8443"]}
    }])
    assert [o["port"] for o in result] == ["80", "8443"]


# ---------------------------------------------------------------------------
# Name handling
# ---------------------------------------------------------------------------

def test_service_names_sanitized():
    _, result = _convert([{"My Service (v2)": {"tcp-portrange": 9000}}])
    assert result[0]["name"] == "My_Service_v2"


def test_colliding_service_names_deduped_with_mapping_for_both():
    conv, result = _convert([
        {"Svc One": {"tcp-portrange": 1000}},
        {"Svc@One": {"tcp-portrange": 2000}},
    ])
    assert [o["name"] for o in result] == ["Svc_One", "Svc_One_2"]
    mapping = conv.get_service_name_mapping()
    # First occurrence owns the base name; the rename is tracked separately.
    assert mapping["Svc_One"] == [("Svc_One", "tcpportobject")]
    assert mapping["Svc_One_2"] == [("Svc_One_2", "tcpportobject")]


def test_malformed_entries_do_not_crash():
    _, result = _convert([None, {}, {"X": "not-a-dict"}, {"OK": {"tcp-portrange": 80}}])
    assert [o["name"] for o in result] == ["OK"]


def test_statistics_totals_are_consistent():
    conv, result = _convert([
        {"A": {"tcp-portrange": [1, 2]}},           # 2 TCP
        {"B": {"udp-portrange": 3}},                # 1 UDP
        {"C": {"tcp-portrange": 4, "udp-portrange": 5}},  # split
        {"D": {"protocol": "ICMP", "icmptype": 3}},  # skipped
    ])
    stats = conv.get_statistics()
    assert stats["total_objects"] == len(result) == 5
    assert stats["tcp_objects"] == 3
    assert stats["udp_objects"] == 2
    assert stats["split_services"] == 1
    assert stats["multi_port_services"] == 2  # A (2 ports) and C (TCP+UDP)
    assert stats["icmp_skipped"] == 1
