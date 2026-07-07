"""Tests for the PaloAltoToFortiGateTool converter modules.

Covers the code-review fixes: schedule emission (C1), vsys selection (H1),
zone sanitization (H2), app-id fail-closed handling (H3), physical
interface guidance + VLAN ordering (H4/H5), plus the supporting
medium/low fixes (dedup limits, escaping, source ports, merged pairs,
shared-object merging, fail-closed reference filtering).
"""
import sys
from pathlib import Path
from typing import Any, Dict

import pytest

# Path setup is also handled in tests/conftest.py for other tool dirs; the
# PaloAltoToFortiGateTool modules are added here so this file is
# self-contained when run directly.
ROOT = Path(__file__).resolve().parents[1]
_PA_FG_DIR = str(ROOT / "PaloAltoToFortiGateTool")
if _PA_FG_DIR not in sys.path:
    sys.path.insert(0, _PA_FG_DIR)

from fg_common import (  # noqa: E402
    dedup_fg_name,
    escape_fg_string,
    topo_sort_groups,
)
from fg_pa_parser import parse_panos_xml  # noqa: E402
from fg_address_group_converter import FGAddressGroupConverter  # noqa: E402
from fg_interface_converter import FGInterfaceConverter  # noqa: E402
from fg_policy_converter import FGPolicyConverter  # noqa: E402
from fg_route_converter import FGRouteConverter  # noqa: E402
from fg_service_converter import (  # noqa: E402
    FGServiceConverter,
    collapse_merged_pairs,
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def _rule(**overrides: Any) -> Dict[str, Any]:
    base: Dict[str, Any] = {
        "name": "rule1",
        "from_zones": ["trust"],
        "to_zones": ["untrust"],
        "sources": ["any"],
        "destinations": ["any"],
        "services": ["any"],
        "applications": ["any"],
        "action": "allow",
        "description": "",
        "disabled": False,
        "log_end": True,
    }
    base.update(overrides)
    return base


def _write_xml(tmp_path, body: str) -> str:
    xml_file = tmp_path / "panos.xml"
    xml_file.write_text(f"<config>{body}</config>", encoding="utf-8")
    return str(xml_file)


_VSYS_XML = """
<devices><entry name="localhost.localdomain"><vsys>
  <entry name="vsys1"><address>
    <entry name="a1"><ip-netmask>10.0.0.1/32</ip-netmask></entry>
  </address></entry>
  <entry name="vsys2"><address>
    <entry name="a2"><ip-netmask>10.0.0.2/32</ip-netmask></entry>
  </address></entry>
</vsys></entry></devices>
"""


# --------------------------------------------------------------------------
# C1: policies must include set schedule "always"
# --------------------------------------------------------------------------

def test_policy_includes_schedule_always() -> None:
    out = FGPolicyConverter({"security_rules": [_rule()]}, {}).convert()
    assert 'set schedule "always"' in out


def test_disabled_pa_rule_emits_status_disable() -> None:
    out = FGPolicyConverter({"security_rules": [_rule(disabled=True)]}, {}).convert()
    assert "set status disable" in out


# --------------------------------------------------------------------------
# H1: --vsys selection
# --------------------------------------------------------------------------

def test_parse_selects_named_vsys(tmp_path) -> None:
    xml_file = _write_xml(tmp_path, _VSYS_XML)
    result = parse_panos_xml(xml_file, vsys_name="vsys2")
    assert [a["name"] for a in result["addresses"]] == ["a2"]


def test_parse_defaults_to_vsys1(tmp_path) -> None:
    xml_file = _write_xml(tmp_path, _VSYS_XML)
    result = parse_panos_xml(xml_file)
    assert [a["name"] for a in result["addresses"]] == ["a1"]


def test_parse_unknown_vsys_raises(tmp_path) -> None:
    xml_file = _write_xml(tmp_path, _VSYS_XML)
    with pytest.raises(ValueError, match="vsys9"):
        parse_panos_xml(xml_file, vsys_name="vsys9")


# --------------------------------------------------------------------------
# H2: zone names sanitized consistently between policies and zones
# --------------------------------------------------------------------------

def test_policy_zone_names_sanitized() -> None:
    rule = _rule(from_zones=['DM"Z'], to_zones=["any"])
    out = FGPolicyConverter({"security_rules": [rule]}, {}).convert()
    assert 'set srcintf "DM_Z"' in out
    assert 'set dstintf "any"' in out
    # matches how the zone converter sanitizes the same name
    zone_out = FGInterfaceConverter(
        {"zones": [{"name": 'DM"Z', "interfaces": []}]}
    ).convert_zones()
    assert 'edit "DM_Z"' in zone_out


# --------------------------------------------------------------------------
# H3: PA app-id restrictions
# --------------------------------------------------------------------------

def test_app_restriction_with_service_any_fails_closed() -> None:
    conv = FGPolicyConverter(
        {"security_rules": [_rule(applications=["ssl", "web-browsing"])]}, {}
    )
    out = conv.convert()
    assert "set status disable" in out
    assert "ssl" in out  # apps listed in the comment
    assert conv.failed_items
    assert conv.get_statistics()["fail_closed"] == 1


def test_app_restriction_with_specific_service_warns() -> None:
    conv = FGPolicyConverter(
        {"security_rules": [_rule(applications=["ssl"], services=["tcp-443"])]}, {}
    )
    out = conv.convert()
    assert "set status disable" not in out
    assert "app-id restriction dropped" in out
    assert any("ssl" in f["reason"] for f in conv.failed_items)


# --------------------------------------------------------------------------
# Fail closed: filtered services/addresses must not widen to ALL/any
# --------------------------------------------------------------------------

def test_all_services_skipped_fails_closed() -> None:
    conv = FGPolicyConverter(
        {"security_rules": [_rule(services=["svcX"])]},
        {},
        skipped_services={"svcX"},
    )
    out = conv.convert()
    assert "set status disable" in out
    assert 'set service "ALL"' in out
    assert any("services were skipped" in f["reason"] for f in conv.failed_items)


def test_all_addresses_skipped_fails_closed() -> None:
    conv = FGPolicyConverter(
        {"security_rules": [_rule(sources=["addrX"])]},
        {},
        skipped_addresses={"addrX"},
    )
    out = conv.convert()
    assert "set status disable" in out
    assert conv.get_statistics()["fail_closed"] == 1


# --------------------------------------------------------------------------
# H4 / H5: interface emission
# --------------------------------------------------------------------------

def test_physical_interface_emitted_as_commented_guidance() -> None:
    conv = FGInterfaceConverter({
        "interfaces": [
            {"name": "ethernet1/1", "type": "physical", "ip": "10.0.0.1/24",
             "description": ""},
        ]
    })
    out = conv.convert_interfaces()
    assert "set type physical" not in out
    assert "# MANUAL" in out
    assert '# edit "ethernet1/1"' in out
    # no uncommented edit for the physical interface
    assert '\n    edit "ethernet1/1"' not in out


def test_vlan_interface_sets_parent_before_vlanid() -> None:
    conv = FGInterfaceConverter({
        "interfaces": [
            {"name": "ethernet1/1.100", "type": "vlan", "ip": "10.1.1.1/24",
             "vlan": "100", "parent": "ethernet1/1", "description": ""},
        ]
    })
    out = conv.convert_interfaces()
    assert out.index('set interface "ethernet1/1"') < out.index("set vlanid 100")


def test_interface_names_truncated_to_15_chars() -> None:
    long_name = "ethernet1/21.4094-extra"
    conv = FGInterfaceConverter({
        "interfaces": [
            {"name": long_name, "type": "loopback", "ip": "", "description": ""},
        ]
    })
    out = conv.convert_interfaces()
    fg_name = conv.get_interface_name_map()[long_name]
    assert len(fg_name) <= 15
    assert f'edit "{fg_name}"' in out


# --------------------------------------------------------------------------
# M2: dedup suffix respects the max length
# --------------------------------------------------------------------------

def test_dedup_suffix_respects_max_length() -> None:
    used: Dict[str, int] = {}
    long_name = "A" * 64
    first = dedup_fg_name(long_name, used)
    second = dedup_fg_name(long_name, used)
    assert first == long_name
    assert second != first
    assert len(second) <= 64
    assert second.endswith("_2")


# --------------------------------------------------------------------------
# M3: shared objects merged with vsys objects (vsys wins)
# --------------------------------------------------------------------------

def test_shared_and_vsys_objects_merged(tmp_path) -> None:
    body = """
    <shared><address>
      <entry name="sh1"><ip-netmask>10.1.1.1/32</ip-netmask></entry>
      <entry name="dup"><ip-netmask>10.1.1.2/32</ip-netmask></entry>
    </address></shared>
    <devices><entry name="localhost.localdomain"><vsys>
      <entry name="vsys1"><address>
        <entry name="v1"><ip-netmask>10.2.2.1/32</ip-netmask></entry>
        <entry name="dup"><ip-netmask>10.9.9.9/32</ip-netmask></entry>
      </address></entry>
    </vsys></entry></devices>
    """
    result = parse_panos_xml(_write_xml(tmp_path, body))
    by_name = {a["name"]: a for a in result["addresses"]}
    assert set(by_name) == {"sh1", "v1", "dup"}
    assert by_name["dup"]["value"] == "10.9.9.9/32"  # vsys wins


# --------------------------------------------------------------------------
# M4: source ports use FortiGate dst:src syntax
# --------------------------------------------------------------------------

def test_service_source_port_emitted() -> None:
    conv = FGServiceConverter({
        "services": [
            {"name": "syslog-src", "protocol": "tcp", "port": "514",
             "source_port": "1024-65535", "description": ""},
        ]
    })
    out = conv.convert()
    assert "set tcp-portrange 514:1024-65535" in out


# --------------------------------------------------------------------------
# M5: skipped services register no mapping; groups fail closed
# --------------------------------------------------------------------------

def test_no_port_service_skipped_without_name_mapping() -> None:
    conv = FGServiceConverter({
        "services": [
            {"name": "empty-svc", "protocol": "tcp", "port": "",
             "source_port": "", "description": ""},
        ]
    })
    out = conv.convert()
    assert out == ""
    assert "empty-svc" not in conv.get_name_map()
    assert "empty-svc" in conv.get_skipped_names()
    assert conv.failed_items


# --------------------------------------------------------------------------
# M6: 0.0.0.0 nexthop is not a gateway
# --------------------------------------------------------------------------

def test_route_zero_nexthop_without_interface_skipped() -> None:
    conv = FGRouteConverter({
        "static_routes": [
            {"name": "r1", "destination": "10.0.0.0/24", "nexthop": "0.0.0.0",
             "interface": "", "metric": 10, "description": ""},
        ]
    })
    out = conv.convert()
    assert out == ""
    assert conv.failed_items
    assert conv.get_statistics()["skipped"] == 1


def test_route_zero_nexthop_with_interface_emits_device_only() -> None:
    conv = FGRouteConverter({
        "static_routes": [
            {"name": "r1", "destination": "10.0.0.0/24", "nexthop": "0.0.0.0",
             "interface": "ethernet1/2", "metric": 10, "description": ""},
        ]
    })
    out = conv.convert()
    assert "set gateway" not in out
    assert 'set device "ethernet1/2"' in out


# --------------------------------------------------------------------------
# M8: group ordering and dynamic groups
# --------------------------------------------------------------------------

def test_groups_emitted_in_dependency_order() -> None:
    groups = [
        {"name": "outer", "members": ["inner"], "description": ""},
        {"name": "inner", "members": ["web1"], "description": ""},
    ]
    ordered = [g["name"] for g in topo_sort_groups(groups)]
    assert ordered.index("inner") < ordered.index("outer")
    out = FGAddressGroupConverter({"address_groups": groups}).convert()
    assert out.index('edit "inner"') < out.index('edit "outer"')


def test_dynamic_group_recorded_and_dependents_fail_closed() -> None:
    conv = FGAddressGroupConverter({
        "address_groups": [
            {"name": "dyn", "members": [], "description": "", "dynamic": True},
            {"name": "uses-dyn", "members": ["dyn"], "description": ""},
        ]
    })
    out = conv.convert()
    assert out == ""
    reasons = [f["reason"] for f in conv.failed_items]
    assert any("dynamic" in r for r in reasons)
    assert any("skipped" in r for r in reasons)


# --------------------------------------------------------------------------
# L3 / L4: TCP/UDP merge behavior
# --------------------------------------------------------------------------

def test_service_named_bare_suffix_kept_unmerged() -> None:
    conv = FGServiceConverter({
        "services": [
            {"name": "_TCP", "protocol": "tcp", "port": "80",
             "source_port": "", "description": ""},
        ]
    })
    out = conv.convert()
    assert 'edit "_TCP"' in out


def test_merged_pair_keeps_individual_halves() -> None:
    conv = FGServiceConverter({
        "services": [
            {"name": "DNS_TCP", "protocol": "tcp", "port": "53",
             "source_port": "", "description": ""},
            {"name": "DNS_UDP", "protocol": "udp", "port": "53",
             "source_port": "", "description": ""},
        ]
    })
    out = conv.convert()
    assert 'edit "DNS"' in out
    assert 'edit "DNS_TCP"' in out
    assert 'edit "DNS_UDP"' in out
    # single-half references stay narrow
    assert conv.get_name_map()["DNS_TCP"] == "DNS_TCP"
    assert conv.get_merged_pairs() == {"DNS": ["DNS_TCP", "DNS_UDP"]}


def test_policy_uses_merged_service_only_when_both_halves_referenced() -> None:
    merged_pairs = {"DNS": ["DNS_TCP", "DNS_UDP"]}
    name_map = {"DNS_TCP": "DNS_TCP", "DNS_UDP": "DNS_UDP"}

    both = FGPolicyConverter(
        {"security_rules": [_rule(services=["DNS_TCP", "DNS_UDP"])]},
        name_map, merged_service_pairs=merged_pairs,
    ).convert()
    assert 'set service "DNS"' in both

    single = FGPolicyConverter(
        {"security_rules": [_rule(services=["DNS_TCP"])]},
        name_map, merged_service_pairs=merged_pairs,
    ).convert()
    assert 'set service "DNS_TCP"' in single


def test_collapse_merged_pairs_pure() -> None:
    pairs = {"DNS": ["DNS_TCP", "DNS_UDP"]}
    assert collapse_merged_pairs(["DNS_TCP", "DNS_UDP", "HTTP"], pairs) == ["DNS", "HTTP"]
    assert collapse_merged_pairs(["DNS_UDP"], pairs) == ["DNS_UDP"]


# --------------------------------------------------------------------------
# L2: secondary IPs
# --------------------------------------------------------------------------

def test_parser_captures_secondary_ips(tmp_path) -> None:
    body = """
    <devices><entry name="localhost.localdomain">
      <network><interface><ethernet><entry name="ethernet1/1">
        <layer3><ip>
          <entry name="10.0.0.1/24"/>
          <entry name="10.0.0.2/24"/>
        </ip></layer3>
      </entry></ethernet></interface></network>
      <vsys><entry name="vsys1"/></vsys>
    </entry></devices>
    """
    result = parse_panos_xml(_write_xml(tmp_path, body))
    intf = result["interfaces"][0]
    assert intf["ip"] == "10.0.0.1/24"
    assert intf["secondary_ips"] == ["10.0.0.2/24"]


def test_secondary_ips_emitted() -> None:
    conv = FGInterfaceConverter({
        "interfaces": [
            {"name": "loop1", "type": "loopback", "ip": "1.1.1.1/32",
             "secondary_ips": ["2.2.2.2/32"], "description": ""},
        ]
    })
    out = conv.convert_interfaces()
    assert "set secondary-IP enable" in out
    assert "set ip 2.2.2.2 255.255.255.255" in out


# --------------------------------------------------------------------------
# L5: CLI string escaping
# --------------------------------------------------------------------------

def test_escape_fg_string_handles_quotes_and_backslashes() -> None:
    assert escape_fg_string('say "hi"') == 'say \\"hi\\"'
    assert escape_fg_string("trailing\\") == "trailing\\\\"
    assert escape_fg_string("") == ""


def test_policy_comment_escaped() -> None:
    rule = _rule(description='ends with backslash\\')
    out = FGPolicyConverter({"security_rules": [rule]}, {}).convert()
    assert 'set comments "ends with backslash\\\\"' in out
