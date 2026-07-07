"""Integration test for fortigate_converter.main() (TODO P3).

Feeds a small FortiGate YAML config through main() and verifies every
output JSON file is created with the expected structure, that YAML
pre-processing strips problematic sections, and that disabled policies
are exported to their own file.
"""
import json

import pytest

import fortigate_converter  # noqa: E402


FG_YAML = """\
system_interface:
  - port1:
      type: physical
      alias: wan1
      ip: [203.0.113.1, 255.255.255.0]
  - port2:
      type: physical
      alias: lan1
      ip: [192.168.1.1, 255.255.255.0]
firewall_address:
  - HOST_A:
      subnet: [10.0.0.5, 255.255.255.255]
      comment: test host
  - NET_B:
      subnet: [10.0.2.0, 255.255.255.0]
  - SSLVPN_TUNNEL_ADDR1:
      type: iprange
      start-ip: 10.212.134.200
      end-ip: 10.212.134.210
firewall_addrgrp:
  - GRP_AB:
      member: [HOST_A, NET_B]
firewall_service_custom:
  - ALL:
      protocol: IP
  - HTTP:
      tcp-portrange: 80
  - MYDNS:
      tcp-portrange: 53
      udp-portrange: 53
firewall_service_group:
  - Web_Group:
      member: [MYDNS, HTTP]
firewall_policy:
  - 1:
      name: Allow_Out
      srcintf: port2
      dstintf: port1
      srcaddr: GRP_AB
      dstaddr: all
      service: MYDNS
      action: accept
  - 2:
      name: Old_Rule
      status: disable
      srcintf: port2
      dstintf: port1
      srcaddr: HOST_A
      dstaddr: all
      service: ALL
      action: accept
router_static:
  - 1:
      dst: [10.50.0.0, 255.255.255.0]
      gateway: 203.0.113.254
      device: port1
dlp_filepattern:
  - 1:
      entries: [ {this is not valid yaml
"""

EXPECTED_SUFFIXES = [
    "_metadata.json",
    "_address_objects.json",
    "_address_groups.json",
    "_service_objects.json",
    "_service_groups.json",
    "_access_rules.json",
    "_access_rules_disabled.json",
    "_static_routes.json",
    "_physical_interfaces.json",
    "_subinterfaces.json",
    "_etherchannels.json",
    "_bridge_groups.json",
    "_security_zones.json",
    "_summary.json",
]


@pytest.fixture(scope="module")
def outputs(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("fg2ftd")
    input_file = tmp_path / "fg.yaml"
    input_file.write_text(FG_YAML, encoding="utf-8")
    base = tmp_path / "out"

    rc = fortigate_converter.main([
        str(input_file), "-o", str(base), "--target-model", "ftd-1010", "--pretty",
    ])
    assert rc == 0
    return base


def _load(base, suffix):
    path = base.parent / (base.name + suffix)
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def test_all_output_files_created(outputs):
    for suffix in EXPECTED_SUFFIXES:
        path = outputs.parent / (outputs.name + suffix)
        assert path.exists(), f"missing output file: {path.name}"


def test_problematic_yaml_section_is_stripped(outputs):
    # The dlp_filepattern section contains invalid YAML on purpose; main()
    # only succeeds (rc == 0, asserted in the fixture) if pre-processing
    # removed it before parsing.
    assert outputs is not None


def test_address_objects_converted_without_factory_defaults(outputs):
    objects = _load(outputs, "_address_objects.json")
    names = {o["name"] for o in objects}
    assert {"HOST_A", "NET_B"} <= names
    assert "SSLVPN_TUNNEL_ADDR1" not in names
    host_a = [o for o in objects if o["name"] == "HOST_A"][0]
    assert host_a["subType"] == "HOST"
    assert host_a["value"] == "10.0.0.5"


def test_address_groups_reference_converted_members(outputs):
    groups = _load(outputs, "_address_groups.json")
    assert len(groups) == 1
    assert groups[0]["name"] == "GRP_AB"
    assert [m["name"] for m in groups[0]["objects"]] == ["HOST_A", "NET_B"]


def test_service_objects_split_and_renamed(outputs):
    services = _load(outputs, "_service_objects.json")
    by_name = {o["name"]: o for o in services}
    # HTTP collides with the FTD built-in and gets the _Custom suffix.
    assert "HTTP_Custom" in by_name
    # MYDNS is split into TCP and UDP halves.
    assert by_name["MYDNS_TCP"]["type"] == "tcpportobject"
    assert by_name["MYDNS_UDP"]["type"] == "udpportobject"
    # The factory-default ALL service is not exported.
    assert "ALL" not in by_name


def test_service_groups_expand_split_members(outputs):
    groups = _load(outputs, "_service_groups.json")
    web = [g for g in groups if g["name"] == "Web_Group"][0]
    member_names = [m["name"] for m in web["objects"]]
    assert member_names == ["MYDNS_TCP", "MYDNS_UDP", "HTTP_Custom"]


def test_access_rules_only_contain_enabled_policies(outputs):
    rules = _load(outputs, "_access_rules.json")
    assert [r["name"] for r in rules] == ["Allow_Out"]
    rule = rules[0]
    assert rule["ruleAction"] == "PERMIT"
    # Group reference typed as a group; zones follow the interface aliases.
    assert rule["sourceNetworks"] == [{"name": "GRP_AB", "type": "networkobjectgroup"}]
    assert rule["sourceZones"] == [{"name": "lan1", "type": "securityzone"}]
    assert rule["destinationZones"] == [{"name": "wan1", "type": "securityzone"}]
    assert {(p["name"], p["type"]) for p in rule["destinationPorts"]} == {
        ("MYDNS_TCP", "tcpportobject"),
        ("MYDNS_UDP", "udpportobject"),
    }


def test_disabled_rules_exported_separately_with_migration_note(outputs):
    disabled = _load(outputs, "_access_rules_disabled.json")
    assert [r["name"] for r in disabled] == ["Old_Rule"]
    assert disabled[0]["_migration"]["sourceStatus"] == "disable"


def test_interfaces_and_zones_exported(outputs):
    physical = _load(outputs, "_physical_interfaces.json")
    names = {i["name"] for i in physical}
    assert {"wan1", "lan1"} <= names

    zones = _load(outputs, "_security_zones.json")
    zone_names = {z["name"] for z in zones}
    assert {"wan1", "lan1"} <= zone_names

    # No aggregates/switches/VLANs in this config.
    assert _load(outputs, "_etherchannels.json") == []
    assert _load(outputs, "_bridge_groups.json") == []
    assert _load(outputs, "_subinterfaces.json") == []


def test_static_routes_are_a_list(outputs):
    routes = _load(outputs, "_static_routes.json")
    assert isinstance(routes, list)


def test_metadata_records_conversion_context(outputs):
    metadata = _load(outputs, "_metadata.json")
    assert metadata["target_model"] == "ftd-1010"
    assert metadata["schema_version"] == 1
    # ftd-1010 has no dedicated HA port.
    assert metadata["ha_port"] is None


def test_summary_structure_and_counts(outputs):
    summary = _load(outputs, "_summary.json")
    cs = summary["conversion_summary"]
    assert cs["address_objects"] >= 2
    assert cs["address_groups"] == 1
    assert cs["service_objects"]["tcp"] == 2
    assert cs["service_objects"]["udp"] == 1
    assert cs["access_rules"]["total"] == 1
    assert cs["access_rules"]["permit"] == 1
    assert cs["access_rules"]["disabled_exported"] == 1
    assert "conversion_failures" in summary


def test_missing_input_file_returns_error():
    rc = fortigate_converter.main(["definitely_not_here.yaml", "-o", "unused"])
    assert rc == 1


def test_empty_yaml_returns_error(tmp_path):
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    rc = fortigate_converter.main([str(empty), "-o", str(tmp_path / "x")])
    assert rc == 1
