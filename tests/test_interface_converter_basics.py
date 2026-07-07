"""Unit tests for the FortiGate -> FTD interface converter basics (TODO P3).

Covers physical/aggregate/switch/VLAN type detection, per-model port
universes, interface name sanitization, and security zone generation.
HA port exclusion is covered in test_ftd_ha_ports.py; network modules,
promotions, and expansions have their own test files.
"""
import pytest

from interface_converter import (  # noqa: E402
    FTD_MODELS,
    InterfaceConverter,
    sanitize_interface_name,
)


def _convert(fg_config, model="ftd-3120", **kwargs):
    conv = InterfaceConverter(fg_config, target_model=model, **kwargs)
    return conv, conv.convert()


# ---------------------------------------------------------------------------
# Name sanitization
# ---------------------------------------------------------------------------

def test_sanitize_lowercases_and_replaces_special_chars():
    assert sanitize_interface_name("WAN-1 (Primary)") == "wan_1_primary"


def test_sanitize_collapses_and_strips_underscores():
    assert sanitize_interface_name("__Core__Switch__") == "core_switch"


def test_sanitize_handles_none_and_numbers():
    assert sanitize_interface_name(None) == ""
    assert sanitize_interface_name(551) == "551"


# ---------------------------------------------------------------------------
# Per-model port universes
# ---------------------------------------------------------------------------

def test_model_port_counts_minus_reserved_ha_port():
    cases = {
        "ftd-1010": 8,    # 8 ports, no HA port
        "ftd-2130": 16,   # 16 ports, no HA port
        "ftd-3120": 15,   # 16 ports, Ethernet1/2 reserved for HA
        "ftd-4215": 23,   # 24 ports, Ethernet1/2 reserved for HA
    }
    for model, expected_free in cases.items():
        conv = InterfaceConverter({"system_interface": []}, target_model=model)
        assert len(conv.available_ftd_ports) == expected_free, model


def test_ports_use_model_prefix():
    conv = InterfaceConverter({"system_interface": []}, target_model="ftd-1010")
    assert all(p.startswith("Ethernet1/") for p in conv.available_ftd_ports)


def test_unknown_model_raises():
    with pytest.raises(ValueError):
        InterfaceConverter({"system_interface": []}, target_model="ftd-9999")


def test_model_catalog_shape():
    for model_id, info in FTD_MODELS.items():
        assert info["total_ports"] > 0, model_id
        assert info["port_prefix"], model_id


# ---------------------------------------------------------------------------
# Interface type detection (physical / aggregate / switch / VLAN)
# ---------------------------------------------------------------------------

def _full_config():
    return {
        "system_interface": [
            {"port1": {"type": "physical", "alias": "wan1",
                       "ip": ["203.0.113.1", "255.255.255.0"]}},
            {"port2": {"type": "physical"}},
            {"port3": {"type": "physical"}},
            {"agg1": {"type": "aggregate", "member": ["port2", "port3"],
                      "ip": ["10.9.9.1", "255.255.255.0"]}},
            {"port4": {"type": "physical"}},
            {"port5": {"type": "physical"}},
            {"lan": {"type": "switch", "ip": ["192.168.1.1", "255.255.255.0"]}},
            {"vlan100": {"interface": "port1", "vlanid": 100, "alias": "dmz",
                         "ip": ["10.100.0.1", "255.255.255.0"]}},
        ],
        "system_switch-interface": [
            {"lan": {"member": "port4 port5"}},
        ],
    }


def test_each_source_type_lands_in_its_output_bucket():
    conv, result = _convert(_full_config())

    assert len(result["etherchannels"]) == 1
    assert len(result["bridge_groups"]) == 1
    assert len(result["subinterfaces"]) == 1
    # port1 + 2 EC members + 2 bridge members
    assert len(result["physical_interfaces"]) == 5

    stats = conv.get_statistics()
    assert stats["etherchannels_created"] == 1
    assert stats["bridge_groups_created"] == 1
    assert stats["subinterfaces_created"] == 1
    assert stats["skipped"] == 0


def test_physical_interface_payload_fields():
    _, result = _convert(_full_config())
    port1 = [i for i in result["physical_interfaces"] if i["name"] == "wan1"][0]
    assert port1["type"] == "physicalinterface"
    assert port1["mode"] == "ROUTED"
    assert port1["enabled"] is True
    assert port1["hardwareName"].startswith("Ethernet1/")
    assert port1["ipv4"]["ipAddress"]["ipAddress"] == "203.0.113.1"
    assert port1["ipv4"]["ipAddress"]["netmask"] == "255.255.255.0"


def test_interface_with_status_down_is_disabled():
    _, result = _convert({
        "system_interface": [
            {"port1": {"type": "physical", "status": "down"}},
        ],
    })
    assert result["physical_interfaces"][0]["enabled"] is False


def test_aggregate_becomes_etherchannel_with_members():
    _, result = _convert(_full_config())
    ec = result["etherchannels"][0]
    assert ec["type"] == "etherchannelinterface"
    assert ec["name"] == "agg1"
    assert ec["hardwareName"] == "Port-channel1"
    assert ec["lacpMode"] == "ACTIVE"
    assert len(ec["memberInterfaces"]) == 2


def test_switch_becomes_bridge_group_with_ip_from_system_interface():
    _, result = _convert(_full_config())
    bg = result["bridge_groups"][0]
    assert bg["type"] == "bridgegroupinterface"
    assert bg["name"] == "lan"
    assert bg["bridgeGroupId"] == 1
    assert len(bg["selectedInterfaces"]) == 2
    assert bg["ipv4"]["ipAddress"]["ipAddress"] == "192.168.1.1"


def test_vlan_becomes_subinterface_on_parent_port():
    conv, result = _convert(_full_config())
    sub = result["subinterfaces"][0]
    assert sub["type"] == "subinterface"
    assert sub["vlanId"] == 100
    assert sub["subIntfId"] == 100
    # Named from alias + fg name, attached to the parent's hardware port.
    assert sub["name"] == "dmz_vlan100"
    parent_hw = conv.port_mapping["port1"]
    assert sub["hardwareName"] == f"{parent_hw}.100"


def test_interface_name_mapping_covers_all_names_and_aliases():
    conv, _ = _convert(_full_config())
    mapping = conv.get_interface_mapping()
    assert mapping["port1"] == "wan1"
    assert mapping["wan1"] == "wan1"
    assert mapping["agg1"] == "agg1"
    assert mapping["lan"] == "lan"
    assert mapping["vlan100"] == "dmz_vlan100"
    assert mapping["dmz"] == "dmz_vlan100"


def test_tunnel_and_loopback_skipped_and_reported():
    conv, result = _convert({
        "system_interface": [
            {"vpn1": {"type": "tunnel"}},
            {"lo0": {"type": "loopback"}},
            {"port1": {"type": "physical"}},
        ],
    })
    assert len(result["physical_interfaces"]) == 1
    assert conv.get_statistics()["skipped"] == 2
    assert {f["name"] for f in conv.failed_items} == {"vpn1", "lo0"}


def test_mgmt_and_ha_interfaces_silently_ignored():
    conv, result = _convert({
        "system_interface": [
            {"mgmt": {"type": "physical", "ip": ["10.0.0.1", "255.255.255.0"]}},
            {"ha1": {"type": "physical"}},
            {"port1": {"type": "physical"}},
        ],
    })
    assert [i["name"] for i in result["physical_interfaces"]] == ["port1"]
    # Infrastructure links are not reported as failures.
    assert conv.failed_items == []


def test_reserved_ftd_name_gets_port_suffix():
    _, result = _convert({
        "system_interface": [
            {"port1": {"type": "physical", "alias": "inside"}},
        ],
    })
    name = result["physical_interfaces"][0]["name"]
    assert name.startswith("inside_port")
    assert name != "inside"


# ---------------------------------------------------------------------------
# Security zone generation
# ---------------------------------------------------------------------------

def test_zone_created_per_interface_with_matching_name():
    _, result = _convert(_full_config())
    zones = {z["name"]: z for z in result["security_zones"]}

    assert "wan1" in zones
    assert "agg1" in zones
    assert "dmz_vlan100" in zones
    assert zones["wan1"]["type"] == "securityzone"
    assert zones["wan1"]["mode"] == "ROUTED"
    assert zones["wan1"]["interfaces"][0]["type"] == "physicalinterface"


def test_bridge_group_members_share_one_zone_named_after_bridge():
    _, result = _convert(_full_config())
    zones = {z["name"]: z for z in result["security_zones"]}

    lan_zone = zones["lan"]
    # Both member ports live in the bridge zone; the BVI itself is not a
    # zone interface.
    assert len(lan_zone["interfaces"]) == 2
    assert all(i["type"] == "physicalinterface" for i in lan_zone["interfaces"])


def test_etherchannel_member_ports_do_not_get_their_own_zones():
    conv, result = _convert(_full_config())
    zone_names = {z["name"] for z in result["security_zones"]}
    # wan1, agg1, lan, dmz_vlan100 - EC member stubs are unnamed and zoneless.
    assert zone_names == {"wan1", "agg1", "lan", "dmz_vlan100"}
    assert conv.get_statistics()["security_zones_created"] == 4
