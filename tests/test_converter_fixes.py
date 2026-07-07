"""Regression tests for the FortiGate->FTD converter code-review fixes.

Covers the High-severity findings:
  H1 - disabled FortiGate policies are not converted
  H2 - rules whose services all filtered out fail closed (skip, not any-service)
  H3 - 'dst:src' port ranges keep the destination and drop the source ports
  H4 - a TCP service merely named "ping" is not converted to ICMP objects
  H5 - sanitization-collision renames (X -> X_2) propagate to groups/policies
  H6 - unmigrated addresses are filtered from groups/policies (fail closed)
  H7 - subinterfaces with an unmapped parent are skipped, not put on Eth1/1
  H8 - unsupported system_interface types are reported, not dropped silently
  H9 - duplicate physical interface names get deduplicated (_2 suffix)
"""

from address_converter import AddressConverter  # noqa: E402
from address_group_converter import AddressGroupConverter  # noqa: E402
from service_converter import ServiceConverter  # noqa: E402
from service_group_converter import ServiceGroupConverter  # noqa: E402
from policy_converter import PolicyConverter  # noqa: E402
from interface_converter import InterfaceConverter  # noqa: E402


# ---------------------------------------------------------------------------
# H1: disabled policies
# ---------------------------------------------------------------------------
def test_disabled_policy_is_not_converted():
    cfg = {"firewall_policy": [
        {1: {"name": "dead_rule", "status": "disable", "action": "accept",
             "srcaddr": "all", "dstaddr": "all", "service": "ALL"}},
        {2: {"name": "live_rule", "action": "accept",
             "srcaddr": "all", "dstaddr": "all", "service": "ALL"}},
    ]}
    conv = PolicyConverter(cfg)
    rules = conv.convert()

    assert [r["name"] for r in rules] == ["live_rule"]
    stats = conv.get_statistics()
    assert stats["disabled_rules"] == 1
    assert any(f["reason"] == "disabled in source config" for f in conv.failed_items)


# ---------------------------------------------------------------------------
# H2: empty destinationPorts must not silently become "any service"
# ---------------------------------------------------------------------------
def test_rule_with_all_services_filtered_fails_closed():
    cfg = {"firewall_policy": [
        {1: {"name": "icmp_only", "action": "accept", "srcaddr": "all",
             "dstaddr": "all", "service": ["MY_ICMP"]}},
    ]}
    conv = PolicyConverter(cfg, skipped_services={"MY_ICMP"})
    rules = conv.convert()

    assert rules == []
    assert conv.failed_items
    assert "services" in conv.failed_items[0]["reason"]
    assert conv.get_statistics()["fail_closed_skipped"] == 1


def test_rule_with_service_all_keeps_any_service():
    """A genuine 'ALL' service rule keeps empty destinationPorts (= any)."""
    cfg = {"firewall_policy": [
        {1: {"name": "open_rule", "action": "accept", "srcaddr": "all",
             "dstaddr": "all", "service": "ALL"}},
    ]}
    conv = PolicyConverter(cfg)
    rules = conv.convert()

    assert len(rules) == 1
    assert rules[0]["destinationPorts"] == []


# ---------------------------------------------------------------------------
# H3: FortiGate 'dst:src' portrange semantics
# ---------------------------------------------------------------------------
def test_source_port_restriction_dropped_destination_kept():
    conv = ServiceConverter({"firewall_service_custom": [
        {"WEB": {"protocol": "TCP/UDP/SCTP", "tcp-portrange": "443:1024-65535"}},
    ]})
    objs = conv.convert()

    web = next(o for o in objs if o["name"] == "WEB")
    assert web["port"] == "443"  # destination only
    assert web["type"] == "tcpportobject"
    # The source range must not appear as any object's (destination) port
    assert all(o.get("port") != "1024-65535" for o in objs)
    # The dropped source restriction is reported
    assert any("source-port restriction" in f["reason"] for f in conv.failed_items)


def test_source_port_restriction_in_list_items():
    conv = ServiceConverter({"firewall_service_custom": [
        {"MULTI": {"tcp-portrange": ["80-90:5000-6000", "8080"]}},
    ]})
    objs = conv.convert()
    ports = sorted(o["port"] for o in objs)
    assert ports == ["80-90", "8080"]


# ---------------------------------------------------------------------------
# H4: name-based ping detection requires an ICMP protocol
# ---------------------------------------------------------------------------
def test_tcp_service_named_ping_stays_tcp():
    conv = ServiceConverter({"firewall_service_custom": [
        {"ping": {"protocol": "TCP/UDP/SCTP", "tcp-portrange": 7}},
    ]})
    objs = conv.convert()

    assert conv.get_extra_port_groups() == []
    obj = next(o for o in objs if o["name"] == "ping")
    assert obj["type"] == "tcpportobject"
    assert obj["port"] == "7"
    assert conv.get_statistics()["ping_services"] == 0


def test_icmp_service_named_ping_still_migrates_to_ping_group():
    conv = ServiceConverter({"firewall_service_custom": [
        {"PING": {"protocol": "ICMP", "icmptype": 8}},
    ]})
    conv.convert()
    assert conv.get_statistics()["ping_services"] == 1
    assert len(conv.get_extra_port_groups()) == 1


# ---------------------------------------------------------------------------
# H5: collision renames propagate; literal X_2 cannot collide
# ---------------------------------------------------------------------------
def test_address_collision_renames_unique_including_literal_x2():
    conv = AddressConverter({"firewall_address": [
        {"srv one": {"subnet": ["10.0.0.1", "255.255.255.255"]}},
        {"srv_one": {"subnet": ["10.0.0.2", "255.255.255.255"]}},
        {"srv_one_2": {"subnet": ["10.0.0.3", "255.255.255.255"]}},
    ]})
    objs = conv.convert()
    names = [o["name"] for o in objs]

    assert len(names) == 3
    assert len(set(names)) == 3  # no duplicate exported names
    assert names[0] == "srv_one"
    assert names[1] == "srv_one_2"  # generated rename
    # the literal source object named srv_one_2 was pushed off the taken name
    assert names[2] not in ("srv_one", "srv_one_2")
    # rename map lets references find the literal srv_one_2 object
    assert conv.get_address_name_mapping()["srv_one_2"] == names[2]


def test_group_members_follow_collision_renames_no_dangling_refs():
    addr = AddressConverter({"firewall_address": [
        {"web srv": {"subnet": ["10.0.0.1", "255.255.255.255"]}},
        {"web_srv": {"subnet": ["10.0.0.2", "255.255.255.255"]}},
    ]})
    objs = addr.convert()
    grp = AddressGroupConverter(
        {"firewall_addrgrp": [{"G": {"member": ["web srv", "web_srv"]}}]},
        address_name_mapping=addr.get_address_name_mapping(),
        skipped_addresses=addr.get_skipped_addresses(),
    )
    groups = grp.convert()

    exported_names = {o["name"] for o in objs}
    assert groups, "group must convert"
    for member in groups[0]["objects"]:
        assert member["name"] in exported_names  # nothing dangling


def test_service_collision_renames_unique_including_literal_x2():
    conv = ServiceConverter({"firewall_service_custom": [
        {"svc one": {"tcp-portrange": 100}},
        {"svc_one": {"tcp-portrange": 200}},
        {"svc_one_2": {"tcp-portrange": 300}},
    ]})
    objs = conv.convert()
    names = [o["name"] for o in objs]
    assert len(names) == 3
    assert len(set(names)) == 3


def test_policy_uses_final_service_group_name():
    grp_conv = ServiceGroupConverter({"firewall_service_group": [
        {"web grp": {"member": ["HTTP_SVC"]}},
    ]}, service_name_mapping={"HTTP_SVC": [("HTTP_SVC", "tcpportobject")]})
    groups = grp_conv.convert()

    pol = PolicyConverter(
        {"firewall_policy": [
            {1: {"name": "r", "action": "accept", "srcaddr": "all",
                 "dstaddr": "all", "service": ["web grp"]}},
        ]},
        service_groups={g["name"] for g in groups},
        service_group_name_mapping=grp_conv.get_group_name_mapping(),
    )
    rules = pol.convert()
    assert rules[0]["destinationPorts"] == [
        {"name": "web_grp", "type": "portobjectgroup"}
    ]


# ---------------------------------------------------------------------------
# H6: skipped/unconverted addresses filtered from groups and policies
# ---------------------------------------------------------------------------
def _converted_addresses():
    addr = AddressConverter({"firewall_address": [
        {"RealObj": {"subnet": ["10.1.0.0", "255.255.255.0"]}},
        # FortiGate factory default - silently ignored by the converter
        {"SSLVPN_TUNNEL_ADDR1": {"type": "iprange",
                                 "start-ip": "10.2.0.1", "end-ip": "10.2.0.5"}},
    ]})
    addr.convert()
    return addr


def test_group_filters_unmigrated_members():
    addr = _converted_addresses()
    grp = AddressGroupConverter(
        {"firewall_addrgrp": [
            {"MIXED": {"member": ["RealObj", "SSLVPN_TUNNEL_ADDR1"]}},
            {"ONLY_DEFAULT": {"member": ["SSLVPN_TUNNEL_ADDR1"]}},
        ]},
        address_name_mapping=addr.get_address_name_mapping(),
        skipped_addresses=addr.get_skipped_addresses(),
    )
    groups = grp.convert()

    assert [g["name"] for g in groups] == ["MIXED"]
    assert [m["name"] for m in groups[0]["objects"]] == ["RealObj"]
    # the emptied group is skipped and reported (FDM rejects empty groups)
    assert any(f["name"] == "ONLY_DEFAULT" for f in grp.failed_items)


def test_policy_fails_closed_when_all_sources_unmigrated():
    addr = _converted_addresses()
    pol = PolicyConverter(
        {"firewall_policy": [
            {1: {"name": "r", "action": "accept",
                 "srcaddr": ["SSLVPN_TUNNEL_ADDR1"], "dstaddr": ["RealObj"],
                 "service": "ALL"}},
        ]},
        address_name_mapping=addr.get_address_name_mapping(),
        skipped_addresses=addr.get_skipped_addresses(),
    )
    rules = pol.convert()

    assert rules == []
    assert any("source addresses" in f["reason"] for f in pol.failed_items)


def test_policy_keeps_rule_with_remaining_addresses():
    addr = _converted_addresses()
    pol = PolicyConverter(
        {"firewall_policy": [
            {1: {"name": "r", "action": "accept",
                 "srcaddr": ["RealObj", "SSLVPN_TUNNEL_ADDR1"],
                 "dstaddr": "all", "service": "ALL"}},
        ]},
        address_name_mapping=addr.get_address_name_mapping(),
        skipped_addresses=addr.get_skipped_addresses(),
    )
    rules = pol.convert()

    assert len(rules) == 1
    assert [n["name"] for n in rules[0]["sourceNetworks"]] == ["RealObj"]


# ---------------------------------------------------------------------------
# H7: subinterface with an unmapped parent is skipped (no Ethernet1/1 fallback)
# ---------------------------------------------------------------------------
def test_vlan_with_unmapped_parent_is_skipped():
    cfg = {"system_interface": [
        {"vlan100": {"interface": "portX", "vlanid": 100,
                     "ip": ["10.0.0.1", "255.255.255.0"]}},
    ]}
    conv = InterfaceConverter(cfg, target_model="ftd-3120", custom_ha_port="none")
    res = conv.convert()

    assert res["subinterfaces"] == []
    assert any("no FTD port mapping" in f["reason"] for f in conv.failed_items)
    assert conv.stats["skipped"] >= 1


def test_vlan_with_mapped_parent_uses_parent_port():
    cfg = {"system_interface": [
        {"port1": {"type": "physical", "ip": ["10.0.0.1", "255.255.255.0"]}},
        {"vlan100": {"interface": "port1", "vlanid": 100,
                     "ip": ["10.0.100.1", "255.255.255.0"]}},
    ]}
    conv = InterfaceConverter(cfg, target_model="ftd-3120", custom_ha_port="none")
    res = conv.convert()

    assert len(res["subinterfaces"]) == 1
    sub = res["subinterfaces"][0]
    parent_hw = conv.port_mapping["port1"]
    assert sub["hardwareName"] == f"{parent_hw}.100"


# ---------------------------------------------------------------------------
# H8: unsupported interface types are reported, not silently dropped
# ---------------------------------------------------------------------------
def test_unsupported_interface_types_are_reported():
    cfg = {"system_interface": [
        {"vpn1": {"type": "tunnel"}},
        {"lo0": {"type": "loopback"}},
        {"vdlink0": {"type": "vdom-link"}},
        {"port1": {"type": "physical", "ip": ["10.0.0.1", "255.255.255.0"]}},
    ]}
    conv = InterfaceConverter(cfg, target_model="ftd-3120", custom_ha_port="none")
    res = conv.convert()

    reasons = {f["name"]: f["reason"] for f in conv.failed_items}
    assert reasons["vpn1"] == "no FTD equivalent"
    assert reasons["lo0"] == "no FTD equivalent"
    assert "unsupported interface type" in reasons["vdlink0"]
    assert conv.stats["skipped"] >= 3
    # the physical interface still converts normally
    assert len(res["physical_interfaces"]) == 1


def test_switch_type_with_virtual_switch_entry_not_reported():
    """A type=switch system_interface entry backed by a system_switch-interface
    definition is the L3 shell of a bridge group - it must not be reported."""
    cfg = {
        "system_interface": [
            {"lan_sw": {"type": "switch", "ip": ["10.0.5.1", "255.255.255.0"]}},
            {"m1": {"type": "physical"}},
        ],
        "system_switch-interface": [{"lan_sw": {"member": ["m1"]}}],
    }
    conv = InterfaceConverter(cfg, target_model="ftd-3120", custom_ha_port="none")
    res = conv.convert()

    assert len(res["bridge_groups"]) == 1
    assert not any(f["name"] == "lan_sw" for f in conv.failed_items)


# ---------------------------------------------------------------------------
# H9: duplicate physical interface names get a _2 suffix
# ---------------------------------------------------------------------------
def test_duplicate_physical_alias_names_deduped():
    cfg = {"system_interface": [
        {"port1": {"type": "physical", "alias": "uplink",
                   "ip": ["10.0.1.1", "255.255.255.0"]}},
        {"port2": {"type": "physical", "alias": "uplink",
                   "ip": ["10.0.2.1", "255.255.255.0"]}},
    ]}
    conv = InterfaceConverter(cfg, target_model="ftd-3120", custom_ha_port="none")
    res = conv.convert()

    names = sorted(p["name"] for p in res["physical_interfaces"])
    assert names == ["uplink", "uplink_2"]
    # mapping stays consistent per FortiGate port
    mapping = conv.get_interface_mapping()
    assert mapping["port1"] == "uplink"
    assert mapping["port2"] == "uplink_2"
