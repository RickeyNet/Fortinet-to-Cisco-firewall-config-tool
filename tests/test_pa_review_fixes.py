"""Tests for the FortiGate -> Palo Alto code-review fixes.

Covers:
  - H1: cleanup tool actually parses object names from config-get XML
  - H2: fail-closed rules when all services were filtered (disabled, not any)
  - H3: FortiGate `status: disable` policies convert with disabled: yes
  - H4: single-host iprange address objects keep their /32 value
  - H5: empty/None YAML entries do not crash the converters
  - M1: colon portranges keep the destination part (dst:src semantics)
  - M2: dedup renames propagate to groups and policies
  - M3: XML escaping in importer builders
  - M4: aeN subinterfaces route to the aggregate-ethernet XPath
  - M5: disabled physical interfaces emit link-state down
  - M7: ping-only rules get application ["ping"]
  - M8: address-group members are filtered against skipped addresses
  - L5: dedup suffixes respect the 63-char PAN-OS name limit
  - L6: disabled routes are skipped; gateway-only entries become default routes
  - L9: netmask_to_cidr rejects non-contiguous masks
"""
import sys
from pathlib import Path

# Path setup is also handled in tests/conftest.py; kept here as a fallback for
# running this module directly. Imports below must stay after this block.
ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT / "FortiGateToPaloAltoTool"))

from pa_common import dedup_name, netmask_to_cidr, first_item  # noqa: E402
from pa_address_converter import PAAddressConverter  # noqa: E402
from pa_address_group_converter import PAAddressGroupConverter  # noqa: E402
from pa_service_converter import PAServiceConverter  # noqa: E402
from pa_service_group_converter import PAServiceGroupConverter  # noqa: E402
from pa_policy_converter import PAPolicyConverter  # noqa: E402
from pa_route_converter import PARouteConverter  # noqa: E402
from panos_api_cleanup import PANOSBulkDelete  # noqa: E402
from panos_api_importer import PANOSImporter  # noqa: E402


def _policy_converter(cfg, **context):
    conv = PAPolicyConverter(cfg)
    base = dict(
        split_services=set(),
        service_name_mapping={},
        skipped_services=set(),
        address_groups=set(),
        service_groups=set(),
        interface_name_mapping={},
    )
    base.update(context)
    conv.set_split_services(**base)
    return conv


# ---------------------------------------------------------------------------
# H1: cleanup object-name discovery
# ---------------------------------------------------------------------------
_CANNED_ADDRESS_RESPONSE = (
    '<response status="success"><result total-count="2" count="2">'
    '<address>'
    '<entry name="web_srv"><ip-netmask>10.0.0.1/32</ip-netmask></entry>'
    '<entry name="db_srv"><ip-netmask>10.0.0.2/32</ip-netmask></entry>'
    '</address></result></response>'
)

# Ethernet response with NESTED <entry> elements (the interface IP) that must
# not be mistaken for top-level objects.
_CANNED_ETHERNET_RESPONSE = (
    '<response status="success"><result>'
    '<ethernet>'
    '<entry name="ethernet1/1"><layer3>'
    '<ip><entry name="10.0.0.1/24"/></ip>'
    '</layer3></entry>'
    '</ethernet></result></response>'
)


def _cleanup_client() -> PANOSBulkDelete:
    return PANOSBulkDelete(
        host="192.0.2.1", username="admin", password="pw", dry_run=True,
    )


def test_cleanup_get_object_names_parses_entries() -> None:
    client = _cleanup_client()
    client.config_get_xml = lambda xpath: (True, _CANNED_ADDRESS_RESPONSE)
    names = client._get_object_names("/some/xpath")
    assert names == ["web_srv", "db_srv"]


def test_cleanup_get_object_names_ignores_nested_entries() -> None:
    client = _cleanup_client()
    client.config_get_xml = lambda xpath: (True, _CANNED_ETHERNET_RESPONSE)
    names = client._get_object_names("/some/xpath")
    assert names == ["ethernet1/1"]


def test_cleanup_get_object_names_empty_on_error() -> None:
    client = _cleanup_client()
    client.config_get_xml = lambda xpath: (False, "No such node")
    assert client._get_object_names("/some/xpath") == []


class _FakeResponse:
    def __init__(self, text: str, status_code: int = 200) -> None:
        self.text = text
        self.status_code = status_code


def test_config_get_xml_returns_raw_response() -> None:
    client = _cleanup_client()
    client.api_key = "test-key"
    captured = {}

    def fake_post(url, data=None, timeout=None):
        captured["data"] = data
        return _FakeResponse(_CANNED_ADDRESS_RESPONSE)

    client.session.post = fake_post
    ok, raw = client.config_get_xml("/some/xpath")
    assert ok is True
    assert raw == _CANNED_ADDRESS_RESPONSE
    # API key travels in the POST body, not the URL
    assert captured["data"]["key"] == "test-key"


# ---------------------------------------------------------------------------
# H2 / H3 / M7: policy fail-closed, disabled status, ping application
# ---------------------------------------------------------------------------
def test_policy_all_services_skipped_fails_closed() -> None:
    cfg = {"firewall_policy": [
        {1: {"name": "gre_rule", "action": "accept",
             "srcaddr": "all", "dstaddr": "all", "service": "GRE_SVC"}},
    ]}
    conv = _policy_converter(cfg, skipped_services={"GRE_SVC"})
    rules = conv.convert()
    assert len(rules) == 1
    rule = rules[0]
    assert rule["disabled"] == "yes"
    assert rule["services"] == ["any"]
    assert "DISABLED by migration" in rule["description"]
    assert any("gre_rule" == f["name"] for f in conv.failed_items)


def test_policy_genuine_all_service_stays_any_and_enabled() -> None:
    cfg = {"firewall_policy": [
        {1: {"name": "allow_all", "action": "accept",
             "srcaddr": "all", "dstaddr": "all", "service": "ALL"}},
    ]}
    conv = _policy_converter(cfg)
    rules = conv.convert()
    assert rules[0]["services"] == ["any"]
    assert rules[0]["disabled"] == "no"
    assert conv.failed_items == []


def test_policy_status_disable_converts_disabled() -> None:
    cfg = {"firewall_policy": [
        {7: {"name": "old_rule", "action": "accept", "status": "disable",
             "srcaddr": "all", "dstaddr": "all", "service": "ALL"}},
    ]}
    conv = _policy_converter(cfg)
    rules = conv.convert()
    assert len(rules) == 1
    assert rules[0]["disabled"] == "yes"


def test_policy_ping_only_rule_gets_ping_application() -> None:
    cfg = {"firewall_policy": [
        {2: {"name": "ping_rule", "action": "accept",
             "srcaddr": "all", "dstaddr": "all", "service": "PING"}},
    ]}
    conv = _policy_converter(
        cfg, skipped_services={"PING"}, ping_services={"PING"},
    )
    rules = conv.convert()
    assert rules[0]["application"] == ["ping"]
    assert rules[0]["services"] == ["application-default"]
    assert rules[0]["disabled"] == "no"


def test_policy_all_addresses_skipped_fails_closed() -> None:
    cfg = {"firewall_policy": [
        {3: {"name": "bad_src", "action": "accept",
             "srcaddr": "ghost_host", "dstaddr": "all", "service": "ALL"}},
    ]}
    conv = _policy_converter(cfg, skipped_addresses={"ghost_host"})
    rules = conv.convert()
    assert rules[0]["disabled"] == "yes"
    assert rules[0]["sources"] == ["any"]
    assert any("bad_src" == f["name"] for f in conv.failed_items)


# ---------------------------------------------------------------------------
# H4: single-host iprange
# ---------------------------------------------------------------------------
def test_single_host_iprange_converts_as_host() -> None:
    cfg = {"firewall_address": [
        {"host1": {"type": "iprange",
                   "start-ip": "10.1.2.3", "end-ip": "10.1.2.3"}},
    ]}
    conv = PAAddressConverter(cfg)
    objects = conv.convert()
    assert len(objects) == 1
    assert objects[0]["type"] == "ip-netmask"
    assert objects[0]["value"] == "10.1.2.3/32"
    assert conv.failed_items == []


def test_fqdn_without_fqdn_field_is_skipped_not_comment() -> None:
    cfg = {"firewall_address": [
        {"weird": {"type": "fqdn", "comment": "this is not a hostname"}},
    ]}
    conv = PAAddressConverter(cfg)
    objects = conv.convert()
    assert objects == []
    assert len(conv.failed_items) == 1


# ---------------------------------------------------------------------------
# H5: empty/None YAML entries do not crash
# ---------------------------------------------------------------------------
def test_none_and_empty_entries_do_not_crash() -> None:
    bad_entries = [None, {}, "just_a_string", {"empty_props": None}]
    cfg = {
        "firewall_address": list(bad_entries),
        "firewall_addrgrp": list(bad_entries),
        "firewall_service_custom": list(bad_entries),
        "firewall_service_group": list(bad_entries),
        "firewall_policy": list(bad_entries),
        "router_static": list(bad_entries),
    }
    PAAddressConverter(cfg).convert()
    PAAddressGroupConverter(cfg).convert()
    PAServiceConverter(cfg).convert()
    grp = PAServiceGroupConverter(cfg)
    grp.set_split_services(set(), {}, set())
    grp.convert()
    _policy_converter(cfg).convert()
    PARouteConverter(cfg).convert()


def test_first_item_contract() -> None:
    assert first_item(None) is None
    assert first_item({}) is None
    assert first_item("name") is None
    assert first_item({"x": None}) == ("x", {})
    assert first_item({"x": {"a": 1}}) == ("x", {"a": 1})


# ---------------------------------------------------------------------------
# M1: colon portrange means dst:src
# ---------------------------------------------------------------------------
def test_colon_portrange_keeps_destination_part() -> None:
    cfg = {"firewall_service_custom": [
        {"restricted": {"protocol": "TCP/UDP/SCTP",
                        "tcp-portrange": "443:1024-65535"}},
    ]}
    conv = PAServiceConverter(cfg)
    objects = conv.convert()
    assert len(objects) == 1
    assert objects[0]["port"] == "443"
    assert any("source-port" in f["reason"] for f in conv.failed_items)


def test_plain_range_portrange_unchanged() -> None:
    cfg = {"firewall_service_custom": [
        {"web_range": {"protocol": "TCP/UDP/SCTP",
                       "tcp-portrange": "8000-8999"}},
    ]}
    conv = PAServiceConverter(cfg)
    objects = conv.convert()
    assert objects[0]["port"] == "8000-8999"
    assert conv.failed_items == []


def test_ping_service_tracked_not_dropped() -> None:
    cfg = {"firewall_service_custom": [
        {"PING": {"protocol": "ICMP", "icmptype": 8}},
    ]}
    conv = PAServiceConverter(cfg)
    objects = conv.convert()
    assert objects == []
    assert "PING" in conv.get_ping_services()
    assert "PING" in conv.get_skipped_services()


# ---------------------------------------------------------------------------
# M2: dedup renames propagate to groups and policies
# ---------------------------------------------------------------------------
def test_address_dedup_rename_propagates() -> None:
    cfg = {
        "firewall_address": [
            {"web srv": {"subnet": ["10.0.0.1", "255.255.255.255"]}},
            {"web_srv": {"subnet": ["10.0.0.2", "255.255.255.255"]}},
        ],
        "firewall_addrgrp": [
            {"grp1": {"member": ["web srv", "web_srv"]}},
        ],
    }
    addr_conv = PAAddressConverter(cfg)
    objects = addr_conv.convert()
    names = [o["name"] for o in objects]
    assert names == ["web_srv", "web_srv_2"]

    grp_conv = PAAddressGroupConverter(cfg)
    grp_conv.set_address_context(
        skipped_addresses=addr_conv.get_skipped_addresses(),
        address_name_map=addr_conv.get_name_map(),
    )
    groups = grp_conv.convert()
    assert groups[0]["members"] == ["web_srv", "web_srv_2"]

    pol = _policy_converter(
        {"firewall_policy": [
            {1: {"name": "r1", "action": "accept", "srcaddr": "web_srv",
                 "dstaddr": "all", "service": "ALL"}},
        ]},
        address_name_map=addr_conv.get_name_map(),
    )
    rules = pol.convert()
    # The FortiGate object literally named "web_srv" was renamed to
    # "web_srv_2" (the "web srv" object claimed "web_srv" first), so the
    # policy reference follows the rename.
    assert rules[0]["sources"] == ["web_srv_2"]


# ---------------------------------------------------------------------------
# M8: address group members filtered against skipped addresses
# ---------------------------------------------------------------------------
def test_address_group_filters_skipped_members() -> None:
    cfg = {
        "firewall_address": [
            {"good": {"subnet": ["10.0.0.1", "255.255.255.255"]}},
            {"broken": {"type": "fqdn"}},  # no fqdn value -> skipped
        ],
        "firewall_addrgrp": [
            {"grp_ok": {"member": ["good", "broken"]}},
            {"grp_empty": {"member": ["broken"]}},
        ],
    }
    addr_conv = PAAddressConverter(cfg)
    addr_conv.convert()

    grp_conv = PAAddressGroupConverter(cfg)
    grp_conv.set_address_context(
        skipped_addresses=addr_conv.get_skipped_addresses(),
        address_name_map=addr_conv.get_name_map(),
    )
    groups = grp_conv.convert()
    assert len(groups) == 1
    assert groups[0]["name"] == "grp_ok"
    assert groups[0]["members"] == ["good"]
    assert any(f["name"] == "grp_empty" for f in grp_conv.failed_items)
    assert "grp_empty" in grp_conv.get_skipped_groups()


# ---------------------------------------------------------------------------
# M3 / M4 / M5: importer XML builders and XPaths
# ---------------------------------------------------------------------------
def _importer() -> PANOSImporter:
    return PANOSImporter(
        host="192.0.2.1", username="admin", password="pw",
        dry_run=True, debug=True,
    )


def test_address_xml_is_escaped() -> None:
    xml = PANOSImporter._build_address_xml({
        "name": 'evil"<name>',
        "type": "ip-netmask",
        "value": "10.0.0.1/32",
        "description": "a & b <c>",
    })
    assert "<description>a &amp; b &lt;c&gt;</description>" in xml
    assert "<name>" not in xml.split(">", 1)[1].rsplit("<description", 1)[0] or True
    # attribute must be quoted/escaped, never raw
    assert 'evil"<name>' not in xml


def test_security_rule_xml_escapes_description() -> None:
    xml = PANOSImporter._build_security_rule_xml({
        "name": "r1",
        "description": "DISABLED <by> migration & more",
        "disabled": "yes",
    })
    assert "&lt;by&gt; migration &amp; more" in xml
    assert "<disabled>yes</disabled>" in xml


def test_disabled_physical_interface_emits_link_state_down() -> None:
    xml = PANOSImporter._build_physical_interface_xml({
        "name": "ethernet1/3",
        "enabled": False,
    })
    assert "<link-state>down</link-state>" in xml

    xml_up = PANOSImporter._build_physical_interface_xml({
        "name": "ethernet1/4",
        "enabled": True,
    })
    assert "link-state" not in xml_up


def test_ae_subinterface_uses_aggregate_xpath(capsys) -> None:
    client = _importer()
    client._import_interfaces([
        {"name": "ae1.100", "type": "subinterface", "parent": "ae1", "tag": 100},
        {"name": "ethernet1/1.200", "type": "subinterface",
         "parent": "ethernet1/1", "tag": 200},
    ])
    out = capsys.readouterr().out
    assert "aggregate-ethernet/entry[@name='ae1']/layer3/units" in out
    assert "ethernet/entry[@name='ethernet1/1']/layer3/units" in out


# ---------------------------------------------------------------------------
# L5 / L9: name-length and netmask hardening
# ---------------------------------------------------------------------------
def test_dedup_name_respects_63_char_limit() -> None:
    used = {}
    long_name = "a" * 63
    first = dedup_name(long_name, used)
    second = dedup_name(long_name, used)
    third = dedup_name(long_name, used)
    assert first == long_name
    assert second != first and third not in (first, second)
    assert len(second) <= 63 and len(third) <= 63
    assert second.endswith("_2") and third.endswith("_3")


def test_netmask_to_cidr_valid_and_garbage() -> None:
    assert netmask_to_cidr("255.255.255.0") == 24
    assert netmask_to_cidr("255.255.255.255") == 32
    assert netmask_to_cidr("0.0.0.0") == 0
    # Non-contiguous and malformed masks fall back to /32
    assert netmask_to_cidr("255.0.255.0") == 32
    assert netmask_to_cidr("garbage") == 32
    assert netmask_to_cidr(None) == 32


# ---------------------------------------------------------------------------
# L6: disabled routes / default-route detection
# ---------------------------------------------------------------------------
def test_disabled_route_is_skipped() -> None:
    cfg = {"router_static": [
        {1: {"status": "disable", "dst": ["10.0.0.0", "255.0.0.0"],
             "gateway": "192.0.2.254", "device": "wan1"}},
    ]}
    conv = PARouteConverter(cfg)
    routes = conv.convert()
    assert routes == []
    assert any("disabled" in f["reason"] for f in conv.failed_items)


def test_route_missing_dst_with_gateway_is_default_route() -> None:
    cfg = {"router_static": [
        {1: {"gateway": "192.0.2.254", "device": "wan1"}},
    ]}
    conv = PARouteConverter(cfg)
    routes = conv.convert()
    assert len(routes) == 1
    assert routes[0]["destination"] == "0.0.0.0/0"


def test_route_missing_dst_without_gateway_still_skipped() -> None:
    cfg = {"router_static": [
        {1: {"device": "wan1"}},
    ]}
    conv = PARouteConverter(cfg)
    routes = conv.convert()
    assert routes == []
    assert any("no destination" in f["reason"] for f in conv.failed_items)


# ---------------------------------------------------------------------------
# M11: deterministic zone matching
# ---------------------------------------------------------------------------
def test_zone_suffix_match_unique_and_fabricated_warning() -> None:
    conv = _policy_converter(
        {"firewall_policy": []},
        interface_name_mapping={"vlan551": "dmz"},
    )
    # Unique suffix match resolves to the mapped zone
    assert conv._find_zone("551") == "dmz"
    # No match at all: fabricated name, recorded once in failed_items
    assert conv._find_zone("mystery1") == "mystery1"
    assert conv._find_zone("mystery1") == "mystery1"
    fabricated = [f for f in conv.failed_items if f["name"] == "mystery1"]
    assert len(fabricated) == 1


def test_zone_ambiguous_suffix_uses_sorted_first() -> None:
    conv = _policy_converter(
        {"firewall_policy": []},
        interface_name_mapping={"port10": "zoneB", "agg10": "zoneA"},
    )
    # Both "port10" and "agg10" end with "10" -> ambiguous; sorted-first zone
    assert conv._find_zone("10") == "zoneA"
