"""Unit tests for the FortiGate -> FTD address converter (TODO P3).

Covers HOST/NETWORK/RANGE/FQDN subtype detection, netmask-to-CIDR
conversion, factory-default/invalid-object filtering, name sanitization
and collision handling, and address value validation.
"""
from typing import Any, Dict, List

from address_converter import AddressConverter  # noqa: E402
from common import netmask_to_cidr, sanitize_name  # noqa: E402


def _convert(addresses: List[Dict[str, Any]]):
    conv = AddressConverter({"firewall_address": addresses})
    return conv, conv.convert()


def _single(addresses: List[Dict[str, Any]]) -> Dict[str, Any]:
    _, result = _convert(addresses)
    assert len(result) == 1
    return result[0]


# ---------------------------------------------------------------------------
# Subtype detection and value formatting
# ---------------------------------------------------------------------------

def test_subnet_with_full_mask_is_host_without_cidr_suffix():
    obj = _single([{"SRV1": {"subnet": ["10.1.2.3", "255.255.255.255"]}}])
    assert obj["subType"] == "HOST"
    assert obj["value"] == "10.1.2.3"
    assert obj["type"] == "networkobject"


def test_subnet_with_partial_mask_is_network_in_cidr_notation():
    obj = _single([{"NET24": {"subnet": ["10.0.2.0", "255.255.255.0"]}}])
    assert obj["subType"] == "NETWORK"
    assert obj["value"] == "10.0.2.0/24"


def test_slash30_network():
    obj = _single([{"P2P": {"subnet": ["10.0.0.4", "255.255.255.252"]}}])
    assert obj["subType"] == "NETWORK"
    assert obj["value"] == "10.0.0.4/30"


def test_iprange_is_range_with_dash_value():
    obj = _single([{
        "RNG": {"type": "iprange", "start-ip": "10.0.0.1", "end-ip": "10.0.0.10"}
    }])
    assert obj["subType"] == "RANGE"
    assert obj["value"] == "10.0.0.1-10.0.0.10"


def test_iprange_with_same_start_and_end_collapses_to_host():
    obj = _single([{
        "ONE": {"type": "iprange", "start-ip": "10.0.0.5", "end-ip": "10.0.0.5"}
    }])
    assert obj["subType"] == "HOST"
    assert obj["value"] == "10.0.0.5"


def test_fqdn_gets_fqdn_subtype_and_dns_resolution():
    obj = _single([{"WebSite": {"type": "fqdn", "fqdn": "www.example.com"}}])
    assert obj["subType"] == "FQDN"
    assert obj["value"] == "www.example.com"
    assert obj["dnsResolution"] == "IPV4_ONLY"


def test_non_fqdn_objects_have_no_dns_resolution_field():
    obj = _single([{"SRV1": {"subnet": ["10.1.2.3", "255.255.255.255"]}}])
    assert "dnsResolution" not in obj


def test_comment_becomes_description():
    obj = _single([{
        "SRV1": {"subnet": ["10.1.2.3", "255.255.255.255"], "comment": "east server"}
    }])
    assert obj["description"] == "east server"


# ---------------------------------------------------------------------------
# Filtering: factory defaults, empty and invalid values
# ---------------------------------------------------------------------------

def test_factory_default_objects_ignored_without_failure_report():
    conv, result = _convert([
        {"all": {"subnet": ["0.0.0.0", "0.0.0.0"]}},
        {"SSLVPN_TUNNEL_ADDR1": {"type": "iprange",
                                 "start-ip": "10.212.134.200",
                                 "end-ip": "10.212.134.210"}},
        {"none": {"subnet": ["0.0.0.0", "255.255.255.255"]}},
        {"KEEP_ME": {"subnet": ["10.0.0.0", "255.255.255.0"]}},
    ])
    assert [o["name"] for o in result] == ["KEEP_ME"]
    # Defaults are registered as skipped so groups/policies drop the refs...
    assert {"all", "SSLVPN_TUNNEL_ADDR1", "none"} <= conv.get_skipped_addresses()
    # ...but they are NOT reported as failures needing attention.
    assert conv.failed_items == []


def test_empty_value_skipped_and_reported():
    conv, result = _convert([{"EMPTY": {}}])
    assert result == []
    assert "EMPTY" in conv.get_skipped_addresses()
    assert len(conv.failed_items) == 1
    assert conv.failed_items[0]["reason"] == "empty value"


def test_malformed_subnet_value_skipped_and_reported():
    # Single-element subnet list yields the raw token, which fails validation.
    conv, result = _convert([{"BAD": {"subnet": ["garbage"]}}])
    assert result == []
    assert "BAD" in conv.get_skipped_addresses()
    assert any("invalid value" in f["reason"] for f in conv.failed_items)


def test_empty_or_malformed_entries_do_not_crash():
    conv, result = _convert([None, {}, {"NAME": "not-a-dict"},
                             {"OK": {"subnet": ["10.0.0.0", "255.255.255.0"]}}])
    assert [o["name"] for o in result] == ["OK"]


# ---------------------------------------------------------------------------
# Name sanitization and collision handling
# ---------------------------------------------------------------------------

def test_names_sanitized_to_alphanumerics_and_underscores():
    obj = _single([{"My Object #1!": {"subnet": ["10.0.0.0", "255.255.255.0"]}}])
    assert obj["name"] == "My_Object_1"


def test_colliding_sanitized_names_get_numeric_suffix():
    conv, result = _convert([
        {"My Obj": {"subnet": ["10.0.0.0", "255.255.255.0"]}},
        {"My@Obj": {"subnet": ["10.0.1.0", "255.255.255.0"]}},
    ])
    assert [o["name"] for o in result] == ["My_Obj", "My_Obj_2"]
    # The rename map keeps the first occurrence for reference-following.
    assert conv.get_address_name_mapping()["My_Obj"] == "My_Obj"


def test_literal_x2_name_cannot_collide_with_generated_suffix():
    _, result = _convert([
        {"Dup": {"subnet": ["10.0.0.0", "255.255.255.0"]}},
        {"Dup ": {"subnet": ["10.0.1.0", "255.255.255.0"]}},   # -> Dup_2
        {"Dup_2": {"subnet": ["10.0.2.0", "255.255.255.0"]}},  # literal Dup_2
    ])
    names = [o["name"] for o in result]
    assert len(names) == len(set(names)) == 3
    assert names[0] == "Dup" and names[1] == "Dup_2"


def test_ip_address_used_as_object_name_is_kept():
    obj = _single([{"192.168.10.50": {"subnet": ["192.168.10.50", "255.255.255.255"]}}])
    assert obj["name"] == sanitize_name("192.168.10.50") == "192_168_10_50"
    assert obj["value"] == "192.168.10.50"


# ---------------------------------------------------------------------------
# Netmask -> CIDR conversion (shared helper used by the converter)
# ---------------------------------------------------------------------------

def test_netmask_to_cidr_common_masks():
    assert netmask_to_cidr("255.255.255.255") == 32
    assert netmask_to_cidr("255.255.255.252") == 30
    assert netmask_to_cidr("255.255.255.0") == 24
    assert netmask_to_cidr("255.255.0.0") == 16
    assert netmask_to_cidr("255.0.0.0") == 8
    assert netmask_to_cidr("0.0.0.0") == 0


def test_netmask_to_cidr_invalid_input_fails_closed_to_host():
    assert netmask_to_cidr("garbage") == 32
    assert netmask_to_cidr("255.255.255") == 32
    assert netmask_to_cidr(None) == 32


# ---------------------------------------------------------------------------
# Address value validation
# ---------------------------------------------------------------------------

def test_value_validation_accepts_cidr_range_and_host():
    conv = AddressConverter({})
    assert conv._is_valid_address_value("10.0.0.0/24")
    assert conv._is_valid_address_value("10.0.0.1-10.0.0.10")
    assert conv._is_valid_address_value("10.0.0.1")


def test_value_validation_rejects_malformed_values():
    conv = AddressConverter({})
    assert not conv._is_valid_address_value("")
    assert not conv._is_valid_address_value("   ")
    assert not conv._is_valid_address_value("/24")          # missing IP part
    assert not conv._is_valid_address_value("10.0.0.0/")    # missing prefix
    assert not conv._is_valid_address_value("10.0.0.0/33")  # prefix out of range
    assert not conv._is_valid_address_value("10.0.0.0/a")   # non-numeric prefix
    assert not conv._is_valid_address_value("1/2/3")        # too many slashes
    assert not conv._is_valid_address_value("10.0.0.1-")    # empty range end
    assert not conv._is_valid_address_value("nodots")       # not an IPv4 shape
