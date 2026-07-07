"""Unit tests for shared FortiGate -> FTD helpers.

These focus on management/HA interface detection and default FortiGate
virtual-interface filtering, both of which feed directly into interface
conversion behavior.
"""

from common import collect_mgmt_ha_interfaces, is_default_fortigate_interface  # noqa: E402


def test_collect_mgmt_ha_interfaces_detects_named_and_dedicated_management_links():
    cfg = {
        "system_interface": [
            {"mgmt": {"type": "physical"}},
            {"ha1": {"type": "physical"}},
            {"port3": {"type": "physical", "dedicated-to": "management"}},
            {"port4": {"type": "physical", "dedicated_to": "management"}},
            {"wan1": {"type": "physical"}},
        ],
    }

    detected = collect_mgmt_ha_interfaces(cfg)
    assert {"mgmt", "ha1", "port3", "port4"} <= detected
    assert "wan1" not in detected


def test_collect_mgmt_ha_interfaces_reads_plain_system_ha_dict():
    cfg = {
        "system_interface": [
            {"port1": {"type": "physical"}},
        ],
        "system_ha": {
            "hbdev": "port10 50 port9 50",
            "ha-mgmt-interface": "port8",
            "session-sync-dev": "port7",
        },
    }

    detected = collect_mgmt_ha_interfaces(cfg)
    assert {"port10", "port9", "port8", "port7"} <= detected
    # Numeric HA priorities in hbdev must be ignored.
    assert "50" not in detected


def test_collect_mgmt_ha_interfaces_reads_wrapped_system_ha_sections():
    cfg = {
        "system_interface": [
            {"port1": {"type": "physical"}},
        ],
        "system_ha": [
            {"hbdev": "port6 60"},
            {"settings": {
                "session-sync-dev": ["port5", "30"],
                "ha_mgmt_interface": "port4",
            }},
        ],
    }

    detected = collect_mgmt_ha_interfaces(cfg)
    assert {"port6", "port5", "port4"} <= detected
    assert "60" not in detected
    assert "30" not in detected


def test_is_default_fortigate_interface_matches_known_virtual_interfaces():
    assert is_default_fortigate_interface("modem")
    assert is_default_fortigate_interface("ssl.root")
    assert is_default_fortigate_interface("l2t.customer")
    assert is_default_fortigate_interface("naf.branch")


def test_is_default_fortigate_interface_rejects_normal_interfaces():
    assert not is_default_fortigate_interface("port1")
    assert not is_default_fortigate_interface("wan1")
    assert not is_default_fortigate_interface(None)
