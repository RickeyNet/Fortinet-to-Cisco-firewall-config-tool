"""Focused tests for FortiGate -> FTD main/helper orchestration code."""

import argparse
import json

import yaml

import fortigate_converter  # noqa: E402


MIDFILE_SKIP_YAML = """\
system_interface:
  - port1:
      type: physical
      ip: [203.0.113.1, 255.255.255.0]
dlp_filepattern:
  - 1:
      entries: [ {this is not valid yaml
firewall_address:
  - HOST_A:
      subnet: [10.0.0.5, 255.255.255.255]
system_automation-trigger:
  - bad:
      event: should_be_removed
router_static:
  - 1:
      dst: [10.50.0.0, 255.255.255.0]
      gateway: 203.0.113.254
      device: port1
"""


CLI_PASS_THROUGH_YAML = """\
system_interface:
  - port1:
      type: physical
      alias: wan
      ip: [203.0.113.1, 255.255.255.0]
  - port2:
      type: physical
      alias: inside
      ip: [192.168.1.1, 255.255.255.0]
  - port3:
      type: physical
      alias: dmz
      ip: [10.0.0.1, 255.255.255.0]
  - port4:
      type: physical
  - port5:
      type: physical
  - agg1:
      type: aggregate
      member: [port4, port5]
  - lan:
      type: switch
      ip: [172.16.0.1, 255.255.255.0]
system_switch-interface:
  - lan:
      member: [port2]
firewall_address:
  - HOST_A:
      subnet: [10.0.0.5, 255.255.255.255]
firewall_service_custom:
  - WEB:
      tcp-portrange: 80
firewall_policy:
  - 1:
      name: Allow_Web
      srcintf: port1
      dstintf: any
      srcaddr: HOST_A
      dstaddr: all
      service: WEB
      action: accept
"""


def test_preprocess_yaml_file_skips_bad_sections_and_resumes_after_dedent(tmp_path):
    input_file = tmp_path / "fg.yaml"
    input_file.write_text(MIDFILE_SKIP_YAML, encoding="utf-8")

    cleaned = fortigate_converter.preprocess_yaml_file(str(input_file))
    parsed = yaml.safe_load(cleaned)

    assert "dlp_filepattern" not in parsed
    assert "system_automation-trigger" not in parsed
    assert parsed["firewall_address"][0]["HOST_A"]["subnet"][0] == "10.0.0.5"
    assert parsed["router_static"][0][1]["gateway"] == "203.0.113.254"


def test_parse_keyvalue_specs_trims_whitespace_and_last_duplicate_wins():
    parsed = fortigate_converter.parse_keyvalue_specs(
        [" wan = Ethernet1/9 ", "wan=Ethernet1/10"],
        "--map-port",
    )
    assert parsed == {"wan": "Ethernet1/10"}


def test_parse_keyvalue_specs_warns_and_skips_invalid_entries(capsys):
    parsed = fortigate_converter.parse_keyvalue_specs(
        ["missing_equals", "=Ethernet1/9", "wan="],
        "--map-port",
    )
    assert parsed == {}

    out = capsys.readouterr().out
    assert "expected KEY=VALUE format" in out
    assert "empty key or value" in out
    assert fortigate_converter.parse_keyvalue_specs(None, "--map-port") == {}


def test_parse_expansion_specs_parses_counts_and_explicit_port_lists():
    parsed = fortigate_converter.parse_expansion_specs(
        ["agg1=4", "lan = Ethernet1/5, Ethernet1/6 "],
    )
    assert parsed == {
        "agg1": 4,
        "lan": ["Ethernet1/5", "Ethernet1/6"],
    }


def test_parse_expansion_specs_warns_and_skips_invalid_entries(capsys):
    parsed = fortigate_converter.parse_expansion_specs(
        ["missing_equals", "pc=", "empty=, , "],
    )
    assert parsed == {}

    out = capsys.readouterr().out
    assert "expected PC=SPEC format" in out
    assert "empty name or spec" in out
    assert "no valid ports" in out


def test_build_conversion_metadata_uses_model_default_ha_port_and_strips_output():
    args = argparse.Namespace(target_model="ftd-3120", output=" out ", ha_port=None)
    metadata = fortigate_converter.build_conversion_metadata(args)

    assert metadata == {
        "target_model": "ftd-3120",
        "output_basename": "out",
        "ha_port": "Ethernet1/2",
        "schema_version": 1,
    }


def test_build_conversion_metadata_honors_none_and_custom_ha_port():
    none_args = argparse.Namespace(target_model="ftd-4215", output="cfg", ha_port="none")
    custom_args = argparse.Namespace(
        target_model="ftd-4215",
        output="cfg",
        ha_port="Ethernet1/5,Ethernet1/6",
    )

    assert fortigate_converter.build_conversion_metadata(none_args)["ha_port"] is None
    assert (
        fortigate_converter.build_conversion_metadata(custom_args)["ha_port"]
        == "Ethernet1/5,Ethernet1/6"
    )


def test_main_passes_parsed_interface_cli_options_to_converter(monkeypatch, tmp_path):
    calls = {}

    def _record(name):
        def _inner(self, value):
            calls[name] = value
        return _inner

    monkeypatch.setattr(
        fortigate_converter.InterfaceConverter,
        "set_port_mapping",
        _record("map_port"),
    )
    monkeypatch.setattr(
        fortigate_converter.InterfaceConverter,
        "set_promotion_subinterface_vlans",
        _record("promote_portchannel_vlan"),
    )
    monkeypatch.setattr(
        fortigate_converter.InterfaceConverter,
        "set_etherchannel_expansion",
        _record("expand_portchannel"),
    )
    monkeypatch.setattr(
        fortigate_converter.InterfaceConverter,
        "set_etherchannel_promotion",
        _record("promote_portchannel"),
    )
    monkeypatch.setattr(
        fortigate_converter.InterfaceConverter,
        "set_bridgegroup_expansion",
        _record("expand_bridgegroup"),
    )
    monkeypatch.setattr(
        fortigate_converter.InterfaceConverter,
        "set_bridgegroup_promotion",
        _record("promote_bridgegroup"),
    )

    input_file = tmp_path / "fg.yaml"
    input_file.write_text(CLI_PASS_THROUGH_YAML, encoding="utf-8")
    out_base = tmp_path / "out"

    rc = fortigate_converter.main([
        str(input_file),
        "-o",
        str(out_base),
        "--ha-port",
        "none",
        "--map-port",
        "wan=Ethernet1/9",
        "--promote-portchannel-vlan",
        "dmz=100",
        "--expand-portchannel",
        "agg1=4",
        "--promote-portchannel",
        "dmz=Ethernet1/10,Ethernet1/11",
        "--expand-bridgegroup",
        "lan=Ethernet1/12,Ethernet1/13",
        "--promote-bridgegroup",
        "inside=2",
    ])

    assert rc == 0
    assert calls == {
        "map_port": {"wan": "Ethernet1/9"},
        "promote_portchannel_vlan": {"dmz": "100"},
        "expand_portchannel": {"agg1": 4},
        "promote_portchannel": {"dmz": ["Ethernet1/10", "Ethernet1/11"]},
        "expand_bridgegroup": {"lan": ["Ethernet1/12", "Ethernet1/13"]},
        "promote_bridgegroup": {"inside": 2},
    }

    metadata = json.loads((tmp_path / "out_metadata.json").read_text(encoding="utf-8"))
    assert metadata["ha_port"] is None
