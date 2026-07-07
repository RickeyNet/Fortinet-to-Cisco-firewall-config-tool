#!/usr/bin/env python3
"""
Cisco FTD FDM JSON Config File Reader
======================================
Reads a Cisco FTD configuration from a JSON file and returns the same
normalized dict as FTDReader.read_all(), so the converter can work with
either a live FDM API connection or a saved/exported JSON file.

SUPPORTED FILE FORMATS
-----------------------
1. Normalized export - direct output of FTDReader.read_all() or a manual
   API snapshot saved as-is:

       {
           "network_objects": [...],
           "network_groups":  [...],
           "tcp_ports":       [...],
           ...
       }

2. FDM API snapshot - each section wrapped in an FDM-style paging dict:

       {
           "network_objects": {"items": [...]},
           "network_groups":  {"items": [...]},
           ...
       }

HOW TO CREATE A COMPATIBLE JSON FILE
--------------------------------------
Option A - Save the API reader output:
    Connect to your FTD device via the FDM API once and save the result:

        from ftd_reader import FTDReader
        import json

        reader = FTDReader(host="192.168.1.1", username="admin",
                           password="P@ss", verify_ssl=False)
        reader.authenticate()
        config = reader.read_all()
        with open("ftd_snapshot.json", "w") as f:
            json.dump(config, f, indent=2)

Option B - Export individual sections from the FDM REST API and combine
    them under the keys listed below, then save as a single JSON file.

REQUIRED KEYS
--------------
    network_objects, network_groups, tcp_ports, udp_ports, icmpv4_ports,
    icmpv6_ports, port_groups, interfaces, etherchannel_interfaces,
    security_zones, static_routes, access_rules

Any missing key is treated as an empty list (the converter will skip
the corresponding conversion phase).
"""

import json
import os
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Section keys - must match FTDReader.read_all() output keys
# ---------------------------------------------------------------------------
_SECTIONS: List[str] = [
    "network_objects",
    "network_groups",
    "tcp_ports",
    "udp_ports",
    "icmpv4_ports",
    "icmpv6_ports",
    "port_groups",
    "interfaces",
    "etherchannel_interfaces",
    "security_zones",
    "static_routes",
    "access_rules",
]


def _unwrap(value: Any) -> List[Dict]:
    """Normalize a section value to a plain list.

    Accepts either:
      - A plain list:              [...] → [...]
      - An FDM paging wrapper:    {"items": [...]} → [...]
      - Anything else:            → []
    """
    if isinstance(value, list):
        return value
    if isinstance(value, dict):
        return value.get("items", [])
    return []


class FTDFileReader:
    """Reads a Cisco FTD configuration from a JSON file.

    The returned dict from read_all() is structurally identical to what
    FTDReader.read_all() returns, so fg_ftd_converter can use either reader
    without any changes to the conversion pipeline.
    """

    def __init__(self, file_path: str) -> None:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"FTD config file not found: {file_path}")
        self.file_path = file_path

    def read_all(self) -> Dict[str, Any]:
        """Load and normalize the JSON config file.

        Returns a dict with the same keys as FTDReader.read_all().
        """
        print(f"  Loading FTD config from: {self.file_path}")
        try:
            with open(self.file_path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Failed to parse FTD config file as JSON: {exc}"
            ) from exc

        if not isinstance(raw, dict):
            raise ValueError(
                "FTD config file must be a JSON object (dict) at the top level."
            )

        result: Dict[str, Any] = {}
        for section in _SECTIONS:
            value = raw.get(section, [])
            result[section] = _unwrap(value)
            count = len(result[section])
            label = section.replace("_", " ")
            print(f"    {count:>4}  {label}")

        return result
