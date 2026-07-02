# Release Notes

## v1.6.0 - Link Aggregation Scale-Up (FTD & Palo Alto), SNMPv3, VLAN Conflict Resolution

### Overview

Adds the ability to scale up link aggregation during migration - grow port channels, promote plain physical interfaces into new port channels, and grow virtual-switch bridge groups with extra member links - on both the FortiGate -> FTD and FortiGate -> Palo Alto paths (mapped to the closest PAN-OS constructs on the Palo Alto side). Also includes STIG-compliant SNMPv3 push for FDM-managed FTDs, automatic VLAN conflict resolution, restricted build profiles for cleanup-free executables, an expanded GUI theme set, tightened importer update-on-existing logic, quieter conversion summaries (management/HA ports and factory-default services are ignored instead of reported as failures), and interface conversion/cleanup reliability fixes.

### New Features

**Scale up link aggregation during FortiGate -> FTD migration**

Previously interface membership was copied 1:1 from the source. Three new options let you add bandwidth and redundancy on the Cisco side during conversion instead:

- **EtherChannel member expansion (`--expand-portchannel`)** - Grow an existing FortiGate port channel to more 10G member links on the FTD side. SPEC is either a target total member count (e.g. `WAN_LAG=4`) or an explicit comma-separated list of FTD ports to add (e.g. `SRV_LAG=Ethernet1/5,Ethernet1/6`). Repeatable.
- **Physical interface -> EtherChannel promotion (`--promote-portchannel`)** - Migrate a plain (non-aggregate) FortiGate physical interface as a NEW FTD EtherChannel so it can carry multiple 10G links. The original FTD port becomes the first member and extra members are added per SPEC. The interface's MTU moves onto the port channel, which is left without an IP - in this design L3 addresses live on the VLAN subinterfaces riding on the channel. Interfaces that carry VLAN subinterfaces are not eligible (they convert normally with a warning).
- **Bridge group member expansion (`--expand-bridgegroup`)** - Grow a FortiGate virtual switch (`system_switch-interface`) -> FTD bridge group (BVI) with more member links. SPEC is a target total member count or an explicit list of FTD ports to add. Added members get unique names, routed mode, and join the bridge group's security zone; the IP correctly stays on the BVI (bridge groups are L3, unlike port channels).
- **Physical interface -> bridge group promotion (`--promote-bridgegroup`)** - Migrate a plain FortiGate physical interface as a NEW FTD bridge group (BVI) so its subnet can span several bridged ports on the Cisco side. The original FTD port becomes the first member and extra members are added per SPEC. Unlike port-channel promotion, the interface's IP and MTU move onto the BVI (a bridge group is the Layer-3 interface for the bridged segment). Interfaces with VLAN subinterfaces are not eligible.
- **Interface Aggregation builder (GUI)** - In the GUI these four options are driven by a single per-interface builder on the Convert tab. Add a row per interface, pick the interface from a dropdown, and supply a member count or explicit port list; the builder auto-detects Expand vs Promote and Port-Channel vs Bridge Group from the interface's type (both remain editable to override). The dropdown is populated by parsing the selected FortiGate config and lists only valid targets - it shows each interface's logical name (`alias`) when present and hides interfaces that aren't aggregatable: existing port-channel/bridge-group member ports (only the parent is shown), the dedicated management port (`set dedicated-to management` or a conventional `mgmt*` name), and HA ports (`hbdev`/`ha-mgmt-interface` from `config system ha`, or a conventional `ha*` name). Refresh notifications use a themed dialog that matches the active GUI theme.
- **Shared guardrails** - Out-of-range, malformed, or already-assigned ports are warned and skipped, and the conversion's Port Analysis estimate accounts for the extra members. Default behavior is unchanged when none of these options are used.

**Scale up interfaces during FortiGate -> Palo Alto migration**

The same four converter flags also work in `pa_converter.py`, mapped to PAN-OS equivalents:

- **Port channel -> aggregate-ethernet (`--expand-portchannel`, `--promote-portchannel`)** - Grow an existing FortiGate aggregate to more `aggregate-ethernet` (LACP) members, or promote a plain physical interface into a NEW `ae`. SPEC is a target total member count or a comma-separated list of PAN-OS ports to add (e.g. `ethernet1/5,ethernet1/6`). Unlike FTD (where the port channel is left IP-less), the IP/MTU stay on the `ae` - in PAN-OS the aggregate-ethernet is itself the Layer-3 interface.
- **Bridge group -> Layer-2 VLAN segment (`--expand-bridgegroup`, `--promote-bridgegroup`)** - PAN-OS has no BVI, so a FortiGate virtual switch (`system_switch-interface`) is now converted to a Layer-2 segment instead of being skipped: member ports become `layer2` interfaces grouped in a VLAN object, and the switch's IP moves onto a `vlan.N` interface (the SVI, the Layer-3 analog of an FTD bridge group). Expansion adds more Layer-2 members; promotion turns a plain physical interface into a new Layer-2 segment with its IP on the SVI. Members land in a dedicated Layer-2 security zone; the SVI lands in a Layer-3 zone, so routes and policies that reference the switch resolve to `vlan.N`.
- **Importer support** - The PAN-OS XML importer gained builders and XPaths for the new interface types (`layer2-member`, `vlan-object`, `vlan-interface`) and now emits `layer2` zones in addition to `layer3` zones.
- **GUI** - The Interface Aggregation builder on the Convert tab is shown for FortiGate -> Palo Alto as well as FortiGate -> FTD. The section label and port-format hints retarget to the active platform (`ethernet1/5` for PAN-OS). The same Expand/Promote x Port-Channel/Bridge-Group rows drive both targets.
- **Default behavior is unchanged** when none of the flags are used, except that FortiGate switch interfaces, previously dropped on the PAN-OS path, now convert to Layer-2 VLAN segments.

**SNMPv3 configuration for FDM-managed FTD (new SNMP tab + CLI)**

FDM does not expose SNMPv3 in its GUI - locally managed FTDs must be configured through the REST API. The tool now does this end to end (STIG CASA-ND-001050 / CASA-ND-001070):

- **New `ftd_snmp_config.py` CLI** - Creates/updates the SNMPv3 user (Auth/Priv: SHA or SHA256 auth + AES128/192/256 privacy, AES256 default), resolves the source interface by logical name (physical, EtherChannel, or subinterface), then creates/updates a network object and SNMP host per manager. Idempotent - re-running with new values updates in place. Optional `--deploy` deploys the staged changes.
- **Multiple SNMP managers** - `--nms-ip` accepts comma-separated values or repeated flags; every manager shares the SNMPv3 user and source interface, and each gets its own network object and SNMP host. Object names are always suffixed with the manager IP, so separate pushes are additive - each management tool can get its own SNMPv3 user by running the push once per tool without overwriting earlier configs.
- **New "SNMP (FTD)" GUI tab** - Visible only when the target platform is Cisco FTD. Connection fields plus SNMP manager IP(s) (comma-separated for multiple), SNMPv3 user, algorithms, masked auth/privacy password fields, source interface, optional location/contact, poll/trap toggles, and deploy-after-push.
- **Custom SNMP host names in the GUI** - New optional "SNMP Host Name" field exposes the CLI's `--host-object-name`, so the per-manager SNMP host objects can carry a meaningful name (e.g. `SolarWinds_10_0_0_50`) instead of the generic `snmpv3-host_<ip>`.
- **Selectable trap events** - New `--trap-events` flag and a "Trap Events (device-wide)" checkbox panel in the GUI select which event types fire SNMP traps (link up/down, cold/warm start, syslog, failover, CPU/memory thresholds, and the rest of the FDM SNMPServer trap enum). Left unset, the device's current trap events are untouched; `none` disables all.
- **SNMP location and contact** - Optional `--location` / `--contact` flags (and matching GUI fields) set the device-global sysLocation/sysContact via the FDM SNMPServer settings object. Omitted fields leave the device's existing values unchanged; FDM length/semicolon restrictions are validated up front.
- **Credential hygiene** - `--auth-password` / `--priv-password` are redacted from the echoed command line and scrubbed from exception output, same as device passwords. Passwords are validated to the 8-character FDM minimum; NoAuth security level is not offered, and AUTH-only prints a STIG compliance warning.
- **Cleanup support** - New `--delete-snmp` flag (and "SNMP Hosts & Users" checkbox in the Cleanup tab) removes SNMP hosts then users; included in `--delete-all` ahead of interfaces and address objects so the SNMP host's references never block deletion.

**Automatic VLAN conflict resolution (FortiGate -> FTD conversion)**

FortiGate allows VLAN interfaces on different parents (physical ports, port channels, virtual switches) to share the same VLAN ID; FTD requires VLAN IDs to be unique device-wide, so the duplicate subinterfaces failed to import. The converter now resolves these conflicts automatically in a new Phase 5B pass:

- **Priority parents keep their VLAN IDs** - Subinterfaces on EtherChannels (port channels) and virtual switches (FTD bridge groups) always keep their original VLAN numbers.
- **Physical-parent subinterfaces are remapped** - Conflicting subinterfaces on physical interfaces move to the nearest unused VLAN ID. `vlanId`, `subIntfId`, and the `hardwareName` suffix are updated together (e.g. `Ethernet1/3.100` -> `Ethernet1/3.102`).
- **References stay intact** - Logical names never change, so security zones, routes, and policies are unaffected. Zone generation runs after the remap and picks up corrected hardware names automatically.
- **No cascade displacement** - A remap never takes a VLAN ID that another subinterface legitimately owns.
- **Fully visible** - Every remap is printed during conversion, appended to the interface description (`[remapped from VLAN 100]`), and counted in the conversion summary (`Duplicate VLAN IDs remapped: N`). If two priority parents collide, the second is remapped with an explicit warning.

**Restricted build profiles**

- New reusable build profiles allow producing limited executables; `--no-cleanup` / `fortigate_to_ftd_no_cleanup` builds omit the Cleanup tab and cleanup-related bundles entirely. The runtime profile carries `features.cleanup`; the GUI and PyInstaller imports respect it.

### Fixes

**FTD conversion - bridge group members emitted twice**

FortiGate virtual-switch member ports were being converted both as bridge group (BVI) members and as standalone physical interfaces, producing duplicate physical-interface payloads for the same hardware port. Switch members are now excluded from standalone conversion, the same way EtherChannel members already were.

**FTD cleanup - EtherChannel/bridge group deletion on HA pairs**

Deleting EtherChannels (and bridge groups) failed on HA-enabled appliances with an "HA monitoring is on" error, because the pre-delete disable step was skipped whenever the API reported `monitorInterface` as off or omitted the field:

- The HA-monitor disable can now be **forced** - it PUTs `monitorInterface: false` even when the GET response claims monitoring is already off.
- If a DELETE is still rejected with an HA-monitoring error, the cleanup force-disables monitoring and **retries the delete once**; both errors are reported together if it still fails.
- Read-only `links` metadata is stripped from the disable PUT so FDM does not reject it.

### Improvements

**Conversion - FortiGate infrastructure ports and factory-default services ignored (FTD & Palo Alto)**

- **Dedicated management and HA ports are no longer converted** - The dedicated management port (`set dedicated-to management`, or a conventional `mgmt*`/`management` name) and HA heartbeat/HA-management/session-sync ports (`hbdev`, `ha-mgmt-interface`, `session-sync-dev` from `config system ha`, or a conventional `ha*` name) are FortiGate infrastructure links with no equivalent on the target firewall. Previously only interfaces named exactly `ha` or `mgmt` were skipped - and even those were reported as failures - so ports like `mgmt1` or hbdev members were converted (consuming a target port) or failed into the conversion summary. They are now printed as `Ignored` during conversion and excluded from the failed-items summary. VLAN subinterfaces riding on an ignored port are ignored with them. The GUI Interface Aggregation builder already hid these ports from its dropdown; the converters now use the same detection, and the `config system ha` parsing handles every YAML shape the parser can emit.
- **More factory-default services silently ignored** - `NONE`, `GRE`, `AH`, `ESP`, and `OSPF` join `ALL`/`ALL_ICMP`/etc. in the factory-default service list: they are ignored during conversion instead of being reported as skipped/failed items. Service groups and policies referencing them are still cleaned up as before. Custom (user-created) non-port services are still reported, since those may need manual attention.

**GUI themes - three new themes, new default, Sandstone redesign**

- **New "Default" theme** - Neutral dark gray with light gray accents; now the theme on launch (previously Coral).
- **New "Voyager" theme** - Deep navy-blue background with gold accents.
- **New "Light" theme** - The first light theme: light gray background, white input/output fields, blue accents.
- **Sandstone redesigned** - Now a dark olive-green palette with warm orange accents and muted green output text, replacing the previous lighter red-accented look.
- All themes remain switchable live from the dropdown in the top-right corner; help-tab descriptions updated to match.

**How-To Guide - keyword search**

- The How-To Guide tab now has a search bar. Type a keyword and use Find Next / Find Prev (or Enter / Shift+Enter) to jump through matches; every match is highlighted, the current one is emphasized and scrolled into view, and a counter shows the position (e.g. "2 of 8"). Search is case-insensitive and wraps around, mirroring the Config Viewer's search.

**FTD import - update-on-existing matching**

- **Unchanged groups and rules now skip correctly** - Payload comparison is recursive and ignores FDM bookkeeping fields (`id`, `version`, `links`) at every nesting level, so a group whose member refs differ only by server-side metadata is recognized as identical and skipped instead of re-PUT (avoids FDM "no changes detected" rejections).
- **Non-name duplicates resolve to updates** - When a duplicate is keyed on something other than the object name, the importer now finds and updates the existing object: EtherChannels match on `hardwareName` (Port-channel ID), subinterfaces on `vlanId`/`subIntfId` under the same parent. Exact name matches always take priority.
- **Cleaner update PUTs** - Read-only `links` metadata is stripped from update payloads.

**Code quality**

- Complete type hints added across the codebase - every function now has parameter and return annotations, with a clean pyright run (0 errors).
- Non-ASCII dashes (em/en) in documentation and comments normalized to ASCII hyphens.

---

## v1.5.0 - Major Release (since v1.4.0)

### Overview

Public release following v1.4.0. Adds Palo Alto and Cisco FTD -> FortiGate conversion paths, GUI source/target improvements, FTD import reliability fixes, and security hardening around credential handling in the GUI output window.

### Security

Several paths could expose operator passwords in the GUI output window:

- **Command-line echo** - The GUI printed the full argv on every run, including `--password` values, as a banner line before the worker started.
- **PAN-OS authentication** - Keygen used HTTP GET with credentials in the URL query string; connection-error tracebacks could include the full URL.
- **FTD authentication** - Failed auth responses dumped raw `response.text`, which FDM can echo back including the submitted password.
- **API error output** - Additional sites across the FTD importer, cleanup, FTD->FortiGate reader, and PAN-OS validation could print raw response bodies instead of parsed error descriptions.
- **Exception handler** - Uncaught exceptions could surface Import/Cleanup tab passwords in tracebacks.

Fixes applied:

- `_redact_argv()` replaces values for `--password`, `-p`, `--api-key`, and `--token` with `***REDACTED***` in echoed command lines (the worker still receives real credentials).
- PAN-OS keygen switched to POST form body; auth and connection errors use parsed messages and `_scrub_secrets()`.
- FTD auth uses `_safe_auth_error()` instead of raw response dumps; connection errors are scrubbed.
- FTD/PAN-OS error paths emit parsed FDM/PAN-OS error descriptions only; the GUI catch-all handler scrubs Import/Cleanup passwords from exceptions and tracebacks.

**Action recommended:** If you ran v1.4.0, any pre-release build, or shared the GUI output window (screen share, screenshots, saved logs), **rotate affected admin passwords**.

### New Features

Two new conversion pipelines produce FortiGate CLI `.conf` files for manual apply (CLI paste or web UI restore). See README for application steps.

| | Palo Alto -> FortiGate | Cisco FTD -> FortiGate |
|--|----------------------|----------------------|
| **Input** | PAN-OS XML running config | FDM REST API (live) or exported JSON |
| **Output** | FortiGate `.conf` | FortiGate `.conf` |
| **Objects converted** | Addresses, groups, services, policies, routes, interfaces, zones | Same |
| **GUI** | "Palo Alto" source locks Target to FortiGate; XML file browser | "Cisco FTD" source locks Target to FortiGate; host/username fields; password via secure dialog |

Packages: `PaloAltoToFortiGateTool/`, `CiscoFTDToFortiGateTool/`.

### Improvements

**GUI**

- Target combobox visually locks (`disabled`) when only one target applies to the selected source.
- Custom Convert/Import output base names survive source and target changes.
- Import and Cleanup tabs fully disabled (not just retitled) when target is FortiGate.
- Import/Cleanup tab titles and section headers update per target platform (FTD, PAN-OS, FortiGate N/A).
- "HA Port" label switches to "FTD Username:" when Cisco FTD is the source.

**FTD import**

- Skip PUT when payload is semantically identical to the existing object (`[SKIP] identical to existing`).
- Session-level 401 hook auto-refreshes FDM tokens during long imports (~30-minute JWT lifetime).
- Update failure messages include HTTP status code.

**Other**

- Optional flair phrasing in FTD cleanup/auth output; `[OK]` / `[SKIP]` / `[FAIL]` tags preserved for log parsing.
- Fixed frozen Windows exe crash when loading the window icon; `build.bat` bundles `app_icon.ico` in the onefile build.

### Dependencies

Runtime minimums in `requirements.txt`: `pyyaml>=6.0.3`, `requests>=2.32.5`, `urllib3>=2.6.3`. Build and dev dependencies updated at release time.

---

## v1.4.0 - Update Existing Objects, Cleanup Password Protection, Python 3.14

### Overview

Adds the ability to update existing firewall objects during import (instead of skipping duplicates), password protection for the cleanup feature, and upgrades the build toolchain to Python 3.14.

---

### New Features

#### Update Existing Objects (FTD Import)

- **Update-by-default** - When an object already exists on the target FTD, the importer now automatically updates it to match the new configuration via GET + merge + PUT instead of skipping it
- **Generic object lookup** - New `_get_object_by_name_from_endpoint()` method uses filter parameters with paginated fallback to find existing objects across all endpoint types
- **Merge-and-PUT pattern** - Retrieves the existing object (to get `id`/`version`), merges the new payload on top, and PUTs it back
- **Works for all object types** - Address objects, address groups, service objects, service groups, security zones, static routes, access rules, EtherChannels, bridge groups, and subinterfaces
- **`--skip-existing` flag** - Opt out of updates and revert to the previous skip-on-duplicate behavior
- **GUI checkbox** - "Update existing objects" checkbox in the Import tab (checked by default)
- **Updated statistics** - `print_statistics()` now shows an "Updated:" count for every object type
- **Threaded support** - Update detection works correctly with the threaded import pool via the `"UPDATED:"` result prefix convention

#### Cleanup Password Protection

- **Password-gated cleanup** - A password prompt appears every time "Start Cleanup" is clicked in the GUI, preventing accidental deletion of firewall objects
- **Built-in default password** - A PBKDF2-HMAC-SHA256 hashed password is baked into the source code at build time (no external files required)
- **User-changeable password** - "Change Cleanup Password" button creates a `cleanup_auth.json` override file next to the application
- **Automatic fallback** - If `cleanup_auth.json` is deleted, the app falls back to the built-in default password (users are never locked out)
- **Reset to default** - "Reset to Default Password" button removes the override file and reverts to the built-in password
- **`set_cleanup_password.py` utility** - Change the built-in default password before building the exe
- **Standard library only** - Uses `hashlib.pbkdf2_hmac` (no third-party crypto dependencies), fully portable across machines

#### Python 3.14 Build

- **Build toolchain upgraded** - `build.bat` now uses `py -3.14` explicitly for both pip and PyInstaller
- **Modern Python features** - Union type syntax (`str | None`), improved performance, and full `cryptography` library compatibility

---

### GUI Changes

- **Import tab** - New "Update existing objects (uncheck to skip duplicates)" checkbox at row 8
- **Cleanup tab** - New "Change Cleanup Password" and "Reset to Default Password" buttons (right-aligned in button row)
- **Cleanup tab** - Password prompt dialog before every cleanup operation

---

### CLI Changes

#### FTD Importer (`ftd_api_importer.py`)

| Flag | Description |
|------|-------------|
| `--skip-existing` | Skip objects that already exist instead of updating them (default: update) |

#### Utility Scripts

| Script | Description |
|--------|-------------|
| `set_cleanup_password.py <password>` | Set the built-in default cleanup password (rebuild exe afterward) |

---

### Files Added

| File | Purpose |
|------|---------|
| `cleanup_auth.py` | Cleanup password authentication module (PBKDF2 hashing, fallback logic) |
| `set_cleanup_password.py` | Utility to change the built-in default cleanup password |

### Files Modified

| File | Changes |
|------|---------|
| `gui_app.py` | Update-existing checkbox, cleanup password UI, password gate on cleanup |
| `FortiGateToFTDTool/ftd_api_importer.py` | `_get_object_by_name_from_endpoint()`, `_update_existing_object()`, update logic in all create methods, `--skip-existing` flag, updated statistics |
| `build.bat` | Python 3.14 (`py -3.14`), `cleanup_auth` hidden import |
| `README.md` | Cleanup password documentation, file listing updates |

---

---

## v1.2.0 - Theme Selector

### Overview

Adds a live theme selector to the GUI with two built-in themes. The theme system is data-driven - adding new themes only requires adding an entry to the `THEMES` dictionary in `gui_app.py`.

---

### New Features

#### Theme Engine

- **Live theme switching** - Theme dropdown in the top toolbar (right-aligned) allows switching themes without restarting the app
- **Ocean Coral** (default) - Dark teal background with coral accents and teal highlights
- **Chris** - Hot pink background with neon green accents and blue text

#### Theme Architecture

- All color values defined in a single `THEMES` dictionary for easy customization
- Theme applies to all ttk-styled widgets (frames, labels, buttons, tabs, entries, comboboxes, checkbuttons, spinboxes, scrollbars)
- Raw tk widgets (Text, Listbox) are registered and recolored on theme change
- Button text color is theme-aware via `btn_fg` key (ensures readability on colored button backgrounds)

#### Adding Custom Themes

Add a new entry to the `THEMES` dict in `gui_app.py` with these keys:

| Key        | Description                         |
|------------|-------------------------------------|
| `bg`       | Root/frame background               |
| `input`    | Entry/combobox field background     |
| `fg`       | Primary text color                  |
| `fg_dim`   | Secondary/disabled text             |
| `accent`   | Accent color (active elements)      |
| `accent_d` | Dark accent (selected tabs, pressed)|
| `accent_h` | Hover accent                        |
| `border`   | Border color                        |
| `btn_bg`   | Button background                   |
| `btn_fg`   | Button text color                   |
| `tab_bg`   | Inactive tab background             |
| `out_bg`   | Output console background           |
| `out_fg`   | Output console text color           |

---

### Other Changes

- Renamed color variables from `_PURPLE`/`_PURPLE_D`/`_PURPLE_H` to `_ACCENT`/`_ACCENT_D`/`_ACCENT_H` for clarity

---

---

## v1.1.0 - Palo Alto PAN-OS Target Support

### Overview

Adds Palo Alto PAN-OS as a second conversion target alongside Cisco FTD. FortiGate configurations can now be migrated to either Cisco FTD or Palo Alto firewalls using the same source YAML input. The Palo Alto implementation includes a full conversion engine, XML API importer, bulk cleanup tool, and GUI integration. **Note:** Palo Alto support is in beta - the base is implemented but live device testing is still in progress.

---

### New Features

#### Palo Alto Conversion Engine (`FortiGateToPaloAltoTool/`)

- **Address Objects** - Hosts (ip-netmask /32), subnets (ip-netmask), IP ranges (ip-range), and FQDNs with PAN-OS name sanitization (63-char max, alphanumeric/underscore/hyphen/period)
- **Address Groups** - Static address groups with nested group support
- **Service Objects** - TCP/UDP port objects; dual-protocol services automatically split into separate PAN-OS objects (one protocol per object requirement)
- **Service Groups** - Port groups with automatic split-service reference resolution and member deduplication
- **Security Rules** - FortiGate policies mapped to PAN-OS security rules with zone-based source/destination, address objects, service objects, and action mapping (accept->allow, deny->deny); logging configurable
- **Static Routes** - IPv4 routes using CIDR notation directly (no separate gateway objects); blackhole route filtering
- **Interfaces** - Physical interfaces, VLAN subinterfaces, and aggregate-ethernet (LACP) with model-aware port mapping
- **Zones** - Auto-generated from interface assignments
- **10 output JSON files** per conversion including summary statistics and metadata

#### Supported Palo Alto Models (6)

| Model   | Description  |
|---------|--------------|
| PA-440  | Entry-level  |
| PA-450  | Entry-level  |
| PA-460  | Entry-level  |
| PA-3220 | Mid-range    |
| PA-3250 | Mid-range    |
| PA-5220 | Enterprise   |

#### PAN-OS XML API Importer (`panos_api_importer.py`)

- **Dependency-ordered import** - Zones -> addresses -> address groups -> services -> service groups -> routes -> security rules
- **API key authentication** - Automatic key generation via PAN-OS keygen endpoint
- **Dry-run mode** - Preview import without making changes
- **Optional auto-commit** - Commit configuration changes after import via `--commit`
- **Debug mode** - Inspect XML API payloads
- **SSL handling** - Self-signed certificate support

#### PAN-OS Bulk Cleanup (`panos_api_cleanup.py`)

- **Selective or full deletion** - Delete specific object types or all custom objects
- **Reverse dependency order** - Security rules -> service groups -> services -> address groups -> addresses -> routes -> zones
- **Dry-run mode** - Preview deletions
- **Interactive confirmation** - Safety prompt before destructive operations
- **Optional auto-commit** - Commit after cleanup

#### GUI Updates

- **Platform selector** - Dropdown at top of GUI to switch between Cisco FTD and Palo Alto PAN-OS
- **Dynamic tab updates** - Convert, Import, and Cleanup tabs adapt to selected platform
- **Palo Alto model selection** - PA model dropdown replaces FTD models when PA is selected
- **Commit toggle** - "Commit after import/cleanup" checkbox for PAN-OS operations

---

### Key Differences: Palo Alto vs Cisco FTD

| Aspect | Palo Alto PAN-OS | Cisco FTD |
|--------|------------------|-----------|
| API | XML API (keygen auth) | REST API (OAuth 2.0) |
| Service objects | One protocol per object (auto-split) | Supports dual-protocol |
| Routes | CIDR notation directly | Separate gateway network objects |
| Zones | Auto-generated from interfaces | Defined in config |
| Import concurrency | Sequential | Multithreaded (`--workers`) |
| HA configuration | Managed externally | Configurable via `--ha-port` |
| Name max length | 63 characters | Varies |

---

### CLI Quick Reference

```bash
# Convert for Palo Alto
python FortiGateToPaloAltoTool/pa_converter.py config.yaml --target-model pa-3220 --pretty

# List PA models
python FortiGateToPaloAltoTool/pa_converter.py --list-models

# Import to PAN-OS
python FortiGateToPaloAltoTool/panos_api_importer.py --host 10.0.0.1 --username admin --commit

# Dry-run import
python FortiGateToPaloAltoTool/panos_api_importer.py --host 10.0.0.1 --username admin --dry-run

# Cleanup PAN-OS
python FortiGateToPaloAltoTool/panos_api_cleanup.py --host 10.0.0.1 --username admin --delete-all --dry-run
```

---

### Known Limitations (Palo Alto)

- ICMP, ICMP6, IP, IPIP, GRE, ESP, and AH protocol services are skipped during conversion
- Application field in security rules is set to "any" (manual tuning recommended post-migration)
- Loopback, tunnel, and switch interfaces are not converted
- Only IPv4 addresses and routes are supported
- Live device testing is in progress - verify results on a test device before production use

---

---

## v1.0.0 - Initial Release

### Overview

FortiGate to Cisco FTD Configuration Converter is a three-phase migration tool that converts FortiGate firewall configurations (YAML) into Cisco FTD-compatible JSON, imports them via the FDM REST API, and provides bulk cleanup/rollback capabilities. Includes a full GUI application and CLI interface.

---

### Features

#### Conversion Engine

- **Network Objects** - Hosts, subnets (CIDR), IP ranges, and FQDNs with automatic type detection and name sanitization
- **Network Groups** - Address groups with automatic nested-group flattening and circular reference detection
- **Service Objects** - TCP/UDP port objects with automatic splitting of dual-protocol services into separate FTD-compatible entries
- **Service Groups** - Port object groups with expanded split-service references and member deduplication
- **Access Control Rules** - Firewall policies with multi-zone, multi-service, and multi-network support; FortiGate action mapping (accept/deny to PERMIT/DENY)
- **Static Routes** - IPv4 routing entries with gateway object creation, default route handling, and blackhole route filtering
- **Interfaces** - Physical interfaces, EtherChannels, subinterfaces (VLANs), and bridge groups with model-aware port mapping
- **Security Zones** - Auto-generated from interface names and aliases
- **13 output JSON files** per conversion including summary statistics and metadata

#### Supported FTD Models (13)

| Model    | Ports | HA Port     |
|----------|-------|-------------|
| FTD-1010 | 8     | None        |
| FTD-1120 | 12    | Ethernet1/2 |
| FTD-1140 | 12    | Ethernet1/2 |
| FTD-2110 | 12    | Ethernet1/2 |
| FTD-2120 | 12    | Ethernet1/2 |
| FTD-2130 | 16    | Ethernet1/2 |
| FTD-2140 | 16    | Ethernet1/2 |
| FTD-3105 | 8     | Ethernet1/2 |
| FTD-3110 | 16    | Ethernet1/2 |
| FTD-3120 | 16    | Ethernet1/2 |
| FTD-3130 | 24    | Ethernet1/2 |
| FTD-3140 | 24    | Ethernet1/2 |
| FTD-4215 | 8     | Ethernet1/2 |

Custom HA port override supported via `--ha-port`.

#### FDM API Import

- **11 selective import filters** - Physical interfaces, EtherChannels, subinterfaces, bridge groups, security zones, address objects, address groups, service objects, service groups, static routes, and access rules
- **Dependency-ordered import** - Objects created in the correct sequence to satisfy FTD reference requirements
- **Idempotent operations** - Existing objects are skipped without error
- **Multithreaded** - Configurable worker count (1-32, default 6) for concurrent object creation
- **OAuth 2.0 authentication** - Automatic token refresh with thread-safe locking and fallback re-authentication
- **Retry with exponential backoff** - Up to 4 attempts with jittered delays for transient errors (429, 503, 504)
- **Optional deployment** - Trigger FTD deployment immediately after import
- **JSON report output** - Machine-readable import summary

#### Bulk Cleanup / Rollback

- **Selective or full deletion** - Delete specific object types or all custom objects
- **Dry-run mode** - Preview what would be deleted without making changes
- **System-object protection** - System-defined objects are never deleted
- **Confirmation prompt** - Interactive approval required before destructive operations
- **Multithreaded deletion** - Same configurable concurrency as import

#### GUI Application

- **Three-tab interface** - Convert, Import to FTD, and Cleanup tabs
- **Real-time console output** - Streaming progress updates during all operations
- **Dark theme** - Professional dark interface with green accents
- **Full control** - All CLI options exposed through the GUI (model selection, worker count, selective imports, dry-run, deploy toggle, debug mode)
- **File/directory browsers** - Native OS dialogs for selecting input configs and output directories

#### CLI Interface

```
# Convert
python fortigate_converter.py config.yaml --target-model ftd-3120 --pretty

# Import
python ftd_api_importer.py --host 192.168.1.1 -u admin --deploy --workers 6

# Cleanup
python ftd_api_cleanup.py --host 192.168.1.1 -u admin --delete-all --dry-run
```

---

### Requirements

- Python 3.9+
- FTD 7.4.x with FDM local management (not FMC-managed)
- Dependencies: `pyyaml>=6.0`, `requests>=2.28.0`, `urllib3>=1.26.0`
- Airgapped installation supported via pip wheel packages

---

### Known Limitations

- ICMP and non-port protocol services are skipped during conversion
- FortiGate schedule-based policies are converted but schedule conditions are not mapped
- Only IPv4 addresses and routes are supported
- FTD must be locally managed via FDM (FMC-managed devices are not supported)
