# FortiGate to Cisco FTD Tool - Improvement TODO

This checklist tracks technical debt, performance hardening, and usability improvements.

## Legend
- [ ] Not started
- [~] In progress
- [x] Completed

---

## P0: Stability and Correctness

- [x] Centralize retry/backoff + worker logic
  - Scope: Extract shared helper for thread pool execution, retry policy, transient-error detection.
  - Done: `FortiGateToFTDTool/concurrency_utils.py` added and wired into importer/cleanup threaded paths.
  - Benefit: Less duplication, easier tuning, fewer regressions.

- [x] Add regression tests for threaded paths
  - Done:
    - `import_address_objects` retry/stat behavior
    - `import_service_objects` retry/stat behavior
    - `delete_all_custom_objects` retry/stat behavior
    - `delete_all_static_routes` retry/stat behavior
    - explicit 503 retry case
    - hard-failure case (max attempts exhausted) assertions
    - `run_with_retry` transient retry behavior
  - Benefit: Prevent silent regressions in concurrency refactors.

- [x] Tighten exception handling and typing in importer
  - Scope: Replace broad `except Exception` and reduce `# pyright: ignore` in `ftd_api_importer.py`.
  - Done:
    - Added `_extract_error_message` helper for safer API error parsing.
    - Tightened exception handling in `get_interface_by_hardware_name`, `get_physical_interface`, `update_physical_interface`, and `create_subinterface`.
    - Added explicit type guards (`isinstance(..., dict)`) at interface lookup call sites.
    - Updated return typing contracts for interface lookup helpers to match runtime behavior.
    - Hardened adjacent interface paths (`get_interface_by_name`, `_get_etherchannel_by_hardware`, `create_etherchannel`, `create_bridge_group`, `create_security_zone`) with stricter type guards and safer error parsing.
    - Replaced broad importer exception handlers in cache/lookup and metadata-loading paths with explicit exception sets.
    - Removed importer `# pyright: ignore` suppressions and validated clean diagnostics.
  - Focus first on:
    - `get_interface_by_hardware_name`
    - `get_physical_interface`
    - `update_physical_interface`
    - `create_subinterface`
  - Acceptance:
    - Narrow exception types (`requests.exceptions.RequestException`, `ValueError`, etc.)
    - Consistent typed return contracts
    - Fewer Pyright suppressions

- [x] Fix bare `except:` clauses in cleanup script
  - Done: Replaced bare `except:` in `delete_object()` with `except (ValueError, KeyError, IndexError, TypeError):`.

- [x] Fix thread-safety bug in `create_port_object`
  - Done: Replaced direct `self.stats[key] += 1` with `self.record_stat(key)` in
    `create_port_object()`, `create_static_route()`, and `create_access_rule()`.

- [x] Fix `AddressConverter.get_object_count()` returning stale data
  - Done: Added `self.ftd_network_objects = network_objects` before the return in `convert()`.

- [x] Handle FQDN address type in address converter
  - Done: Added FQDN detection in `_determine_address_type()` and `_extract_address_value()`.
    FQDN objects now produce `subType: "FQDN"` with the domain as value.
    IP validation is skipped for FQDN types.

---

## P1: Consistency and Maintainability

- [x] Normalize interface/media model logic
  - Scope: Move model family sets (`ftd_1000_series`, `ftd_3100_series`, etc.) to one shared module.
  - Candidate file: `FortiGateToFTDTool/platform_profiles.py`
  - Done:
    - Added shared model-family module: `FortiGateToFTDTool/platform_profiles.py`.
    - Replaced duplicated inline model sets in importer with `is_ftd_1000(...)` and `is_ftd_3100(...)` helpers.
    - Replaced duplicated inline model sets in cleanup with shared helpers.
  - Acceptance:
    - Single source of truth for model families
    - Importer and cleanup use shared constants/helpers
  - Benefit: Fewer drift bugs when tweaking platform behavior.

- [~] Standardize operator UX/logging
  - Scope:
    - Normalize statuses to `OK | SKIP | FAIL`
    - Ensure threaded progress output flushes consistently
    - Optional `--verbose` levels
    - Optional `--json-report <path>`
  - Done:
    - Standardized many importer/cleanup action outcomes to `[OK] | [SKIP] | [FAIL]`.
    - Added `flush=True` to threaded progress prints for more reliable live output.
    - Added `--json-report` to both importer and cleanup CLIs with machine-readable summaries.
    - Fixed `import_access_rules` `[Success!]` -> `[OK]`.
    - Fixed `authenticate()` `FAIL` -> `[FAIL]` with brackets.
  - Remaining:
    - Add configurable `--verbose` levels and gate non-essential output by verbosity.
  - Acceptance:
    - Consistent message format across importer/cleanup
    - Machine-readable summary output option

- [x] README operational docs refresh
  - Done: Performance/concurrency section, `--workers` guidance, API rate-limit troubleshooting.

- [x] Extract shared API base class for importer and cleanup
  - Done: Created `FTDBaseClient` in `FortiGateToFTDTool/ftd_api_base.py` with:
    - `authenticate()` - unified OAuth 2.0 token flow
    - `validate_endpoints()` - preflight probe of all FDM endpoints
    - `get_default_virtual_router_id()` - cached VR discovery
    - Shared `__init__` for host/session/token attributes
  - Both `FTDAPIClient` and `FTDBulkDelete` now inherit from `FTDBaseClient`.
  - `compute_outcome()` remains in each subclass (different stat structures).
  - Benefit: Single point of change for auth, endpoint validation, and VR discovery.

- [x] Use `write_json_file()` helper consistently in converter
  - Done: Replaced all 12 inline `json.dump` blocks in `fortigate_converter.py` with
    `write_json_file(path, data, args.pretty)`. ~90 lines removed.

- [x] Extract duplicated group-flattening logic to a shared base or utility
  - Done: Added `build_group_lookup()` and `flatten_group_members()` to `common.py`.
    Removed `_build_group_lookup()`, `_is_group()`, and `_flatten_members()` from both
    `address_group_converter.py` and `service_group_converter.py`.

- [x] Extract duplicated API create/error pattern in importer
  - Done: Added `_create_api_object(endpoint, payload, stat_prefix, track_stats)` to `FTDAPIClient`.
    Refactored `create_network_object`, `create_network_group`, `create_port_object`,
    `create_port_group`, `create_access_rule`, and `create_static_route` to delegate to it.
    Uses existing `_extract_error_message()` for consistent 422 error parsing.
  - Benefit: ~150 lines removed, single POST/duplicate/error pattern, easier to add new object types.

- [x] Remove large commented-out block in converter
  - Done: Deleted 35-line commented-out "Method 1 vs Method 2" block from `fortigate_converter.py`.

- [x] Remove `_validate_group()` dead code
  - Done: Deleted unused `_validate_group()` method from `address_group_converter.py`.

- [x] Clean up remaining `# pyright: ignore` suppressions in converters
  - Done: Replaced `param: Set[str] = None` with `param: Optional[Set[str]] = None` and
    added `Optional` to imports in `address_group_converter.py`, `service_group_converter.py`,
    `policy_converter.py`, and removed the suppression in `fortigate_converter.py`.

- [x] Fix step-number comment drift in importer
  - Done: Renumbered import step comments in `ftd_api_importer.py` from 5-10 to 7-12 to match
    the printed step list.

---

## P2: Additional Improvements (Recommended)

- [x] Add idempotency summary and exit codes
  - Done: Exit codes 0/1/2/3, `compute_outcome()`, JSON report fields.

- [x] Add lightweight integration smoke mode
  - Done: `--validate-only` for both importer and cleanup.

- [x] Add configurable retry policy flags
  - Done: Added `--max-attempts`, `--base-backoff`, `--max-jitter` to both importer and cleanup CLIs.
    Threaded through to `run_with_retry()` calls in all threaded import/delete paths.

- [x] Add timing per phase to final report (cleanup)
  - Done: Added `record_phase()` to cleanup `main()` with per-phase timing summary and
    `phase_timings`/`total_seconds` fields in JSON report output.

- [x] Add tests for concurrency helper edge cases
  - Done: Added 3 edge-case tests in `tests/test_concurrency_refactor.py`:
    - `test_run_with_retry_max_attempts_one` (no retry)
    - `test_run_with_retry_non_retryable_fails_immediately` (400 fails on first attempt)
    - `test_run_indexed_thread_pool_empty_list` (completes without error)

- [ ] Add pre-commit quality checks
  - Suggested: `ruff` (or `flake8`) + `black` + `pytest`.
  - Benefit: Catch style/type/test issues before commit.

- [x] Add `requirements.txt` or `pyproject.toml`
  - Done: Created `requirements.txt` with `pyyaml>=6.0`, `requests>=2.28.0`, `urllib3>=1.26.0`.

- [x] Add `__init__.py` to make `FortiGateToFTDTool` a proper package
  - Done: Added `FortiGateToFTDTool/__init__.py`.

- [x] Make hardcoded sleep delays configurable
  - Done: Added `--delay` CLI flag (default 0.2) to both importer and cleanup.
    All sequential import/cleanup functions accept a `delay` parameter.
    Cleanup etherchannels/bridge groups default to 0.3 for HA-related operations.

- [x] Add exception propagation to `run_indexed_thread_pool`
  - Done: Collected futures and called `.result()` via `as_completed()` to propagate
    unhandled worker exceptions.

- [x] Validate `--workers` CLI argument range
  - Done: Added `_positive_int` type validator (1-32) to `--workers` in both
    `ftd_api_importer.py` and `ftd_api_cleanup.py`.

- [x] Fix FTD-3105 model port count inconsistency
  - Done: Verified `total_ports: 16` is correct (8 RJ45 + 8 SFP = 16 data ports).
    No code change needed - the original values were accurate.

- [x] Remove unnecessary defensive guard in converter
  - Done: Replaced verbose `args.debug if 'args' in locals() ...` with `getattr(args, 'debug', False)`.

---

## P3: Test Coverage Expansion

- [x] Add unit tests for address converter
  - Scope: Test HOST/NETWORK/RANGE/FQDN detection, netmask-to-CIDR conversion,
    IP-address-name filtering, name sanitization edge cases.
  - Done: `tests/test_address_converter.py` (20 tests) — subtype detection, netmask-to-CIDR,
    factory-default/invalid filtering, name sanitization and collision handling, value validation.

- [x] Add unit tests for service converter
  - Scope: Test TCP/UDP splitting, multi-port expansion, ICMP skipping,
    FTD built-in name collision handling, colon-separated port parsing.
  - Done: `tests/test_service_converter.py` (21 tests) — TCP/UDP splitting, multi-port expansion,
    ICMP/IP-protocol skipping, colon-separated ports, built-in name collisions, name mapping.

- [x] Add unit tests for policy converter
  - Scope: Test action mapping, zone lookup strategies, service expansion,
    address group type detection, "any"/"all" filtering.
  - Done: `tests/test_policy_converter.py` (27 tests) — action mapping, zone lookup, service/address
    expansion, group type detection, "any"/"all" filtering. Fail-closed/disabled rules in
    `tests/test_converter_fixes.py`.

- [x] Add unit tests for interface converter
  - Scope: Test physical/aggregate/switch/VLAN detection, port mapping per model,
    HA port exclusion, name sanitization, security zone generation.
  - Done: `tests/test_interface_converter_basics.py` (20 tests) — physical/aggregate/switch/VLAN
    detection, per-model port universes, name sanitization, security zones. HA port exclusion
    in `tests/test_ftd_ha_ports.py`.

- [x] Add unit tests for group flattening (address & service groups)
  - Scope: Test circular reference detection, deep nesting, duplicate removal,
    single-member normalization, empty group handling.
  - Done: `tests/test_group_flattening.py` (20 tests) — shared `build_group_lookup()` /
    `flatten_group_members()` helpers plus address and service group converter edge cases.

- [x] Add integration-style test for `fortigate_converter.py` main()
  - Scope: Feed a small YAML config through `main()` and verify all 13 JSON output files
    are created with correct structure.
  - Done: `tests/test_fortigate_converter_main.py` (14 tests) — end-to-end YAML through `main()`,
    all 14 output files (including metadata/summary), YAML pre-processing, disabled-policy export.

---

## P4: GUI - Source/Target Matrix Polish

Follow-up items identified during v1.6.1 label/tab fixes. The app supports multiple
source→target pairs but several UI elements still carry FTD-centric defaults or wording.

- [x] Disable the Target combobox when a source locks it to a single choice
  - Done (v1.6.2): Target combobox now toggles between `disabled` (ASA / PA / FTD
    sources) and `readonly` (FortiGate source) in `_on_source_change`, alongside
    the existing `values=` update.
  - Follow-up (still open): add a "→" arrow label between Source and Target on
    the top bar. Low priority cosmetic.

- [x] Surface the supported conversion matrix in the UI
  - Done: Added a dim hint line directly under the Source/Target bar in
    `gui_app.py` listing the supported pairs
    ("FortiGate ↔ Cisco FTD | FortiGate ↔ Palo Alto PAN-OS | Cisco ASA → Palo Alto PAN-OS").
    The bidirectional arrows cover FG→FTD/FTD→FG and FG→PAN-OS/PA→FG without
    enumerating each direction separately.

- [x] Preserve user-edited "Output Base Name" across source/target changes
  - Done (v1.6.2): Added `DEFAULT_OUTPUT_BASES = {"", "ftd_config", "pa_config",
    "fg_config"}` constant. All six call sites in `_on_platform_change` (three for
    `conv_output_var`, three for `imp_base_var`) now guard the `.set(...)` with
    `if self.conv_output_var.get().strip() in DEFAULT_OUTPUT_BASES`. Custom names
    typed by the user now survive any number of source/target changes.

- [ ] Make Input Config label wording consistent across sources
  - Scope: Current labels mix format, generic, and connection wording:
    "Input YAML:" (FG), "Input Config:" (ASA), "Input XML:" (PA),
    "FTD Config JSON:" (FTD file mode), "FTD Host / IP:" (FTD API mode).
  - Suggested pattern: `"<Source> Config (<format>):"` for file inputs,
    keep "FTD Host / IP:" as the exception for API mode.
  - Priority: Low - cosmetic polish.

- [x] Dim or hide Import/Cleanup tabs when target is FortiGate
  - Done (v1.6.2): Took the "dim and disable" approach. Added `_set_tab_enabled()`
    helper that recursively walks a tab frame and toggles interactive widgets
    (Entry / Checkbutton / Spinbox / Combobox / Button) - output Text widgets are
    skipped so prior logs stay readable. `_retitle_import_cleanup_tabs()` sets
    `_imp_locked_by_target` / `_cln_locked_by_target` flags that `_set_buttons_state()`
    respects so the shared run/cancel toggle never re-enables locked buttons.
    The `cln_reset_pw_btn` state is re-derived from `has_custom_password()` on unlock.

- [ ] Filter Import tab "Selective Import" checkboxes per target
  - Scope: Types at `gui_app.py:880-892` (Physical Interfaces, EtherChannels,
    Subinterfaces, Bridge Groups, Security Zones, etc.) are FTD-specific terminology.
    For PAN-OS target, rebuild the list with PAN-OS-relevant types, or hide the
    whole Selective Import frame when the target doesn't support granular import.
  - Priority: Medium - current state can mislead PAN-OS users into thinking they're
    enabling filters that get ignored.

- [ ] Filter Cleanup tab "What to Delete" checkboxes per target
  - Scope: Same issue as the Import tab - delete-types at `gui_app.py:973-985` include
    FDM-specific items like "Physical Interfaces (reset)". Rebuild per target.
  - Priority: Medium.

- [ ] Audit Config Viewer tab for target-specific behavior
  - Scope: Verify whether the Viewer handles YAML (FG), XML (PA), JSON (FTD/PAN-OS
    exports) appropriately, or hide/disable the tab for unsupported targets.
  - Priority: Medium - unknown impact until audited.

- [ ] Update Help tab to reflect FTD-username repurposing and new source/target pairs
  - Scope: Help text at `gui_app.py:1391-1394` describes "HA Port (optional):" as
    "FTD only" for HA purposes. With the v1.6.1 label fix, that field also serves as
    FTD username when Cisco FTD is the source. Also expand the Help content to cover
    the Palo Alto → FortiGate and Cisco FTD → FortiGate pipelines (added in v1.5.0 / v1.6.0).
  - Priority: Medium.

- [ ] Simplify the window-title template
  - Scope: Seven hardcoded title strings across `_on_platform_change` branches.
    Replace with a single template: `f"Firewall Migration Tool - {source} → {target} v{APP_VERSION}"`.
  - Benefit: Fewer bespoke strings, consistent formatting, one place to change wording.
  - Priority: Low.

- [ ] Tooltip / helper text for the "Use JSON config file instead of live FDM API" toggle
  - Scope: Checkbox has no context for where a user would obtain the JSON export.
    Add a short hint line ("Exported via `curl` from FDM `/api/fdm/v6/object` …" or
    a pointer to docs).
  - Priority: Low.

---

## P5: Feature Coverage - Migration Completeness

Config domains not yet handled by any converter. Today the tool covers interfaces,
address/service objects + groups, security (allow) policies, static routes, zones, and
SNMP (FTD). The items below are what a config needs to actually function after cutover.
Each should follow the existing per-domain `*_converter.py` pattern and ship for every
supported direction (FG->FTD, FG->PA, ASA->PA, FTD->FG, PA->FG) where applicable.

### Tier 1 - Showstoppers (config will not work without these)

- [ ] NAT conversion
  - Scope: Source NAT/PAT, destination NAT, static (1:1) NAT. FortiGate `firewall vip`
    and `firewall ippool` -> FTD auto/manual NAT rules, PAN-OS NAT rules. Reuse existing
    address/service object infrastructure.
  - Priority: Critical - most common reason a migrated firewall fails in production.

- [ ] Policy NAT linkage
  - Scope: FortiGate policies carry `nat: enable` (+ optional ippool/VIP); that intent is
    currently dropped. Wire policy-embedded NAT into the NAT converter output.
  - Priority: Critical - depends on NAT conversion.

- [ ] VPN conversion
  - Scope: Site-to-site IPsec (IKE/IPsec proposals, peers, PSKs/certs, tunnel interfaces,
    crypto maps, traffic selectors) and remote-access / SSL VPN. High effort.
  - Priority: Critical for edge firewalls.

### Tier 2 - Control plane & policy depth

- [ ] Dynamic routing (OSPF / BGP / RIP)
  - Scope: Process/peer config, redistribution, route maps, prefix lists, distribute lists.
    Only static routes are handled today.
  - Priority: High.

- [ ] Security profiles / UTM
  - Scope: AV, IPS/intrusion, web/URL filtering, application control, DNS/file filtering ->
    FTD intrusion + file policies, PAN-OS security profile groups, FortiGate UTM profiles.
    Profile-to-policy attachment mapping.
  - Priority: High.

- [ ] Schedules / time-based policies
  - Scope: FortiGate `firewall schedule` (recurring + one-time) -> PAN-OS schedules /
    FTD time ranges; attach to the converted rules.
  - Priority: Medium.

- [ ] Application & URL mapping
  - Scope: L7 app-id and URL categories. Not 1:1 - requires a maintained cross-vendor
    mapping table and a fallback for unmatched entries.
  - Priority: Medium.

- [ ] Users / identity
  - Scope: LDAP / RADIUS / SAML auth servers, FSSO / User-ID agents, identity-based rules
    (user/group as a policy match criterion).
  - Priority: Medium.

### Tier 3 - Platform & scale

- [ ] Multi-context (VDOM / vsys / security context)
  - Scope: Per-VDOM / per-vsys scoping and object namespacing. Tool currently assumes a
    single context.
  - Priority: Medium.

- [ ] IPv6 throughout
  - Scope: IPv6 address objects, policies, and routes end to end. Currently IPv4-centric.
  - Priority: Medium.

- [ ] HA configuration
  - Scope: HA pairing/cluster settings, failover links, priorities.
  - Priority: Low-Medium.

- [ ] DHCP server config
  - Scope: Per-interface DHCP scopes, reservations, options.
  - Priority: Low.

- [ ] QoS / traffic shaping
  - Scope: Shapers, shaping policies, bandwidth guarantees/limits -> QoS profiles/policies.
  - Priority: Low.

- [ ] Certificates & syslog/logging settings
  - Scope: Cert objects/chains referenced by VPN/inspection; syslog servers, log forwarding.
  - Priority: Low.

- [ ] Object nuances
  - Scope: FQDN (partially done for FTD), wildcard, geo/country, and dynamic address objects
    across all directions.
  - Priority: Low-Medium.

### Tier 4 - Migration quality & safety (high leverage)

- [ ] Pre-flight validation + diff
  - Scope: Parse source and report exactly what will / will not convert BEFORE pushing;
    per-object source->target diff. Builds on the existing `verify` skill at config level.
  - Priority: High - de-risks every other migration.

- [ ] Rollback / snapshot
  - Scope: Capture target state before import; one-command revert.
  - Priority: High.

- [ ] Object dedup & merge
  - Scope: Collapse duplicate address/service objects (same value, different names) across
    the source config; rewrite references.
  - Priority: Medium.

- [ ] Rule optimization
  - Scope: Detect shadowed / redundant / overly-broad rules during migration; report (and
    optionally prune) them.
  - Priority: Medium.

- [ ] Naming-collision strategy
  - Scope: Consistent, configurable collision handling shared across all object types
    (suffix, source-prefix, interactive).
  - Priority: Medium.

- [ ] Round-trip verification
  - Scope: Re-read the target after import and compare against source intent; report drift.
  - Priority: Medium.

- [ ] Coverage-matrix completeness
  - Scope: Fill in missing direction pairs (e.g. ASA->FTD, PA->FTD) so the matrix is symmetric.
  - Priority: Medium.
