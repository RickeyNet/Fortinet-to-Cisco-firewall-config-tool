#!/usr/bin/env python3
"""PAN-OS Security Rule Converter - FortiGate Target
======================================================
Converts PAN-OS security rules to FortiGate ``firewall policy`` CLI config.

Key translation notes:
    - PAN-OS zones  -> FortiGate srcintf / dstintf (zone names are reused,
      sanitized the same way as the zone converter so references match)
    - PAN-OS "any" zone      -> FortiGate "any" interface wildcard
    - PAN-OS "any" address   -> FortiGate "all" built-in address object
    - PAN-OS action allow    -> FortiGate action accept
    - PAN-OS action deny/drop/reset-* -> FortiGate action deny
    - PAN-OS log-end yes     -> FortiGate logtraffic all
    - PAN-OS disabled yes    -> FortiGate status disable
    - PAN-OS service "application-default" -> FortiGate service "ALL"

Fail-closed behavior:
    - If every specific address/service a rule references was skipped
      during conversion, the policy is emitted with ``set status disable``
      and an explanatory comment instead of silently widening to all/ALL.
    - PAN-OS app-id restrictions cannot be expressed in a FortiGate
      firewall policy.  A rule with app restrictions AND service "any" /
      "application-default" is emitted disabled (converting it would drop
      the only traffic restriction).  With a specific service the rule is
      converted, but the dropped app restriction is noted in the comment
      and recorded in ``failed_items``.

FortiGate policies use integer IDs.  Sequential IDs are assigned starting
from 1 in the order policies appear in the PAN-OS config.  Policy names
are truncated to FortiGate's 35-character limit (with dedup suffixes).

FortiGate CLI output format:
    config firewall policy
        edit 1
            set name "Allow_Web"
            set srcintf "untrust"
            set dstintf "trust"
            set srcaddr "any_src"
            set dstaddr "webserver"
            set schedule "always"
            set service "HTTP" "HTTPS"
            set action accept
            set logtraffic all
            set comments "Allow web traffic"
        next
    end
"""

from typing import Any, Dict, List, Optional, Set

from fg_common import (
    FG_POLICY_NAME_MAX_LENGTH,
    dedup_fg_name,
    escape_fg_string,
    fg_members_str,
    sanitize_fg_name,
)
from fg_service_converter import collapse_merged_pairs


# PA actions that map to FortiGate "deny"
_PA_DENY_ACTIONS = {"deny", "drop", "reset-client", "reset-server", "reset-both"}

# PA "application-default" service token -> use FortiGate's ANY service
_APP_DEFAULT = "application-default"


class FGPolicyConverter:
    """Convert PAN-OS security rules to FortiGate firewall policy format."""

    def __init__(
        self,
        pa_config: Dict[str, Any],
        service_name_map: Dict[str, str],
        address_name_map: Optional[Dict[str, str]] = None,
        skipped_services: Optional[Set[str]] = None,
        skipped_addresses: Optional[Set[str]] = None,
        merged_service_pairs: Optional[Dict[str, List[str]]] = None,
    ) -> None:
        self.pa_config = pa_config
        self._service_name_map = service_name_map
        self._address_name_map = dict(address_name_map or {})
        self._skipped_services = set(skipped_services or ())
        self._skipped_addresses = set(skipped_addresses or ())
        self._merged_service_pairs = dict(merged_service_pairs or {})
        self.failed_items: List[Dict] = []
        self._stats = {
            "total": 0,
            "allow": 0,
            "deny": 0,
            "disabled": 0,
            "fail_closed": 0,
        }

    def convert(self) -> str:
        """Convert all security rules and return FortiGate CLI block.

        Returns:
            A string containing the ``config firewall policy`` block,
            or an empty string if there are no rules.
        """
        rules = self.pa_config.get("security_rules", [])
        if not rules:
            print("  Warning: No security rules found in PAN-OS configuration")
            return ""

        entries: List[str] = []
        used_names: Dict[str, int] = {}
        policy_id = 1

        for rule in rules:
            name = sanitize_fg_name(rule.get("name", f"Policy_{policy_id}"))
            if not name:
                name = f"Policy_{policy_id}"
            # FortiGate policy names are limited to 35 characters
            name = dedup_fg_name(name, used_names, FG_POLICY_NAME_MAX_LENGTH)

            fail_closed_reasons: List[str] = []

            # --- Action ---
            pa_action = str(rule.get("action", "deny")).strip().lower()
            if pa_action in _PA_DENY_ACTIONS:
                fg_action = "deny"
                self._stats["deny"] += 1
            else:
                fg_action = "accept"
                self._stats["allow"] += 1

            # --- Source / destination zones -> srcintf / dstintf ---
            from_zones = self._resolve_zones(rule.get("from_zones", []))
            to_zones = self._resolve_zones(rule.get("to_zones", []))

            # --- Source / destination addresses (fail closed if emptied) ---
            sources = self._resolve_addresses(rule.get("sources", []))
            if not sources:
                fail_closed_reasons.append(
                    "all source addresses were skipped during conversion"
                )
                sources = ["all"]
            destinations = self._resolve_addresses(rule.get("destinations", []))
            if not destinations:
                fail_closed_reasons.append(
                    "all destination addresses were skipped during conversion"
                )
                destinations = ["all"]

            # --- Services (fail closed if emptied) ---
            raw_services = _to_list(rule.get("services", []))
            services = self._resolve_services(raw_services)
            if not services:
                fail_closed_reasons.append(
                    "all services were skipped during conversion"
                )
                services = ["ALL"]

            # --- Application restrictions (not expressible on FortiGate) ---
            apps = [
                str(a).strip()
                for a in _to_list(rule.get("applications", []))
                if str(a).strip() and str(a).strip().lower() != "any"
            ]
            app_note = ""
            if apps:
                app_list = ", ".join(apps)
                service_is_any = all(
                    str(s).strip().lower() in ("any", _APP_DEFAULT)
                    for s in raw_services
                ) if raw_services else True
                if service_is_any:
                    fail_closed_reasons.append(
                        f"PA app-id restriction cannot be converted "
                        f"(apps: {app_list})"
                    )
                else:
                    app_note = f"PA app-id restriction dropped (apps: {app_list})"
                    self.failed_items.append({
                        "name": name,
                        "reason": f"warning: {app_note}",
                    })

            # --- Logging ---
            log_end = rule.get("log_end", True)
            logtraffic = "all" if log_end else "disable"

            # --- Description ---
            description = str(rule.get("description", "")).strip()
            if not description:
                description = name

            # --- Disabled ---
            disabled = rule.get("disabled", False)
            if disabled:
                self._stats["disabled"] += 1

            # --- Fail closed: disable rather than emit an over-broad rule ---
            if fail_closed_reasons:
                reason_text = "; ".join(fail_closed_reasons)
                self.failed_items.append({"name": name, "reason": reason_text})
                self._stats["fail_closed"] += 1
                if not disabled:
                    self._stats["disabled"] += 1
                    disabled = True
                description = f"DISABLED BY CONVERTER: {reason_text} | {description}"
            elif app_note:
                description = f"{description} | {app_note}"

            lines = [f"    edit {policy_id}"]
            lines.append(f'        set name "{name}"')
            lines.append(f"        set srcintf {fg_members_str(from_zones)}")
            lines.append(f"        set dstintf {fg_members_str(to_zones)}")
            lines.append(f"        set srcaddr {fg_members_str(sources)}")
            lines.append(f"        set dstaddr {fg_members_str(destinations)}")
            lines.append('        set schedule "always"')
            lines.append(f"        set service {fg_members_str(services)}")
            lines.append(f"        set action {fg_action}")
            lines.append(f"        set logtraffic {logtraffic}")
            if disabled:
                lines.append("        set status disable")
            lines.append(f'        set comments "{escape_fg_string(description)}"')
            lines.append("    next")

            entries.append("\n".join(lines))
            self._stats["total"] += 1
            policy_id += 1

            action_label = fg_action.upper()
            status_label = " [DISABLED-FAIL-CLOSED]" if fail_closed_reasons else ""
            print(
                f"  Converted policy: [{policy_id - 1}] {name} "
                f"[{action_label}]{status_label} "
                f"({', '.join(from_zones)} -> {', '.join(to_zones)})"
            )

        if not entries:
            return ""

        block = "config firewall policy\n"
        block += "\n".join(entries)
        block += "\nend\n"
        return block

    def get_statistics(self) -> Dict[str, int]:
        return dict(self._stats)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _resolve_zones(self, zones: List) -> List[str]:
        """Sanitize zone names (matching the zone converter); keep 'any'."""
        result: List[str] = []
        seen: set = set()
        for z in _to_list(zones):
            z_str = str(z).strip()
            if not z_str:
                continue
            if z_str.lower() == "any":
                fg_z = "any"  # FortiGate accepts "any" directly for interfaces
            else:
                fg_z = sanitize_fg_name(z_str)
            if fg_z not in seen:
                result.append(fg_z)
                seen.add(fg_z)
        return result if result else ["any"]

    def _resolve_addresses(self, addrs: List) -> List[str]:
        """Map PAN-OS 'any' to FG 'all'; resolve renames; drop skipped.

        Returns [] when the rule referenced only specific addresses and
        every one of them was skipped - the caller must fail closed.
        """
        result: List[str] = []
        seen: set = set()
        had_specific = False
        for a in _to_list(addrs):
            a_str = str(a).strip()
            if not a_str:
                continue
            if a_str.lower() == "any":
                if "all" not in seen:
                    result.append("all")
                    seen.add("all")
                continue
            had_specific = True
            sanitized = sanitize_fg_name(a_str)
            if sanitized in self._skipped_addresses:
                continue
            fg_a = self._address_name_map.get(sanitized, sanitized)
            if fg_a not in seen:
                result.append(fg_a)
                seen.add(fg_a)
        if not result:
            return [] if had_specific else ["all"]
        return result

    def _resolve_services(self, services: List) -> List[str]:
        """Resolve service names through the service name map.

        Handles:
          - 'any'                 -> 'ALL'
          - 'application-default' -> 'ALL'
          - dedup-renamed names   -> resolved FG name
          - skipped services      -> dropped ([] returned when all dropped,
                                     so the caller can fail closed)
          - both halves of a merged TCP+UDP pair -> the merged service
        """
        result: List[str] = []
        seen: set = set()
        had_specific = False
        for s in _to_list(services):
            s_str = str(s).strip()
            if not s_str:
                continue
            if s_str.lower() in ("any", _APP_DEFAULT):
                if "ALL" not in seen:
                    result.append("ALL")
                    seen.add("ALL")
                continue
            had_specific = True
            sanitized = sanitize_fg_name(s_str)
            if sanitized in self._skipped_services:
                continue
            fg_s = self._service_name_map.get(sanitized, sanitized)
            if fg_s not in seen:
                result.append(fg_s)
                seen.add(fg_s)
        if not result:
            return [] if had_specific else ["ALL"]
        return collapse_merged_pairs(result, self._merged_service_pairs)


def _to_list(value: Any) -> List:
    """Ensure value is a list."""
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]
