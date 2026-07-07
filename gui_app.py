#!/usr/bin/env python3
"""
Firewall Migration Tool - GUI Application
=====================================================
Self-contained Tkinter GUI that wraps the converter, importer, and cleanup
tools for both Cisco FTD and Palo Alto PAN-OS targets.

All phases run **in-process** (no subprocess), so the entire application can
be frozen into a single Windows .exe with PyInstaller.

Build:  see build.bat in the project root.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
import threading
import ctypes
import sys
import os
import re
import glob
import io
import json
import queue
import random
import traceback
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Path setup - ensure converter modules are importable regardless of CWD
# ---------------------------------------------------------------------------
if getattr(sys, "frozen", False):
    # Running inside a PyInstaller bundle
    APP_DIR = os.path.dirname(sys.executable)
    _PKG_DIR = getattr(sys, "_MEIPASS", APP_DIR)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))
    _PKG_DIR = APP_DIR

# Add enabled tool directories to sys.path. Restricted builds bundle a
# build_profile_runtime.json file into the PyInstaller temp directory.
_FTD_DIR = os.path.join(APP_DIR, "FortiGateToFTDTool")
_PA_DIR = os.path.join(APP_DIR, "FortiGateToPaloAltoTool")
_ASA_DIR = os.path.join(APP_DIR, "CiscoASAToPaloAltoTool")
_PA_TO_FG_DIR = os.path.join(APP_DIR, "PaloAltoToFortiGateTool")
_FTD_TO_FG_DIR = os.path.join(APP_DIR, "CiscoFTDToFortiGateTool")

_TOOL_DIRS = {
    "FortiGateToFTDTool": _FTD_DIR,
    "FortiGateToPaloAltoTool": _PA_DIR,
    "CiscoASAToPaloAltoTool": _ASA_DIR,
    "PaloAltoToFortiGateTool": _PA_TO_FG_DIR,
    "CiscoFTDToFortiGateTool": _FTD_TO_FG_DIR,
}


def _load_runtime_profile() -> Dict[str, Any]:
    profile_path = os.environ.get("FMT_BUILD_PROFILE_FILE", "").strip()
    candidates = [profile_path] if profile_path else []
    candidates.extend([
        os.path.join(_PKG_DIR, "build_profile_runtime.json"),
        os.path.join(APP_DIR, "build_profile_runtime.json"),
    ])
    for path in candidates:
        if not path or not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue  # unreadable/corrupt candidate - try the next one
        if isinstance(data, dict):
            return data
    return {}


_RUNTIME_PROFILE = _load_runtime_profile()
_ENABLED_TOOL_DIR_NAMES = _RUNTIME_PROFILE.get("tool_dirs") or list(_TOOL_DIRS)


def _profile_feature(name: str, default: bool = True) -> bool:
    features = _RUNTIME_PROFILE.get("features")
    if isinstance(features, dict) and name in features:
        return bool(features[name])
    return default


_CLEANUP_ENABLED = _profile_feature("cleanup", True)

# Add the on-disk tool directories to sys.path ONLY when running from source.
#
# In a frozen (PyInstaller) build, every tool module is bundled inside the
# executable. APP_DIR then points at the folder the .exe lives in, so inserting
# APP_DIR-relative tool dirs would let a stale copy of the source that happens
# to sit next to the .exe (e.g. on a file share) shadow the bundled modules.
# That causes version-mismatch crashes like "main() takes 0 positional
# arguments but 1 was given" when the bundled GUI calls an old on-disk main().
# When frozen we rely solely on the bundled modules (via _PKG_DIR / _MEIPASS).
if not getattr(sys, "frozen", False):
    for _name in _ENABLED_TOOL_DIR_NAMES:
        _d = _TOOL_DIRS.get(_name)
        if _d and os.path.isdir(_d) and _d not in sys.path:
            sys.path.insert(0, _d)
if _PKG_DIR not in sys.path:
    sys.path.insert(0, _PKG_DIR)

# Import the FTD entry points
from fortigate_converter import main as convert_main   # noqa: E402
from ftd_api_importer import main as import_main       # noqa: E402
from ftd_snmp_config import main as snmp_main          # noqa: E402

# These names are bound conditionally below (behind _CLEANUP_ENABLED / try-except
# ImportError). Initialize to None first so they are always bound for static
# analysis; runtime usage is guarded by the corresponding availability flags.
cleanup_main = None
set_password = None
verify_password = None
has_custom_password = None
reset_to_default = None
pa_convert_main = None
pa_import_main = None
pa_cleanup_main = None
asa_convert_main = None
pa_to_fg_convert_main = None
ftd_to_fg_convert_main = None

_CLEANUP_IMPORT_ERROR = ""
if _CLEANUP_ENABLED:
    try:
        from ftd_api_cleanup import main as cleanup_main       # noqa: E402
        from cleanup_auth import (                              # noqa: E402
            set_password, verify_password,
            has_custom_password, reset_to_default,
        )  # stdlib only - no third-party deps, portable across machines
    except ImportError as _e:
        # A cleanup-stripped frozen build can still end up with a profile that
        # claims cleanup is enabled (e.g. a missing/corrupt runtime profile
        # falls back to full-featured defaults). Degrade to cleanup-disabled
        # with a visible warning instead of crashing a windowed exe.
        _CLEANUP_ENABLED = False
        _CLEANUP_IMPORT_ERROR = str(_e)

# Palo Alto modules - optional (only needed when PA platform is selected)
_PA_IMPORT_ERROR = ""
try:
    from pa_converter import main as pa_convert_main          # noqa: E402
    from panos_api_importer import main as pa_import_main     # noqa: E402
    _PA_AVAILABLE = True
    if _CLEANUP_ENABLED:
        try:
            from panos_api_cleanup import main as pa_cleanup_main     # noqa: E402
        except ImportError as _e:
            # Same degradation as above: keep PA convert/import usable but
            # disable the Cleanup feature instead of crashing at startup.
            _CLEANUP_ENABLED = False
            _CLEANUP_IMPORT_ERROR = _CLEANUP_IMPORT_ERROR or str(_e)
except ImportError as _e:
    _PA_AVAILABLE = False
    _PA_IMPORT_ERROR = str(_e)

# Cisco ASA → Palo Alto modules - optional
_ASA_IMPORT_ERROR = ""
try:
    from asa_converter import main as asa_convert_main        # noqa: E402
    _ASA_AVAILABLE = True
except ImportError as _e:
    _ASA_AVAILABLE = False
    _ASA_IMPORT_ERROR = str(_e)

# Palo Alto → FortiGate modules - optional
_PA_TO_FG_IMPORT_ERROR = ""
try:
    from fg_converter import main as pa_to_fg_convert_main    # noqa: E402
    _PA_TO_FG_AVAILABLE = True
except ImportError as _e:
    _PA_TO_FG_AVAILABLE = False
    _PA_TO_FG_IMPORT_ERROR = str(_e)

# Cisco FTD → FortiGate modules - optional
_FTD_TO_FG_IMPORT_ERROR = ""
try:
    from fg_ftd_converter import main as ftd_to_fg_convert_main  # noqa: E402
    _FTD_TO_FG_AVAILABLE = True
except ImportError as _e:
    _FTD_TO_FG_AVAILABLE = False
    _FTD_TO_FG_IMPORT_ERROR = str(_e)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
FTD_MODEL_LIST = [
    "ftd-1010", "ftd-1120", "ftd-1140",
    "ftd-2110", "ftd-2120", "ftd-2130", "ftd-2140",
    "ftd-3105", "ftd-3110", "ftd-3120", "ftd-3130", "ftd-3140",
    "ftd-4215",
]

PA_MODEL_LIST = [
    "pa-440", "pa-450", "pa-460",
    "pa-3220", "pa-3250",
    "pa-5220",
]

# Optional FTD network modules - pulled from the converter so the GUI and the
# CLI/converter stay in lock-step. Falls back to a minimal stub if the import
# is unavailable (keeps the GUI importable in stripped builds).
try:
    from interface_converter import (  # noqa: E402
        FTD_NETWORK_MODULES as _FTD_NM,
        FTD_MODELS as _FTD_MODELS_INFO,
    )
except Exception:  # noqa: BLE001
    _FTD_NM = {"none": {"label": "None (fixed ports only)", "ports": 0, "speed": None}}
    _FTD_MODELS_INFO = {}

FTD_MODULE_IDS = list(_FTD_NM.keys())
FTD_MODULE_LABELS = [_FTD_NM[m].get("label", m) for m in FTD_MODULE_IDS]
FTD_MODULE_LABEL_TO_ID = {
    _FTD_NM[m].get("label", m): m for m in FTD_MODULE_IDS
}
FTD_MODULE_ID_TO_LABEL = {
    m: _FTD_NM[m].get("label", m) for m in FTD_MODULE_IDS
}


def _ftd_model_module_capable(model: str) -> bool:
    """True if the FTD model has at least one network-module slot."""
    return bool(_FTD_MODELS_INFO.get(model, {}).get("module_slots"))

def _profile_list(key: str, default: List[str]) -> List[str]:
    value = _RUNTIME_PROFILE.get(key)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value or default
    return default


def _profile_text(key: str, default: str = "") -> str:
    value = _RUNTIME_PROFILE.get(key)
    return value.strip() if isinstance(value, str) and value.strip() else default


SOURCE_PLATFORM_LIST = _profile_list(
    "source_platforms", ["FortiGate", "Cisco ASA", "Palo Alto", "Cisco FTD"],
)

PLATFORM_LIST = _profile_list(
    "target_platforms", ["Cisco FTD", "Palo Alto PAN-OS", "FortiGate"],
)

DEFAULT_SOURCE_PLATFORM = SOURCE_PLATFORM_LIST[0]
DEFAULT_TARGET_PLATFORM = PLATFORM_LIST[0]

# ---------------------------------------------------------------------------
# Interface link-aggregation builder (Convert tab, FortiGate -> FTD only)
# ---------------------------------------------------------------------------
# Each builder row describes one interface to scale up on the FTD side. The
# (action x target) pair maps to a converter CLI flag:
#   Expand   + Port-Channel  -> --expand-portchannel
#   Promote  + Port-Channel  -> --promote-portchannel
#   Expand   + Bridge Group  -> --expand-bridgegroup
#   Promote  + Bridge Group  -> --promote-bridgegroup
AGG_ACTION_MAP = "Map / Assign"
AGG_ACTION_EXPAND = "Expand"
AGG_ACTION_PROMOTE = "Promote"
AGG_ACTIONS = [AGG_ACTION_MAP, AGG_ACTION_EXPAND, AGG_ACTION_PROMOTE]

AGG_TARGET_PORTCHANNEL = "Port-Channel"
AGG_TARGET_BRIDGEGROUP = "Bridge Group"
AGG_TARGETS = [AGG_TARGET_PORTCHANNEL, AGG_TARGET_BRIDGEGROUP]

# (action, target) -> converter flag. Map/Assign ignores the target (it's a
# straight 1:1 port assignment, no aggregation).
AGG_FLAG_MAP = {
    (AGG_ACTION_EXPAND, AGG_TARGET_PORTCHANNEL): "--expand-portchannel",
    (AGG_ACTION_PROMOTE, AGG_TARGET_PORTCHANNEL): "--promote-portchannel",
    (AGG_ACTION_EXPAND, AGG_TARGET_BRIDGEGROUP): "--expand-bridgegroup",
    (AGG_ACTION_PROMOTE, AGG_TARGET_BRIDGEGROUP): "--promote-bridgegroup",
}

SUPPORTED_PAIRS_TEXT = _profile_text(
    "supported_pairs_text",
    (
        "Supported pairs:  FortiGate <-> Cisco FTD   |   "
        "FortiGate <-> Palo Alto PAN-OS   |   "
        "Cisco ASA -> Palo Alto PAN-OS"
    ),
)

APP_TITLE_OVERRIDE = _profile_text("app_title")

# Known auto-generated defaults for the "Output Base Name" field. When the field
# holds any of these, platform changes may overwrite it; when the user has typed
# a custom value, it is preserved.
DEFAULT_OUTPUT_BASES = {"", "ftd_config", "pa_config", "fg_config"}

DEFAULT_DIR = APP_DIR


def _profile_title(default: str) -> str:
    if APP_TITLE_OVERRIDE:
        return APP_TITLE_OVERRIDE.format(version=APP_VERSION)
    return default


# ---------------------------------------------------------------------------
# Cleanup "What to Delete" options
# ---------------------------------------------------------------------------
# One entry per checkbox on the Cleanup tab:
#   (key, FTD label, FTD flag, PA label, PA flag)
# A None PA label/flag means panos_api_cleanup.py has no equivalent, so the
# checkbox is hidden (and unchecked) while the target is Palo Alto PAN-OS.
# PA's single --delete-interfaces flag both resets ethernet interfaces and
# deletes aggregate-ethernet configs, so it maps to the interface-reset row.
CLEANUP_DELETE_OPTIONS = [
    ("rules", "Access Rules", "--delete-rules",
     "Security Rules", "--delete-security-rules"),
    ("routes", "Static Routes", "--delete-routes",
     "Static Routes", "--delete-static-routes"),
    ("subinterfaces", "Subinterfaces", "--delete-subinterfaces",
     None, None),
    ("etherchannels", "EtherChannels", "--delete-etherchannels",
     None, None),
    ("security-zones", "Security Zones", "--delete-security-zones",
     "Zones", "--delete-zones"),
    ("bridge-groups", "Bridge Groups", "--delete-bridge-groups",
     None, None),
    ("service-groups", "Service Groups", "--delete-service-groups",
     "Service Groups", "--delete-service-groups"),
    ("service-objects", "Service Objects", "--delete-service-objects",
     "Service Objects", "--delete-service-objects"),
    ("address-groups", "Address Groups", "--delete-address-groups",
     "Address Groups", "--delete-address-groups"),
    ("address-objects", "Address Objects", "--delete-address-objects",
     "Address Objects", "--delete-address-objects"),
    ("snmp", "SNMP Hosts & Users", "--delete-snmp",
     None, None),
    ("reset-physical-interfaces", "Physical Interfaces (reset)",
     "--reset-physical-interfaces",
     "Interfaces (reset ethernet, delete aggregates)", "--delete-interfaces"),
]

# key -> CLI flag, per platform (PA values may be None = unsupported).
CLEANUP_FTD_FLAGS = {key: ftd_flag for key, _fl, ftd_flag, _pl, _pf in CLEANUP_DELETE_OPTIONS}
CLEANUP_PA_FLAGS = {key: pa_flag for key, _fl, _ff, _pl, pa_flag in CLEANUP_DELETE_OPTIONS}

# ---------------------------------------------------------------------------
# argv redaction
# ---------------------------------------------------------------------------
# Flags whose immediate value is sensitive and must never be echoed to the
# output window or logs. Add to this set if a new credential-bearing flag is
# introduced anywhere the GUI shells out.
_SENSITIVE_FLAGS = frozenset({
    "--password", "-p", "--api-key", "--token",
    "--auth-password", "--priv-password",
})


def _redact_argv(argv: List[str]) -> List[str]:
    """Return a copy of ``argv`` with values following sensitive flags
    replaced by ``***REDACTED***``. Handles both the two-token form
    (``--password secret``) and the ``--password=secret`` form. Used before
    echoing the command line to the GUI output widget so admin passwords
    don't leak into the run log.
    """
    out = []
    redact_next = False
    for token in argv:
        if redact_next:
            out.append("***REDACTED***")
            redact_next = False
            continue
        flag, sep, _value = token.partition("=")
        if sep and flag in _SENSITIVE_FLAGS:
            out.append(f"{flag}=***REDACTED***")
            continue
        out.append(token)
        if token in _SENSITIVE_FLAGS:
            redact_next = True
    return out


def _argv_secret_values(argv: List[str]) -> List[str]:
    """Return the credential values embedded in ``argv`` (the values that
    follow sensitive flags, in either the two-token or ``--flag=value`` form).
    Used to build the plain-string secret snapshot handed to worker threads.
    """
    secrets: List[str] = []
    grab_next = False
    for token in argv:
        if grab_next:
            if token:
                secrets.append(token)
            grab_next = False
            continue
        flag, sep, value = token.partition("=")
        if sep and flag in _SENSITIVE_FLAGS:
            if value:
                secrets.append(value)
            continue
        if token in _SENSITIVE_FLAGS:
            grab_next = True
    return secrets


# ---------------------------------------------------------------------------
# Stdout / stderr redirection
# ---------------------------------------------------------------------------
class _QueueWriter(io.TextIOBase):
    """Thread-safe stdout/stderr substitute that feeds text into a Queue."""

    def __init__(self, q: queue.Queue, tag: Any) -> None:
        super().__init__()
        self._q = q
        self._tag = tag

    def write(self, text: str) -> int:
        if text:
            self._q.put((self._tag, text))
        return len(text) if text else 0

    def flush(self) -> None:
        pass

    def isatty(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# Theme definitions
# ---------------------------------------------------------------------------
THEMES = {
    "Default": {
        "bg":       "#1a1a1a",
        "input":    "#2d2d2d",
        "fg":       "#d4d4d4",
        "fg_dim":   "#909090",
        "accent":   "#b0b0b0",
        "accent_d": "#242424",
        "accent_h": "#c8c8c8",
        "border":   "#3c3c3c",
        "btn_bg":   "#b0b0b0",
        "btn_fg":   "#1a1a1a",
        "tab_bg":   "#242424",
        "out_bg":   "#2d2d2d",
        "out_fg":   "#a6e3a1",
    },
    "Coral": {
        "bg":       "#0b1e24",
        "input":    "#112e35",
        "fg":       "#e0d4bc",
        "fg_dim":   "#7a9a8a",
        "accent":   "#f08a65",
        "accent_d": "#1a4450",
        "accent_h": "#5abaa0",
        "border":   "#3e6058",
        "btn_bg":   "#f08a65",
        "btn_fg":   "#000000",
        "tab_bg":   "#112e35",
        "out_bg":   "#0b1e24",
        "out_fg":   "#5abaa0",
    },
    "Sandstone": {
        "bg":       "#4f5544",
        "input":    "#2e3128",
        "fg":       "#d8d2bc",
        "fg_dim":   "#9a9480",
        "accent":   "#c97b3a",
        "accent_d": "#3e4337",
        "accent_h": "#e0934a",
        "border":   "#2a2d23",
        "btn_bg":   "#c97b3a",
        "btn_fg":   "#2e3128",
        "tab_bg":   "#3e4337",
        "out_bg":   "#2e3128",
        "out_fg":   "#a3b878",
    },
    "Chris": {
        "bg":       "#ff69b4",
        "input":    "#ff3399",
        "fg":       "#1b00ff",
        "fg_dim":   "#ff6600",
        "accent":   "#00ff00",
        "accent_d": "#ffd700",
        "accent_h": "#ffff00",
        "border":   "#8b00ff",
        "btn_bg":   "#00ff00",
        "btn_fg":   "#000000",
        "tab_bg":   "#ff85c2",
        "out_bg":   "#ebfa21",
        "out_fg":   "#ff0000",
    },
    "Voyager": {
        "bg":       "#0f1a3d",
        "input":    "#070d24",
        "fg":       "#e6ebf5",
        "fg_dim":   "#7d89b0",
        "accent":   "#f5a623",
        "accent_d": "#19234d",
        "accent_h": "#ffb840",
        "border":   "#1f2a5c",
        "btn_bg":   "#f5a623",
        "btn_fg":   "#0f1a3d",
        "tab_bg":   "#19234d",
        "out_bg":   "#070d24",
        "out_fg":   "#7dd3a0",
    },
    "Simulation": {
        "bg":       "#000000",
        "input":    "#0a140a",
        "fg":       "#00e63c",
        "fg_dim":   "#0f7a2a",
        "accent":   "#00ff41",
        "accent_d": "#0d1f0d",
        "accent_h": "#7dff9f",
        "border":   "#123d1c",
        "btn_bg":   "#00ff41",
        "btn_fg":   "#000000",
        "tab_bg":   "#0a140a",
        "out_bg":   "#000000",
        "out_fg":   "#00ff41",
    },
    "Light": {
        "bg":       "#f0f0eb",
        "input":    "#ffffff",
        "fg":       "#1e1e1e",
        "fg_dim":   "#6a6a6a",
        "accent":   "#0066cc",
        "accent_d": "#e2e2dc",
        "accent_h": "#0055aa",
        "border":   "#c0bfb5",
        "btn_bg":   "#0066cc",
        "btn_fg":   "#ffffff",
        "tab_bg":   "#e2e2dc",
        "out_bg":   "#ffffff",
        "out_fg":   "#1a6e1a",
    },
}

DEFAULT_THEME = "Default"

# Initialize module-level colors from the default theme
_t = THEMES[DEFAULT_THEME]
_BG       = _t["bg"]
_INPUT    = _t["input"]
_FG       = _t["fg"]
_FG_DIM   = _t["fg_dim"]
_ACCENT   = _t["accent"]
_ACCENT_D = _t["accent_d"]
_ACCENT_H = _t["accent_h"]
_BORDER   = _t["border"]
_BTN_BG   = _t["btn_bg"]
_BTN_FG   = _t["btn_fg"]
_TAB_BG   = _t["tab_bg"]
_OUT_BG   = _t["out_bg"]
_OUT_FG   = _t["out_fg"]

APP_VERSION = "1.6.0"


# ---------------------------------------------------------------------------
# Matrix "digital rain" overlay (Simulation theme)
# ---------------------------------------------------------------------------
class _MatrixRain:
    """Animated Matrix-style digital rain drawn over an idle output console.

    A borderless Canvas is placed exactly over the host Text widget and
    animates falling glyph columns. The overlay is purely decorative: it is
    shown only while the console is empty and no operation is running (see
    App._update_matrix_rain), so it can never cover real output. Drawing
    pauses while the canvas is not viewable (e.g. its tab is hidden).
    """

    _GLYPHS = "ｱｲｳｴｵｶｷｸｹｺｻｼｽｾｿﾀﾁﾂﾃﾅﾆﾇﾈﾊﾋﾎﾏﾐﾑﾒﾓﾔﾕﾗﾘﾜ0123456789Z:=*+-<>"
    # Head glyph first, then progressively darker greens down the trail.
    _TRAIL = ("#d8ffe4", "#00ff41", "#00e63c", "#00b32d",
              "#008f26", "#0f7a2a", "#0a3f16", "#062b10")
    _CELL_W = 14
    _CELL_H = 17
    _TICK_MS = 70

    def __init__(self, host: tk.Text) -> None:
        self._host = host
        self._canvas: Optional[tk.Canvas] = None
        self._after_id: Optional[str] = None
        self._columns: List[Dict[str, Any]] = []
        self._width = 0
        self._height = 0
        self._tick_count = 0
        self._active = False

    def start(self) -> None:
        if self._active:
            return
        if self._canvas is None:
            # Sibling of the host placed over it - the standard Tk overlay
            # trick; the Text widget underneath stays untouched.
            self._canvas = tk.Canvas(
                self._host.master, highlightthickness=0, bd=0,
                bg="#000000", takefocus=0,
            )
        self._canvas.place(in_=self._host, x=0, y=0, relwidth=1.0, relheight=1.0)
        # Canvas.lift() is aliased to tag_raise (canvas items), so raise the
        # widget itself via Misc.tkraise to stack it above the Text.
        tk.Misc.tkraise(self._canvas)
        self._active = True
        self._tick()

    def stop(self) -> None:
        self._active = False
        if self._after_id is not None:
            try:
                self._host.after_cancel(self._after_id)
            except tk.TclError:
                pass
            self._after_id = None
        if self._canvas is not None:
            try:
                self._canvas.delete("all")
                self._canvas.place_forget()
            except tk.TclError:
                self._canvas = None
        self._columns = []
        self._width = 0

    def _rebuild_columns(self, width: int, height: int) -> None:
        self._width, self._height = width, height
        if self._canvas is not None:
            self._canvas.delete("all")
        rows = max(1, height // self._CELL_H)
        self._columns = []
        for i in range(max(1, width // self._CELL_W)):
            self._columns.append({
                "x": i * self._CELL_W + self._CELL_W // 2,
                # Stagger starts above the visible area so columns trickle in
                "row": -random.randint(0, rows * 2),
                # 1 = advance every tick, 2 = every other tick (slow column)
                "skip": random.choice((1, 1, 2)),
                "phase": random.randint(0, 1),
                "items": [],  # canvas item ids, oldest first
            })
        self._tick_count = 0

    def _tick(self) -> None:
        if not self._active:
            return
        try:
            self._after_id = self._host.after(self._TICK_MS, self._tick)
            canvas = self._canvas
            if canvas is None or not canvas.winfo_viewable():
                return
            w, h = canvas.winfo_width(), canvas.winfo_height()
            if w <= 1 or h <= 1:
                return
            if w != self._width or h != self._height:
                self._rebuild_columns(w, h)
            self._tick_count += 1
            rows = h // self._CELL_H + 1
            trail_len = len(self._TRAIL)
            for col in self._columns:
                if (self._tick_count + col["phase"]) % col["skip"]:
                    continue
                col["row"] += 1
                row = col["row"]
                items = col["items"]
                if row - trail_len > rows:
                    # Fully off-screen: respawn above the top
                    for item in items:
                        canvas.delete(item)
                    del items[:]
                    col["row"] = -random.randint(0, rows)
                    continue
                if 0 <= row <= rows:
                    items.append(canvas.create_text(
                        col["x"], row * self._CELL_H,
                        text=random.choice(self._GLYPHS),
                        fill=self._TRAIL[0], font=("Consolas", 11),
                    ))
                elif items:
                    # Head ran past the bottom - drain the tail
                    canvas.delete(items.pop(0))
                # Fade the trail: newest item gets the head color
                for age, item in enumerate(reversed(items)):
                    canvas.itemconfigure(
                        item, fill=self._TRAIL[min(age, trail_len - 1)])
                while len(items) > trail_len:
                    canvas.delete(items.pop(0))
        except tk.TclError:
            # Widget destroyed mid-animation (window closing)
            self._active = False
            self._after_id = None


class App(tk.Tk):
    """Main application window."""

    def __init__(self) -> None:
        super().__init__()
        self._set_window_title(f"Firewall Migration Tool v{APP_VERSION}")
        self.geometry("960x720")
        self.minsize(800, 600)

        # Window icon - load from bundle dir when frozen, project dir otherwise.
        # Wrapped because a bad/missing .ico must never crash the GUI.
        try:
            base = getattr(sys, "_MEIPASS", APP_DIR) if getattr(sys, "frozen", False) else APP_DIR
            icon_path = os.path.join(base, "app_icon.ico")
            if os.path.isfile(icon_path):
                self.iconbitmap(icon_path)
        except tk.TclError:
            pass

        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._output_queue: queue.Queue = queue.Queue()

        # Widgets whose 'state' is managed explicitly (Run/Cancel buttons via
        # _set_buttons_state, the Workers spinbox via the platform branches).
        # _set_tab_enabled's recursive walk skips these so a tab lock/unlock
        # never clobbers their managed state.
        self._state_managed_widgets: set = set()

        # Canvases created by _make_scrollable. One persistent global
        # MouseWheel binding dispatches to whichever of these is under the
        # pointer (see _on_global_mousewheel).
        self._wheel_canvases: List[Any] = []
        self.bind_all("<MouseWheel>", self._on_global_mousewheel)

        # Confirm before closing mid-operation (see _on_close).
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        # Current platform selection
        self._current_platform = DEFAULT_TARGET_PLATFORM
        self._current_source = DEFAULT_SOURCE_PLATFORM

        # Interface link-aggregation builder state (Convert tab). Each entry in
        # _agg_rows is a dict of the row's widgets/vars; the index maps a
        # (lowercased) FortiGate interface name to its category so the builder
        # can auto-detect Expand vs Promote and Port-Channel vs Bridge Group.
        self._agg_rows: List[Dict[str, Any]] = []
        self._agg_iface_index: Dict[str, str] = {}
        self._agg_iface_names: List[str] = []
        self._agg_visible = False
        # Target platform the builder rows were created for; rows are cleared
        # when the target changes (port-name formats differ per platform).
        self._agg_shown_platform: Optional[str] = None

        # Import/Cleanup tab lockout state (set by _retitle_import_cleanup_tabs
        # when target doesn't support API-based import/cleanup).
        self._imp_locked_by_target = False
        self._cln_locked_by_target = False
        self._cleanup_enabled = _CLEANUP_ENABLED

        # Track current theme
        self._current_theme = DEFAULT_THEME
        self._tk_widgets = []  # raw tk widgets that need manual recolor

        # Matrix rain overlays for the output consoles (Simulation theme).
        # Built lazily by _update_matrix_rain once the consoles exist.
        self._rain_overlays: Dict[str, _MatrixRain] = {}

        self._apply_theme(THEMES[self._current_theme])
        self._build_ui()
        self._update_matrix_rain()

    def _set_window_title(self, default: str) -> None:
        self.title(_profile_title(default))

    def _on_close(self) -> None:
        """WM_DELETE_WINDOW handler - warn before closing mid-operation."""
        if self._running:
            if not self._ask_yes_no(
                "Operation In Progress",
                "An operation is in progress; closing now may leave the "
                "firewall half-configured.\n\nClose anyway?",
            ):
                return
        self.destroy()

    # ------------------------------------------------------------------
    # Theme engine
    # ------------------------------------------------------------------
    def _apply_theme(self, t: dict) -> None:
        """Apply a theme dictionary to all ttk styles and tk widget defaults."""
        # Active palette for runtime configure() calls (labels re-tinted on
        # platform change, picker Toplevels, message glyphs, ...). Using this
        # instead of the module-level constants keeps those sites in sync
        # with the selected theme.
        self._colors = dict(t)
        bg       = t["bg"]
        inp      = t["input"]
        fg       = t["fg"]
        fg_dim   = t["fg_dim"]
        accent   = t["accent"]
        accent_d = t["accent_d"]
        accent_h = t["accent_h"]
        border   = t["border"]
        btn_bg   = t["btn_bg"]
        btn_fg   = t["btn_fg"]
        tab_bg   = t["tab_bg"]
        out_bg   = t["out_bg"]
        out_fg   = t["out_fg"]

        self.configure(bg=bg)

        # Pure-tk widget defaults (messageboxes, dialogs, etc.)
        self.option_add("*background", bg)
        self.option_add("*foreground", fg)
        self.option_add("*activeBackground", accent_d)
        self.option_add("*activeForeground", fg)
        self.option_add("*selectBackground", accent_d)
        self.option_add("*selectForeground", fg)
        self.option_add("*relief", "flat")
        # Combobox popup listbox
        self.option_add("*TCombobox*Listbox.background", inp)
        self.option_add("*TCombobox*Listbox.foreground", fg)
        self.option_add("*TCombobox*Listbox.selectBackground", accent_d)
        self.option_add("*TCombobox*Listbox.selectForeground", fg)

        style = ttk.Style(self)
        style.theme_use("clam")

        # --- Frames ---
        style.configure("TFrame", background=bg)
        style.configure("TPanedwindow", background=bg)

        # --- LabelFrame (panels) ---
        style.configure(
            "TLabelframe",
            background=bg,
            bordercolor=accent_d,
            relief="groove",
        )
        style.configure(
            "TLabelframe.Label",
            background=bg,
            foreground=accent,
            font=("Segoe UI", 9, "bold"),
        )

        # --- Labels ---
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure(
            "Status.TLabel",
            background=tab_bg,
            foreground=fg_dim,
            relief="flat",
        )

        # --- Entry ---
        style.configure(
            "TEntry",
            fieldbackground=inp,
            foreground=fg,
            insertcolor=fg,
            bordercolor=border,
            lightcolor=border,
            darkcolor=border,
        )
        style.map(
            "TEntry",
            bordercolor=[("focus", accent)],
            lightcolor=[("focus", accent)],
        )

        # --- Button ---
        style.configure(
            "TButton",
            background=btn_bg,
            foreground=btn_fg,
            bordercolor=accent_d,
            focuscolor=accent,
            relief="flat",
            padding=(10, 5),
        )
        style.map(
            "TButton",
            background=[
                ("active", accent_h),
                ("pressed", accent_d),
                ("disabled", tab_bg),
            ],
            foreground=[("disabled", fg_dim)],
            bordercolor=[("active", accent), ("focus", accent)],
        )

        # --- Checkbutton ---
        style.configure(
            "TCheckbutton",
            background=bg,
            foreground=fg,
            indicatorbackground=inp,
            indicatorforeground=accent,
        )
        style.map(
            "TCheckbutton",
            background=[("active", bg)],
            indicatorbackground=[("selected", accent_d), ("active", inp)],
            indicatorforeground=[("selected", accent), ("active", fg_dim)],
            foreground=[("active", fg)],
        )

        # --- Combobox ---
        style.configure(
            "TCombobox",
            fieldbackground=inp,
            foreground=fg,
            background=tab_bg,
            bordercolor=border,
            arrowcolor=fg_dim,
            insertcolor=fg,
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", inp), ("disabled", bg)],
            foreground=[("disabled", fg_dim)],
            bordercolor=[("focus", accent)],
            arrowcolor=[("active", accent)],
        )

        # --- Spinbox ---
        style.configure(
            "TSpinbox",
            fieldbackground=inp,
            foreground=fg,
            background=tab_bg,
            bordercolor=border,
            arrowcolor=fg_dim,
            insertcolor=fg,
        )
        style.map(
            "TSpinbox",
            bordercolor=[("focus", accent)],
            arrowcolor=[("active", accent)],
        )

        # --- Notebook (tabs) ---
        style.configure(
            "TNotebook",
            background=bg,
            bordercolor=border,
            tabmargins=[2, 5, 2, 0],
        )
        style.configure(
            "TNotebook.Tab",
            background=tab_bg,
            foreground=fg_dim,
            bordercolor=border,
            padding=[12, 5],
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", accent_d), ("active", accent_h)],
            foreground=[("selected", fg), ("active", fg)],
            expand=[("selected", [1, 1, 1, 0])],
        )

        # --- Scrollbar ---
        style.configure(
            "TScrollbar",
            background=tab_bg,
            troughcolor=bg,
            bordercolor=border,
            arrowcolor=fg_dim,
            relief="flat",
        )
        style.map(
            "TScrollbar",
            background=[("active", accent_d), ("pressed", accent)],
            arrowcolor=[("active", fg)],
        )

        # Recolor raw tk widgets (Text, Listbox) that don't use ttk styles
        for w in getattr(self, "_tk_widgets", []):
            w.configure(
                bg=out_bg, fg=out_fg,
                selectbackground=accent_d, selectforeground=out_fg,
                highlightbackground=border, highlightcolor=accent,
            )
            # insertbackground is only supported by Text, not Listbox
            try:
                w.configure(insertbackground=out_fg)
            except tk.TclError:
                pass

        # Re-tint text tags whose colors were baked in at build time.
        help_text = getattr(self, "_help_text", None)
        if help_text is not None:
            help_text.tag_configure("title", foreground=accent)
            help_text.tag_configure("h1", foreground=accent)
            help_text.tag_configure("h2", foreground=accent_h)
            help_text.tag_configure("italic", foreground=fg_dim)
            help_text.tag_configure("code", foreground=accent_h)
            help_text.tag_configure("tip", foreground=accent_h)
            help_text.tag_configure("warning", foreground=accent)
            help_text.tag_configure("search_hit", foreground=out_fg)
        viewer_text = getattr(self, "viewer_text", None)
        if viewer_text is not None:
            viewer_text.tag_configure("search_hit", foreground=out_fg)

    def _on_theme_change(self, event: Optional[Any] = None) -> None:
        """Handle theme selector change."""
        name = self.theme_var.get()
        if name == self._current_theme:
            return
        self._current_theme = name
        self._apply_theme(THEMES[name])
        self._update_matrix_rain()

    def _update_matrix_rain(self) -> None:
        """Show/hide the Matrix rain overlays (Simulation theme only).

        The rain runs over an output console only while that console is empty
        and no operation is running, so it can never cover real output. Called
        on theme change, run start/finish, and console clear.
        """
        simulation = self._current_theme == "Simulation"
        for attr in ("conv_output", "imp_output", "cln_output", "snmp_output"):
            widget = getattr(self, attr, None)
            if widget is None:
                continue
            overlay = self._rain_overlays.get(attr)
            if overlay is None:
                overlay = self._rain_overlays[attr] = _MatrixRain(widget)
            try:
                empty = not widget.get("1.0", "end-1c").strip()
            except tk.TclError:
                continue
            if simulation and not self._running and empty:
                overlay.start()
            else:
                overlay.stop()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_ui(self) -> None:
        # Platform selector bar
        platform_frame = ttk.Frame(self)
        platform_frame.pack(fill=tk.X, padx=6, pady=(6, 0))

        ttk.Label(platform_frame, text="Source:").pack(side=tk.LEFT, padx=(4, 4))
        self.source_var = tk.StringVar(value=self._current_source)
        # Idle (not-running) states for the platform selectors; both combos
        # are force-disabled while an operation runs (_set_buttons_state).
        self._source_combo_idle_state = (
            tk.DISABLED if len(SOURCE_PLATFORM_LIST) == 1 else "readonly"
        )
        self.source_combo = ttk.Combobox(
            platform_frame, textvariable=self.source_var,
            values=SOURCE_PLATFORM_LIST,
            state=self._source_combo_idle_state,
            width=14,
        )
        self.source_combo.pack(side=tk.LEFT)
        self.source_combo.bind("<<ComboboxSelected>>", self._on_source_change)

        ttk.Label(platform_frame, text="Target:").pack(side=tk.LEFT, padx=(12, 4))
        self.platform_var = tk.StringVar(value=self._current_platform)
        self._platform_combo_idle_state = (
            tk.DISABLED if len(PLATFORM_LIST) == 1 else "readonly"
        )
        self.platform_combo = ttk.Combobox(
            platform_frame, textvariable=self.platform_var,
            values=PLATFORM_LIST,
            state=self._platform_combo_idle_state,
            width=20,
        )
        self.platform_combo.pack(side=tk.LEFT)
        self.platform_combo.bind("<<ComboboxSelected>>", self._on_platform_change)

        if "Palo Alto PAN-OS" in PLATFORM_LIST and not _PA_AVAILABLE:
            self._pa_warning = ttk.Label(
                platform_frame, text="(PA modules not found)", foreground=_FG_DIM,
            )
            self._pa_warning.pack(side=tk.LEFT, padx=8)

        if _CLEANUP_IMPORT_ERROR:
            # Cleanup modules were expected but could not be imported -
            # the feature degraded to disabled at startup (see module imports).
            ttk.Label(
                platform_frame,
                text="(cleanup modules missing - Cleanup disabled)",
                foreground=self._colors["fg_dim"],
            ).pack(side=tk.LEFT, padx=8)

        # Theme selector (right-aligned)
        self.theme_var = tk.StringVar(value=self._current_theme)
        theme_combo = ttk.Combobox(
            platform_frame, textvariable=self.theme_var,
            values=list(THEMES.keys()), state="readonly", width=14,
        )
        theme_combo.pack(side=tk.RIGHT, padx=(4, 4))
        theme_combo.bind("<<ComboboxSelected>>", self._on_theme_change)
        ttk.Label(platform_frame, text="Theme:").pack(side=tk.RIGHT)

        # Supported conversion matrix hint
        matrix_frame = ttk.Frame(self)
        matrix_frame.pack(fill=tk.X, padx=6, pady=(2, 0))
        ttk.Label(
            matrix_frame,
            text=SUPPORTED_PAIRS_TEXT,
            foreground=_FG_DIM,
        ).pack(side=tk.LEFT, padx=(4, 0))

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self._notebook = notebook

        self._build_convert_tab(notebook)
        self._build_import_tab(notebook)
        if self._cleanup_enabled:
            self._build_cleanup_tab(notebook)
        else:
            self._cln_tab = None
        self._build_snmp_tab(notebook)
        self._build_viewer_tab(notebook)
        self._build_help_tab(notebook)

        # Apply profile/source defaults after all tab widgets exist.
        self._on_source_change()

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(
            self, textvariable=self.status_var, style="Status.TLabel",
            anchor=tk.W, padding=(6, 2),
        ).pack(side=tk.BOTTOM, fill=tk.X)

    def _targets_for_source(self, source: str) -> List[str]:
        target_map = {
            "FortiGate": ["Cisco FTD", "Palo Alto PAN-OS"],
            "Cisco ASA": ["Palo Alto PAN-OS"],
            "Palo Alto": ["FortiGate"],
            "Cisco FTD": ["FortiGate"],
        }
        candidates = target_map.get(source, PLATFORM_LIST)
        return [target for target in candidates if target in PLATFORM_LIST]

    def _configure_target_selector(self, targets: List[str]) -> None:
        state = tk.DISABLED if len(targets) <= 1 else "readonly"
        self._platform_combo_idle_state = state
        self.platform_combo.configure(values=targets, state=state)
        if targets and self.platform_var.get() not in targets:
            self.platform_var.set(targets[0])

    def _on_source_change(self, event: Optional[Any] = None) -> None:
        """Handle source platform change - update target list and input label."""
        source = self.source_var.get()
        self._current_source = source
        targets = self._targets_for_source(source)
        if not targets:
            messagebox.showerror(
                "Unsupported Profile",
                f"No enabled targets are available for source platform: {source}",
            )
            return

        if source != "Cisco FTD":
            # The FTD file-mode toggle only applies to a Cisco FTD source.
            # Reset and hide it for every other source so its side effects
            # (labels, disabled browse/username fields) don't leak in; each
            # branch below then restores its own labels via
            # _on_platform_change().
            self.conv_ftd_file_var.set(False)
            self.conv_ftd_file_check.grid_remove()

        if source == "Cisco ASA":
            # When source is ASA, target must be Palo Alto PAN-OS
            self._configure_target_selector(targets)
            self._on_platform_change()
            self.conv_input_label.configure(text="Input Config:")
            self.conv_browse_btn.configure(state=tk.NORMAL)
        elif source == "Palo Alto":
            # When source is Palo Alto, target must be FortiGate
            self._configure_target_selector(targets)
            self._on_platform_change()
            self.conv_input_label.configure(text="Input XML:")
            self.conv_browse_btn.configure(state=tk.NORMAL)
        elif source == "Cisco FTD":
            # FTD → FortiGate: default to live API mode
            self._configure_target_selector(targets)
            self._on_platform_change()
            self.conv_ftd_file_var.set(False)
            self.conv_ftd_file_check.grid()  # show the mode toggle
            self.conv_input_label.configure(text="FTD Host / IP:")
            self.conv_input_var.set("")
            self.conv_browse_btn.configure(state=tk.DISABLED)
            self.conv_ha_label.configure(text="FTD Username:", foreground=self._colors["fg"])
            self.conv_ha_entry.configure(state=tk.NORMAL)
            self.conv_ha_var.set("admin")
            self.conv_ha_hint.configure(text="FTD username (leave blank for 'admin')")
            self._update_ha_pick_visible()
        else:
            # FortiGate - restore FTD and PA targets (not FortiGate-as-target)
            self._configure_target_selector(targets)
            self._on_platform_change()
            self.conv_input_label.configure(text="Input YAML:")
            self.conv_browse_btn.configure(state=tk.NORMAL)

        # The FortiGate YAML export how-to only applies to a FortiGate source.
        self._set_fortinet_help_visible(source == "FortiGate")

    def _on_ftd_mode_change(self) -> None:
        """Toggle between live FDM API and JSON file input for Cisco FTD source."""
        if self.conv_ftd_file_var.get():
            # File mode - enable browse, update labels, hide username field
            self.conv_input_label.configure(text="FTD Config JSON:")
            self.conv_input_var.set("")
            self.conv_browse_btn.configure(state=tk.NORMAL)
            self.conv_ha_entry.configure(state=tk.DISABLED)
            self.conv_ha_label.configure(text="FTD Username:", foreground=self._colors["fg_dim"])
            self.conv_ha_hint.configure(text="(username/password not needed for file mode)")
        else:
            # API mode - restore host/username fields, disable browse
            self.conv_input_label.configure(text="FTD Host / IP:")
            self.conv_input_var.set("")
            self.conv_browse_btn.configure(state=tk.DISABLED)
            self.conv_ha_entry.configure(state=tk.NORMAL)
            self.conv_ha_label.configure(text="FTD Username:", foreground=self._colors["fg"])
            self.conv_ha_var.set("admin")
            self.conv_ha_hint.configure(text="FTD username (leave blank for 'admin')")
        self._update_ha_pick_visible()

    def _on_platform_change(self, event: Optional[Any] = None) -> None:
        """Handle platform selector change - update model lists and labels."""
        platform = self.platform_var.get()
        self._current_platform = platform

        if platform == "Palo Alto PAN-OS":
            if not _PA_AVAILABLE:
                detail = f"\n\nError: {_PA_IMPORT_ERROR}" if _PA_IMPORT_ERROR else ""
                search_path = _PA_DIR or "(not found)"
                messagebox.showwarning(
                    "PA Modules Missing",
                    "Palo Alto converter modules not found.\n\n"
                    f"Searched: {search_path}\n"
                    "Make sure the FortiGateToPaloAltoTool directory exists "
                    f"with all required .py files.{detail}",
                )
                self.platform_var.set("Cisco FTD")
                self._current_platform = "Cisco FTD"
                return

            # Update Convert tab - re-enable model combo if a FortiGate
            # target had disabled it.
            self.conv_model_combo.configure(state="readonly")
            self.conv_model_combo.configure(values=PA_MODEL_LIST)
            self.conv_model_var.set("pa-440")
            if self.conv_output_var.get().strip() in DEFAULT_OUTPUT_BASES:
                self.conv_output_var.set("pa_config")
            self.conv_ha_var.set("")
            self.conv_ha_entry.configure(state=tk.DISABLED)
            self.conv_ha_label.configure(text="HA Port (optional):", foreground=self._colors["fg_dim"])
            self.conv_ha_hint.configure(text="(not applicable for PAN-OS)")

            # Update Import tab labels
            self.imp_host_label.configure(text="PAN-OS Host / IP:")
            if self.imp_base_var.get().strip() in DEFAULT_OUTPUT_BASES:
                self.imp_base_var.set("pa_config")
            self.imp_workers_label.configure(foreground=self._colors["fg_dim"])
            self.imp_workers_spin.configure(state=tk.DISABLED)
            self.imp_deploy_cb.configure(text="Commit after import")

            # Update Cleanup tab labels
            if self._cleanup_enabled:
                self.cln_host_label.configure(text="PAN-OS Host / IP:")
                self.cln_model_combo.configure(values=PA_MODEL_LIST)
                self.cln_model_var.set("pa-440")
                self.cln_deploy_cb.configure(text="Commit after cleanup")
                self._update_cleanup_delete_options(is_pa=True)

            self._retitle_import_cleanup_tabs("PAN-OS")

            source = self._current_source
            if source == "Cisco ASA":
                self._set_window_title(
                    f"Cisco ASA to Palo Alto PAN-OS Migration Tool v{APP_VERSION}",
                )
            else:
                self._set_window_title(
                    f"FortiGate to Palo Alto PAN-OS Migration Tool v{APP_VERSION}",
                )

        elif platform == "FortiGate":
            source = self._current_source
            # FTD→FG needs its own converter; PA→FG needs a different one
            needed_available = (
                _FTD_TO_FG_AVAILABLE if source == "Cisco FTD" else _PA_TO_FG_AVAILABLE
            )
            if not needed_available:
                err = (
                    _FTD_TO_FG_IMPORT_ERROR if source == "Cisco FTD"
                    else _PA_TO_FG_IMPORT_ERROR
                )
                searched = (
                    _FTD_TO_FG_DIR if source == "Cisco FTD" else _PA_TO_FG_DIR
                )
                label = "FTD→FG" if source == "Cisco FTD" else "PA→FG"
                messagebox.showwarning(
                    f"{label} Modules Missing",
                    f"{label} converter modules not found.\n\n"
                    f"Searched: {searched}\n"
                    f"Error: {err}",
                )
                self.source_var.set("FortiGate")
                self._current_source = "FortiGate"
                fallback_targets = self._targets_for_source("FortiGate")
                self._configure_target_selector(fallback_targets)
                self._current_platform = self.platform_var.get()
                self._on_platform_change()
                return

            # Update Convert tab - no model needed for FortiGate target
            self.conv_model_combo.configure(values=["(not applicable)"])
            self.conv_model_var.set("(not applicable)")
            self.conv_model_combo.configure(state=tk.DISABLED)
            if self.conv_output_var.get().strip() in DEFAULT_OUTPUT_BASES:
                self.conv_output_var.set("fg_config")

            if source == "Cisco FTD":
                # HA entry repurposed as FTD username when FTD source
                self.conv_ha_var.set("admin")
                self.conv_ha_entry.configure(state=tk.NORMAL)
                self.conv_ha_label.configure(text="FTD Username:", foreground=self._colors["fg"])
                self.conv_ha_hint.configure(text="FTD username (leave blank for 'admin')")
            else:
                self.conv_ha_var.set("")
                self.conv_ha_entry.configure(state=tk.DISABLED)
                self.conv_ha_label.configure(text="HA Port (optional):", foreground=self._colors["fg_dim"])
                self.conv_ha_hint.configure(text="(not applicable for FortiGate)")

            # Import/Cleanup not supported for FortiGate target
            self.imp_host_label.configure(text="FortiGate Host / IP:")
            if self.imp_base_var.get().strip() in DEFAULT_OUTPUT_BASES:
                self.imp_base_var.set("fg_config")
            self.imp_workers_label.configure(foreground=self._colors["fg_dim"])
            self.imp_workers_spin.configure(state=tk.DISABLED)
            self.imp_deploy_cb.configure(text="(not applicable)")

            if self._cleanup_enabled:
                self.cln_host_label.configure(text="FortiGate Host / IP:")
                self.cln_model_combo.configure(values=["(not applicable)"])
                self.cln_model_var.set("(not applicable)")
                self.cln_deploy_cb.configure(text="(not applicable)")

            self._retitle_import_cleanup_tabs("FortiGate")

            source = self._current_source
            if source == "Cisco FTD":
                self._set_window_title(
                    f"Cisco FTD to FortiGate Migration Tool v{APP_VERSION}",
                )
            else:
                self._set_window_title(
                    f"Palo Alto to FortiGate Migration Tool v{APP_VERSION}",
                )

        else:
            # Restore FTD defaults - also re-enable model combo if it was disabled
            self.conv_model_combo.configure(state="readonly")
            self.conv_model_combo.configure(values=FTD_MODEL_LIST)
            self.conv_model_var.set("ftd-3120")
            if self.conv_output_var.get().strip() in DEFAULT_OUTPUT_BASES:
                self.conv_output_var.set("ftd_config")
            self.conv_ha_entry.configure(state=tk.NORMAL)
            self.conv_ha_label.configure(text="HA Port (optional):", foreground=self._colors["fg"])
            self.conv_ha_hint.configure(text="click Pick… to choose HA port(s), or type e.g. Ethernet1/2,Ethernet1/3  (blank = none)")

            self.imp_host_label.configure(text="FTD Host / IP:")
            if self.imp_base_var.get().strip() in DEFAULT_OUTPUT_BASES:
                self.imp_base_var.set("ftd_config")
            self.imp_workers_label.configure(foreground=self._colors["fg"])
            self.imp_workers_spin.configure(state=tk.NORMAL)
            self.imp_deploy_cb.configure(text="Deploy after import")

            if self._cleanup_enabled:
                self.cln_host_label.configure(text="FTD Host / IP:")
                self.cln_model_combo.configure(values=FTD_MODEL_LIST)
                self.cln_model_var.set("ftd-3120")
                self.cln_deploy_cb.configure(text="Deploy after cleanup")
                self._update_cleanup_delete_options(is_pa=False)

            self._retitle_import_cleanup_tabs("FTD")

            self._set_window_title(f"FortiGate to Cisco FTD Converter v{APP_VERSION}")

        # Show/hide the interface-aggregation builder for the new direction.
        self._update_aggregation_visibility()
        # Show/hide the FTD network-module selector for the new target.
        self._update_module_selector()
        # Show the HA port picker only in FTD HA-port mode (not username mode).
        self._update_ha_pick_visible()

    def _retitle_import_cleanup_tabs(self, target: str) -> None:
        """Update Import/Cleanup tab titles, section frame labels, and enabled state
        for the target platform. When target is FortiGate, API-based import/cleanup
        is not supported and the tab forms are disabled.

        Also manages SNMP tab visibility: SNMPv3 push is FDM-specific, so the
        tab is only shown when the target is Cisco FTD."""
        if getattr(self, "_snmp_tab", None) is not None:
            if target == "FTD":
                self._notebook.add(self._snmp_tab)   # restores a hidden tab in place
            else:
                self._notebook.hide(self._snmp_tab)

        if target == "FortiGate":
            imp_tab_text = "  Import (N/A for FortiGate)  "
            cln_tab_text = "  Cleanup (N/A for FortiGate)  "
            imp_frame_text = "FortiGate Connection (not applicable)"
            cln_frame_text = "FortiGate Connection (not applicable)"
            tabs_locked = True
        else:
            imp_tab_text = f"  Import to {target}  "
            cln_tab_text = f"  Cleanup {target}  "
            imp_frame_text = f"{target} Connection & Import Options"
            cln_frame_text = f"{target} Connection"
            tabs_locked = False

        self._notebook.tab(self._imp_tab, text=imp_tab_text)
        self._imp_opts_frame.configure(text=imp_frame_text)

        self._imp_locked_by_target = tabs_locked
        self._set_tab_enabled(self._imp_tab, skip=(self.imp_output,), enabled=not tabs_locked)

        if self._cleanup_enabled:
            self._notebook.tab(self._cln_tab, text=cln_tab_text)
            self._cln_opts_frame.configure(text=cln_frame_text)

            self._cln_locked_by_target = tabs_locked
            self._set_tab_enabled(self._cln_tab, skip=(self.cln_output,), enabled=not tabs_locked)

            # Reset-password button's enabled state depends on has_custom_password(),
            # not on target lockout - restore it when unlocking.
            if not tabs_locked:
                self.cln_reset_pw_btn.configure(
                    # has_custom_password is bound only when _CLEANUP_ENABLED; runtime-guarded.
                    state=tk.NORMAL if has_custom_password() else tk.DISABLED,  # pyright: ignore[reportOptionalCall]
                )

        # Run/Cancel button states are excluded from the walk above (they are
        # in _state_managed_widgets); re-apply them for the new lock flags.
        if not self._running:
            self._set_buttons_state(tk.NORMAL)

    def _set_tab_enabled(
        self, tab: Any, skip: Tuple[Any, ...] = (), enabled: bool = True,
    ) -> None:
        """Recursively enable/disable all interactive widgets in a tab.
        `skip` holds widgets (like the output Text area) whose state is managed elsewhere.
        Widgets in self._state_managed_widgets (Run/Cancel buttons, the
        Workers spinbox) are always skipped - their state is set explicitly
        by _set_buttons_state / the platform-change branches, and a blind
        re-enable here would clobber it.
        Combobox widgets are restored to 'readonly' rather than 'normal' so the
        dropdown arrow stays visible without allowing free-text editing."""
        state = tk.NORMAL if enabled else tk.DISABLED
        managed = self._state_managed_widgets

        def walk(widget: Any) -> None:
            for child in widget.winfo_children():
                if child in skip or child in managed:
                    continue
                try:
                    if isinstance(child, ttk.Combobox):
                        child.configure(state="readonly" if enabled else tk.DISABLED)
                    else:
                        child.configure(state=state)
                except tk.TclError:
                    pass  # widget doesn't support 'state' (e.g. ttk.Frame, LabelFrame)
                walk(child)

        walk(tab)

    # ==================== CONVERT TAB ====================
    def _build_convert_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="  Convert  ")

        # How-to banner for exporting the FortiGate config (FortiGate source only;
        # toggled in _on_source_change via _set_fortinet_help_visible()).
        self.conv_fortinet_help = ttk.Label(
            tab,
            text=("ℹ  How to get the FortiGate config file:  on your FortiGate, "
                  "click the user menu (top-right) → Configuration → Backup → "
                  "select YAML → OK to download.  Then click Browse… below to "
                  "select the downloaded file."),
            foreground=_ACCENT, wraplength=760, justify=tk.LEFT,
        )
        self.conv_fortinet_help.pack(fill=tk.X, padx=10, pady=(8, 0), anchor=tk.W)

        opts = ttk.LabelFrame(tab, text="Conversion Options", padding=10)
        self._conv_opts_frame = opts
        opts.pack(fill=tk.X, padx=8, pady=(8, 4))

        # Row 0: Input file
        self.conv_input_label = ttk.Label(opts, text="Input YAML:")
        self.conv_input_label.grid(row=0, column=0, sticky=tk.W, pady=3)
        self.conv_input_var = tk.StringVar()
        ttk.Entry(opts, textvariable=self.conv_input_var, width=60).grid(
            row=0, column=1, sticky=tk.EW, padx=4,
        )
        self.conv_browse_btn = ttk.Button(opts, text="Browse...", command=self._browse_yaml)
        self.conv_browse_btn.grid(row=0, column=2, padx=4)

        # Row 1: Output directory
        ttk.Label(opts, text="Output Directory:").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.conv_outdir_var = tk.StringVar(value=DEFAULT_DIR)
        ttk.Entry(opts, textvariable=self.conv_outdir_var, width=60).grid(
            row=1, column=1, sticky=tk.EW, padx=4,
        )
        ttk.Button(opts, text="Browse...", command=self._browse_outdir).grid(
            row=1, column=2, padx=4,
        )

        # Row 2: Output base name
        ttk.Label(opts, text="Output Base Name:").grid(row=2, column=0, sticky=tk.W, pady=3)
        self.conv_output_var = tk.StringVar(value="ftd_config")
        ttk.Entry(opts, textvariable=self.conv_output_var, width=30).grid(
            row=2, column=1, sticky=tk.W, padx=4,
        )

        # Row 3: Target model
        ttk.Label(opts, text="Target Model:").grid(row=3, column=0, sticky=tk.W, pady=3)
        self.conv_model_var = tk.StringVar(value="ftd-3120")
        self.conv_model_combo = ttk.Combobox(
            opts, textvariable=self.conv_model_var,
            values=FTD_MODEL_LIST, state="readonly", width=18,
        )
        self.conv_model_combo.grid(row=3, column=1, sticky=tk.W, padx=4)
        # Selecting a model toggles whether the network-module dropdown applies.
        self.conv_model_combo.bind(
            "<<ComboboxSelected>>", lambda _e: self._update_module_selector(),
        )

        # Row 4: HA port (optional). The entry + "Pick..." button share a cell;
        # the button opens a checkbox port picker (FTD HA-port mode only). The
        # same field is reused as a free-text FTD Username field for FTD->FG, so
        # the entry stays and the picker button is hidden in that mode.
        self.conv_ha_label = ttk.Label(opts, text="HA Port (optional):")
        self.conv_ha_label.grid(row=4, column=0, sticky=tk.W, pady=3)
        self.conv_ha_var = tk.StringVar()
        self._conv_ha_cell = ttk.Frame(opts)
        self._conv_ha_cell.grid(row=4, column=1, sticky=tk.W, padx=4)
        self.conv_ha_entry = ttk.Entry(
            self._conv_ha_cell, textvariable=self.conv_ha_var, width=28,
        )
        self.conv_ha_entry.pack(side=tk.LEFT)
        self.conv_ha_pick_btn = ttk.Button(
            self._conv_ha_cell, text="Pick…", width=6, command=self._ha_pick_ports,
        )
        self.conv_ha_pick_btn.pack(side=tk.LEFT, padx=(3, 0))
        self.conv_ha_hint = ttk.Label(opts, text="click Pick… to choose HA port(s), or type e.g. Ethernet1/2,Ethernet1/3  (blank = none)")
        self.conv_ha_hint.grid(row=5, column=1, sticky=tk.W)

        # Row 6: Network module (FTD only; enabled for models with an NM slot)
        self.conv_module_label = ttk.Label(opts, text="Network Module:")
        self.conv_module_label.grid(row=6, column=0, sticky=tk.W, pady=3)
        self.conv_module_var = tk.StringVar(value=FTD_MODULE_ID_TO_LABEL["none"])
        self.conv_module_combo = ttk.Combobox(
            opts, textvariable=self.conv_module_var,
            values=FTD_MODULE_LABELS, state="readonly", width=22,
        )
        self.conv_module_combo.grid(row=6, column=1, sticky=tk.W, padx=4)
        self.conv_module_hint = ttk.Label(
            opts, text="Add-on module ports (Ethernet2/1…) join the available pool",
            foreground=_FG_DIM,
        )
        self.conv_module_hint.grid(row=7, column=1, sticky=tk.W)

        # Interface link-aggregation scale-up (Expand/Promote Port-Channels and
        # Bridge Groups) lives in its own builder section below the opts grid -
        # see _build_aggregation_section(). It is FortiGate->FTD only.

        # Row 14: FTD file mode toggle (hidden unless source is Cisco FTD)
        self.conv_ftd_file_var = tk.BooleanVar(value=False)
        self.conv_ftd_file_check = ttk.Checkbutton(
            opts,
            text="Use JSON config file instead of live FDM API",
            variable=self.conv_ftd_file_var,
            command=self._on_ftd_mode_change,
        )
        self.conv_ftd_file_check.grid(row=14, column=1, sticky=tk.W, padx=4, pady=3)
        self.conv_ftd_file_check.grid_remove()  # hidden until FTD source is selected

        # Row 15: Pretty-print
        self.conv_pretty_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            opts, text="Pretty-print JSON output", variable=self.conv_pretty_var,
        ).grid(row=15, column=1, sticky=tk.W, padx=4, pady=3)

        opts.columnconfigure(1, weight=1)

        # Interface aggregation builder (FortiGate->FTD only; hidden otherwise)
        self._build_aggregation_section(tab)

        # Buttons
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, padx=8, pady=4)
        self._conv_btn_frame = btn_frame
        self.conv_run_btn = ttk.Button(
            btn_frame, text="Run Conversion", command=self._run_convert,
        )
        self.conv_run_btn.pack(side=tk.LEFT)
        self.conv_cancel_btn = ttk.Button(
            btn_frame, text="Cancel", command=self._cancel_operation,
            state=tk.DISABLED,
        )
        self.conv_cancel_btn.pack(side=tk.LEFT, padx=8)
        ttk.Button(
            btn_frame, text="Clear Output",
            command=lambda: self._clear_output(self.conv_output),
        ).pack(side=tk.LEFT, padx=8)

        self.conv_output = self._make_output_area(tab)

        # Sync builder visibility with the initial source/target selection.
        self._update_aggregation_visibility()
        self._update_module_selector()

    # ==================== INTERFACE AGGREGATION BUILDER ====================
    def _build_aggregation_section(self, tab: ttk.Frame) -> None:
        """Build the interface link-aggregation builder (FortiGate -> FTD only).

        Replaces the old four free-text 'Expand/Promote' fields with a small
        per-interface table. Each row picks an interface (from the parsed
        config), the converter auto-detects Expand vs Promote and the target
        type, and the user just supplies a member count or explicit port list.
        The whole section is hidden unless the migration is FortiGate -> FTD.
        """
        frame = ttk.LabelFrame(
            tab, text="Interface Aggregation  (FortiGate → FTD)", padding=10,
        )
        self._agg_frame = frame

        self._agg_hint_label = ttk.Label(
            frame,
            text=(
                "Optional: control how each FortiGate interface lands on the "
                "target. Add a row per interface.\n"
                "• Map / Assign = pin the interface to one specific port (no "
                "aggregation).\n"
                "• Expand = grow an existing Port-Channel/Bridge Group.  "
                "• Promote = turn a plain interface into a new one.\n"
                "Members = a target count (e.g. 4) or an explicit port list "
                "(e.g. Ethernet1/5,Ethernet1/6) - click \"Pick…\" to choose ports.  "
                "L3 VLAN = tag for the subinterface that carries the IP when "
                "promoting to a Port-Channel.  Leave a row empty to migrate 1:1."
            ),
            justify=tk.LEFT,
        )
        self._agg_hint_label.grid(row=0, column=0, columnspan=6, sticky=tk.W, pady=(0, 8))

        # Header + dynamic rows share ONE grid so every column title sits
        # directly above its field (separate frames can't align columns).
        grid = ttk.Frame(frame)
        grid.grid(row=1, column=0, columnspan=6, sticky=tk.EW)
        self._agg_grid = grid
        # Column minsizes set the field widths; Interface and Members stretch.
        col_minsize = (150, 110, 130, 240, 80, 36)
        for col, msize in enumerate(col_minsize):
            grid.columnconfigure(col, minsize=msize)
        grid.columnconfigure(0, weight=1)  # Interface
        grid.columnconfigure(3, weight=2)  # Members

        # Column titles - hidden until the first row is added (no point showing
        # headers above an empty table).
        self._agg_header_labels = []
        for col, text in enumerate((
            "Interface", "Action", "Target",
            "Members (count or ports)", "L3 VLAN", "",
        )):
            lbl = ttk.Label(grid, text=text, anchor=tk.W)
            lbl.grid(row=0, column=col, sticky=tk.W, padx=2, pady=(0, 2))
            lbl.grid_remove()
            self._agg_header_labels.append(lbl)

        # Empty-state hint, shown only when there are no rows
        self._agg_empty_label = ttk.Label(
            frame,
            text="No interfaces queued - click \"+ Add Interface\" to scale one up.",
            foreground=_FG_DIM,
        )
        self._agg_empty_label.grid(row=3, column=0, columnspan=6, sticky=tk.W, pady=(2, 6))

        # Action buttons
        btns = ttk.Frame(frame)
        btns.grid(row=4, column=0, columnspan=6, sticky=tk.W, pady=(4, 0))
        ttk.Button(btns, text="+ Add Interface", command=lambda: self._agg_add_row()).pack(
            side=tk.LEFT,
        )
        ttk.Button(
            btns, text="↻ Refresh from config",
            command=lambda: self._agg_refresh_interfaces(silent=False),
        ).pack(side=tk.LEFT, padx=8)

        frame.columnconfigure(0, weight=1)
        # Packed/un-packed by _update_aggregation_visibility(); start hidden.

    def _agg_add_row(
        self, iface: str = "", action: str = "", target: str = "", members: str = "",
        vlan: str = "",
    ) -> None:
        """Append one interface row to the builder.

        Each widget is gridded directly into the shared self._agg_grid (one
        column each) so it lines up under its header title. Fields use
        sticky=EW so they fill - and widen with - their column.
        """
        grid = self._agg_grid
        grid_row = len(self._agg_rows) + 1  # row 0 is the header

        iface_var = tk.StringVar(value=iface)
        iface_combo = ttk.Combobox(
            grid, textvariable=iface_var, values=self._agg_iface_names,
        )
        iface_combo.grid(row=grid_row, column=0, sticky=tk.EW, padx=2, pady=2)

        action_var = tk.StringVar(value=action or AGG_ACTION_PROMOTE)
        action_combo = ttk.Combobox(
            grid, textvariable=action_var, values=AGG_ACTIONS, state="readonly",
        )
        action_combo.grid(row=grid_row, column=1, sticky=tk.EW, padx=2, pady=2)

        target_var = tk.StringVar(value=target or AGG_TARGET_PORTCHANNEL)
        target_combo = ttk.Combobox(
            grid, textvariable=target_var, values=AGG_TARGETS, state="readonly",
        )
        target_combo.grid(row=grid_row, column=2, sticky=tk.EW, padx=2, pady=2)

        members_var = tk.StringVar(value=members)
        members_cell = ttk.Frame(grid)
        members_cell.grid(row=grid_row, column=3, sticky=tk.EW, padx=2, pady=2)
        members_entry = ttk.Entry(members_cell, textvariable=members_var)
        members_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        vlan_var = tk.StringVar(value=vlan)
        vlan_entry = ttk.Entry(grid, textvariable=vlan_var)
        vlan_entry.grid(row=grid_row, column=4, sticky=tk.EW, padx=2, pady=2)

        row: Dict[str, Any] = {
            "iface_var": iface_var,
            "action_var": action_var,
            "target_var": target_var,
            "members_var": members_var,
            "vlan_var": vlan_var,
            "iface_combo": iface_combo,
        }

        # "Pick..." opens a checkbox list of the target model's ports so the
        # user can choose explicit member ports without typing them. It just
        # fills members_var with a comma-separated port list; typing a count
        # still works. For Map / Assign only one port may be chosen.
        ttk.Button(
            members_cell, text="Pick…", width=6,
            command=lambda: self._agg_pick_ports(row),
        ).pack(side=tk.LEFT, padx=(3, 0))

        remove_btn = ttk.Button(
            grid, text="✕", width=3, command=lambda: self._agg_remove_row(row),
        )
        remove_btn.grid(row=grid_row, column=5, sticky=tk.W, padx=2, pady=2)

        # All widgets in this row, for re-flowing/removal.
        row["widgets"] = [
            iface_combo, action_combo, target_combo, members_cell,
            vlan_entry, remove_btn,
        ]

        # Auto-detect action/target from the chosen interface's category.
        iface_combo.bind(
            "<<ComboboxSelected>>", lambda _e: self._agg_on_iface_selected(row),
        )
        iface_var.trace_add("write", lambda *_a: self._agg_on_iface_selected(row))

        self._agg_rows.append(row)
        self._agg_empty_label.grid_remove()
        self._agg_set_header_visible(True)

    def _agg_set_header_visible(self, visible: bool) -> None:
        """Show the column titles only when there is at least one row."""
        for lbl in getattr(self, "_agg_header_labels", []):
            if visible:
                lbl.grid()
            else:
                lbl.grid_remove()

    def _agg_remove_row(self, row: Dict[str, Any]) -> None:
        """Remove one interface row and re-flow the remaining rows."""
        if row not in self._agg_rows:
            return
        for w in row.get("widgets", []):
            w.destroy()
        self._agg_rows.remove(row)
        # Re-grid the survivors so there are no gaps (header stays at row 0).
        for idx, r in enumerate(self._agg_rows):
            for col, w in enumerate(r.get("widgets", [])):
                sticky = tk.W if col == 5 else tk.EW
                w.grid_configure(row=idx + 1, column=col, sticky=sticky)
        if not self._agg_rows:
            self._agg_empty_label.grid()
            self._agg_set_header_visible(False)

    def _agg_clear_rows(self) -> None:
        """Destroy all interface rows (used when the section is hidden/reset)."""
        for row in self._agg_rows:
            for w in row.get("widgets", []):
                w.destroy()
        self._agg_rows.clear()
        if getattr(self, "_agg_empty_label", None) is not None:
            self._agg_empty_label.grid()
        self._agg_set_header_visible(False)

    def _agg_on_iface_selected(self, row: Dict[str, Any]) -> None:
        """Auto-set Action/Target from the selected interface's category.

        aggregate -> Expand / Port-Channel; switch -> Expand / Bridge Group;
        physical (or unknown) -> Promote, keeping whatever target the user
        already chose. Users can still override either dropdown afterwards.
        """
        name = row["iface_var"].get().strip().lower()
        category = self._agg_iface_index.get(name)
        if category == "aggregate":
            row["action_var"].set(AGG_ACTION_EXPAND)
            row["target_var"].set(AGG_TARGET_PORTCHANNEL)
        elif category == "switch":
            row["action_var"].set(AGG_ACTION_EXPAND)
            row["target_var"].set(AGG_TARGET_BRIDGEGROUP)
        elif category == "physical":
            # Keep the user's choice if they already picked Map / Assign;
            # otherwise default a plain interface to Promote.
            if row["action_var"].get() != AGG_ACTION_MAP:
                row["action_var"].set(AGG_ACTION_PROMOTE)

    def _agg_row_to_argv(self, row: Dict[str, Any]) -> List[str]:
        """Translate one builder row into converter CLI args.

        Resolves the flag from the interface's KNOWN category so an existing
        aggregate/switch is always Expanded (never misrouted to Promote, which
        the converter would silently ignore). Map / Assign emits --map-port;
        a Promote-to-Port-Channel with an L3 VLAN also emits
        --promote-portchannel-vlan so the IP lands on a subinterface.
        """
        name = row["iface_var"].get().strip()
        members = row["members_var"].get().strip()
        if not name:
            return []

        action = row["action_var"].get()
        category = self._agg_iface_index.get(name.lower())

        # Straight 1:1 assignment - one port, no aggregation.
        if action == AGG_ACTION_MAP and category not in ("aggregate", "switch"):
            port = next((p.strip() for p in members.split(",") if p.strip()), "")
            if not port:
                return []
            return ["--map-port", f"{name}={port}"]

        if not members:
            return []

        # Force Expand for things that are already aggregated; otherwise honor
        # the (action, target) pair the user chose.
        if category == "aggregate":
            flag = "--expand-portchannel"
        elif category == "switch":
            flag = "--expand-bridgegroup"
        else:
            flag = AGG_FLAG_MAP.get((action, row["target_var"].get()))
        if not flag:
            return []

        argv = [flag, f"{name}={members}"]

        # Promote -> Port-Channel with an L3 VLAN: carry the IP on a subinterface.
        if (flag == "--promote-portchannel"):
            vlan = row.get("vlan_var").get().strip() if row.get("vlan_var") else ""
            if vlan:
                argv.extend(["--promote-portchannel-vlan", f"{name}={vlan}"])
        return argv

    def _agg_model_ports(self, mark_ha_reserved: bool = True) -> List[Dict[str, Any]]:
        """Return the data ports of the currently selected target model.

        Each entry is {'name', 'label', 'reserved'}: 'name' is the hardware
        port (e.g. 'Ethernet1/9'), 'label' adds a speed/HA hint for the picker,
        and 'reserved' is True for HA ports (shown disabled - they can't be
        members). Returns [] if the model/port count can't be determined.

        Set mark_ha_reserved=False for the HA picker itself, where the HA ports
        are exactly what's being chosen (so none should be disabled).
        """
        model = self.conv_model_var.get().strip()
        if not model or model == "(not applicable)":
            return []

        info = None
        prefix = "Ethernet1/"
        speed_groups = None
        reserved_ports: set = set()
        module = None  # (prefix, count, speed) for an installed network module
        try:
            if self._current_platform == "Cisco FTD":
                from interface_converter import FTD_MODELS  # lazy import
                info = FTD_MODELS.get(model)
                if info:
                    speed_groups = info.get("port_speed_groups")
                # Mark the HA port(s) entered on the Convert tab as reserved.
                ha_raw = self.conv_ha_var.get().strip()
                if mark_ha_reserved and ha_raw and ha_raw.lower() != "none":
                    for tok in re.split(r"[,;\s]+", ha_raw):
                        tok = tok.strip()
                        if tok:
                            reserved_ports.add(tok)
                # Include installed network-module ports, if any.
                module_id = FTD_MODULE_LABEL_TO_ID.get(
                    self.conv_module_var.get(), "none",
                ) if getattr(self, "conv_module_var", None) else "none"
                mod = _FTD_NM.get(module_id)
                if (info and module_id != "none" and mod and mod.get("ports")
                        and info.get("module_slots")):
                    module = (
                        info.get("module_port_prefix", "Ethernet2/"),
                        int(mod["ports"]),
                        mod.get("speed") or "",
                    )
            elif self._current_platform == "Palo Alto PAN-OS":
                from pa_interface_converter import PA_MODELS  # lazy import
                info = PA_MODELS.get(model)
                prefix = "ethernet1/"
        except Exception:  # noqa: BLE001 - best effort; fall back to no picker
            info = None

        if not info:
            return []
        total = int(info.get("total_ports", 0) or 0)

        def speed_of(num: int) -> str:
            if not speed_groups:
                return ""
            for label, nums in speed_groups.items():
                if num in nums:
                    return label
            return ""

        def make_entry(name: str, speed: str) -> Dict[str, Any]:
            hints = []
            if speed:
                hints.append(speed)
            is_reserved = name in reserved_ports
            if is_reserved:
                hints.append("HA - reserved")
            label = name + (f"   ({', '.join(hints)})" if hints else "")
            return {"name": name, "label": label, "reserved": is_reserved}

        ports: List[Dict[str, Any]] = []
        for num in range(1, total + 1):
            ports.append(make_entry(f"{prefix}{num}", speed_of(num)))
        # Network-module ports (Ethernet2/1..N) at the module's link speed.
        if module:
            m_prefix, m_count, m_speed = module
            for num in range(1, m_count + 1):
                ports.append(make_entry(f"{m_prefix}{num}", m_speed))
        return ports

    def _agg_pick_ports(self, row: Dict[str, Any]) -> None:
        """Open a checkbox picker of the target model's ports and write the
        chosen ones back into the row's Members field as a comma list.

        In Map / Assign mode only ONE port can be chosen (a straight 1:1
        assignment), so ticking a port clears the others."""
        ports = self._agg_model_ports()
        if not ports:
            self._show_message(
                "Pick Ports",
                "Choose a target model on the Convert tab first so the "
                "available ports are known.",
                kind="warning",
            )
            return

        single = row["action_var"].get() == AGG_ACTION_MAP
        current = {
            p.strip() for p in row["members_var"].get().split(",") if p.strip()
        }

        win = tk.Toplevel(self)
        win.title("Select port" if single else "Select member ports")
        win.transient(self)
        win.configure(bg=self._colors["bg"])

        ttk.Label(
            win,
            text=("Tick the one port to assign this interface to."
                  if single else
                  "Tick the ports to use as members. Port-Channel (LACP) "
                  "members must all be the same speed."),
            wraplength=320, justify=tk.LEFT,
        ).pack(anchor=tk.W, padx=10, pady=(10, 4))

        container, inner = self._make_scrollable(win)
        container.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)

        vars_by_port: Dict[str, tk.BooleanVar] = {}

        def make_single_guard(picked: str):
            # Radio-like behavior: ticking one port unticks every other.
            def guard() -> None:
                if vars_by_port[picked].get():
                    for name, var in vars_by_port.items():
                        if name != picked:
                            var.set(False)
            return guard

        for port in ports:
            var = tk.BooleanVar(value=(port["name"] in current))
            cb = ttk.Checkbutton(
                inner, text=port["label"], variable=var,
                state=(tk.DISABLED if port["reserved"] else tk.NORMAL),
            )
            cb.pack(anchor=tk.W, pady=1)
            if not port["reserved"]:
                vars_by_port[port["name"]] = var
                if single:
                    cb.configure(command=make_single_guard(port["name"]))

        def apply_selection() -> None:
            chosen = [
                p["name"] for p in ports
                if p["name"] in vars_by_port and vars_by_port[p["name"]].get()
            ]
            if single:
                chosen = chosen[:1]
            row["members_var"].set(",".join(chosen))
            win.destroy()

        btns = ttk.Frame(win)
        btns.pack(fill=tk.X, padx=10, pady=(4, 10))
        ttk.Button(btns, text="OK", command=apply_selection).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Cancel", command=win.destroy).pack(
            side=tk.RIGHT, padx=(0, 6),
        )

        win.geometry("360x440")
        win.grab_set()

    def _agg_refresh_interfaces(self, silent: bool = True) -> None:
        """Parse the selected FortiGate YAML and index its interfaces.

        Builds a name -> category map (aggregate / switch / physical) used to
        populate the row dropdowns and auto-detect Expand vs Promote. Best
        effort: any parse failure leaves the dropdowns editable (free-text)
        so the feature still works without a readable config.
        """
        self._agg_iface_index = {}
        self._agg_iface_names = []

        path = self.conv_input_var.get().strip()
        if not path or not os.path.isfile(path):
            if not silent:
                self._show_message(
                    "No Config Selected",
                    "Select a FortiGate YAML file first, then refresh to list "
                    "its interfaces.",
                )
            self._agg_apply_iface_values()
            return

        try:
            import yaml  # lazy: only needed when the builder is used
            from fortigate_converter import preprocess_yaml_file

            cfg = yaml.safe_load(preprocess_yaml_file(path)) or {}
        except Exception as exc:  # noqa: BLE001 - best-effort parse, stay editable
            if not silent:
                self._show_message(
                    "Could Not Read Interfaces",
                    f"Unable to parse interfaces from the config:\n{exc}\n\n"
                    "You can still type interface names manually.",
                    kind="warning",
                )
            self._agg_apply_iface_values()
            return

        names: List[str] = []

        def to_ports(value: Any) -> List[str]:
            """Normalize a FortiGate interface-list value to a list of names.
            May be a list, a single string, or a space-separated string (e.g.
            'member' or HA 'hbdev')."""
            if isinstance(value, str):
                return value.split()  # FortiGate may store "port5 port6"
            if isinstance(value, list):
                return [str(m) for m in value]
            return []

        # First pass: collect ports that should be hidden from the candidate
        # list. Two groups:
        #   member_set  - ports that belong to an aggregate or a virtual switch;
        #                 only the parent Port-Channel / Bridge Group is a valid
        #                 target, so showing the members too is confusing.
        #   special_set - the dedicated management port and HA heartbeat ports;
        #                 these are infrastructure links, never aggregation
        #                 targets.
        member_set: set = set()
        special_set: set = set()
        # Conventional FortiGate names for the mgmt and HA interfaces.
        _MGMT_HA_NAMES = {"mgmt", "mgmt1", "mgmt2", "management", "ha", "ha1", "ha2"}

        for intf_dict in cfg.get("system_interface", []) or []:
            if not isinstance(intf_dict, dict) or not intf_dict:
                continue
            name = next(iter(intf_dict))
            props = intf_dict[name]
            nm = str(name).strip().lower()
            if not isinstance(props, dict):
                continue
            if props.get("type") == "aggregate":
                for m in to_ports(props.get("member", [])):
                    member_set.add(m.strip().lower())
            # Dedicated management port: "set dedicated-to management", or a
            # conventional mgmt*/ha* name.
            dedicated = str(
                props.get("dedicated-to", props.get("dedicated_to", "")),
            ).strip().lower()
            if dedicated == "management" or nm in _MGMT_HA_NAMES:
                special_set.add(nm)

        for sw_dict in cfg.get("system_switch-interface", []) or []:
            if not isinstance(sw_dict, dict) or not sw_dict:
                continue
            sw_props = sw_dict[next(iter(sw_dict))]
            if isinstance(sw_props, dict):
                for m in to_ports(sw_props.get("member", [])):
                    member_set.add(m.strip().lower())

        # HA heartbeat / HA-management ports from `config system ha`. The YAML
        # parser may emit this section as a plain dict, a list holding the
        # settings dict, or a list of single-key wrapper dicts, so check every
        # dict at both levels. hbdev can interleave interface names with
        # numeric priorities (e.g. "port10 50 port9 50"), so drop pure-number
        # tokens.
        ha_cfg = cfg.get("system_ha")
        ha_sections: List[Dict[str, Any]] = []
        if isinstance(ha_cfg, dict):
            ha_sections.append(ha_cfg)
        elif isinstance(ha_cfg, list):
            for entry in ha_cfg:
                if not isinstance(entry, dict):
                    continue
                ha_sections.append(entry)
                ha_sections.extend(v for v in entry.values() if isinstance(v, dict))
        for section in ha_sections:
            for field in (
                "hbdev", "ha-mgmt-interface", "ha_mgmt_interface", "session-sync-dev",
            ):
                for tok in to_ports(section.get(field, [])):
                    t = tok.strip().lower()
                    if t and not t.isdigit():
                        special_set.add(t)

        # Physical / aggregate interfaces live under system_interface. The dict
        # key is the FortiGate port (e.g. "port1"); the human-facing interface
        # name is the optional 'alias'. The converter matches a spec by either
        # one, so we display the alias when present (that's what users recognize)
        # and index both the alias and the port so matching/auto-detect work
        # regardless of which the user types.
        for intf_dict in cfg.get("system_interface", []) or []:
            if not isinstance(intf_dict, dict) or not intf_dict:
                continue
            intf_name = next(iter(intf_dict))
            props = intf_dict[intf_name]
            if not isinstance(props, dict):
                continue
            if "interface" in props and "vlanid" in props:
                continue  # VLAN subinterface - not an aggregation candidate
            intf_type = props.get("type", "physical")
            if intf_type == "aggregate":
                category = "aggregate"
            elif intf_type == "physical":
                category = "physical"
            else:
                continue  # tunnel, loopback, etc.
            port = str(intf_name).strip()
            # Hide physical ports that are members of a Port-Channel / Bridge
            # Group (only the parent is a valid target), plus the dedicated
            # management and HA ports.
            if category == "physical" and (
                port.lower() in member_set or port.lower() in special_set
            ):
                continue
            alias = str(props.get("alias", "")).strip()
            display = alias or port
            # Index every identifier the converter will accept.
            self._agg_iface_index[port.lower()] = category
            if alias:
                self._agg_iface_index[alias.lower()] = category
            names.append(display)

        # Virtual-switch bridge groups live under system_switch-interface
        for sw_dict in cfg.get("system_switch-interface", []) or []:
            if not isinstance(sw_dict, dict) or not sw_dict:
                continue
            sw_name = next(iter(sw_dict))
            sw_props = sw_dict[sw_name]
            sw_alias = ""
            if isinstance(sw_props, dict):
                sw_alias = str(sw_props.get("alias", "")).strip()
            port = str(sw_name).strip()
            self._agg_iface_index[port.lower()] = "switch"
            if sw_alias:
                self._agg_iface_index[sw_alias.lower()] = "switch"
            names.append(sw_alias or port)

        self._agg_iface_names = sorted(names, key=str.lower)
        self._agg_apply_iface_values()

        if not silent:
            self._show_message(
                "Interfaces Loaded",
                f"Found {len(self._agg_iface_names)} interface(s) available to "
                "scale up.",
            )

    def _agg_apply_iface_values(self) -> None:
        """Push the current interface-name list into every row's combobox."""
        for row in self._agg_rows:
            combo = row.get("iface_combo")
            if combo is not None:
                combo.configure(values=self._agg_iface_names)

    def _set_fortinet_help_visible(self, visible: bool) -> None:
        """Show the FortiGate export how-to banner only for a FortiGate source."""
        lbl = getattr(self, "conv_fortinet_help", None)
        opts = getattr(self, "_conv_opts_frame", None)
        if lbl is None or opts is None:
            return
        if visible:
            if not lbl.winfo_ismapped():
                # Keep it above the options frame after a hide/show cycle.
                lbl.pack(fill=tk.X, padx=10, pady=(8, 0), anchor=tk.W, before=opts)
        else:
            lbl.pack_forget()

    def _update_ha_pick_visible(self) -> None:
        """Show the HA 'Pick…' button only when the field is in FTD HA-port mode
        and editable. It's hidden when the field is repurposed as the FTD
        Username field, or disabled (PAN-OS / FortiGate targets)."""
        btn = getattr(self, "conv_ha_pick_btn", None)
        if btn is None:
            return
        label = str(self.conv_ha_label.cget("text"))
        editable = str(self.conv_ha_entry.cget("state")) == "normal"
        show = label.startswith("HA Port") and editable
        if show:
            if not btn.winfo_ismapped():
                btn.pack(side=tk.LEFT, padx=(3, 0))
        else:
            btn.pack_forget()

    def _ha_pick_ports(self) -> None:
        """Open a checkbox picker of the target model's ports and write the
        chosen HA port(s) back into the HA field as a comma list."""
        ports = self._agg_model_ports(mark_ha_reserved=False)
        if not ports:
            self._show_message(
                "Pick HA Port(s)",
                "Choose an FTD target model on the Convert tab first so the "
                "available ports are known.",
                kind="warning",
            )
            return

        current = {
            p.strip() for p in self.conv_ha_var.get().split(",")
            if p.strip() and p.strip().lower() != "none"
        }

        win = tk.Toplevel(self)
        win.title("Select HA port(s)")
        win.transient(self)
        win.configure(bg=self._colors["bg"])

        ttk.Label(
            win,
            text=("Tick the port(s) reserved for the HA link. They are excluded "
                  "from the data-interface conversion. Most setups use one; pick "
                  "two for separate control/data HA links."),
            wraplength=340, justify=tk.LEFT,
        ).pack(anchor=tk.W, padx=10, pady=(10, 4))

        container, inner = self._make_scrollable(win)
        container.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)

        vars_by_port: Dict[str, tk.BooleanVar] = {}
        for port in ports:
            var = tk.BooleanVar(value=(port["name"] in current))
            ttk.Checkbutton(inner, text=port["label"], variable=var).pack(
                anchor=tk.W, pady=1,
            )
            vars_by_port[port["name"]] = var

        def apply_selection() -> None:
            chosen = [p["name"] for p in ports if vars_by_port[p["name"]].get()]
            self.conv_ha_var.set(",".join(chosen))
            win.destroy()

        btns = ttk.Frame(win)
        btns.pack(fill=tk.X, padx=10, pady=(4, 10))
        ttk.Button(btns, text="OK", command=apply_selection).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Cancel", command=win.destroy).pack(
            side=tk.RIGHT, padx=(0, 6),
        )

        win.geometry("360x440")
        win.grab_set()

    def _update_module_selector(self) -> None:
        """Show the Network Module dropdown only for an FTD target, and enable
        it only for models that actually have a network-module slot. Resets to
        'None' whenever it is hidden or disabled."""
        widgets = (
            getattr(self, "conv_module_label", None),
            getattr(self, "conv_module_combo", None),
            getattr(self, "conv_module_hint", None),
        )
        if any(w is None for w in widgets):
            return
        label, combo, hint = widgets

        if self._current_platform != "Cisco FTD":
            self.conv_module_var.set(FTD_MODULE_ID_TO_LABEL["none"])
            label.grid_remove()
            combo.grid_remove()
            hint.grid_remove()
            return

        label.grid()
        combo.grid()
        hint.grid()
        if _ftd_model_module_capable(self.conv_model_var.get().strip()):
            combo.configure(state="readonly")
            label.configure(foreground=self._colors["fg"])
            hint.configure(text="Add-on module ports (Ethernet2/1…) join the available pool")
        else:
            # No slot on this model - force None and grey the control out.
            self.conv_module_var.set(FTD_MODULE_ID_TO_LABEL["none"])
            combo.configure(state=tk.DISABLED)
            label.configure(foreground=self._colors["fg_dim"])
            hint.configure(text="(this model has no network-module slot)")

    def _update_aggregation_visibility(self) -> None:
        """Show the builder for FortiGate -> FTD and FortiGate -> Palo Alto;
        hide it for every other direction."""
        frame = getattr(self, "_agg_frame", None)
        if frame is None:
            return
        is_supported = self._current_source == "FortiGate" and (
            self._current_platform in ("Cisco FTD", "Palo Alto PAN-OS")
        )
        if is_supported:
            # Rows built for another target hold that platform's port-name
            # format in Members (e.g. FTD "Ethernet1/5" vs PA "ethernet1/5"),
            # so they would emit wrongly-formatted converter args. Drop them
            # and let the user re-add for the new target.
            if (self._agg_rows
                    and getattr(self, "_agg_shown_platform", None)
                    != self._current_platform):
                self._agg_clear_rows()
                status = getattr(self, "status_var", None)
                if status is not None:
                    status.set(
                        "Interface Aggregation rows cleared - port names "
                        "differ per target platform; re-add rows for "
                        f"{self._current_platform}.",
                    )
            self._agg_shown_platform = self._current_platform
            # Retarget the section label/port hint to the active platform.
            target_short = (
                "FTD" if self._current_platform == "Cisco FTD" else "Palo Alto"
            )
            self._agg_frame.configure(
                text=f"Interface Aggregation  (FortiGate → {target_short})",
            )
            port_example = (
                "Ethernet1/5,Ethernet1/6"
                if self._current_platform == "Cisco FTD"
                else "ethernet1/5,ethernet1/6"
            )
            self._agg_hint_label.configure(
                text=(
                    "Optional: scale up link aggregation on the "
                    f"{target_short} side. Add a row per interface to grow into "
                    "a Port-Channel or Bridge Group.\n"
                    "Members = a target count (e.g. 4) or an explicit port list "
                    f"(e.g. {port_example}) - click \"Pick…\" to choose ports "
                    "instead of typing. Leave empty to migrate 1:1."
                ),
            )
            if not self._agg_visible:
                frame.pack(
                    fill=tk.X, padx=8, pady=4, before=self._conv_btn_frame,
                )
                self._agg_visible = True
            self._agg_refresh_interfaces(silent=True)
        elif self._agg_visible:
            frame.pack_forget()
            self._agg_visible = False
            # Hidden directions never use the builder - drop stale rows now so
            # they can't resurface later with the wrong port-name format.
            self._agg_clear_rows()
            self._agg_shown_platform = None

    # ==================== IMPORT TAB ====================
    def _build_import_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="  Import to FTD  ")
        self._imp_tab = tab

        opts = ttk.LabelFrame(tab, text="FTD Connection & Import Options", padding=10)
        opts.pack(fill=tk.X, padx=8, pady=(8, 4))
        self._imp_opts_frame = opts

        # Connection settings
        self.imp_host_label = ttk.Label(opts, text="FTD Host / IP:")
        self.imp_host_label.grid(row=0, column=0, sticky=tk.W, pady=3)
        self.imp_host_var = tk.StringVar()
        ttk.Entry(opts, textvariable=self.imp_host_var, width=30).grid(
            row=0, column=1, sticky=tk.W, padx=4,
        )

        ttk.Label(opts, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.imp_user_var = tk.StringVar(value="admin")
        ttk.Entry(opts, textvariable=self.imp_user_var, width=30).grid(
            row=1, column=1, sticky=tk.W, padx=4,
        )

        ttk.Label(opts, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=3)
        self.imp_pass_var = tk.StringVar()
        ttk.Entry(opts, textvariable=self.imp_pass_var, show="*", width=30).grid(
            row=2, column=1, sticky=tk.W, padx=4,
        )

        # Config directory
        ttk.Label(opts, text="Config Directory:").grid(row=3, column=0, sticky=tk.W, pady=3)
        self.imp_dir_var = tk.StringVar(value=DEFAULT_DIR)
        ttk.Entry(opts, textvariable=self.imp_dir_var, width=50).grid(
            row=3, column=1, sticky=tk.EW, padx=4,
        )
        ttk.Button(opts, text="Browse...", command=self._browse_impdir).grid(
            row=3, column=2, padx=4,
        )

        ttk.Label(opts, text="JSON Base Name:").grid(row=4, column=0, sticky=tk.W, pady=3)
        self.imp_base_var = tk.StringVar(value="ftd_config")
        ttk.Entry(opts, textvariable=self.imp_base_var, width=30).grid(
            row=4, column=1, sticky=tk.W, padx=4,
        )

        self.imp_workers_label = ttk.Label(opts, text="Workers:")
        self.imp_workers_label.grid(row=5, column=0, sticky=tk.W, pady=3)
        self.imp_workers_var = tk.StringVar(value="6")
        self.imp_workers_spin = ttk.Spinbox(
            opts, from_=1, to=32, textvariable=self.imp_workers_var, width=6,
        )
        self.imp_workers_spin.grid(row=5, column=1, sticky=tk.W, padx=4)

        self.imp_deploy_var = tk.BooleanVar()
        self.imp_deploy_cb = ttk.Checkbutton(
            opts, text="Deploy after import", variable=self.imp_deploy_var,
        )
        self.imp_deploy_cb.grid(row=6, column=1, sticky=tk.W, padx=4, pady=3)

        self.imp_debug_var = tk.BooleanVar()
        ttk.Checkbutton(
            opts, text="Debug mode (show API payloads)", variable=self.imp_debug_var,
        ).grid(row=7, column=1, sticky=tk.W, padx=4, pady=3)

        self.imp_update_existing_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            opts, text="Update existing objects (uncheck to skip duplicates)",
            variable=self.imp_update_existing_var,
        ).grid(row=8, column=1, sticky=tk.W, padx=4, pady=3)

        opts.columnconfigure(1, weight=1)

        # Selective import
        sel = ttk.LabelFrame(
            tab, text="Selective Import (leave unchecked to import all)", padding=8,
        )
        sel.pack(fill=tk.X, padx=8, pady=4)

        self.imp_only_vars = {}
        only_types = [
            ("Physical Interfaces", "physical-interfaces"),
            ("EtherChannels", "etherchannels"),
            ("Subinterfaces", "subinterfaces"),
            ("Bridge Groups", "bridge-groups"),
            ("Security Zones", "security-zones"),
            ("Address Objects", "address-objects"),
            ("Address Groups", "address-groups"),
            ("Service Objects", "service-objects"),
            ("Service Groups", "service-groups"),
            ("Static Routes", "routes"),
            ("Access Rules", "rules"),
        ]
        for i, (label, key) in enumerate(only_types):
            var = tk.BooleanVar()
            self.imp_only_vars[key] = var
            row, col = divmod(i, 3)
            ttk.Checkbutton(sel, text=label, variable=var).grid(
                row=row, column=col, sticky=tk.W, padx=6, pady=2,
            )

        # Buttons
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, padx=8, pady=4)
        self.imp_run_btn = ttk.Button(
            btn_frame, text="Start Import", command=self._run_import,
        )
        self.imp_run_btn.pack(side=tk.LEFT)
        self.imp_cancel_btn = ttk.Button(
            btn_frame, text="Cancel", command=self._cancel_operation,
            state=tk.DISABLED,
        )
        self.imp_cancel_btn.pack(side=tk.LEFT, padx=8)
        ttk.Button(
            btn_frame, text="Clear Output",
            command=lambda: self._clear_output(self.imp_output),
        ).pack(side=tk.LEFT, padx=8)

        # Run/Cancel state is owned by _set_buttons_state; the Workers spinbox
        # is enabled/disabled by the platform-change branches (it stays
        # disabled for PAN-OS, where the importer has no --workers flag).
        self._state_managed_widgets.update(
            {self.imp_run_btn, self.imp_cancel_btn, self.imp_workers_spin},
        )

        self.imp_output = self._make_output_area(tab)

    # ==================== CLEANUP TAB ====================
    def _build_cleanup_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="  Cleanup FTD  ")
        self._cln_tab = tab

        opts = ttk.LabelFrame(tab, text="FTD Connection", padding=10)
        opts.pack(fill=tk.X, padx=8, pady=(8, 4))
        self._cln_opts_frame = opts

        self.cln_host_label = ttk.Label(opts, text="FTD Host / IP:")
        self.cln_host_label.grid(row=0, column=0, sticky=tk.W, pady=3)
        self.cln_host_var = tk.StringVar()
        ttk.Entry(opts, textvariable=self.cln_host_var, width=30).grid(
            row=0, column=1, sticky=tk.W, padx=4,
        )

        ttk.Label(opts, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.cln_user_var = tk.StringVar(value="admin")
        ttk.Entry(opts, textvariable=self.cln_user_var, width=30).grid(
            row=1, column=1, sticky=tk.W, padx=4,
        )

        ttk.Label(opts, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=3)
        self.cln_pass_var = tk.StringVar()
        ttk.Entry(opts, textvariable=self.cln_pass_var, show="*", width=30).grid(
            row=2, column=1, sticky=tk.W, padx=4,
        )

        ttk.Label(opts, text="Target Model:").grid(row=3, column=0, sticky=tk.W, pady=3)
        self.cln_model_var = tk.StringVar(value="ftd-3120")
        self.cln_model_combo = ttk.Combobox(
            opts, textvariable=self.cln_model_var,
            values=FTD_MODEL_LIST, state="readonly", width=18,
        )
        self.cln_model_combo.grid(row=3, column=1, sticky=tk.W, padx=4)

        ttk.Label(opts, text="Workers:").grid(row=4, column=0, sticky=tk.W, pady=3)
        self.cln_workers_var = tk.StringVar(value="6")
        ttk.Spinbox(
            opts, from_=1, to=32, textvariable=self.cln_workers_var, width=6,
        ).grid(row=4, column=1, sticky=tk.W, padx=4)

        opts.columnconfigure(1, weight=1)

        # Delete options
        del_frame = ttk.LabelFrame(tab, text="What to Delete", padding=8)
        del_frame.pack(fill=tk.X, padx=8, pady=4)

        self.cln_all_var = tk.BooleanVar()
        ttk.Checkbutton(
            del_frame, text="Delete ALL custom objects", variable=self.cln_all_var,
        ).grid(row=0, column=0, columnspan=3, sticky=tk.W, padx=6, pady=4)

        # Checkboxes come from the shared CLEANUP_DELETE_OPTIONS catalog so the
        # labels/flags stay in lock-step with what each cleanup CLI actually
        # accepts. _update_cleanup_delete_options() retitles/hides them when
        # the target platform changes.
        self.cln_del_vars = {}
        self.cln_del_checks = {}
        for i, (key, ftd_label, _ftd_flag, _pa_label, _pa_flag) in enumerate(
            CLEANUP_DELETE_OPTIONS,
        ):
            var = tk.BooleanVar()
            self.cln_del_vars[key] = var
            row, col = divmod(i, 3)
            check = ttk.Checkbutton(del_frame, text=ftd_label, variable=var)
            check.grid(row=row + 1, column=col, sticky=tk.W, padx=6, pady=2)
            self.cln_del_checks[key] = check

        # Flags
        flag_frame = ttk.Frame(tab)
        flag_frame.pack(fill=tk.X, padx=8, pady=4)
        self.cln_dry_var = tk.BooleanVar()
        ttk.Checkbutton(
            flag_frame, text="Dry run (preview only)", variable=self.cln_dry_var,
        ).pack(side=tk.LEFT, padx=6)
        self.cln_deploy_var = tk.BooleanVar()
        self.cln_deploy_cb = ttk.Checkbutton(
            flag_frame, text="Deploy after cleanup", variable=self.cln_deploy_var,
        )
        self.cln_deploy_cb.pack(side=tk.LEFT, padx=6)

        # Buttons
        btn_frame = ttk.Frame(tab)
        btn_frame.pack(fill=tk.X, padx=8, pady=4)
        self.cln_run_btn = ttk.Button(
            btn_frame, text="Start Cleanup", command=self._run_cleanup,
        )
        self.cln_run_btn.pack(side=tk.LEFT)
        self.cln_cancel_btn = ttk.Button(
            btn_frame, text="Cancel", command=self._cancel_operation,
            state=tk.DISABLED,
        )
        self.cln_cancel_btn.pack(side=tk.LEFT, padx=8)
        ttk.Button(
            btn_frame, text="Clear Output",
            command=lambda: self._clear_output(self.cln_output),
        ).pack(side=tk.LEFT, padx=8)

        # Password management (right-aligned)
        self.cln_reset_pw_btn = ttk.Button(
            btn_frame,
            text="Reset to Default Password",
            command=self._reset_cleanup_password,
            # has_custom_password is bound only when _CLEANUP_ENABLED; runtime-guarded.
            state=tk.NORMAL if has_custom_password() else tk.DISABLED,  # pyright: ignore[reportOptionalCall]
        )
        self.cln_reset_pw_btn.pack(side=tk.RIGHT, padx=4)

        self.cln_pw_btn = ttk.Button(
            btn_frame,
            text="Change Cleanup Password",
            command=self._manage_cleanup_password,
        )
        self.cln_pw_btn.pack(side=tk.RIGHT, padx=4)

        # Run/Cancel state is owned by _set_buttons_state.
        self._state_managed_widgets.update({self.cln_run_btn, self.cln_cancel_btn})

        self.cln_output = self._make_output_area(tab)

    def _update_cleanup_delete_options(self, is_pa: bool) -> None:
        """Retitle / show the What-to-Delete checkboxes for the active target.

        Object types with no PAN-OS cleanup flag are hidden (and unchecked)
        while the target is Palo Alto, so the GUI can never emit a
        --delete-* flag panos_api_cleanup.py doesn't define."""
        if not self._cleanup_enabled:
            return
        visible = 0
        for key, ftd_label, _ftd_flag, pa_label, _pa_flag in CLEANUP_DELETE_OPTIONS:
            check = self.cln_del_checks[key]
            label = pa_label if is_pa else ftd_label
            if label is None:
                self.cln_del_vars[key].set(False)
                check.grid_remove()
                continue
            check.configure(text=label)
            row, col = divmod(visible, 3)
            check.grid(row=row + 1, column=col, sticky=tk.W, padx=6, pady=2)
            visible += 1

    # ==================== SNMP TAB ====================
    def _build_snmp_tab(self, notebook: ttk.Notebook) -> None:
        """SNMPv3 configuration tab - FTD targets only (FDM has no SNMP GUI).

        The tab is hidden whenever the target platform is not Cisco FTD;
        visibility is managed in _retitle_import_cleanup_tabs().
        """
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="  SNMP (FTD)  ")
        self._snmp_tab = tab

        # Settings on the left, console output on the right (the tab is too
        # tall for a stacked layout). The sash is draggable.
        paned = ttk.PanedWindow(tab, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)
        # The settings column is taller than the window, so make it scrollable
        # to guarantee the action buttons at the bottom are always reachable.
        left_container, left = self._make_scrollable(paned)
        paned.add(left_container, weight=0)
        right = ttk.Frame(paned)
        paned.add(right, weight=1)

        conn = ttk.LabelFrame(left, text="FTD Connection", padding=10)
        conn.pack(fill=tk.X, padx=(0, 4), pady=(0, 4))

        ttk.Label(conn, text="FTD Host / IP:").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.snmp_host_var = tk.StringVar()
        ttk.Entry(conn, textvariable=self.snmp_host_var, width=30).grid(
            row=0, column=1, sticky=tk.W, padx=4,
        )

        ttk.Label(conn, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.snmp_user_var = tk.StringVar(value="admin")
        ttk.Entry(conn, textvariable=self.snmp_user_var, width=30).grid(
            row=1, column=1, sticky=tk.W, padx=4,
        )

        ttk.Label(conn, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=3)
        self.snmp_pass_var = tk.StringVar()
        ttk.Entry(conn, textvariable=self.snmp_pass_var, show="*", width=30).grid(
            row=2, column=1, sticky=tk.W, padx=4,
        )

        conn.columnconfigure(1, weight=1)

        # SNMPv3 settings
        snmp_opts = ttk.LabelFrame(
            left, text="SNMPv3 Settings (STIG: Auth/Priv - SHA auth + AES privacy)",
            padding=10,
        )
        snmp_opts.pack(fill=tk.X, padx=(0, 4), pady=4)

        ttk.Label(snmp_opts, text="SNMP Manager IP(s):").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.snmp_nms_var = tk.StringVar()
        ttk.Entry(snmp_opts, textvariable=self.snmp_nms_var, width=28).grid(
            row=0, column=1, sticky=tk.W, padx=4,
        )
        ttk.Label(
            snmp_opts, text="(comma-separated for multiple, e.g. 10.0.0.50, 10.1.0.50)",
            foreground=_FG_DIM, wraplength=220, justify=tk.LEFT,
        ).grid(row=0, column=2, sticky=tk.W, padx=4)

        ttk.Label(snmp_opts, text="SNMP Host Name (optional):").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.snmp_hostname_var = tk.StringVar()
        ttk.Entry(snmp_opts, textvariable=self.snmp_hostname_var, width=30).grid(
            row=1, column=1, sticky=tk.W, padx=4,
        )
        ttk.Label(
            snmp_opts, text="(base name for the SNMP host object(s); the manager "
                            "IP is appended. Default: snmpv3-host)",
            foreground=_FG_DIM, wraplength=220, justify=tk.LEFT,
        ).grid(row=1, column=2, sticky=tk.W, padx=4)

        ttk.Label(snmp_opts, text="SNMPv3 User Name:").grid(row=2, column=0, sticky=tk.W, pady=3)
        self.snmp_v3user_var = tk.StringVar(value="FWADMIN")
        ttk.Entry(snmp_opts, textvariable=self.snmp_v3user_var, width=30).grid(
            row=2, column=1, sticky=tk.W, padx=4,
        )

        ttk.Label(snmp_opts, text="Auth Algorithm:").grid(row=3, column=0, sticky=tk.W, pady=3)
        self.snmp_auth_alg_var = tk.StringVar(value="SHA")
        ttk.Combobox(
            snmp_opts, textvariable=self.snmp_auth_alg_var,
            values=["SHA", "SHA256"], state="readonly", width=12,
        ).grid(row=3, column=1, sticky=tk.W, padx=4)

        ttk.Label(snmp_opts, text="Auth Password:").grid(row=4, column=0, sticky=tk.W, pady=3)
        self.snmp_auth_pw_var = tk.StringVar()
        ttk.Entry(snmp_opts, textvariable=self.snmp_auth_pw_var, show="*", width=30).grid(
            row=4, column=1, sticky=tk.W, padx=4,
        )
        ttk.Label(
            snmp_opts, text="(min 8 characters)", foreground=_FG_DIM,
        ).grid(row=4, column=2, sticky=tk.W, padx=4)

        ttk.Label(snmp_opts, text="Privacy Algorithm:").grid(row=5, column=0, sticky=tk.W, pady=3)
        self.snmp_priv_alg_var = tk.StringVar(value="AES256")
        ttk.Combobox(
            snmp_opts, textvariable=self.snmp_priv_alg_var,
            values=["AES128", "AES192", "AES256"], state="readonly", width=12,
        ).grid(row=5, column=1, sticky=tk.W, padx=4)
        ttk.Label(
            snmp_opts, text="(AES128 = STIG minimum, AES256 preferred)", foreground=_FG_DIM,
        ).grid(row=5, column=2, sticky=tk.W, padx=4)

        ttk.Label(snmp_opts, text="Privacy Password:").grid(row=6, column=0, sticky=tk.W, pady=3)
        self.snmp_priv_pw_var = tk.StringVar()
        ttk.Entry(snmp_opts, textvariable=self.snmp_priv_pw_var, show="*", width=30).grid(
            row=6, column=1, sticky=tk.W, padx=4,
        )
        ttk.Label(
            snmp_opts, text="(min 8 characters)", foreground=_FG_DIM,
        ).grid(row=6, column=2, sticky=tk.W, padx=4)

        ttk.Label(snmp_opts, text="Source Interface:").grid(row=7, column=0, sticky=tk.W, pady=3)
        self.snmp_intf_var = tk.StringVar()
        ttk.Entry(snmp_opts, textvariable=self.snmp_intf_var, width=30).grid(
            row=7, column=1, sticky=tk.W, padx=4,
        )
        ttk.Label(
            snmp_opts, text="(logical name, e.g. outside - not Ethernet1/1)",
            foreground=_FG_DIM, wraplength=220, justify=tk.LEFT,
        ).grid(row=7, column=2, sticky=tk.W, padx=4)

        ttk.Label(snmp_opts, text="Location (optional):").grid(row=8, column=0, sticky=tk.W, pady=3)
        self.snmp_location_var = tk.StringVar()
        ttk.Entry(snmp_opts, textvariable=self.snmp_location_var, width=28).grid(
            row=8, column=1, sticky=tk.W, padx=4,
        )
        ttk.Label(
            snmp_opts, text="(sysLocation, e.g. site/rack - no semicolons)",
            foreground=_FG_DIM, wraplength=220, justify=tk.LEFT,
        ).grid(row=8, column=2, sticky=tk.W, padx=4)

        ttk.Label(snmp_opts, text="Contact (optional):").grid(row=9, column=0, sticky=tk.W, pady=3)
        self.snmp_contact_var = tk.StringVar()
        ttk.Entry(snmp_opts, textvariable=self.snmp_contact_var, width=28).grid(
            row=9, column=1, sticky=tk.W, padx=4,
        )
        ttk.Label(
            snmp_opts, text="(sysContact, e.g. admin name/email - no semicolons)",
            foreground=_FG_DIM, wraplength=220, justify=tk.LEFT,
        ).grid(row=9, column=2, sticky=tk.W, padx=4)

        self.snmp_poll_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            snmp_opts, text="Enable polling (UDP 161)", variable=self.snmp_poll_var,
        ).grid(row=10, column=1, sticky=tk.W, padx=4, pady=3)

        self.snmp_trap_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            snmp_opts, text="Enable traps (UDP 162)", variable=self.snmp_trap_var,
        ).grid(row=11, column=1, sticky=tk.W, padx=4, pady=3)

        self.snmp_deploy_var = tk.BooleanVar()
        ttk.Checkbutton(
            snmp_opts, text="Deploy after push", variable=self.snmp_deploy_var,
        ).grid(row=12, column=1, sticky=tk.W, padx=4, pady=3)

        ttk.Label(
            snmp_opts,
            text="Note: All manager IPs in one push share the same SNMPv3 user. "
                 "To give each manager its own user name, run one push per manager "
                 "(one IP + its user name each time) - object names are suffixed "
                 "with the manager IP, so each push adds to earlier configs "
                 "instead of overwriting them.",
            foreground=_FG_DIM, wraplength=600, justify=tk.LEFT,
        ).grid(row=13, column=0, columnspan=3, sticky=tk.W, pady=(8, 0))

        snmp_opts.columnconfigure(1, weight=0)

        # Device-global trap event types (SNMPServer settings singleton)
        trap_frame = ttk.LabelFrame(left, text="Trap Events (device-wide)", padding=10)
        trap_frame.pack(fill=tk.X, padx=(0, 4), pady=4)

        self.snmp_trapevents_enable_var = tk.BooleanVar()
        ttk.Checkbutton(
            trap_frame,
            text="Configure trap event types (unchecked = leave device unchanged)",
            variable=self.snmp_trapevents_enable_var,
            command=self._toggle_snmp_trap_events,
        ).grid(row=0, column=0, columnspan=4, sticky=tk.W, pady=(0, 4))

        # Select-all toggle: checks/unchecks every trap event at once.
        self.snmp_trap_all_var = tk.BooleanVar()
        self._snmp_trap_all_check = ttk.Checkbutton(
            trap_frame, text="Select all", variable=self.snmp_trap_all_var,
            command=self._toggle_snmp_trap_all, state=tk.DISABLED,
        )
        self._snmp_trap_all_check.grid(
            row=1, column=0, columnspan=4, sticky=tk.W, padx=(6, 2), pady=(0, 4),
        )

        # (label, FDM enum value, on by default - mirrors the ASA defaults, note)
        trap_event_defs = [
            ("SNMP authentication", "SNMP_AUTHENTICATION", True,
             "failed SNMP auth attempts"),
            ("Link up", "SNMP_LINKUP", True,
             "interface comes up"),
            ("Link down", "SNMP_LINKDOWN", True,
             "interface goes down"),
            ("Cold start", "SNMP_COLDSTART", True,
             "device restarted"),
            ("Warm start", "SNMP_WARMSTART", True,
             "agent restart, no reload"),
            ("Syslog", "SYSLOG", False,
             "every syslog msg (noisy)"),
            ("Connection limit reached", "CONNECTION_LIMIT_REACHED", False,
             "conn limit was hit"),
            ("NAT packet discard", "NAT_PACKET_DISCARD", False,
             "NAT pool exhausted"),
            ("CPU threshold rising", "CPU_THRESHOLD_RISING", False,
             "CPU crossed threshold"),
            ("Memory threshold", "MEM_THRESHOLD", False,
             "memory crossed threshold"),
            ("Failover state", "FAILOVER", False,
             "HA failover state changed"),
            ("Cluster state", "CLUSTER", False,
             "cluster membership changed"),
            ("Peer flap", "PEER_FLAP", False,
             "BGP peer flapping"),
            ("FRU insert", "FRU_INSERT", False,
             "module inserted"),
            ("FRU remove", "FRU_REMOVE", False,
             "module removed"),
            ("Config change", "CONFIG_CHANGE", False,
             "running config changed"),
        ]
        self.snmp_trap_vars = {}
        self._snmp_trap_checks = []
        for i, (label, key, default_on, note) in enumerate(trap_event_defs):
            var = tk.BooleanVar(value=default_on)
            self.snmp_trap_vars[key] = var
            row, col = divmod(i, 2)
            check = ttk.Checkbutton(
                trap_frame, text=label, variable=var, state=tk.DISABLED,
                command=self._sync_snmp_trap_all,
            )
            check.grid(row=row + 2, column=col * 2, sticky=tk.W, padx=(6, 2), pady=1)
            ttk.Label(trap_frame, text=f"- {note}", foreground=_FG_DIM,
                      font=("Segoe UI", 8)).grid(
                row=row + 2, column=col * 2 + 1, sticky=tk.W, padx=(0, 12), pady=1,
            )
            self._snmp_trap_checks.append(check)
        self._sync_snmp_trap_all()

        # Buttons
        btn_frame = ttk.Frame(left)
        btn_frame.pack(fill=tk.X, padx=(0, 4), pady=4)
        self.snmp_run_btn = ttk.Button(
            btn_frame, text="Push SNMP Config", command=self._run_snmp,
        )
        self.snmp_run_btn.pack(side=tk.LEFT)
        self.snmp_cancel_btn = ttk.Button(
            btn_frame, text="Cancel", command=self._cancel_operation,
            state=tk.DISABLED,
        )
        self.snmp_cancel_btn.pack(side=tk.LEFT, padx=8)
        ttk.Button(
            btn_frame, text="Clear Output",
            command=lambda: self._clear_output(self.snmp_output),
        ).pack(side=tk.LEFT, padx=8)

        self.snmp_output = self._make_output_area(right)

    def _toggle_snmp_trap_events(self) -> None:
        state = tk.NORMAL if self.snmp_trapevents_enable_var.get() else tk.DISABLED
        self._snmp_trap_all_check.configure(state=state)
        for check in self._snmp_trap_checks:
            check.configure(state=state)

    def _toggle_snmp_trap_all(self) -> None:
        """Set every trap event to match the 'Select all' checkbox."""
        value = self.snmp_trap_all_var.get()
        for var in self.snmp_trap_vars.values():
            var.set(value)

    def _sync_snmp_trap_all(self) -> None:
        """Reflect the combined state of the individual events in 'Select all'."""
        self.snmp_trap_all_var.set(
            all(var.get() for var in self.snmp_trap_vars.values())
        )

    def _run_snmp(self) -> None:
        host = self.snmp_host_var.get().strip()
        password = self.snmp_pass_var.get()
        nms_ip = self.snmp_nms_var.get().strip()
        v3_user = self.snmp_v3user_var.get().strip()
        auth_pw = self.snmp_auth_pw_var.get()
        priv_pw = self.snmp_priv_pw_var.get()
        interface = self.snmp_intf_var.get().strip()

        missing = []
        if not host:
            missing.append("FTD host/IP")
        if not password:
            missing.append("FTD password")
        if not nms_ip:
            missing.append("SNMP manager IP(s)")
        if not v3_user:
            missing.append("SNMPv3 user name")
        if not auth_pw:
            missing.append("auth password")
        if not priv_pw:
            missing.append("privacy password")
        if not interface:
            missing.append("source interface")
        if missing:
            messagebox.showerror(
                "Missing Fields", "Please fill in: " + ", ".join(missing),
            )
            return

        if len(auth_pw) < 8 or len(priv_pw) < 8:
            messagebox.showerror(
                "Password Too Short",
                "SNMPv3 auth and privacy passwords must be at least 8 characters.",
            )
            return

        # Credential/host values use the --flag=value form so values starting
        # with '-' aren't mistaken for flags by argparse.
        argv = [
            f"--host={host}",
            f"--username={self.snmp_user_var.get().strip() or 'admin'}",
            f"--password={password}",
            "--nms-ip", nms_ip,
            "--snmp-user", v3_user,
            "--auth-algorithm", self.snmp_auth_alg_var.get(),
            f"--auth-password={auth_pw}",
            "--priv-algorithm", self.snmp_priv_alg_var.get(),
            f"--priv-password={priv_pw}",
            "--interface", interface,
        ]
        host_obj_name = self.snmp_hostname_var.get().strip()
        if host_obj_name:
            argv.extend(["--host-object-name", host_obj_name])
        location = self.snmp_location_var.get().strip()
        contact = self.snmp_contact_var.get().strip()
        if location:
            argv.extend(["--location", location])
        if contact:
            argv.extend(["--contact", contact])
        if self.snmp_trapevents_enable_var.get():
            selected = [key for key, var in self.snmp_trap_vars.items() if var.get()]
            argv.extend(["--trap-events", ",".join(selected) if selected else "none"])
        if not self.snmp_poll_var.get():
            argv.append("--no-poll")
        if not self.snmp_trap_var.get():
            argv.append("--no-trap")
        if self.snmp_deploy_var.get():
            argv.append("--deploy")

        self._run_in_thread(snmp_main, argv, self.snmp_output, "SNMP Config")

    # ==================== CONFIG VIEWER TAB ====================
    def _build_viewer_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="  Config Viewer  ")

        # Top bar: directory selector
        top = ttk.LabelFrame(tab, text="Config Files", padding=10)
        top.pack(fill=tk.X, padx=8, pady=(8, 4))

        ttk.Label(top, text="Config Directory:").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.viewer_dir_var = tk.StringVar(value=DEFAULT_DIR)
        ttk.Entry(top, textvariable=self.viewer_dir_var, width=50).grid(
            row=0, column=1, sticky=tk.EW, padx=4,
        )
        ttk.Button(top, text="Browse...", command=self._browse_viewer_dir).grid(
            row=0, column=2, padx=4,
        )

        ttk.Label(top, text="JSON Base Name:").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.viewer_base_var = tk.StringVar(value="ftd_config")
        ttk.Entry(top, textvariable=self.viewer_base_var, width=30).grid(
            row=1, column=1, sticky=tk.W, padx=4,
        )

        ttk.Button(top, text="Load Files", command=self._load_viewer_files).grid(
            row=1, column=2, padx=4,
        )

        top.columnconfigure(1, weight=1)

        # Middle: file selector listbox + JSON viewer (side by side)
        body = ttk.Frame(tab)
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        # Left pane: file list
        list_frame = ttk.Frame(body)
        list_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 4))

        ttk.Label(list_frame, text="Config Files:").pack(anchor=tk.W)
        self.viewer_listbox = tk.Listbox(
            list_frame, width=30, font=("Consolas", 10),
            bg=_OUT_BG, fg=_OUT_FG,
            selectbackground=_ACCENT_D, selectforeground=_OUT_FG,
            highlightthickness=1, highlightbackground=_BORDER, highlightcolor=_ACCENT,
            relief=tk.FLAT, bd=1,
        )
        list_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.viewer_listbox.yview)
        self.viewer_listbox.configure(yscrollcommand=list_scroll.set)
        list_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.viewer_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.viewer_listbox.bind("<<ListboxSelect>>", self._on_viewer_select)
        self._tk_widgets.append(self.viewer_listbox)

        # Right pane: JSON content
        content_frame = ttk.Frame(body)
        content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        ttk.Label(content_frame, text="File Contents:").pack(anchor=tk.W)

        # Search bar
        search_bar = ttk.Frame(content_frame)
        search_bar.pack(fill=tk.X, pady=(0, 2))
        ttk.Label(search_bar, text="Search:").pack(side=tk.LEFT)
        self._viewer_search_var = tk.StringVar()
        search_entry = ttk.Entry(search_bar, textvariable=self._viewer_search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=4)
        search_entry.bind("<Return>", lambda e: self._viewer_find_next())
        ttk.Button(search_bar, text="Find Next", command=self._viewer_find_next).pack(side=tk.LEFT, padx=2)
        ttk.Button(search_bar, text="Find Prev", command=self._viewer_find_prev).pack(side=tk.LEFT, padx=2)
        self._viewer_match_label = ttk.Label(search_bar, text="")
        self._viewer_match_label.pack(side=tk.LEFT, padx=6)
        self._viewer_search_idx = "1.0"

        self.viewer_text = tk.Text(
            content_frame, wrap=tk.NONE, font=("Consolas", 10),
            bg=_OUT_BG, fg=_OUT_FG,
            insertbackground=_OUT_FG,
            selectbackground=_ACCENT_D, selectforeground=_OUT_FG,
            state=tk.DISABLED, relief=tk.FLAT, bd=1,
            highlightthickness=1, highlightbackground=_BORDER, highlightcolor=_ACCENT,
        )
        yscroll = ttk.Scrollbar(content_frame, orient=tk.VERTICAL, command=self.viewer_text.yview)
        xscroll = ttk.Scrollbar(content_frame, orient=tk.HORIZONTAL, command=self.viewer_text.xview)
        self.viewer_text.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        yscroll.pack(side=tk.RIGHT, fill=tk.Y)
        xscroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.viewer_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._tk_widgets.append(self.viewer_text)

        # Storage for discovered file paths
        self._viewer_files: list[str] = []

    def _browse_viewer_dir(self) -> None:
        d = filedialog.askdirectory(title="Select Config Files Directory")
        if d:
            self.viewer_dir_var.set(d)

    def _load_viewer_files(self) -> None:
        """Scan the config directory for JSON files matching the base name."""
        config_dir = self.viewer_dir_var.get().strip()
        base = self.viewer_base_var.get().strip() or "ftd_config"

        if not config_dir or not os.path.isdir(config_dir):
            messagebox.showerror("Invalid Directory", "Please select a valid config directory.")
            return

        pattern = os.path.join(config_dir, f"{base}_*.json")
        files = sorted(glob.glob(pattern))

        self.viewer_listbox.delete(0, tk.END)
        self._viewer_files = files

        if not files:
            messagebox.showinfo("No Files", f"No files matching '{base}_*.json' found in:\n{config_dir}")
            return

        for f in files:
            self.viewer_listbox.insert(tk.END, os.path.basename(f))

    def _on_viewer_select(self, event: Optional[Any]) -> None:
        """Display the selected JSON file in the viewer."""
        sel = self.viewer_listbox.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx >= len(self._viewer_files):
            return

        filepath = self._viewer_files[idx]
        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                raw = fh.read()
            # Pretty-print if valid JSON
            try:
                data = json.loads(raw)
                display = json.dumps(data, indent=2)
            except (json.JSONDecodeError, ValueError):
                display = raw
        except OSError as exc:
            display = f"Error reading file: {exc}"

        self.viewer_text.configure(state=tk.NORMAL)
        self.viewer_text.delete("1.0", tk.END)
        self.viewer_text.insert("1.0", display)
        self.viewer_text.configure(state=tk.DISABLED)
        # Reset search position when a new file is loaded
        self._viewer_search_idx = "1.0"
        self._viewer_clear_highlights()
        self._viewer_match_label.configure(text="")

    def _viewer_clear_highlights(self) -> None:
        self.viewer_text.tag_remove("search_hit", "1.0", tk.END)
        self.viewer_text.tag_remove("search_current", "1.0", tk.END)

    def _viewer_find(self, forwards: bool = True) -> None:
        query = self._viewer_search_var.get()
        if not query:
            self._viewer_clear_highlights()
            self._viewer_match_label.configure(text="")
            return

        self._viewer_clear_highlights()

        # Highlight all matches
        self.viewer_text.tag_configure("search_hit", background="#3a3a00", foreground=self._colors["out_fg"])
        self.viewer_text.tag_configure("search_current", background="#48ea33", foreground="#000000")

        count_var = tk.IntVar()
        total = 0
        pos = "1.0"
        while True:
            pos = self.viewer_text.search(query, pos, stopindex=tk.END, nocase=True, count=count_var)
            if not pos:
                break
            end = f"{pos}+{count_var.get()}c"
            self.viewer_text.tag_add("search_hit", pos, end)
            total += 1
            pos = end

        if total == 0:
            self._viewer_match_label.configure(text="No matches")
            return

        # Find next/prev from current position
        if forwards:
            hit = self.viewer_text.search(query, self._viewer_search_idx, stopindex=tk.END, nocase=True, count=count_var)
            if not hit:
                # Wrap to beginning
                hit = self.viewer_text.search(query, "1.0", stopindex=tk.END, nocase=True, count=count_var)
        else:
            hit = self.viewer_text.search(query, self._viewer_search_idx, stopindex="1.0", backwards=True, nocase=True, count=count_var)
            if not hit:
                # Wrap to end
                hit = self.viewer_text.search(query, tk.END, stopindex="1.0", backwards=True, nocase=True, count=count_var)

        if hit:
            end = f"{hit}+{count_var.get()}c"
            self.viewer_text.tag_add("search_current", hit, end)
            self.viewer_text.see(hit)
            # Advance past this match for the next search
            self._viewer_search_idx = end if forwards else hit

        # Count which match we're on
        match_num = 0
        pos = "1.0"
        while hit and pos:
            pos = self.viewer_text.search(query, pos, stopindex=tk.END, nocase=True, count=count_var)
            if not pos:
                break
            match_num += 1
            if self.viewer_text.compare(pos, "==", hit):
                break
            pos = f"{pos}+{count_var.get()}c"

        self._viewer_match_label.configure(text=f"{match_num} of {total}")

    def _viewer_find_next(self) -> None:
        self._viewer_find(forwards=True)

    def _viewer_find_prev(self) -> None:
        self._viewer_find(forwards=False)

    # ==================== HOW-TO GUIDE TAB ====================
    def _build_help_tab(self, notebook: ttk.Notebook) -> None:
        tab = ttk.Frame(notebook)
        notebook.add(tab, text="  How-To Guide  ")

        # Search bar - lets users jump to keywords in the guide
        search_bar = ttk.Frame(tab)
        search_bar.pack(fill=tk.X, padx=8, pady=(8, 0))
        ttk.Label(search_bar, text="Search:").pack(side=tk.LEFT)
        self._help_search_var = tk.StringVar()
        help_search_entry = ttk.Entry(
            search_bar, textvariable=self._help_search_var, width=30,
        )
        help_search_entry.pack(side=tk.LEFT, padx=4)
        help_search_entry.bind("<Return>", lambda e: self._help_find_next())
        help_search_entry.bind("<Shift-Return>", lambda e: self._help_find_prev())
        ttk.Button(
            search_bar, text="Find Next", command=self._help_find_next,
        ).pack(side=tk.LEFT, padx=2)
        ttk.Button(
            search_bar, text="Find Prev", command=self._help_find_prev,
        ).pack(side=tk.LEFT, padx=2)
        self._help_match_label = ttk.Label(search_bar, text="")
        self._help_match_label.pack(side=tk.LEFT, padx=6)
        self._help_search_idx = "1.0"

        # Scrollable text widget for the guide content
        frame = ttk.Frame(tab)
        frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        help_text = tk.Text(
            frame, wrap=tk.WORD, font=("Segoe UI", 10),
            bg=_OUT_BG, fg=_OUT_FG,
            insertbackground=_OUT_FG,
            selectbackground=_ACCENT_D, selectforeground=_OUT_FG,
            state=tk.DISABLED, relief=tk.FLAT, bd=1,
            highlightthickness=1, highlightbackground=_BORDER, highlightcolor=_ACCENT,
            padx=12, pady=10, spacing1=2, spacing3=4,
        )
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=help_text.yview)
        help_text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        help_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._tk_widgets.append(help_text)
        self._help_text = help_text

        # Tag styles for rich formatting
        help_text.tag_configure("title", font=("Segoe UI", 18, "bold"), foreground=_ACCENT,
                                spacing1=8, spacing3=12)
        help_text.tag_configure("h1", font=("Segoe UI", 14, "bold"), foreground=_ACCENT,
                                spacing1=16, spacing3=6)
        help_text.tag_configure("h2", font=("Segoe UI", 11, "bold"), foreground=_ACCENT_H,
                                spacing1=12, spacing3=4)
        help_text.tag_configure("bold", font=("Segoe UI", 10, "bold"))
        help_text.tag_configure("italic", font=("Segoe UI", 10, "italic"),
                                foreground=_FG_DIM)
        help_text.tag_configure("code", font=("Consolas", 9), foreground=_ACCENT_H)
        help_text.tag_configure("bullet", lmargin1=20, lmargin2=34)
        help_text.tag_configure("sub_bullet", lmargin1=40, lmargin2=54)
        help_text.tag_configure("tip", foreground=_ACCENT_H, font=("Segoe UI", 10, "italic"))
        help_text.tag_configure("warning", foreground=_ACCENT, font=("Segoe UI", 10, "bold"))
        help_text.tag_configure("separator", font=("Segoe UI", 4), spacing1=6, spacing3=6)
        # Search highlight tags (raised above formatting tags so they win)
        help_text.tag_configure("search_hit", background="#3a3a00", foreground=_OUT_FG)
        help_text.tag_configure("search_current", background="#48ea33", foreground="#000000")

        # Helper to insert styled text
        def put(text: str, *tags: str) -> None:
            help_text.insert(tk.END, text, tags)

        help_text.configure(state=tk.NORMAL)

        # ----- Title -----
        put("Firewall Migration Tool - How-To Guide\n", "title")
        put("=" * 70 + "\n\n", "separator")

        # ----- Overview -----
        put("Overview\n", "h1")
        put("This tool converts firewall configurations between vendors. Pick a "
            "source platform and a supported target platform, run a Convert pass "
            "to produce vendor-ready output, then either Import via API "
            "(FTD / PAN-OS) or restore the generated CLI file (FortiGate). Each "
            "phase has its own tab.\n\n")

        put("Supported Source \u2192 Target Pairs\n", "h2")
        put("\u2022  ", "bullet")
        put("FortiGate", "bold")
        put(" (YAML) \u2192 ", "bullet")
        put("Cisco FTD", "bold")
        put(" (FDM REST API)\n", "bullet")
        put("\u2022  ", "bullet")
        put("FortiGate", "bold")
        put(" (YAML) \u2192 ", "bullet")
        put("Palo Alto PAN-OS", "bold")
        put(" (XML API)\n", "bullet")
        put("\u2022  ", "bullet")
        put("Cisco ASA", "bold")
        put(" (text) \u2192 ", "bullet")
        put("Palo Alto PAN-OS", "bold")
        put(" (XML API)\n", "bullet")
        put("\u2022  ", "bullet")
        put("Palo Alto", "bold")
        put(" (XML export) \u2192 ", "bullet")
        put("FortiGate", "bold")
        put(" (CLI .conf, restored on the device)\n", "bullet")
        put("\u2022  ", "bullet")
        put("Cisco FTD", "bold")
        put(" (live FDM API or exported JSON) \u2192 ", "bullet")
        put("FortiGate", "bold")
        put(" (CLI .conf)\n\n", "bullet")
        put("Note: ", "warning")
        if self._cleanup_enabled:
            put("When the target is FortiGate, the Import and Cleanup tabs are "
                "disabled - FortiGate output is a CLI .conf file you restore "
                "from the FortiGate GUI (System \u2192 Configuration \u2192 Restore).\n\n",
                "italic")
        else:
            put("When the target is FortiGate, the Import tab is "
                "disabled - FortiGate output is a CLI .conf file you restore "
                "from the FortiGate GUI (System \u2192 Configuration \u2192 Restore).\n\n",
                "italic")

        # ----- Getting Started -----
        put("Getting Started\n", "h1")
        put("=" * 70 + "\n\n", "separator")

        put("Step 1: Select Source and Target\n", "h2")
        put("Use the toolbar at the top of the window. The Target dropdown "
            "auto-narrows based on the Source you pick (e.g., choosing Palo Alto "
            "as source locks Target to FortiGate).\n\n")

        put("Step 2: Convert\n", "h2")
        put("Run the Convert tab to produce JSON files (FTD / PAN-OS targets) "
            "or a .conf file (FortiGate target).\n\n")

        put("Step 3: Deliver to the Target Device\n", "h2")
        put("\u2022  ", "bullet")
        put("FTD or PAN-OS target: ", "bold")
        put("use the Import tab to push via API.\n", "bullet")
        put("\u2022  ", "bullet")
        put("FortiGate target: ", "bold")
        put("upload the generated .conf via the FortiGate GUI's Restore feature. "
            "No Import tab is used.\n\n", "bullet")

        put("Step 4: Verify\n", "h2")
        put("Use the ", "")
        put("Config Viewer", "bold")
        put(" tab to browse JSON output. (Not used for FortiGate .conf output.)\n\n", "")

        if self._cleanup_enabled:
            put("Step 5: Rollback if Needed\n", "h2")
            put("Use the ", "")
            put("Cleanup", "bold")
            put(" tab to delete imported objects from FTD or PAN-OS. (Not available "
                "when the target is FortiGate.)\n\n", "")

        put(f"Step {6 if self._cleanup_enabled else 5}: Configure SNMP "
            "Monitoring (FTD targets only)\n", "h2")
        put("Use the ", "")
        put("SNMP (FTD)", "bold")
        put(" tab to push an SNMPv3 user and SNMP manager hosts to the FTD. "
            "The tab only appears when the target platform is Cisco FTD.\n\n", "")

        snmp_tab_num = 4 if self._cleanup_enabled else 3
        viewer_tab_num = snmp_tab_num + 1
        put("Tab 1: Convert\n", "h1")
        put("=" * 70 + "\n\n", "separator")
        put("Converts your source configuration into the format the target "
            "platform expects.\n\n")

        put("Input Field by Source\n", "h2")
        put("The Convert tab's input field changes based on the selected source:\n\n")
        put("\u2022  ", "bullet")
        put("FortiGate: ", "bold")
        put("Input YAML - path to a FortiGate config exported as YAML.\n", "bullet")
        put("\u2022  ", "bullet")
        put("Cisco ASA: ", "bold")
        put("Input Config - plain-text ASA config (.txt, .cfg, .conf).\n", "bullet")
        put("\u2022  ", "bullet")
        put("Palo Alto: ", "bold")
        put("Input XML - a PAN-OS configuration export (running-config XML).\n", "bullet")
        put("\u2022  ", "bullet")
        put("Cisco FTD: ", "bold")
        put("two modes - ", "bullet")
        put("live API", "italic")
        put(" (enter FTD Host / IP plus FTD username, then a password prompt) "
            "or ", "bullet")
        put("file mode", "italic")
        put(" (check the toggle and browse to an exported FTD config JSON).\n\n",
            "bullet")

        put("Other Convert Fields\n", "h2")
        put("\u2022  Output Directory: ", "bullet")
        put("Where generated files are saved. Auto-set to the input file's "
            "folder when you browse.\n", "bullet")
        put("\u2022  Output Base Name: ", "bullet")
        put("Prefix for output files. Defaults: ", "bullet")
        put("ftd_config", "code")
        put(" (FTD target), ", "bullet")
        put("pa_config", "code")
        put(" (PAN-OS target), ", "bullet")
        put("fg_config", "code")
        put(" (FortiGate target).\n", "bullet")
        put("\u2022  Target Model: ", "bullet")
        put("Hardware model for the target appliance - controls interface "
            "port mapping and port count. Not applicable when the target is "
            "FortiGate.\n", "bullet")
        put("\u2022  HA Port / FTD Username: ", "bullet")
        put("This field is repurposed by source/target. With FTD as ", "bullet")
        put("target", "italic")
        put(" it is the optional HA port (e.g. ", "bullet")
        put("Ethernet1/X", "code")
        put("). With FTD as ", "bullet")
        put("source", "italic")
        put(" (live API mode) it is the FTD username. Disabled otherwise.\n", "bullet")
        put("\u2022  Pretty-print JSON output: ", "bullet")
        put("Formats JSON with indentation. Enabled by default.\n\n", "bullet")

        put("Output Format\n", "h2")
        put("\u2022  ", "bullet")
        put("FTD or PAN-OS target: ", "bold")
        put("multiple JSON files (e.g. ", "bullet")
        put("{base}_address_objects.json", "code")
        put(", ", "bullet")
        put("{base}_access_rules.json", "code")
        put(") consumed by the Import tab.\n", "bullet")
        put("\u2022  ", "bullet")
        put("FortiGate target: ", "bold")
        put("a single ", "bullet")
        put("{base}.conf", "code")
        put(" CLI file you restore from the FortiGate GUI (System \u2192 "
            "Configuration \u2192 Restore).\n\n", "bullet")

        put("Automatic VLAN Conflict Resolution (FortiGate \u2192 FTD)\n", "h2")
        put("FortiGate allows VLAN interfaces on different parents to share a "
            "VLAN ID; FTD requires device-wide unique VLAN IDs. The converter "
            "resolves these conflicts automatically:\n\n")
        put("\u2022  Subinterfaces on EtherChannels and virtual switches keep "
            "their original VLAN IDs; conflicting subinterfaces on physical "
            "ports are remapped to the nearest unused VLAN ID.\n", "bullet")
        put("\u2022  Logical names never change, so zones, routes, and policies "
            "are unaffected.\n", "bullet")
        put("\u2022  Every remap is printed during conversion, noted in the "
            "interface description (", "bullet")
        put("[remapped from VLAN N]", "code")
        put("), and counted in the conversion summary.\n\n", "bullet")

        put("Interface Aggregation Scale-Up (FortiGate \u2192 FTD / Palo Alto)\n", "h2")
        put("Optional. Lets you add bandwidth and redundancy on the target side "
            "during conversion - grow an existing aggregate, or turn a plain "
            "physical interface into one. The ", "")
        put("Interface Aggregation", "bold")
        put(" panel appears on the Convert tab for FortiGate \u2192 FTD and "
            "FortiGate \u2192 Palo Alto migrations. Leave it empty to migrate "
            "interfaces 1:1 (default).\n\n", "")
        put("On Palo Alto the same controls map to PAN-OS equivalents: a "
            "Port-Channel becomes an ", "")
        put("aggregate-ethernet", "italic")
        put(" (LACP) interface, and a Bridge Group becomes a Layer-2 ", "")
        put("VLAN", "italic")
        put(" whose member ports are bridged and whose IP lives on a ", "")
        put("vlan.N", "code")
        put(" interface (the SVI). Port names use the PAN-OS form (", "")
        put("ethernet1/5", "code")
        put(").\n\n", "")
        put("To use it, click ", "")
        put("+ Add Interface", "bold")
        put(" to add a row, then for each row:\n\n", "")
        put("\u2022  Interface: ", "bullet")
        put("Pick the interface from the dropdown. The list is read from the "
            "selected FortiGate config and shows each interface's logical name "
            "(alias) when it has one. Click ", "bullet")
        put("\u21bb Refresh from config", "bold")
        put(" after changing the input file to reload it.\n", "bullet")
        put("\u2022  Action and Target: ", "bullet")
        put("Auto-detected from the chosen interface, but you can override it - ", "bullet")
        put("Map / Assign", "italic")
        put(" to pin a plain interface to one specific port (no aggregation), ", "bullet")
        put("Expand", "italic")
        put(" for an interface that is already an aggregate, or ", "bullet")
        put("Promote", "italic")
        put(" to turn a plain physical port into a new ", "bullet")
        put("Port-Channel", "italic")
        put(" or ", "bullet")
        put("Bridge Group", "italic")
        put(". An existing aggregate or virtual switch is always Expanded "
            "(never accidentally Promoted), so an \"expand to N\" is honored.\n", "bullet")
        put("\u2022  Members: ", "bullet")
        put("Either a target total member count (e.g. ", "bullet")
        put("4", "code")
        put(") or an explicit comma-separated list of FTD ports to add (e.g. ", "bullet")
        put("Ethernet1/5,Ethernet1/6", "code")
        put("); for ", "bullet")
        put("Map / Assign", "italic")
        put(" it is the single target port. Click ", "bullet")
        put("Pick\u2026", "bold")
        put(" to choose ports. Leave a row's Members empty to skip it.\n", "bullet")
        put("\u2022  L3 VLAN: ", "bullet")
        put("Only for ", "bullet")
        put("Promote + Port-Channel", "italic")
        put(". A port-channel can't hold an IP directly, so the promoted "
            "interface's IP is placed on a subinterface (", "bullet")
        put("Port-channelN.tag", "code")
        put(") using this VLAN tag. Leave it blank to apply the IP directly to "
            "the routed port-channel instead.\n\n", "bullet")
        put("The resulting combinations:\n\n", "")
        put("\u2022  Map / Assign: ", "bullet")
        put("send a plain interface straight to one chosen port, converting "
            "normally (no aggregation).\n", "bullet")
        put("\u2022  Expand + Port-Channel: ", "bullet")
        put("grow an existing FortiGate port channel with more 10G member "
            "links.\n", "bullet")
        put("\u2022  Promote + Port-Channel: ", "bullet")
        put("convert a plain physical interface into a new EtherChannel; its IP "
            "moves to a subinterface (set the L3 VLAN tag) or, if no tag is "
            "given, onto the routed channel.\n", "bullet")
        put("\u2022  Expand + Bridge Group: ", "bullet")
        put("grow a FortiGate virtual switch into a larger FTD bridge group "
            "(BVI).\n", "bullet")
        put("\u2022  Promote + Bridge Group: ", "bullet")
        put("convert a plain physical interface into a new bridge group so its "
            "subnet can span several bridged ports (the IP moves to the BVI).\n\n",
            "bullet")
        put("Tip: ", "tip")
        put("The dropdown lists only valid targets - it hides interfaces that "
            "already belong to a port channel or virtual switch (only the parent "
            "is shown) and the dedicated management and HA ports.\n\n", "italic")

        put("How to Run\n", "h2")
        put("1.  Pick Source and Target in the toolbar.\n", "bullet")
        put("2.  Provide the input (browse to a file, or for FTD live mode "
            "enter Host / IP and username).\n", "bullet")
        put("3.  Verify the output directory and base name.\n", "bullet")
        put("4.  Select the target model (when applicable).\n", "bullet")
        put("5.  Click ", "bullet")
        put("Run Conversion", "bold")
        put(". Watch the console for progress, warnings, and the final summary.\n\n",
            "bullet")

        # ----- Import Tab -----
        put("Tab 2: Import\n", "h1")
        put("=" * 70 + "\n\n", "separator")
        put("Pushes the converted JSON files to a Cisco FTD or Palo Alto PAN-OS "
            "appliance via its management API. ", "")
        put("Disabled when the target is FortiGate", "warning")
        put(" - use the FortiGate GUI's Restore feature instead.\n\n", "")

        put("Connection Fields\n", "h2")
        put("\u2022  Host / IP: ", "bullet")
        put("Management IP or hostname of the target appliance.\n", "bullet")
        put("\u2022  Username: ", "bullet")
        put("Admin account (default: ", "bullet")
        put("admin", "code")
        put(").\n", "bullet")
        put("\u2022  Password: ", "bullet")
        put("Admin password.\n", "bullet")
        put("\u2022  Config Directory: ", "bullet")
        put("Folder containing the JSON files from Convert.\n", "bullet")
        put("\u2022  JSON Base Name: ", "bullet")
        put("Must match the base name used during conversion.\n", "bullet")
        put("\u2022  Workers: ", "bullet")
        put("Concurrent API threads (1-32, default 6). FTD only; disabled "
            "for PAN-OS.\n", "bullet")
        put("\u2022  Deploy / Commit after import: ", "bullet")
        put("Activate the configuration on the appliance after import "
            "completes.\n", "bullet")
        put("\u2022  Debug mode: ", "bullet")
        put("Prints full API request/response payloads to the console.\n\n", "bullet")

        put("Selective Import\n", "h2")
        put("By default (no boxes checked), all object types are imported in "
            "dependency order. Check one or more to import only those types:\n\n")
        put("\u2022  Physical Interfaces", "bullet")
        put(" - port configurations (IP, name, enabled state)\n", "bullet")
        put("\u2022  EtherChannels", "bullet")
        put(" - port-channel / LACP bond configurations\n", "bullet")
        put("\u2022  Subinterfaces", "bullet")
        put(" - VLAN subinterface configurations\n", "bullet")
        put("\u2022  Bridge Groups", "bullet")
        put(" - bridge group / BVI configurations\n", "bullet")
        put("\u2022  Security Zones", "bullet")
        put(" - zone definitions\n", "bullet")
        put("\u2022  Address Objects", "bullet")
        put(" - host, network, range, FQDN\n", "bullet")
        put("\u2022  Address Groups", "bullet")
        put(" - groups of address objects\n", "bullet")
        put("\u2022  Service Objects", "bullet")
        put(" - TCP/UDP port objects\n", "bullet")
        put("\u2022  Service Groups", "bullet")
        put(" - groups of service objects\n", "bullet")
        put("\u2022  Static Routes", "bullet")
        put(" - IPv4 static route entries\n", "bullet")
        put("\u2022  Access Rules", "bullet")
        put(" - firewall policy / access control rules\n\n", "bullet")

        put("How Existing Objects Are Handled\n", "h2")
        put("\u2022  ", "bullet")
        put("Cisco FTD target: ", "bold")
        put("when an object with the same name already exists, the importer "
            "issues a PUT to update it to the new payload. This is the default "
            "(", "bullet")
        put("update_existing=True", "code")
        put("); the older skip-on-conflict behavior is available only via the "
            "CLI flag ", "bullet")
        put("--skip-existing", "code")
        put(".\n", "bullet")
        put("\u2022  ", "bullet")
        put("Palo Alto PAN-OS target: ", "bold")
        put("the XML API ", "bullet")
        put("set", "code")
        put(" action natively merges into existing entries, so re-running an "
            "import keeps existing objects in sync without an explicit update "
            "step.\n", "bullet")
        put("\u2022  ", "bullet")
        put("Physical interfaces (FTD): ", "bold")
        put("always PUT - they pre-exist on the device.\n\n", "bullet")
        put("Tip: ", "tip")
        put("Imports are safe to re-run. Existing objects are updated in place "
            "(FTD) or merged (PAN-OS) rather than skipped, so the target stays "
            "in sync with your source config.\n\n")

        put("How to Run\n", "h2")
        put("1.  Enter ", "bullet")
        put("Host / IP", "bold")
        put(", ", "bullet")
        put("Username", "bold")
        put(", ", "bullet")
        put("Password", "bold")
        put(".\n", "bullet")
        put("2.  Set the Config Directory to your Convert output folder.\n", "bullet")
        put("3.  Verify the JSON Base Name matches the conversion output.\n", "bullet")
        put("4.  (Optional) Check specific object types for selective import.\n", "bullet")
        put("5.  (Optional) Check ", "bullet")
        put("Deploy/Commit after import", "bold")
        put(" to activate immediately.\n", "bullet")
        put("6.  Click ", "bullet")
        put("Start Import", "bold")
        put(" and monitor the console.\n\n", "bullet")

        # ----- Cleanup Tab -----
        if self._cleanup_enabled:
            put("Tab 3: Cleanup / Rollback\n", "h1")
            put("=" * 70 + "\n\n", "separator")
            put("Deletes imported objects from a Cisco FTD or PAN-OS appliance. ", "")
            put("Disabled when the target is FortiGate", "warning")
            put(".\n\n", "")
            put("Cleanup Password: ", "warning")
            put("Cleanup is gated by a password to prevent accidental destructive "
                "runs. The first time you use Cleanup, enter the built-in default "
                "password when prompted, then use the ", "italic")
            put("Change Password", "bold")
            put(" button next to the Cleanup form to set your own. ", "italic")
            put("Reset Password", "bold")
            put(" reverts to the default (and requires the current password to do "
                "so).\n\n", "italic")

            put("Connection Fields\n", "h2")
            put("\u2022  Host / IP, Username, Password: ", "bullet")
            put("Same as the Import tab.\n", "bullet")
            put("\u2022  Target Model: ", "bullet")
            put("Model of the appliance being cleaned.\n", "bullet")
            put("\u2022  Workers: ", "bullet")
            put("Concurrent threads for deletion (1-32, default 6).\n\n", "bullet")

            put("What to Delete\n", "h2")
            put("\u2022  Delete ALL custom objects: ", "bullet")
            put("Master checkbox that selects every object type.\n", "bullet")
            put("\u2022  Individual checkboxes: ", "bullet")
            put("Delete specific types: Access Rules, Static Routes, Subinterfaces, "
                "EtherChannels, Security Zones, Bridge Groups, Service Groups, "
                "Service Objects, Address Groups, Address Objects, SNMP Hosts & "
                "Users, Physical Interfaces (reset to defaults).\n\n", "bullet")

            put("Flags\n", "h2")
            put("\u2022  Dry run (preview only): ", "bullet")
            put("Shows what would be deleted without actually deleting. ", "bullet")
            put("Always use this first.\n", "warning")
            put("\u2022  Deploy / Commit after cleanup: ", "bullet")
            put("Activate the changes on the appliance after deletion.\n\n", "bullet")

            put("How to Run\n", "h2")
            put("1.  Enter the target appliance credentials.\n", "bullet")
            put("2.  Select the Target Model.\n", "bullet")
            put("3.  Check ", "bullet")
            put("Delete ALL custom objects", "bold")
            put(" or individual types.\n", "bullet")
            put("4.  Check ", "bullet")
            put("Dry run", "bold")
            put(" first to preview.\n", "bullet")
            put("5.  Click ", "bullet")
            put("Start Cleanup", "bold")
            put(" - you will be prompted for the cleanup password.\n", "bullet")
            put("6.  Review the dry-run output, then uncheck Dry run and run again "
                "to perform the deletion.\n", "bullet")
            put("7.  A confirmation dialog appears before destructive operations.\n\n",
                "bullet")
            put("Important: ", "warning")
            put("Objects are deleted in reverse dependency order (rules first, then "
                "routes, then interfaces, etc.) to avoid reference errors.\n\n")

        # ----- SNMP Tab -----
        put(f"Tab {snmp_tab_num}: SNMP (FTD)\n", "h1")
        put("=" * 70 + "\n\n", "separator")
        put("Pushes a STIG-compliant SNMPv3 configuration to an FDM-managed "
            "FTD. FDM's GUI does not expose SNMPv3, so locally managed FTDs "
            "must be configured through the REST API - this tab does it end "
            "to end. ", "")
        put("Only visible when the target platform is Cisco FTD.\n\n", "warning")

        put("What It Creates\n", "h2")
        put("•  An SNMPv3 user with the chosen auth and privacy "
            "algorithms.\n", "bullet")
        put("•  A network object and SNMP host entry per manager IP, bound "
            "to the source interface. Object names are suffixed with the "
            "manager IP, so pushes are additive - run once per management "
            "tool without overwriting earlier configs.\n", "bullet")
        put("•  Re-running with new values updates the existing objects in "
            "place.\n\n", "bullet")

        put("Fields\n", "h2")
        put("•  FTD Host / IP, Username, Password: ", "bullet")
        put("Admin credentials for the FTD, same as the Import tab.\n", "bullet")
        put("•  SNMP Manager IP(s): ", "bullet")
        put("IP address(es) of your monitoring server(s). Comma-separated "
            "for multiple.\n", "bullet")
        put("•  SNMP Host Name (optional): ", "bullet")
        put("Base name for the SNMP host object(s) created on the FTD; the "
            "manager IP is appended (e.g. ", "bullet")
        put("SolarWinds_10_0_0_50", "code")
        put("). Default: ", "bullet")
        put("snmpv3-host", "code")
        put(".\n", "bullet")
        put("•  SNMPv3 User Name: ", "bullet")
        put("Name of the SNMPv3 user to create (default ", "bullet")
        put("FWADMIN", "code")
        put(").\n", "bullet")
        put("•  Auth Algorithm / Auth Password: ", "bullet")
        put("SHA or SHA256, password minimum 8 characters.\n", "bullet")
        put("•  Privacy Algorithm / Privacy Password: ", "bullet")
        put("AES128, AES192, or AES256 (default AES256; AES128 is the STIG "
            "minimum), password minimum 8 characters.\n", "bullet")
        put("•  Source Interface: ", "bullet")
        put("Logical name of the interface the managers reach the FTD "
            "through (e.g. ", "bullet")
        put("outside", "code")
        put(", not ", "bullet")
        put("Ethernet1/1", "code")
        put("). Physical interfaces, EtherChannels, and subinterfaces are "
            "all supported.\n", "bullet")
        put("•  Location / Contact (optional): ", "bullet")
        put("Device-global SNMP system location and contact (sysLocation / "
            "sysContact), e.g. a site identifier and an admin email. No "
            "semicolons. Left blank, the device's existing values are "
            "unchanged.\n", "bullet")
        put("•  Enable polling / Enable traps: ", "bullet")
        put("Allow SNMP polling (UDP 161) and/or traps (UDP 162) for this "
            "manager. Both on by default.\n", "bullet")
        put("•  Trap Events (device-wide): ", "bullet")
        put("Which event types fire traps (link up/down, cold/warm start, "
            "syslog, failover, CPU/memory thresholds, etc.). Check "
            "\"Configure trap event types\" to set them; left unchecked, the "
            "device's current trap events are not touched. The default "
            "selection mirrors the platform defaults (authentication, link "
            "up/down, cold/warm start). Note: some ASA CLI traps (ipsec, "
            "ikev2, interface-threshold) are not exposed by the FDM API and "
            "cannot be set here.\n", "bullet")
        put("•  Deploy after push: ", "bullet")
        put("Deploy the staged changes on the FTD after the push "
            "completes.\n\n", "bullet")

        put("How to Run\n", "h2")
        put("1.  Set the target platform to Cisco FTD so the tab is "
            "visible.\n", "bullet")
        put("2.  Enter the FTD connection credentials.\n", "bullet")
        put("3.  Enter the SNMP manager IP(s) and SNMPv3 user settings.\n", "bullet")
        put("4.  Enter the source interface's logical name.\n", "bullet")
        put("5.  Click ", "bullet")
        put("Push SNMP Config", "bold")
        put(" and monitor the console. Check ", "bullet")
        put("Deploy after push", "bold")
        put(" first to activate immediately.\n\n", "bullet")
        put("Tip: ", "tip")
        if self._cleanup_enabled:
            put("Passwords are redacted from the echoed command line and error "
                "output. To remove SNMP config later, use the Cleanup tab's "
                "\"SNMP Hosts & Users\" checkbox.\n\n")
        else:
            put("Passwords are redacted from the echoed command line and error "
                "output.\n\n")

        # ----- Config Viewer Tab -----
        put(f"Tab {viewer_tab_num}: Config Viewer\n", "h1")
        put("=" * 70 + "\n\n", "separator")
        put("Browse and search the generated JSON files without leaving the "
            "application. (Designed for FTD / PAN-OS JSON output; FortiGate "
            ".conf output is plain text and is not displayed here.)\n\n")

        put("How to Use\n", "h2")
        put("1.  Set the Config Directory to the folder with your JSON files.\n", "bullet")
        put("2.  Enter the JSON Base Name (e.g., ", "bullet")
        put("ftd_config", "code")
        put(" or ", "bullet")
        put("pa_config", "code")
        put(").\n", "bullet")
        put("3.  Click ", "bullet")
        put("Load Files", "bold")
        put(". The left pane shows all matching files.\n", "bullet")
        put("4.  Click a file to view its contents (auto-formatted as "
            "pretty-printed JSON) in the right pane.\n", "bullet")
        put("5.  Use the Search bar to find text within the displayed file:\n", "bullet")
        put("    \u2013  Type a term and press Enter or click Find Next.\n", "sub_bullet")
        put("    \u2013  Click Find Prev to search backward.\n", "sub_bullet")
        put("    \u2013  The match counter shows your position (e.g., \"3 of 7\").\n", "sub_bullet")
        put("    \u2013  Search wraps around automatically.\n\n", "sub_bullet")

        # ----- Theme Selector -----
        put("Theme Selector\n", "h1")
        put("=" * 70 + "\n\n", "separator")
        put("The theme dropdown in the top-right corner switches the color "
            "scheme instantly. No restart required.\n\n")
        put("\u2022  Default: ", "bullet")
        put("Neutral dark gray background with light gray accents. Clean and "
            "understated.\n", "bullet")
        put("\u2022  Coral: ", "bullet")
        put("Dark teal background with coral accents. Professional and easy "
            "on the eyes.\n", "bullet")
        put("\u2022  Sandstone: ", "bullet")
        put("Dark olive-green background with warm orange accents. Earthy and "
            "muted.\n", "bullet")
        put("\u2022  Chris: ", "bullet")
        put("Hot pink background with neon green accents. High contrast and "
            "vibrant.\n", "bullet")
        put("\u2022  Voyager: ", "bullet")
        put("Deep navy-blue background with gold accents. Bold and nautical.\n",
            "bullet")
        put("\u2022  Simulation: ", "bullet")
        put("Pure black background with phosphor-green text. Idle output "
            "consoles show falling code, just like the Matrix. There is no "
            "spoon.\n", "bullet")
        put("\u2022  Light: ", "bullet")
        put("Light gray background with blue accents. Bright, for well-lit "
            "rooms.\n\n", "bullet")

        # ----- Tips -----
        put("Tips and Notes\n", "h1")
        put("=" * 70 + "\n\n", "separator")
        put("\u2022  ", "bullet")
        put("One operation at a time: ", "bold")
        if self._cleanup_enabled:
            put("Only one background operation (convert, import, cleanup, or "
                "SNMP push) can run at a time. The Run buttons are disabled "
                "while an operation is in progress.\n", "bullet")
        else:
            put("Only one background operation (convert, import, or SNMP push) "
                "can run at a time. The Run buttons are disabled while an "
                "operation is in progress.\n", "bullet")
        put("\u2022  ", "bullet")
        put("Cancel safely: ", "bold")
        put("Clicking Cancel interrupts the running operation. It may take a "
            "few seconds to stop.\n", "bullet")
        put("\u2022  ", "bullet")
        put("Status bar: ", "bold")
        put("The bottom of the window shows the current status (Ready, Running, "
            "Cancelling, or Finished).\n", "bullet")
        put("\u2022  ", "bullet")
        put("Directory consistency: ", "bold")
        put("The Convert tab's output directory and the Import tab's config "
            "directory should point to the same folder.\n", "bullet")
        put("\u2022  ", "bullet")
        put("Base name consistency: ", "bold")
        put("The output base name in Convert must match the JSON base name in "
            "Import and Config Viewer.\n", "bullet")
        put("\u2022  ", "bullet")
        put("Separate credentials: ", "bold")
        if self._cleanup_enabled:
            put("The Import and Cleanup tabs have their own credential fields. "
                "Credentials are not shared between tabs.\n", "bullet")
        else:
            put("The Import tab stores its own credentials.\n", "bullet")
        put("\u2022  ", "bullet")
        put("Compiled executable: ", "bold")
        put("When running from the .exe, all functionality is identical. No "
            "Python installation is needed.\n", "bullet")

        help_text.configure(state=tk.DISABLED)

    def _help_clear_highlights(self) -> None:
        self._help_text.tag_remove("search_hit", "1.0", tk.END)
        self._help_text.tag_remove("search_current", "1.0", tk.END)

    def _help_find(self, forwards: bool = True) -> None:
        """Search the How-To Guide, highlighting all matches and stepping to the
        next/previous one (case-insensitive, wraps around). Mirrors the Config
        Viewer search."""
        query = self._help_search_var.get()
        if not query:
            self._help_clear_highlights()
            self._help_match_label.configure(text="")
            return

        self._help_clear_highlights()

        # Highlight every match
        count_var = tk.IntVar()
        total = 0
        pos = "1.0"
        while True:
            pos = self._help_text.search(
                query, pos, stopindex=tk.END, nocase=True, count=count_var,
            )
            if not pos:
                break
            end = f"{pos}+{count_var.get()}c"
            self._help_text.tag_add("search_hit", pos, end)
            total += 1
            pos = end

        if total == 0:
            self._help_match_label.configure(text="No matches")
            return

        # Step to the next/previous match from the current position
        if forwards:
            hit = self._help_text.search(
                query, self._help_search_idx, stopindex=tk.END,
                nocase=True, count=count_var,
            )
            if not hit:  # wrap to the top
                hit = self._help_text.search(
                    query, "1.0", stopindex=tk.END, nocase=True, count=count_var,
                )
        else:
            hit = self._help_text.search(
                query, self._help_search_idx, stopindex="1.0",
                backwards=True, nocase=True, count=count_var,
            )
            if not hit:  # wrap to the bottom
                hit = self._help_text.search(
                    query, tk.END, stopindex="1.0", backwards=True,
                    nocase=True, count=count_var,
                )

        if hit:
            end = f"{hit}+{count_var.get()}c"
            self._help_text.tag_add("search_current", hit, end)
            self._help_text.see(hit)
            self._help_search_idx = end if forwards else hit

        # Report which match we landed on
        match_num = 0
        pos = "1.0"
        while hit and pos:
            pos = self._help_text.search(
                query, pos, stopindex=tk.END, nocase=True, count=count_var,
            )
            if not pos:
                break
            match_num += 1
            if self._help_text.compare(pos, "==", hit):
                break
            pos = f"{pos}+{count_var.get()}c"

        self._help_match_label.configure(text=f"{match_num} of {total}")

    def _help_find_next(self) -> None:
        self._help_find(forwards=True)

    def _help_find_prev(self) -> None:
        self._help_find(forwards=False)

    # ------------------------------------------------------------------
    # Shared widgets / helpers
    # ------------------------------------------------------------------
    def _make_scrollable(self, parent: Any) -> tuple:
        """Wrap a vertically scrollable area inside *parent*.

        Returns ``(container, inner)``. Add ``container`` to the parent
        (pack/grid/PanedWindow.add); pack your widgets into ``inner``. A
        vertical scrollbar appears and the mouse wheel scrolls whenever the
        content is taller than the visible area, so nothing (e.g. action
        buttons at the bottom) can be clipped off-screen.
        """
        container = ttk.Frame(parent)
        canvas = tk.Canvas(
            container, background=self._colors["bg"], highlightthickness=0,
            borderwidth=0,
        )
        vscroll = ttk.Scrollbar(
            container, orient=tk.VERTICAL, command=canvas.yview,
        )
        canvas.configure(yscrollcommand=vscroll.set)
        vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        inner = ttk.Frame(canvas)
        window_id = canvas.create_window((0, 0), window=inner, anchor="nw")

        def _on_inner_configure(_event: Any) -> None:
            # Update the scrollable region and keep the canvas as wide as its
            # content so nothing is clipped horizontally.
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.configure(width=inner.winfo_reqwidth())

        inner.bind("<Configure>", _on_inner_configure)

        def _on_canvas_configure(event: Any) -> None:
            # Stretch the inner frame to fill the canvas when the canvas is
            # wider than the content (so fill=X widgets behave as before).
            if event.width > inner.winfo_reqwidth():
                canvas.itemconfigure(window_id, width=event.width)
            else:
                canvas.itemconfigure(window_id, width=inner.winfo_reqwidth())

        canvas.bind("<Configure>", _on_canvas_configure)

        # Wheel scrolling is handled by one persistent application-wide
        # binding (_on_global_mousewheel) that dispatches to the registered
        # canvas under the pointer. Per-canvas bind_all/unbind_all pairs are
        # deliberately avoided: unbind_all would nuke sibling panels' handler,
        # and a binding left behind by a destroyed picker window would raise
        # on the next wheel event anywhere in the app.
        self._wheel_canvases.append(canvas)

        return container, inner

    def _on_global_mousewheel(self, event: Any) -> None:
        """Scroll the _make_scrollable canvas (if any) under the pointer."""
        # Prune canvases whose windows have been destroyed (closed pickers).
        self._wheel_canvases = [
            c for c in self._wheel_canvases if c.winfo_exists()
        ]
        try:
            widget = self.winfo_containing(event.x_root, event.y_root)
        except (KeyError, tk.TclError):
            return
        # Walk up from the hovered widget; scroll the first enclosing canvas.
        while widget is not None:
            if widget in self._wheel_canvases:
                widget.yview_scroll(int(-1 * (event.delta / 120)), "units")
                return
            widget = getattr(widget, "master", None)

    def _make_output_area(self, parent: Any) -> tk.Text:
        """Create a scrollable text widget for command output."""
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        text = tk.Text(
            frame, wrap=tk.WORD, font=("Consolas", 10),
            bg=_OUT_BG, fg=_OUT_FG,
            insertbackground=_OUT_FG,
            selectbackground=_ACCENT_D, selectforeground=_OUT_FG,
            state=tk.DISABLED, relief=tk.FLAT, bd=1,
            highlightthickness=1, highlightbackground=_BORDER, highlightcolor=_ACCENT,
        )
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._tk_widgets.append(text)
        return text

    def _append_output(self, text_widget: tk.Text, content: str) -> None:
        """Append text to a read-only text widget and auto-scroll."""
        text_widget.configure(state=tk.NORMAL)
        text_widget.insert(tk.END, content)
        text_widget.see(tk.END)
        text_widget.configure(state=tk.DISABLED)

    def _clear_output(self, text_widget: tk.Text) -> None:
        text_widget.configure(state=tk.NORMAL)
        text_widget.delete("1.0", tk.END)
        text_widget.configure(state=tk.DISABLED)
        self._update_matrix_rain()

    def _browse_yaml(self) -> None:
        if self._current_source == "Cisco ASA":
            path = filedialog.askopenfilename(
                title="Select Cisco ASA Configuration File",
                filetypes=[
                    ("Config files", "*.txt *.cfg *.conf"),
                    ("All files", "*.*"),
                ],
            )
        elif self._current_source == "Palo Alto":
            path = filedialog.askopenfilename(
                title="Select PAN-OS XML Configuration File",
                filetypes=[
                    ("XML files", "*.xml"),
                    ("All files", "*.*"),
                ],
            )
        elif self._current_source == "Cisco FTD":
            if not self.conv_ftd_file_var.get():
                return  # API mode - no file to browse
            path = filedialog.askopenfilename(
                title="Select FTD FDM JSON Config File",
                filetypes=[
                    ("JSON files", "*.json"),
                    ("All files", "*.*"),
                ],
            )
            if path:
                self.conv_input_var.set(path)
                self.conv_outdir_var.set(os.path.dirname(path))
            return
        else:
            path = filedialog.askopenfilename(
                title="Select FortiGate YAML Configuration",
                filetypes=[("YAML files", "*.yaml *.yml"), ("All files", "*.*")],
            )
        if path:
            self.conv_input_var.set(path)
            # Auto-set output directory to same folder as the input file
            self.conv_outdir_var.set(os.path.dirname(path))
            # Refresh the aggregation builder's interface list from the new file
            if self._agg_visible:
                self._agg_refresh_interfaces(silent=True)

    def _browse_outdir(self) -> None:
        d = filedialog.askdirectory(title="Select Output Directory")
        if d:
            self.conv_outdir_var.set(d)

    def _browse_impdir(self) -> None:
        d = filedialog.askdirectory(title="Select Config Files Directory")
        if d:
            self.imp_dir_var.set(d)

    def _set_buttons_state(self, state: str) -> None:
        """Enable or disable all run buttons (and toggle cancel buttons inversely).
        Import/Cleanup run buttons stay disabled when the current target locks them out."""
        cancel_state = tk.DISABLED if state == tk.NORMAL else tk.NORMAL
        self.conv_run_btn.configure(state=state)
        self.imp_run_btn.configure(
            state=tk.DISABLED if self._imp_locked_by_target else state,
        )
        if self._cleanup_enabled:
            self.cln_run_btn.configure(
                state=tk.DISABLED if self._cln_locked_by_target else state,
            )
        self.conv_cancel_btn.configure(state=cancel_state)
        self.imp_cancel_btn.configure(
            state=tk.DISABLED if self._imp_locked_by_target else cancel_state,
        )
        if self._cleanup_enabled:
            self.cln_cancel_btn.configure(
                state=tk.DISABLED if self._cln_locked_by_target else cancel_state,
            )
        # SNMP tab is hidden (not locked) for non-FTD targets, so no lock flag
        self.snmp_run_btn.configure(state=state)
        self.snmp_cancel_btn.configure(state=cancel_state)
        # Lock the source/target selectors while an operation runs - a
        # mid-run platform switch would retitle/unlock tabs and clobber the
        # running state. Restore each combo's idle state afterwards.
        if state == tk.NORMAL:
            self.source_combo.configure(state=self._source_combo_idle_state)
            self.platform_combo.configure(state=self._platform_combo_idle_state)
        else:
            self.source_combo.configure(state=tk.DISABLED)
            self.platform_combo.configure(state=tk.DISABLED)

    # ------------------------------------------------------------------
    # In-process execution engine
    # ------------------------------------------------------------------
    def _run_in_thread(
        self,
        func: Any,
        argv: List[str],
        text_widget: tk.Text,
        label: str = "Operation",
    ) -> None:
        """
        Run a module's main(argv) in a background thread while capturing
        all stdout/stderr output and streaming it to the given text widget.
        """
        if self._running:
            messagebox.showwarning(
                "Busy", "An operation is already running. Please wait.",
            )
            return

        self._clear_output(text_widget)
        self._append_output(text_widget, f"> {label} {' '.join(_redact_argv(argv))}\n\n")
        self._set_buttons_state(tk.DISABLED)
        self._running = True
        self.status_var.set(f"Running: {label}...")
        self._update_matrix_rain()

        # Snapshot every secret as a plain string on the Tk main thread. Tk
        # variables must never be read from the worker thread, so the worker
        # scrubs exception text against this snapshot instead. argv secrets
        # cover credentials with no Tk variable (e.g. the FTD->FG live-API
        # password prompted via a dialog).
        secrets = self._collect_secret_values() + _argv_secret_values(argv)

        def _worker() -> None:
            old_stdout, old_stderr = sys.stdout, sys.stderr
            writer = _QueueWriter(self._output_queue, text_widget)
            sys.stdout = writer
            sys.stderr = writer
            try:
                exit_code = func(argv)
                if exit_code is None:
                    exit_code = 0
                self._output_queue.put(
                    (text_widget, f"\n--- Finished (exit code {exit_code}) ---\n"),
                )
            except SystemExit as exc:
                code = exc.code if exc.code is not None else 0
                self._output_queue.put(
                    (text_widget, f"\n--- Finished (exit code {code}) ---\n"),
                )
            except Exception as exc:
                # Scrub any operator passwords typed into the GUI before
                # surfacing the exception or traceback - defense in depth in
                # case a future code path puts credentials into a URL or body
                # that ends up in a network exception string.
                err_text = self._scrub_secrets(str(exc), secrets)
                tb_text = self._scrub_secrets(traceback.format_exc(), secrets)
                self._output_queue.put(
                    (text_widget, f"\n--- ERROR: {err_text} ---\n"),
                )
                self._output_queue.put((text_widget, tb_text))
            finally:
                sys.stdout = old_stdout
                sys.stderr = old_stderr
                self._output_queue.put((text_widget, None))  # sentinel

        self._worker_thread = threading.Thread(target=_worker, daemon=True)
        self._worker_thread.start()
        self._poll_output()

    def _collect_secret_values(self) -> List[str]:
        """Snapshot the credential fields as plain strings.

        MUST be called on the Tk main thread - Tk variables are not safe to
        read from worker threads. The returned list is handed to the worker,
        which passes it to _scrub_secrets().
        """
        secrets: List[str] = []
        for var_name in ("imp_pass_var", "cln_pass_var",
                         "snmp_pass_var", "snmp_auth_pw_var", "snmp_priv_pw_var"):
            var = getattr(self, var_name, None)
            if var is None:
                continue
            try:
                pw = var.get()
            except tk.TclError:
                continue
            if pw:
                secrets.append(pw)
        return secrets

    @staticmethod
    def _scrub_secrets(text: str, secrets: List[str]) -> str:
        """Redact any operator passwords typed into the GUI from arbitrary text.

        Used on exception strings and tracebacks before they are written to
        the output window, so a network error that happens to embed
        credentials in a URL never shows them in plaintext. ``secrets`` is a
        plain-string snapshot taken on the main thread (thread-safe to use
        from the worker).
        """
        if not text:
            return text
        for pw in secrets:
            if pw:
                text = text.replace(pw, "***REDACTED***")
        return text

    def _poll_output(self) -> None:
        """Drain the output queue and schedule the next poll."""
        try:
            while True:
                widget, text = self._output_queue.get_nowait()
                if text is None:
                    # Worker thread finished
                    self._running = False
                    self._set_buttons_state(tk.NORMAL)
                    self.status_var.set("Ready")
                    self._update_matrix_rain()
                    return
                self._append_output(widget, text)
        except queue.Empty:
            pass
        self.after(50, self._poll_output)

    def _cancel_operation(self) -> None:
        """Cancel the currently running operation by raising SystemExit in the worker thread.

        Note: PyThreadState_SetAsyncExc only delivers the exception the next
        time the worker executes Python bytecode - a blocking socket
        connect/read cannot be interrupted, so cancellation takes effect at
        the next API operation.
        """
        if not self._running or self._worker_thread is None:
            return
        tid = self._worker_thread.ident
        if tid is None:
            return
        # Raise SystemExit asynchronously in the worker thread
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(
            ctypes.c_ulong(tid), ctypes.py_object(SystemExit),
        )
        if res == 0:
            return  # thread already finished
        if res > 1:
            # Per the CPython docs: if more than one thread state was
            # modified, undo the damage with a second call passing exc=NULL.
            ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_ulong(tid), None)
            return
        self.status_var.set(
            "Cancelling... (takes effect at the worker's next operation; a "
            "blocked network call cannot be interrupted)",
        )

    # ------------------------------------------------------------------
    # Run commands
    # ------------------------------------------------------------------
    def _validated_workers(self, raw: str) -> Optional[str]:
        """Validate a Workers field as a whole number 1-32 (the range the FTD
        CLIs accept). The ttk.Spinbox allows free text, so the value can't be
        trusted. Returns the normalized string, or None after showing a
        friendly error dialog."""
        value = raw.strip()
        try:
            num = int(value)
        except ValueError:
            num = -1
        if not 1 <= num <= 32:
            messagebox.showerror(
                "Invalid Workers",
                f"Workers must be a whole number between 1 and 32 (got: {value or '(blank)'}).",
            )
            return None
        return str(num)

    def _run_convert(self) -> None:
        is_asa = self._current_source == "Cisco ASA"
        is_pa_source = self._current_source == "Palo Alto"
        is_ftd_source = self._current_source == "Cisco FTD"
        is_fg_target = self._current_platform == "FortiGate"
        is_pa = self._current_platform == "Palo Alto PAN-OS"

        input_field = self.conv_input_var.get().strip()

        # ── FTD → FortiGate ─────────────────────────────────────────────
        if is_ftd_source and is_fg_target:
            if not _FTD_TO_FG_AVAILABLE:
                messagebox.showerror(
                    "FTD→FG Modules Missing",
                    f"Cisco FTD to FortiGate converter modules not found.\n\n"
                    f"Searched: {_FTD_TO_FG_DIR}\n"
                    f"Error: {_FTD_TO_FG_IMPORT_ERROR}",
                )
                return
            outdir = self.conv_outdir_var.get().strip()
            base = self.conv_output_var.get().strip() or "fg_config"
            full_base = os.path.join(outdir, base) if outdir else base

            if self.conv_ftd_file_var.get():
                # File mode
                json_path = input_field
                if not json_path:
                    messagebox.showerror("Missing Input",
                                         "Please select a FTD FDM JSON config file.")
                    return
                if not os.path.isfile(json_path):
                    messagebox.showerror("File Not Found",
                                         f"Config file not found:\n{json_path}")
                    return
                argv = ["--input-file", json_path, "-o", full_base]
            else:
                # API mode
                host = input_field
                if not host:
                    messagebox.showerror("Missing Field",
                                         "Please enter the FTD host / IP address.")
                    return
                username = self.conv_ha_var.get().strip() or "admin"
                password = simpledialog.askstring(
                    "FTD Password",
                    f"Enter FDM password for {username}@{host}:",
                    show="*",
                    parent=self,
                )
                if password is None:  # User cancelled
                    return
                if not password:
                    messagebox.showerror("Missing Field", "Password cannot be empty.")
                    return
                # --flag=value form so credentials starting with '-' aren't
                # mistaken for flags by argparse.
                argv = [f"--host={host}", f"--username={username}",
                        f"--password={password}",
                        "-o", full_base, "--no-ssl-verify"]

            self._run_in_thread(ftd_to_fg_convert_main, argv, self.conv_output, "Convert")
            return

        # ── File-based conversions ──────────────────────────────────────
        input_file = input_field
        if not input_file:
            if is_asa:
                file_type = "Cisco ASA config"
            elif is_pa_source:
                file_type = "PAN-OS XML"
            else:
                file_type = "FortiGate YAML"
            messagebox.showerror("Missing Input", f"Please select a {file_type} file.")
            return

        outdir = self.conv_outdir_var.get().strip()
        if is_pa:
            default_base = "pa_config"
        elif is_fg_target:
            default_base = "fg_config"
        else:
            default_base = "ftd_config"
        base = self.conv_output_var.get().strip() or default_base
        full_base = os.path.join(outdir, base) if outdir else base

        argv = [input_file, "-o", full_base]

        if is_fg_target:
            # PA→FG: no model, no HA port, no pretty flag (outputs .conf not JSON)
            if not _PA_TO_FG_AVAILABLE:
                messagebox.showerror(
                    "PA→FG Modules Missing",
                    f"Palo Alto to FortiGate converter modules not found.\n\n"
                    f"Error: {_PA_TO_FG_IMPORT_ERROR}",
                )
                return
            main_fn = pa_to_fg_convert_main
        else:
            model = self.conv_model_var.get()
            if model and model != "(not applicable)":
                argv.extend(["-m", model])

            if not is_pa:
                ha_port = self.conv_ha_var.get().strip()
                argv.extend(["--ha-port", ha_port if ha_port else "none"])

                # Optional FTD network module (only meaningful for an FTD target).
                if self._current_platform == "Cisco FTD":
                    module_id = FTD_MODULE_LABEL_TO_ID.get(
                        self.conv_module_var.get(), "none",
                    )
                    if module_id and module_id != "none":
                        argv.extend(["--network-module", module_id])

            # Interface builder: FortiGate -> FTD and FortiGate -> Palo Alto
            # both accept the same flags (port-channel maps to aggregate-ethernet,
            # bridge group to a Layer-2 VLAN on PA). Each row -> one converter
            # flag. The flag is resolved from the interface's KNOWN category
            # (not just the Action dropdown) so an existing aggregate/switch is
            # always Expanded, never accidentally routed to Promote.
            if self._current_source == "FortiGate" and (
                is_pa or self._current_platform == "Cisco FTD"
            ):
                for row in self._agg_rows:
                    argv.extend(self._agg_row_to_argv(row))

            if self.conv_pretty_var.get():
                argv.append("--pretty")

            if is_asa:
                if not _ASA_AVAILABLE:
                    messagebox.showerror(
                        "ASA Modules Missing",
                        f"Cisco ASA converter modules not found.\n\n"
                        f"Error: {_ASA_IMPORT_ERROR}",
                    )
                    return
                main_fn = asa_convert_main
            elif is_pa:
                main_fn = pa_convert_main
            else:
                main_fn = convert_main

        self._run_in_thread(main_fn, argv, self.conv_output, "Convert")

    def _run_import(self) -> None:
        # Import to FortiGate via API is not supported - config is applied manually
        if self._current_platform == "FortiGate" or self._current_source == "Cisco FTD":
            messagebox.showinfo(
                "Not Applicable",
                "Direct import to FortiGate is not supported.\n\n"
                "Apply the generated .conf file manually:\n"
                "  \u2022 FortiGate CLI: paste the config commands, or\n"
                "  \u2022 Web UI: System \u2192 Configuration \u2192 Restore",
            )
            return

        host = self.imp_host_var.get().strip()
        password = self.imp_pass_var.get()
        is_pa = self._current_platform == "Palo Alto PAN-OS"

        platform_label = "PAN-OS" if is_pa else "FTD"
        if not host:
            messagebox.showerror("Missing Field", f"Please enter the {platform_label} host/IP address.")
            return
        if not password:
            messagebox.showerror("Missing Field", f"Please enter the {platform_label} password.")
            return

        impdir = self.imp_dir_var.get().strip()
        base = self.imp_base_var.get().strip() or ("pa_config" if is_pa else "ftd_config")
        full_base = os.path.join(impdir, base) if impdir else base

        # Credential/host values use the --flag=value form so values starting
        # with '-' aren't mistaken for flags by argparse.
        if is_pa:
            argv = [
                f"--host={host}",
                f"--username={self.imp_user_var.get().strip() or 'admin'}",
                f"--password={password}",
                "--input", full_base,
            ]
            if self.imp_deploy_var.get():
                argv.append("--commit")
            if self.imp_debug_var.get():
                argv.append("--debug")

            self._run_in_thread(pa_import_main, argv, self.imp_output, "Import (PAN-OS)")
        else:
            workers = self._validated_workers(self.imp_workers_var.get())
            if workers is None:
                return
            argv = [
                f"--host={host}",
                f"--username={self.imp_user_var.get().strip() or 'admin'}",
                f"--password={password}",
                "--base", full_base,
                "--workers", workers,
            ]

            if self.imp_deploy_var.get():
                argv.append("--deploy")
            if self.imp_debug_var.get():
                argv.append("--debug")
            if not self.imp_update_existing_var.get():
                argv.append("--skip-existing")

            # Selective import flags
            selected = [k for k, v in self.imp_only_vars.items() if v.get()]
            for key in selected:
                argv.append(f"--only-{key}")

            self._run_in_thread(import_main, argv, self.imp_output, "Import")

    # ------------------------------------------------------------------
    # Cleanup password management
    # ------------------------------------------------------------------
    def _prompt_password(self, title: str, prompt: str) -> Optional[str]:
        """Show a modal dialog that asks for a single masked password.

        Returns the entered string, or None if the user cancelled.
        """
        result: List[Optional[str]] = [None]

        dlg = tk.Toplevel(self)
        dlg.title(title)
        dlg.geometry("360x150")
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.grab_set()

        ttk.Label(dlg, text=prompt).pack(padx=16, pady=(16, 4), anchor=tk.W)
        pw_var = tk.StringVar()
        entry = ttk.Entry(dlg, textvariable=pw_var, show="*", width=36)
        entry.pack(padx=16, pady=4)
        entry.focus_set()

        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(pady=12)

        def on_ok(_event: Optional[Any] = None) -> None:
            result[0] = pw_var.get()
            dlg.destroy()

        def on_cancel(_event: Optional[Any] = None) -> None:
            dlg.destroy()

        entry.bind("<Return>", on_ok)
        dlg.bind("<Escape>", on_cancel)
        ttk.Button(btn_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_frame, text="Cancel", command=on_cancel).pack(side=tk.LEFT, padx=8)

        dlg.wait_window()
        return result[0]

    def _show_message(self, title: str, message: str, kind: str = "info") -> None:
        """Show a themed modal message dialog (info / warning / error).

        Replacement for messagebox.showinfo/showwarning/showerror, which always
        use native OS styling and ignore the app theme. The ttk widgets pick up
        the current theme's styles automatically.
        """
        glyph, glyph_fg = {
            "info": ("ℹ", self._colors["accent"]),     # information source
            "warning": ("⚠", self._colors["accent_h"]),  # warning sign
            "error": ("✖", "#ff6b6b"),  # heavy multiplication x
        }.get(kind, ("ℹ", self._colors["accent"]))

        dlg = tk.Toplevel(self)
        dlg.title(title)
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.grab_set()

        body = ttk.Frame(dlg, padding=(20, 18, 20, 8))
        body.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            body, text=glyph, foreground=glyph_fg, font=("Segoe UI", 20),
        ).grid(row=0, column=0, sticky=tk.N, padx=(0, 14))
        ttk.Label(
            body, text=message, justify=tk.LEFT, wraplength=380,
        ).grid(row=0, column=1, sticky=tk.W)

        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(pady=(4, 16))

        def on_ok(_event: Optional[Any] = None) -> None:
            dlg.destroy()

        ok_btn = ttk.Button(btn_frame, text="OK", command=on_ok, width=10)
        ok_btn.pack()
        dlg.bind("<Return>", on_ok)
        dlg.bind("<Escape>", on_ok)
        ok_btn.focus_set()

        # Center over the main window
        dlg.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - dlg.winfo_width()) // 2
        y = self.winfo_y() + (self.winfo_height() - dlg.winfo_height()) // 2
        dlg.geometry(f"+{x}+{y}")

        dlg.wait_window()

    def _ask_yes_no(self, title: str, message: str) -> bool:
        """Show a themed modal Yes/No confirmation dialog.

        Replacement for messagebox.askyesno, which always uses native OS
        styling and ignores the app theme. Returns True if Yes was clicked.
        """
        result = [False]

        dlg = tk.Toplevel(self)
        dlg.title(title)
        dlg.resizable(False, False)
        dlg.transient(self)
        dlg.grab_set()

        ttk.Label(
            dlg, text=message, justify=tk.LEFT, wraplength=380
        ).pack(padx=20, pady=(18, 8), anchor=tk.W)

        btn_frame = ttk.Frame(dlg)
        btn_frame.pack(pady=(4, 16))

        def on_yes(_event: Optional[Any] = None) -> None:
            result[0] = True
            dlg.destroy()

        def on_no(_event: Optional[Any] = None) -> None:
            dlg.destroy()

        yes_btn = ttk.Button(btn_frame, text="Yes", command=on_yes, width=10)
        yes_btn.pack(side=tk.LEFT, padx=8)
        ttk.Button(btn_frame, text="No", command=on_no, width=10).pack(
            side=tk.LEFT, padx=8
        )
        dlg.bind("<Return>", on_yes)
        dlg.bind("<Escape>", on_no)
        yes_btn.focus_set()

        # Center over the main window
        dlg.update_idletasks()
        x = self.winfo_x() + (self.winfo_width() - dlg.winfo_width()) // 2
        y = self.winfo_y() + (self.winfo_height() - dlg.winfo_height()) // 2
        dlg.geometry(f"+{x}+{y}")

        dlg.wait_window()
        return result[0]

    def _manage_cleanup_password(self) -> None:
        """Change the cleanup password (requires current password first)."""
        # Verify current password
        current = self._prompt_password(
            "Verify Password",
            "Enter your current cleanup password:",
        )
        if current is None:
            return
        if not verify_password(current):  # pyright: ignore[reportOptionalCall]
            messagebox.showerror("Incorrect Password", "The current password is incorrect.")
            return

        # Get new password
        new_pw = self._prompt_password(
            "New Cleanup Password",
            "Enter new cleanup password:",
        )
        if not new_pw:
            if new_pw is None:
                return  # cancelled
            messagebox.showerror("Empty Password", "Password cannot be empty.")
            return

        # Confirm new password
        confirm = self._prompt_password(
            "Confirm Password",
            "Confirm new cleanup password:",
        )
        if confirm is None:
            return
        if new_pw != confirm:
            messagebox.showerror("Mismatch", "Passwords do not match.")
            return

        try:
            set_password(new_pw)  # pyright: ignore[reportOptionalCall]
        except OSError as exc:
            # e.g. PermissionError when the app dir is read-only
            messagebox.showerror(
                "Could Not Save Password",
                "Failed to write cleanup_auth.json next to the application:\n"
                f"{exc}\n\nThe cleanup password was NOT changed.",
            )
            return
        self.cln_reset_pw_btn.configure(state=tk.NORMAL)
        messagebox.showinfo("Success", "Cleanup password has been changed.")

    def _reset_cleanup_password(self) -> None:
        """Reset to the built-in default password (requires current password)."""
        current = self._prompt_password(
            "Verify Password",
            "Enter your current cleanup password to reset:",
        )
        if current is None:
            return
        if not verify_password(current):  # pyright: ignore[reportOptionalCall]
            messagebox.showerror("Incorrect Password", "The current password is incorrect.")
            return

        if not self._ask_yes_no(
            "Confirm Reset",
            "This will reset the cleanup password to the built-in default.\n\n"
            "Are you sure?",
        ):
            return

        try:
            reset_to_default()  # pyright: ignore[reportOptionalCall]
        except OSError as exc:
            messagebox.showerror(
                "Could Not Reset Password",
                "Failed to remove cleanup_auth.json next to the application:\n"
                f"{exc}\n\nThe cleanup password was NOT reset.",
            )
            return
        self.cln_reset_pw_btn.configure(state=tk.DISABLED)
        messagebox.showinfo("Success", "Cleanup password has been reset to default.")

    def _verify_cleanup_access(self) -> bool:
        """Gate cleanup behind the password. Returns True if access granted."""
        entered = self._prompt_password(
            "Cleanup Password",
            "Enter the cleanup password to continue:",
        )
        if entered is None:
            return False
        if not verify_password(entered):  # pyright: ignore[reportOptionalCall]
            messagebox.showerror("Access Denied", "Incorrect cleanup password.")
            return False
        return True

    # ------------------------------------------------------------------
    # Cleanup execution
    # ------------------------------------------------------------------
    def _run_cleanup(self) -> None:
        if not self._cleanup_enabled:
            return
        # Cleanup for FortiGate via API is not supported
        if self._current_platform == "FortiGate":
            messagebox.showinfo(
                "Not Applicable",
                "API-based cleanup is not supported for FortiGate.\n\n"
                "To remove objects, use the FortiGate web UI or CLI.",
            )
            return

        # --- Password gate ---
        if not self._verify_cleanup_access():
            return

        host = self.cln_host_var.get().strip()
        password = self.cln_pass_var.get()
        is_pa = self._current_platform == "Palo Alto PAN-OS"

        platform_label = "PAN-OS" if is_pa else "FTD"
        if not host:
            messagebox.showerror("Missing Field", f"Please enter the {platform_label} host/IP address.")
            return
        if not password:
            messagebox.showerror("Missing Field", f"Please enter the {platform_label} password.")
            return

        # Credential/host values use the --flag=value form so values starting
        # with '-' aren't mistaken for flags by argparse.
        if is_pa:
            argv = [
                f"--host={host}",
                f"--username={self.cln_user_var.get().strip() or 'admin'}",
                f"--password={password}",
            ]

            if self.cln_dry_var.get():
                argv.append("--dry-run")
            if self.cln_deploy_var.get():
                argv.append("--commit")

            if self.cln_all_var.get():
                argv.append("--delete-all")
            else:
                selected = [k for k, v in self.cln_del_vars.items() if v.get()]
                if not selected:
                    messagebox.showerror(
                        "Nothing Selected",
                        "Please check 'Delete ALL' or select specific object types.",
                    )
                    return
                # Map checkbox keys to the flags panos_api_cleanup.py actually
                # defines. Keys with no PA flag are hidden/unchecked on the
                # PAN-OS layout, so None lookups can't happen here - but skip
                # them defensively anyway.
                for key in selected:
                    flag = CLEANUP_PA_FLAGS.get(key)
                    if flag and flag not in argv:
                        argv.append(flag)

            # Confirm before destructive cleanup
            if not self.cln_dry_var.get():
                if not self._ask_yes_no(
                    "Confirm Cleanup",
                    "This will DELETE objects from the PAN-OS device.\n\n"
                    "Are you sure you want to proceed?\n\n"
                    "(Use 'Dry run' to preview first)",
                ):
                    return

            self._run_in_thread(pa_cleanup_main, argv, self.cln_output, "Cleanup (PAN-OS)")
        else:
            workers = self._validated_workers(self.cln_workers_var.get())
            if workers is None:
                return
            argv = [
                f"--host={host}",
                f"--username={self.cln_user_var.get().strip() or 'admin'}",
                f"--password={password}",
                "--appliance-model", self.cln_model_var.get(),
                "--workers", workers,
                "--yes",  # skip CLI interactive prompt (GUI has its own dialog)
            ]

            if self.cln_dry_var.get():
                argv.append("--dry-run")
            if self.cln_deploy_var.get():
                argv.append("--deploy")

            if self.cln_all_var.get():
                argv.append("--delete-all")
            else:
                selected = [k for k, v in self.cln_del_vars.items() if v.get()]
                if not selected:
                    messagebox.showerror(
                        "Nothing Selected",
                        "Please check 'Delete ALL' or select specific object types.",
                    )
                    return
                for key in selected:
                    flag = CLEANUP_FTD_FLAGS.get(key)
                    if flag:
                        argv.append(flag)

            # Confirm before destructive cleanup
            if not self.cln_dry_var.get():
                if not self._ask_yes_no(
                    "Confirm Cleanup",
                    "This will DELETE objects from the FTD device.\n\n"
                    "Are you sure you want to proceed?\n\n"
                    "(Use 'Dry run' to preview first)",
                ):
                    return

            self._run_in_thread(cleanup_main, argv, self.cln_output, "Cleanup")


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
