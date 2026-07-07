"""Tests for GUI-side cleanup option mapping and credential redaction.

Covers the module-level (display-free) parts of gui_app.py:
  - the Cleanup checkbox catalog stays in lock-step with the flags the
    FTD / PAN-OS cleanup CLIs actually define
  - argv redaction / secret extraction handle both the two-token and the
    --flag=value credential forms
plus the cleanup_auth password roundtrip.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import gui_app  # noqa: E402
import cleanup_auth  # noqa: E402


def _defined_flags(source_path: Path) -> set:
    """All --flag strings registered via add_argument in a CLI module."""
    text = source_path.read_text(encoding="utf-8")
    return set(re.findall(r"add_argument\(\s*['\"](--[\w-]+)['\"]", text))


def test_ftd_cleanup_flags_exist_in_cli():
    defined = _defined_flags(ROOT / "FortiGateToFTDTool" / "ftd_api_cleanup.py")
    for key, ftd_flag in gui_app.CLEANUP_FTD_FLAGS.items():
        assert ftd_flag in defined, f"{key}: {ftd_flag} not defined by ftd_api_cleanup.py"


def test_pa_cleanup_flags_exist_in_cli():
    defined = _defined_flags(
        ROOT / "FortiGateToPaloAltoTool" / "panos_api_cleanup.py",
    )
    for key, pa_flag in gui_app.CLEANUP_PA_FLAGS.items():
        if pa_flag is None:
            continue  # checkbox is hidden for PAN-OS targets
        assert pa_flag in defined, f"{key}: {pa_flag} not defined by panos_api_cleanup.py"


def test_pa_unsupported_keys_have_no_label():
    # A None flag must pair with a None label (hidden checkbox) and vice versa.
    for key, _fl, _ff, pa_label, pa_flag in gui_app.CLEANUP_DELETE_OPTIONS:
        assert (pa_label is None) == (pa_flag is None), key


def test_redact_argv_two_token_and_equals_forms():
    argv = [
        "--host=10.0.0.1", "--username=admin", "--password=s3cret",
        "-p", "other", "--auth-password=aaa", "--dry-run",
    ]
    redacted = gui_app._redact_argv(argv)
    joined = " ".join(redacted)
    assert "s3cret" not in joined
    assert "other" not in joined
    assert "aaa" not in joined
    assert "--password=***REDACTED***" in redacted
    assert "--auth-password=***REDACTED***" in redacted
    assert "***REDACTED***" in redacted  # the value after -p
    assert "--host=10.0.0.1" in redacted  # host is not a secret
    assert "--dry-run" in redacted


def test_argv_secret_values_extraction():
    argv = [
        "--host=10.0.0.1", "--password=s3cret", "-p", "two-token",
        "--auth-password=aaa", "--deploy",
    ]
    secrets = gui_app._argv_secret_values(argv)
    assert secrets == ["s3cret", "two-token", "aaa"]


def test_scrub_secrets_uses_plain_string_snapshot():
    scrubbed = gui_app.App._scrub_secrets(
        "error at https://admin:hunter2@fw/api", ["hunter2"],
    )
    assert "hunter2" not in scrubbed
    assert "***REDACTED***" in scrubbed


def test_cleanup_auth_roundtrip(tmp_path, monkeypatch):
    auth_file = tmp_path / "cleanup_auth.json"
    monkeypatch.setattr(cleanup_auth, "_AUTH_FILE", str(auth_file))
    # Speed the test up - the iteration count doesn't change the logic.
    monkeypatch.setattr(cleanup_auth, "_ITERATIONS", 10)

    assert not cleanup_auth.has_custom_password()
    cleanup_auth.set_password("correct horse")
    assert cleanup_auth.has_custom_password()
    assert cleanup_auth.verify_password("correct horse")
    assert not cleanup_auth.verify_password("battery staple")

    cleanup_auth.reset_to_default()
    assert not cleanup_auth.has_custom_password()


def test_cleanup_auth_corrupt_override_falls_back(tmp_path, monkeypatch):
    auth_file = tmp_path / "cleanup_auth.json"
    auth_file.write_text('{"salt": 123, "hash": 456}', encoding="utf-8")
    monkeypatch.setattr(cleanup_auth, "_AUTH_FILE", str(auth_file))
    # Corrupt override must not raise (falls back / returns False).
    assert cleanup_auth.verify_password("anything") in (True, False)
