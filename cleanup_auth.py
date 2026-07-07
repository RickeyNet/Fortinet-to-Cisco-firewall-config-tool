#!/usr/bin/env python3
"""
Cleanup Authentication Module
===============================
Manages a hashed password that gates access to the Cleanup tab.

Password resolution order:
    1. ``cleanup_auth.json`` next to the app (user-changed password)
    2. Built-in default hash (baked into this source file)

If the user changes the password, a JSON file is created.  If that file
is deleted, the built-in default is used automatically - users are
never locked out.

Uses PBKDF2-HMAC-SHA256 (standard library only - no third-party deps)
with a random 16-byte salt and 600 000 iterations.  Only the hash is
stored, so the original password cannot be recovered.

To change the built-in default, run:
    python set_cleanup_password.py <new-password>
"""

import hashlib
import hmac
import json
import os
import sys

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
if getattr(sys, "frozen", False):
    _APP_DIR = os.path.dirname(sys.executable)
else:
    _APP_DIR = os.path.dirname(os.path.abspath(__file__))

_AUTH_FILE = os.path.join(_APP_DIR, "cleanup_auth.json")

_ITERATIONS = 600_000
_HASH_LEN = 32  # bytes

# ---------------------------------------------------------------------------
# Built-in default password hash  (set via set_cleanup_password.py)
# ---------------------------------------------------------------------------
_DEFAULT_SALT = "0bf3eb4f96e174824d2e704f9859d9aa"
_DEFAULT_HASH = "5238d7dc32b0ab68aeb86c15f5391b909292b6817c449a30ad513b4350395c70"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _hash_password(plaintext: str, salt: bytes) -> str:
    """Return the hex-encoded PBKDF2-HMAC-SHA256 hash of *plaintext*."""
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        plaintext.encode("utf-8"),
        salt,
        _ITERATIONS,
        dklen=_HASH_LEN,
    )
    return dk.hex()


def _load_credentials() -> tuple[str, str]:
    """Return (salt_hex, hash_hex) from the JSON file or the built-in default."""
    if os.path.isfile(_AUTH_FILE):
        try:
            with open(_AUTH_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data["salt"], data["hash"]
        except (KeyError, ValueError, json.JSONDecodeError):
            pass  # fall through to default
    return _DEFAULT_SALT, _DEFAULT_HASH


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def is_password_set() -> bool:
    """Return True if a cleanup password is available (always True now)."""
    return True


def has_custom_password() -> bool:
    """Return True if the user has set a custom password (JSON file exists)."""
    return os.path.isfile(_AUTH_FILE)


def set_password(plaintext: str) -> None:
    """Hash *plaintext* and save it to the JSON override file."""
    salt = os.urandom(16)
    pw_hash = _hash_password(plaintext, salt)

    data = {
        "salt": salt.hex(),
        "hash": pw_hash,
    }
    with open(_AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def verify_password(plaintext: str) -> bool:
    """Return True if *plaintext* matches the active password hash.

    Checks the JSON override first, then falls back to the built-in default.
    """
    salt_hex, expected_hash = _load_credentials()
    try:
        salt = bytes.fromhex(salt_hex)
    except (TypeError, ValueError):
        return False  # corrupt override file (salt not a hex string)
    # Constant-time comparison - avoids leaking hash prefixes via timing.
    try:
        return hmac.compare_digest(_hash_password(plaintext, salt), expected_hash)
    except TypeError:
        return False  # corrupt override file (hash not an ASCII hex string)


def reset_to_default() -> None:
    """Remove the JSON override, reverting to the built-in default password."""
    if os.path.isfile(_AUTH_FILE):
        os.remove(_AUTH_FILE)
