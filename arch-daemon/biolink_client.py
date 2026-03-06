#!/usr/bin/env python3
"""
biolink_client.py – PAM exec client for BioLink 4FA
=====================================================

This script is called by ``pam_exec`` during a PAM authentication stack.
It connects to the Unix socket exposed by ``biolink_daemon.py``, requests
an authentication, and exits with code 0 (success) or 1 (failure / timeout).

The daemon performs the full challenge-response cycle against the paired
Android device and signals success or failure back here.

PAM configuration example (see pam-config.example):
    auth required pam_exec.so expose_authtok /usr/bin/biolink-client

Emergency bypass:
    If the daemon is unreachable (phone lost, Bluetooth down, …) the script
    respects the ``BIOLINK_BYPASS_TOKEN`` environment variable: if it is set
    and matches the SHA-256 hash stored in ``/etc/biolink/bypass_hash``, the
    authentication is allowed.  This prevents lockout in emergencies.
    Keep the bypass token secret and stored offline (e.g. printed paper).
"""

import hashlib
import os
import socket
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
SOCKET_PATH      = "/run/biolink/auth.sock"
TIMEOUT_SECONDS  = 35          # Slightly longer than daemon's 30-s challenge timeout
BYPASS_HASH_FILE = "/etc/biolink/bypass_hash"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _notify(message: str):
    """Best-effort desktop notification while running under PAM."""
    import shlex
    uid = os.getuid()
    wayland_display = os.environ.get("WAYLAND_DISPLAY", "wayland-1")
    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{uid}")
    dbus_addr = os.environ.get(
        "DBUS_SESSION_BUS_ADDRESS",
        f"unix:path={xdg_runtime}/bus",
    )
    safe_msg = shlex.quote(message)

    # hyprctl notify (Hyprland)
    os.system(
        f'DISPLAY=:0 WAYLAND_DISPLAY={shlex.quote(wayland_display)} '
        f'hyprctl notify -1 4000 "rgb(00aaff)" "BioLink: {message}" 2>/dev/null || true'
    )
    # fallback: dunstify
    os.system(
        f'DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS={shlex.quote(dbus_addr)} '
        f'dunstify -t 4000 "BioLink 4FA" {safe_msg} 2>/dev/null || true'
    )


def _check_bypass() -> bool:
    """Return True if a valid emergency bypass token is present."""
    token = os.environ.get("BIOLINK_BYPASS_TOKEN", "").strip()
    if not token:
        return False
    hash_file = Path(BYPASS_HASH_FILE)
    if not hash_file.exists():
        return False
    expected = hash_file.read_text().strip().lower()
    actual = hashlib.sha256(token.encode()).hexdigest().lower()
    if actual == expected:
        print("BioLink: emergency bypass accepted", file=sys.stderr)
        return True
    return False


def _request_auth() -> bool:
    """Connect to the daemon socket and wait for auth result."""
    sock_path = SOCKET_PATH
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT_SECONDS)
            s.connect(sock_path)
            response = s.recv(16).decode().strip()
            return response == "OK"
    except FileNotFoundError:
        print(f"BioLink: daemon socket not found at {sock_path}", file=sys.stderr)
        return False
    except socket.timeout:
        print("BioLink: authentication timed out", file=sys.stderr)
        return False
    except Exception as exc:
        print(f"BioLink: socket error – {exc}", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    # 1. Emergency bypass check
    if _check_bypass():
        return 0

    # 2. Notify user that phone auth is in progress
    _notify("Waiting for phone fingerprint…")

    # 3. Request authentication from daemon
    success = _request_auth()

    if success:
        _notify("✓ Authenticated")
        return 0
    else:
        _notify("✗ Authentication failed")
        return 1


if __name__ == "__main__":
    sys.exit(main())
