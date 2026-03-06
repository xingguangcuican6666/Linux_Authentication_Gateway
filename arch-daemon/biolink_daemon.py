#!/usr/bin/env python3
"""
biolink_daemon.py – Arch Linux BLE Peripheral + WebSocket Auth Daemon
======================================================================

This daemon acts as the **GATT server** (peripheral / advertiser) side of the
BioLink 4FA system.  It:

  1. Advertises a BLE GATT service with UUID ``12345678-1234-5678-1234-56789abcdef0``.
  2. When a PAM authentication is triggered (via ``biolink_client.py``) it:
       a. Generates a fresh 32-byte random challenge.
       b. Writes the challenge to the BLE challenge characteristic so the
          paired Android device receives it via a GATT indication.
       c. Simultaneously sends the same challenge over a WebSocket channel as
          a JSON message (race / dual-link: whichever channel wins is used).
  3. Receives the ECDSA signature written back by the Android app.
  4. Verifies the signature against the stored public key.
  5. Signals success / failure back to ``biolink_client.py`` via a Unix domain
     socket so PAM can accept or reject the login.

Dependencies (install via pip):
    bleak>=0.21.1      – BLE Central/Peripheral (Linux uses BlueZ backend)
    bless>=0.2         – BLE GATT server (peripheral) built on BlueZ/D-Bus
    cryptography>=42   – ECDSA verification (P-256 / SHA-256)
    websockets>=12     – WebSocket server for the LAN fallback channel

Usage:
    python biolink_daemon.py [--ws-port 7777] [--pubkey /etc/biolink/pubkey.pem]

Run as a systemd service (see biolink.service).
"""

import argparse
import asyncio
import base64
import json
import logging
import os
import secrets
import signal
import socket
import struct
import sys
import time
from pathlib import Path
import subprocess
from typing import Optional

# ---------------------------------------------------------------------------
# Optional imports – daemon degrades gracefully if BLE libraries are absent
# so unit tests can import the module without a BlueZ stack.
# ---------------------------------------------------------------------------


try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    from cryptography.exceptions import InvalidSignature
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    logging.error("cryptography library not found – cannot verify signatures!")



# ---------------------------------------------------------------------------
# Unix domain socket used to communicate with PAM client (biolink_client.py)
# ---------------------------------------------------------------------------
PAM_SOCKET_PATH = "/run/biolink/.android/auth.sock"

# ---------------------------------------------------------------------------
# Default paths
# ---------------------------------------------------------------------------
DEFAULT_PUBKEY_PATH = "/etc/biolink/pubkey.pem"
DEFAULT_WS_PORT     = 7777

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("biolink.daemon")

ADB_TIMEOUT = 30.0 # Timeout for ADB operations
ADB_APP_PACKAGE = "com.biolink.adbauth"
ADB_AUTH_ACTIVITY = f"{ADB_APP_PACKAGE}.AdbAuthActivity"
ADB_RESULT_FILE = f"/data/data/{ADB_APP_PACKAGE}/cache/adb_auth_result.txt"
ADB_PUBKEY_FILE = f"/data/data/{ADB_APP_PACKAGE}/cache/adb_pubkey.txt"
EXTRA_CHALLENGE = "challenge"

async def _run_adb_command(args: list[str], timeout: float = ADB_TIMEOUT) -> str:
    """Run an ADB command and return its stdout, or raise an exception on error."""
    cmd = ["adb"] + args
    log.debug("Running ADB command: %s", " ".join(cmd))
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        if proc.returncode != 0:
            error_msg = f"ADB command failed with exit code {proc.returncode}: {stderr.decode().strip()}"
            log.error(error_msg)
            raise RuntimeError(error_msg)

        output = stdout.decode().strip()
        log.debug("ADB command output: %s", output)
        return output
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        error_msg = f"ADB command timed out after {timeout} seconds: {' '.join(cmd)}"
        log.error(error_msg)
        raise RuntimeError(error_msg)
    except FileNotFoundError:
        error_msg = "ADB command not found. Is ADB installed and in PATH?"
        log.error(error_msg)
        raise RuntimeError(error_msg)
    except Exception as exc:
        error_msg = f"Error running ADB command {' '.join(cmd)}: {exc}"
        log.error(error_msg)
        raise RuntimeError(error_msg)

# ===========================================================================
# Public-key management
# ===========================================================================

def load_public_key(path: str):
    """Load an EC public key from a PEM file.  Returns None if file missing."""
    if not CRYPTO_AVAILABLE:
        return None
    p = Path(path)
    if not p.exists():
        log.warning("Public key file not found: %s", path)
        return None
    try:
        pub_key = serialization.load_pem_public_key(p.read_bytes())
        log.info("Public key loaded from %s", path)
        return pub_key
    except Exception as exc:
        log.error("Failed to load public key: %s", exc)
        return None


def save_public_key(der_bytes: bytes, path: str) -> bool:
    """Save a DER-encoded EC public key (X.509 SubjectPublicKeyInfo) as PEM."""
    if not CRYPTO_AVAILABLE:
        return False
    try:
        pub_key = serialization.load_der_public_key(der_bytes)
        pem = pub_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(pem)
        log.info("Public key saved to %s (%d bytes DER)", path, len(der_bytes))
        return True
    except Exception as exc:
        log.error("Failed to save public key: %s", exc)
        return False


def verify_ecdsa_signature(public_key, challenge: bytes, signature_der: bytes) -> bool:
    """Return True iff the DER-encoded ECDSA signature is valid over challenge."""
    if not CRYPTO_AVAILABLE or public_key is None:
        log.error("Crypto unavailable or no public key – rejecting")
        return False
    try:
        public_key.verify(signature_der, challenge, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        log.warning("Signature verification FAILED")
        return False
    except Exception as exc:
        log.error("Unexpected error during verification: %s", exc)
        return False


# ===========================================================================
# BioLink Daemon
# ===========================================================================

class BioLinkDaemon:
    """Coordinates BLE GATT server + WebSocket server for 4FA authentication."""

    def __init__(self, pubkey_path: str):
        self.pubkey_path = pubkey_path

        # Loaded public key (cryptography library EC public key object)
        self.public_key = load_public_key(pubkey_path)

        # Current pending authentication context
        self._challenge: Optional[bytes] = None
        self._auth_event: asyncio.Event = asyncio.Event()
        self._auth_result: bool = False

        # Unix-socket PAM listener task
        self._pam_queue: asyncio.Queue = asyncio.Queue()

    # -----------------------------------------------------------------------
    # Entry point
    # -----------------------------------------------------------------------

    async def run(self):
        tasks = [self._pam_server_loop()]
        await asyncio.gather(*tasks)

    # -----------------------------------------------------------------------
    # PAM server – listens on a Unix domain socket for auth requests
    # -----------------------------------------------------------------------

    async def _pam_server_loop(self):
        sock_path = Path(PAM_SOCKET_PATH)
        sock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if sock_path.exists():
            sock_path.unlink()

        server = await asyncio.start_unix_server(
            self._handle_pam_client, path=str(sock_path)
        )
        os.chmod(str(sock_path), 0o600)
        log.info("PAM socket listening on %s", sock_path)
        async with server:
            await server.serve_forever()

    async def _handle_pam_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """Handle a single PAM authentication request."""
        try:
            log.info("PAM auth request received")
            result = await self._perform_auth()
            writer.write(b"OK\n" if result else b"FAIL\n")
            await writer.drain()
        except Exception as exc:
            log.error("PAM handler error: %s", exc)
            writer.write(b"FAIL\n")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    # -----------------------------------------------------------------------
    # Core authentication flow
    # -----------------------------------------------------------------------

    async def _perform_auth(self, timeout: float = 30.0) -> bool:
        """
        Generate a challenge, send it to the Android device via ADB,
        wait for a signed response, verify, and return True on success.
        """
        challenge = secrets.token_bytes(32)
        self._challenge = challenge
        self._auth_event.clear()
        self._auth_result = False

        log.info("Challenge: %s", challenge.hex())

        # Send challenge to Android device via ADB
        try:
            # Clear previous result file
            await _run_adb_command(["shell", "rm", "-f", ADB_RESULT_FILE])

            # Launch AdbAuthActivity with challenge (Base64 encoded)
            challenge_b64 = base64.b64encode(challenge).decode('utf-8') # Ensure utf-8 encoding
            await _run_adb_command([
                "shell", "am", "start", "-n", ADB_AUTH_ACTIVITY,
                "-a", f"{ADB_APP_PACKAGE}.ACTION_AUTH",
                "--es", EXTRA_CHALLENGE, challenge_b64 # Pass as key-value string
            ], timeout=5.0) # Short timeout for launching activity

            # Wait for the phone to write the result file (and user to authenticate)
            # We poll for the file existence/content
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    await _run_adb_command(["shell", "test", "-f", ADB_RESULT_FILE])
                    # If test -f succeeds, file exists, pull it
                    break
                except RuntimeError:
                    # File not yet present, wait and retry
                    await asyncio.sleep(0.5)
            else:
                log.warning("Authentication timed out: result file not created.")
                return False

            # Pull result file
            local_result_path = Path("/tmp") / f"adb_auth_result_{os.getpid()}.txt"
            try:
                await _run_adb_command(["pull", ADB_RESULT_FILE, str(local_result_path)])
                result_content = local_result_path.read_text().strip()
                local_result_path.unlink() # Clean up

                if result_content.startswith("OK"):
                    # Format: "OK<base64_signature>"
                    parts = result_content.split("OK", 1)
                    if len(parts) > 1 and parts[1]:
                        signature_b64 = parts[1]
                        signature_der = base64.b64decode(signature_b64)
                        self._on_signature_received(signature_der)
                    else:
                        log.error("ADB result malformed: %s", result_content)
                        return False
                else:
                    log.warning("Authentication failed on device: %s", result_content)
                    return False
            except Exception as exc:
                log.error("Failed to retrieve or parse ADB result: %s", exc)
                return False

        except RuntimeError as e:
            log.error("ADB authentication failed: %s", e)
            return False
        except asyncio.TimeoutError:
            log.warning("ADB operation timed out during authentication.")
            return False
        except Exception as e:
            log.error("Unexpected error during ADB authentication: %s", e)
            return False

        return self._auth_result

    def _on_signature_received(self, signature_der: bytes):
        """Called when the Android app writes a signature (via BLE or WS)."""
        if self._challenge is None:
            log.warning("Signature received but no pending challenge")
            return
        if self._auth_event.is_set():
            log.debug("Duplicate signature ignored")
            return

        ok = verify_ecdsa_signature(self.public_key, self._challenge, signature_der)
        log.info("Signature valid: %s", ok)
        self._auth_result = ok
        self._auth_event.set()

    async def get_public_key_from_device(self) -> bytes:
        """Retrieve public key from Android device via ADB and return its DER bytes."""
        log.info("Requesting public key from Android device...")
        try:
            # Clear previous pubkey file
            await _run_adb_command(["shell", "rm", "-f", ADB_PUBKEY_FILE])

            # Launch AdbAuthActivity with GET_PUBKEY action
            await _run_adb_command([
                "shell", "am", "start", "-n", ADB_AUTH_ACTIVITY,
                "-a", f"{ADB_APP_PACKAGE}.ACTION_GET_PUBKEY",
            ], timeout=5.0)

            # Wait for the phone to write the pubkey file
            start_time = time.time()
            timeout = 10.0 # Shorter timeout for pubkey retrieval
            while time.time() - start_time < timeout:
                try:
                    await _run_adb_command(["shell", "test", "-f", ADB_PUBKEY_FILE])
                    break
                except RuntimeError:
                    await asyncio.sleep(0.5)
            else:
                raise RuntimeError("Timeout waiting for public key file.")

            # Pull pubkey file
            local_pubkey_path = Path("/tmp") / f"adb_pubkey_{os.getpid()}.txt"
            try:
                await _run_adb_command(["pull", ADB_PUBKEY_FILE, str(local_pubkey_path)])
                result_content = local_pubkey_path.read_text().strip()
                local_pubkey_path.unlink()

                if result_content.startswith("OK"):
                    parts = result_content.split("OK", 1)
                    if len(parts) > 1 and parts[1]:
                        pubkey_b64 = parts[1]
                        return base64.b64decode(pubkey_b64)
                    else:
                        raise RuntimeError(f"ADB public key result malformed: {result_content}")
                else:
                    raise RuntimeError(f"Failed to retrieve public key from device: {result_content}")
            except Exception as exc:
                raise RuntimeError(f"Failed to retrieve or parse ADB public key: {exc}")

        except Exception as e:
            log.error("ADB public key retrieval failed: %s", e)
            raise




# ===========================================================================
# CLI entry point
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(description="BioLink 4FA Arch Daemon")
    parser.add_argument(
        "--pubkey", default=DEFAULT_PUBKEY_PATH,
        help=f"Path to EC public key PEM file (default: {DEFAULT_PUBKEY_PATH})"
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity"
    )
    parser.add_argument(
        "--pair", action="store_true",
        help="Retrieve public key from paired Android device via ADB and save it."
    )
    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    daemon = BioLinkDaemon(pubkey_path=args.pubkey)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # If --pair is set, trigger pairing and exit
    if args.pair:
        log.info("Starting ADB pairing process...")
        try:
            pub_key_der = loop.run_until_complete(daemon.get_public_key_from_device())
            if save_public_key(pub_key_der, args.pubkey):
                log.info("Public key successfully retrieved and saved for pairing.")
                sys.exit(0)
            else:
                log.error("Failed to save public key after retrieval.")
                sys.exit(1)
        except Exception as e:
            log.error("ADB pairing failed: %s", e)
            sys.exit(1)

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, loop.stop)

    try:
        loop.run_until_complete(daemon.run())
    finally:
        loop.close()
        log.info("Daemon stopped")


if __name__ == "__main__":
    main()
