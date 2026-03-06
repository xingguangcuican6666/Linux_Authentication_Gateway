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
from typing import Optional

# ---------------------------------------------------------------------------
# Optional imports – daemon degrades gracefully if BLE libraries are absent
# so unit tests can import the module without a BlueZ stack.
# ---------------------------------------------------------------------------
try:
    from bless import BlessServer, BlessGATTCharacteristic, GATTCharacteristicProperties, GATTAttributePermissions  # type: ignore
    BLE_AVAILABLE = True
except ImportError:
    BLE_AVAILABLE = False
    logging.warning("bless library not found – BLE peripheral mode disabled")

try:
    import websockets  # type: ignore
    WS_AVAILABLE = True
except ImportError:
    WS_AVAILABLE = False
    logging.warning("websockets library not found – WebSocket fallback disabled")

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
# BLE UUIDs  (must match android/app/src/main/java/com/biolink/auth/Constants.kt)
# ---------------------------------------------------------------------------
SERVICE_UUID        = "12345678-1234-5678-1234-56789abcdef0"
CHALLENGE_CHAR_UUID = "12345678-1234-5678-1234-56789abcdef1"
SIGNATURE_CHAR_UUID = "12345678-1234-5678-1234-56789abcdef2"
PUBKEY_CHAR_UUID    = "12345678-1234-5678-1234-56789abcdef3"

# Client Characteristic Configuration Descriptor UUID
CCCD_UUID = "00002902-0000-1000-8000-00805f9b34fb"

# ---------------------------------------------------------------------------
# Unix domain socket used to communicate with PAM client (biolink_client.py)
# ---------------------------------------------------------------------------
PAM_SOCKET_PATH = "/run/biolink/auth.sock"

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

    def __init__(self, ws_port: int, pubkey_path: str):
        self.ws_port = ws_port
        self.pubkey_path = pubkey_path

        # Loaded public key (cryptography library EC public key object)
        self.public_key = load_public_key(pubkey_path)

        # Current pending authentication context
        self._challenge: Optional[bytes] = None
        self._auth_event: asyncio.Event = asyncio.Event()
        self._auth_result: bool = False

        # BLE GATT server
        self._ble_server: Optional[object] = None

        # Connected WebSocket clients
        self._ws_clients: set = set()

        # Unix-socket PAM listener task
        self._pam_queue: asyncio.Queue = asyncio.Queue()

    # -----------------------------------------------------------------------
    # Entry point
    # -----------------------------------------------------------------------

    async def run(self):
        tasks = [self._pam_server_loop()]
        if BLE_AVAILABLE:
            tasks.append(self._ble_server_loop())
        if WS_AVAILABLE:
            tasks.append(self._ws_server_loop())
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
        Generate a challenge, broadcast it over BLE + WS, wait for a signed
        response, verify, and return True on success.
        """
        challenge = secrets.token_bytes(32)
        self._challenge = challenge
        self._auth_event.clear()
        self._auth_result = False

        log.info("Challenge: %s", challenge.hex())

        # Notify over both channels concurrently
        await asyncio.gather(
            self._ble_send_challenge(challenge),
            self._ws_broadcast_challenge(challenge),
            return_exceptions=True,
        )

        # Wait for the phone to respond (via either channel)
        try:
            await asyncio.wait_for(self._auth_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            log.warning("Authentication timed out after %.0fs", timeout)
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

    # -----------------------------------------------------------------------
    # BLE GATT server (peripheral)
    # -----------------------------------------------------------------------

    async def _ble_server_loop(self):
        if not BLE_AVAILABLE:
            return
        try:
            server = BlessServer(name="BioLink-Arch")
            server.read_request_func = self._ble_read_handler
            server.write_request_func = self._ble_write_handler

            await server.add_gatt(self._build_gatt_dict())
            await server.start()
            self._ble_server = server
            log.info("BLE GATT server started (UUID: %s)", SERVICE_UUID)

            # Keep alive
            await asyncio.Event().wait()
        except Exception as exc:
            log.error("BLE server error: %s", exc)

    def _build_gatt_dict(self) -> dict:
        """Build the GATT service definition for bless."""
        props_indicate = (
            GATTCharacteristicProperties.indicate
        )
        props_write = (
            GATTCharacteristicProperties.write
        )
        props_read_write = (
            GATTCharacteristicProperties.read |
            GATTCharacteristicProperties.write
        )
        perms_rw = (
            GATTAttributePermissions.readable |
            GATTAttributePermissions.writeable
        )
        return {
            SERVICE_UUID: {
                CHALLENGE_CHAR_UUID: {
                    "Properties": props_indicate,
                    "Permissions": GATTAttributePermissions.readable,
                    "Value": bytearray(32),
                    "Descriptors": {
                        CCCD_UUID: {
                            "Properties": (
                                GATTCharacteristicProperties.read |
                                GATTCharacteristicProperties.write
                            ),
                            "Permissions": perms_rw,
                            "Value": bytearray(2),
                        }
                    },
                },
                SIGNATURE_CHAR_UUID: {
                    "Properties": props_write,
                    "Permissions": GATTAttributePermissions.writeable,
                    "Value": None,
                },
                PUBKEY_CHAR_UUID: {
                    "Properties": props_read_write,
                    "Permissions": perms_rw,
                    "Value": bytearray(0),
                },
            }
        }

    def _ble_read_handler(self, characteristic: object, **kwargs) -> bytearray:
        char_uuid = str(getattr(characteristic, "uuid", "")).lower()
        if char_uuid == PUBKEY_CHAR_UUID.lower():
            if self.public_key and CRYPTO_AVAILABLE:
                der = self.public_key.public_bytes(
                    serialization.Encoding.DER,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                return bytearray(der)
        return bytearray(0)

    def _ble_write_handler(self, characteristic: object, value: bytearray, **kwargs):
        char_uuid = str(getattr(characteristic, "uuid", "")).lower()

        if char_uuid == SIGNATURE_CHAR_UUID.lower():
            log.info("BLE: signature received (%d bytes)", len(value))
            self._on_signature_received(bytes(value))

        elif char_uuid == PUBKEY_CHAR_UUID.lower():
            log.info("BLE: public key received (%d bytes) – saving for pairing", len(value))
            if save_public_key(bytes(value), self.pubkey_path):
                self.public_key = load_public_key(self.pubkey_path)

    async def _ble_send_challenge(self, challenge: bytes):
        """Update the challenge characteristic value so connected clients get notified."""
        if not BLE_AVAILABLE or self._ble_server is None:
            return
        try:
            self._ble_server.get_characteristic(CHALLENGE_CHAR_UUID).value = bytearray(challenge)
            await self._ble_server.update_value(SERVICE_UUID, CHALLENGE_CHAR_UUID)
            log.debug("BLE challenge updated")
        except Exception as exc:
            log.warning("BLE challenge send failed: %s", exc)

    # -----------------------------------------------------------------------
    # WebSocket server (LAN fallback)
    # -----------------------------------------------------------------------

    async def _ws_server_loop(self):
        if not WS_AVAILABLE:
            return
        try:
            async with websockets.serve(  # type: ignore[attr-defined]
                self._ws_handler, "0.0.0.0", self.ws_port
            ):
                log.info("WebSocket server listening on port %d", self.ws_port)
                await asyncio.Event().wait()
        except Exception as exc:
            log.error("WebSocket server error: %s", exc)

    async def _ws_handler(self, websocket):
        self._ws_clients.add(websocket)
        log.info("WS client connected: %s", websocket.remote_address)
        try:
            async for raw in websocket:
                try:
                    msg = json.loads(raw)
                except json.JSONDecodeError:
                    await websocket.send(json.dumps({"error": "invalid JSON"}))
                    continue

                msg_type = msg.get("type")
                if msg_type == "signature":
                    sig_hex = msg.get("signature", "")
                    try:
                        sig_bytes = bytes.fromhex(sig_hex)
                    except ValueError:
                        await websocket.send(json.dumps({"error": "invalid hex"}))
                        continue
                    log.info("WS: signature received (%d bytes)", len(sig_bytes))
                    self._on_signature_received(sig_bytes)
                    await websocket.send(json.dumps({"type": "ack"}))

                elif msg_type == "pubkey":
                    pubkey_b64 = msg.get("pubkey", "")
                    try:
                        der_bytes = base64.b64decode(pubkey_b64)
                    except Exception:
                        await websocket.send(json.dumps({"error": "invalid base64"}))
                        continue
                    if save_public_key(der_bytes, self.pubkey_path):
                        self.public_key = load_public_key(self.pubkey_path)
                        await websocket.send(json.dumps({"type": "paired"}))

        except Exception as exc:
            log.warning("WS client error: %s", exc)
        finally:
            self._ws_clients.discard(websocket)
            log.info("WS client disconnected")

    async def _ws_broadcast_challenge(self, challenge: bytes):
        """Send the challenge to all connected WebSocket clients."""
        if not WS_AVAILABLE or not self._ws_clients:
            return
        msg = json.dumps({"type": "challenge", "challenge": challenge.hex()})
        disconnected = set()
        for ws in list(self._ws_clients):
            try:
                await ws.send(msg)
            except Exception:
                disconnected.add(ws)
        self._ws_clients -= disconnected


# ===========================================================================
# CLI entry point
# ===========================================================================

def main():
    parser = argparse.ArgumentParser(description="BioLink 4FA Arch Daemon")
    parser.add_argument(
        "--ws-port", type=int, default=DEFAULT_WS_PORT,
        help=f"WebSocket server port (default: {DEFAULT_WS_PORT})"
    )
    parser.add_argument(
        "--pubkey", default=DEFAULT_PUBKEY_PATH,
        help=f"Path to EC public key PEM file (default: {DEFAULT_PUBKEY_PATH})"
    )
    parser.add_argument(
        "--log-level", default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity"
    )
    args = parser.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    daemon = BioLinkDaemon(ws_port=args.ws_port, pubkey_path=args.pubkey)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, loop.stop)

    try:
        loop.run_until_complete(daemon.run())
    finally:
        loop.close()
        log.info("Daemon stopped")


if __name__ == "__main__":
    main()
