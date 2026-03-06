"""
Tests for biolink_daemon.py – core crypto logic and auth flow.

These tests do NOT require a Bluetooth adapter or network; they use
mocked BLE / WS infrastructure to validate the ECDSA challenge-response
logic and the daemon's state machine.
"""

import asyncio
import base64
import hashlib
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Make sure we can import the daemon module without BlueZ / bless
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Stub out optional heavy dependencies before importing the daemon
sys.modules.setdefault("bless", MagicMock())
sys.modules.setdefault("bleak", MagicMock())
sys.modules.setdefault("websockets", MagicMock())

import biolink_daemon as daemon  # noqa: E402  (after sys.path tweak)


# ===========================================================================
# Helpers
# ===========================================================================

def _generate_test_keypair():
    """Generate a fresh P-256 key pair for testing."""
    from cryptography.hazmat.primitives.asymmetric import ec
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def _sign_challenge(private_key, challenge: bytes) -> bytes:
    """Sign a challenge with the given EC private key (DER-encoded output)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    return private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))


# ===========================================================================
# Test: verify_ecdsa_signature
# ===========================================================================

class TestVerifyEcdsaSignature(unittest.TestCase):

    def setUp(self):
        self.private_key, self.public_key = _generate_test_keypair()
        self.challenge = os.urandom(32)

    def test_valid_signature(self):
        sig = _sign_challenge(self.private_key, self.challenge)
        self.assertTrue(
            daemon.verify_ecdsa_signature(self.public_key, self.challenge, sig)
        )

    def test_wrong_challenge(self):
        sig = _sign_challenge(self.private_key, self.challenge)
        wrong_challenge = os.urandom(32)
        # Ensure we actually have a different challenge
        while wrong_challenge == self.challenge:
            wrong_challenge = os.urandom(32)
        self.assertFalse(
            daemon.verify_ecdsa_signature(self.public_key, wrong_challenge, sig)
        )

    def test_tampered_signature(self):
        sig = bytearray(_sign_challenge(self.private_key, self.challenge))
        sig[-1] ^= 0xFF  # flip last byte
        self.assertFalse(
            daemon.verify_ecdsa_signature(self.public_key, self.challenge, bytes(sig))
        )

    def test_wrong_public_key(self):
        _, other_pub = _generate_test_keypair()
        sig = _sign_challenge(self.private_key, self.challenge)
        self.assertFalse(
            daemon.verify_ecdsa_signature(other_pub, self.challenge, sig)
        )

    def test_none_public_key(self):
        sig = _sign_challenge(self.private_key, self.challenge)
        self.assertFalse(
            daemon.verify_ecdsa_signature(None, self.challenge, sig)
        )


# ===========================================================================
# Test: save_public_key / load_public_key round-trip
# ===========================================================================

class TestPublicKeyPersistence(unittest.TestCase):

    def test_save_and_load_roundtrip(self):
        import tempfile
        priv, pub = _generate_test_keypair()
        from cryptography.hazmat.primitives import serialization
        der = pub.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
            path = f.name
        try:
            daemon.save_public_key(der, path)
            loaded = daemon.load_public_key(path)
            self.assertIsNotNone(loaded)
            # Verify a signature with the loaded key
            challenge = os.urandom(32)
            sig = _sign_challenge(priv, challenge)
            self.assertTrue(daemon.verify_ecdsa_signature(loaded, challenge, sig))
        finally:
            os.unlink(path)

    def test_load_missing_file(self):
        result = daemon.load_public_key("/tmp/definitely_does_not_exist_biolink.pem")
        self.assertIsNone(result)


# ===========================================================================
# Test: BioLinkDaemon._on_signature_received
# ===========================================================================

class TestDaemonSignatureHandling(unittest.TestCase):

    def _make_daemon(self) -> daemon.BioLinkDaemon:
        d = daemon.BioLinkDaemon(ws_port=0, pubkey_path="/dev/null")
        self.private_key, d.public_key = _generate_test_keypair()
        return d

    def test_valid_signature_sets_event(self):
        d = self._make_daemon()
        challenge = os.urandom(32)
        d._challenge = challenge
        d._auth_event.clear()

        sig = _sign_challenge(self.private_key, challenge)
        d._on_signature_received(sig)

        self.assertTrue(d._auth_event.is_set())
        self.assertTrue(d._auth_result)

    def test_invalid_signature_sets_event_but_false(self):
        d = self._make_daemon()
        challenge = os.urandom(32)
        d._challenge = challenge
        d._auth_event.clear()

        bad_sig = os.urandom(64)  # random junk
        d._on_signature_received(bad_sig)

        self.assertTrue(d._auth_event.is_set())
        self.assertFalse(d._auth_result)

    def test_no_pending_challenge_ignored(self):
        d = self._make_daemon()
        d._challenge = None
        d._auth_event.clear()

        sig = _sign_challenge(self.private_key, os.urandom(32))
        d._on_signature_received(sig)

        # Event should NOT be set – nothing to verify against
        self.assertFalse(d._auth_event.is_set())

    def test_duplicate_signature_ignored(self):
        """Second call after event is already set should not change result."""
        d = self._make_daemon()
        challenge = os.urandom(32)
        d._challenge = challenge
        d._auth_event.clear()

        sig = _sign_challenge(self.private_key, challenge)
        d._on_signature_received(sig)
        self.assertTrue(d._auth_result)

        # Simulate a second (bad) signature arriving on the other channel
        d._on_signature_received(b"\x00" * 64)
        # Result should be unchanged
        self.assertTrue(d._auth_result)


# ===========================================================================
# Test: _perform_auth timeout
# ===========================================================================

class TestPerformAuthTimeout(unittest.IsolatedAsyncioTestCase):

    async def test_timeout_returns_false(self):
        d = daemon.BioLinkDaemon(ws_port=0, pubkey_path="/dev/null")

        # Patch out BLE/WS broadcast so we don't need hardware
        async def _noop(c):
            return None

        d._ble_send_challenge = _noop
        d._ws_broadcast_challenge = _noop

        result = await d._perform_auth(timeout=0.05)  # 50ms – phone can't respond
        self.assertFalse(result)


# ===========================================================================
# Test: biolink_client emergency bypass
# ===========================================================================

class TestClientBypass(unittest.TestCase):

    def test_bypass_accepted_with_correct_token(self):
        import tempfile
        import importlib
        import biolink_client as client

        token = "super-secret-emergency-token"
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as f:
            f.write(token_hash + "\n")
            hash_path = f.name

        try:
            with patch.object(client, "BYPASS_HASH_FILE", hash_path):
                with patch.dict(os.environ, {"BIOLINK_BYPASS_TOKEN": token}):
                    self.assertTrue(client._check_bypass())
        finally:
            os.unlink(hash_path)

    def test_bypass_rejected_with_wrong_token(self):
        import tempfile
        import biolink_client as client

        token = "correct-token"
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".hash", delete=False) as f:
            f.write(token_hash + "\n")
            hash_path = f.name

        try:
            with patch.object(client, "BYPASS_HASH_FILE", hash_path):
                with patch.dict(os.environ, {"BIOLINK_BYPASS_TOKEN": "wrong-token"}):
                    self.assertFalse(client._check_bypass())
        finally:
            os.unlink(hash_path)

    def test_bypass_skipped_when_no_token_env(self):
        import biolink_client as client

        env = {k: v for k, v in os.environ.items() if k != "BIOLINK_BYPASS_TOKEN"}
        with patch.dict(os.environ, env, clear=True):
            self.assertFalse(client._check_bypass())


if __name__ == "__main__":
    unittest.main()
