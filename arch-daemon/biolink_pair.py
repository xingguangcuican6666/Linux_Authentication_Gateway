#!/usr/bin/env python3
"""
biolink_pair.py – One-time pairing helper
==========================================

Reads the Base64-encoded public key from stdin (or --pubkey argument) and
saves it to the configured PEM file so the daemon can start verifying
signatures immediately.

Usage:
    # Paste from app's QR code text field:
    echo "<base64 pubkey>" | python biolink_pair.py

    # Or provide directly:
    python biolink_pair.py --pubkey "<base64 pubkey>"

    # Import from a PEM file exported from the Android app:
    python biolink_pair.py --pem /path/to/pubkey.pem
"""

import argparse
import base64
import sys
from pathlib import Path

DEFAULT_PUBKEY_PATH = "/etc/biolink/pubkey.pem"


def save_from_der(der_bytes: bytes, path: str) -> bool:
    try:
        from cryptography.hazmat.primitives import serialization  # type: ignore
        pub_key = serialization.load_der_public_key(der_bytes)
        pem = pub_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(pem)
        print(f"Public key saved to {path}")
        return True
    except Exception as exc:
        print(f"Error saving public key: {exc}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(description="BioLink one-time pairing tool")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--pubkey", help="Base64-encoded DER public key")
    group.add_argument("--pem", help="Path to existing PEM public key file")
    parser.add_argument(
        "--output", default=DEFAULT_PUBKEY_PATH,
        help=f"Output PEM path (default: {DEFAULT_PUBKEY_PATH})"
    )
    args = parser.parse_args()

    if args.pem:
        pem_bytes = Path(args.pem).read_bytes()
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_bytes(pem_bytes)
        print(f"PEM copied to {args.output}")
        return

    if args.pubkey:
        b64 = args.pubkey.strip()
    else:
        print("Paste the Base64 public key from the BioLink app, press Enter, then press Ctrl-D on a new line:")
        b64 = sys.stdin.read().strip()

    try:
        der_bytes = base64.b64decode(b64)
    except Exception as exc:
        print(f"Invalid Base64: {exc}", file=sys.stderr)
        sys.exit(1)

    if not save_from_der(der_bytes, args.output):
        sys.exit(1)


if __name__ == "__main__":
    main()
