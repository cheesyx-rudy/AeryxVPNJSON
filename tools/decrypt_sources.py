from __future__ import annotations

import argparse
import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"AERYX-SOURCES-V1\n"
NONCE_SIZE = 12
KEY_ENV = "SOURCE_DECRYPTION_KEY"


def load_key() -> bytes:
    encoded = os.environ.get(KEY_ENV, "").strip()
    if not encoded:
        raise SystemExit(f"{KEY_ENV} is not configured")
    try:
        key = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise SystemExit(f"{KEY_ENV} must be a valid base64-encoded 32-byte key") from exc
    if len(key) != 32:
        raise SystemExit(f"{KEY_ENV} must decode to exactly 32 bytes")
    return key


def main() -> int:
    parser = argparse.ArgumentParser(description="Decrypt the AeryxVPN source list for the parser run.")
    parser.add_argument("--input", type=Path, default=Path("sources.enc"))
    parser.add_argument("--output", type=Path, default=Path("sources.txt"))
    args = parser.parse_args()

    if not args.input.is_file():
        raise SystemExit(f"Encrypted source file not found: {args.input}")

    payload = args.input.read_bytes()
    header_size = len(MAGIC)
    if not payload.startswith(MAGIC) or len(payload) <= header_size + NONCE_SIZE:
        raise SystemExit("Encrypted source file has an unsupported or incomplete format")

    nonce = payload[header_size : header_size + NONCE_SIZE]
    ciphertext = payload[header_size + NONCE_SIZE :]
    try:
        plaintext = AESGCM(load_key()).decrypt(nonce, ciphertext, MAGIC)
    except Exception as exc:
        raise SystemExit("Source-list decryption failed: invalid key or corrupted file") from exc

    if not plaintext.strip():
        raise SystemExit("Decrypted source list is empty; refusing to continue")

    args.output.write_bytes(plaintext)
    try:
        args.output.chmod(0o600)
    except OSError:
        pass
    print("Private source list decrypted for this workflow run.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
