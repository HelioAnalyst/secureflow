"""Optional payload encryption.

Everything written to a public chain is readable by anyone. When a caller asks
for an encrypted attestation, the payload is sealed with AES-256-GCM before it
leaves the service, and only the ciphertext goes on-chain.

Envelope format (stored as the attestation's ``data`` string)::

    sf1:<base64(nonce[12] || ciphertext || tag[16])>

The recipient address is bound in as associated data, so a ciphertext copied
into an attestation for a different recipient fails authentication.

The key comes from ``SECUREFLOW_ENCRYPTION_KEY`` (32 random bytes, base64) and
is never generated implicitly: a key that changed on every restart would make
everything encrypted before the restart unreadable.
"""

from __future__ import annotations

import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "sf1:"
NONCE_BYTES = 12


class CryptoError(ValueError):
    """Bad key, or a ciphertext that fails to decrypt or authenticate."""


def generate_key() -> str:
    """Return a fresh base64-encoded 256-bit key, for putting in .env."""
    return base64.b64encode(os.urandom(32)).decode("ascii")


def is_encrypted(data: str) -> bool:
    return data.startswith(PREFIX)


class PayloadCipher:
    def __init__(self, key_b64: str) -> None:
        try:
            key = base64.b64decode(key_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CryptoError("SECUREFLOW_ENCRYPTION_KEY is not valid base64") from exc
        if len(key) != 32:
            raise CryptoError(f"SECUREFLOW_ENCRYPTION_KEY must decode to 32 bytes, got {len(key)}")
        self._aead = AESGCM(key)

    @staticmethod
    def _aad(recipient: str) -> bytes:
        return recipient.lower().encode("ascii")

    def encrypt(self, plaintext: str, recipient: str) -> str:
        nonce = os.urandom(NONCE_BYTES)
        sealed = self._aead.encrypt(nonce, plaintext.encode("utf-8"), self._aad(recipient))
        return PREFIX + base64.b64encode(nonce + sealed).decode("ascii")

    def decrypt(self, envelope: str, recipient: str) -> str:
        if not is_encrypted(envelope):
            raise CryptoError("not an encrypted payload")
        try:
            raw = base64.b64decode(envelope[len(PREFIX) :], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CryptoError("malformed ciphertext") from exc
        if len(raw) < NONCE_BYTES + 16:
            raise CryptoError("ciphertext too short")
        nonce, sealed = raw[:NONCE_BYTES], raw[NONCE_BYTES:]
        try:
            return self._aead.decrypt(nonce, sealed, self._aad(recipient)).decode("utf-8")
        except InvalidTag as exc:
            raise CryptoError("ciphertext failed authentication (wrong key or recipient)") from exc


if __name__ == "__main__":  # python -m secureflow.crypto
    print(generate_key())
