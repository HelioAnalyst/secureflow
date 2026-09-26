"""API-key authentication for write endpoints.

Reads (verify, list, health) are public: anyone should be able to check an
attestation. Issuing and revoking spend gas and speak for the issuer, so they
need a key.

Keys are never stored. ``SECUREFLOW_API_KEYS`` holds ``name:sha256hex`` pairs,
and the server hashes each presented key and compares it in constant time.

    python -m secureflow.auth ci-bot
    # key:  sf_live_...   (give this to the client)
    # env:  ci-bot:5d41...  (append to SECUREFLOW_API_KEYS)
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sys
from dataclasses import dataclass

KEY_PREFIX = "sf_"
_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class AuthConfigError(ValueError):
    pass


@dataclass(frozen=True)
class Principal:
    """Who made the request. ``anonymous`` only exists when auth is disabled."""

    name: str


ANONYMOUS = Principal("anonymous")


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_key() -> str:
    return KEY_PREFIX + secrets.token_urlsafe(32)


def parse_key_hashes(spec: str | None) -> dict[str, str]:
    """Parse ``name:hash,name:hash`` into {hash: name}."""
    out: dict[str, str] = {}
    for entry in filter(None, (part.strip() for part in (spec or "").split(","))):
        name, sep, digest = entry.partition(":")
        digest = digest.strip().lower()
        if not sep or not _NAME.match(name) or not _HEX64.match(digest):
            raise AuthConfigError(f"bad SECUREFLOW_API_KEYS entry {entry[:20]!r}: expected name:sha256hex")
        out[digest] = name
    return out


class KeyRing:
    def __init__(self, hashes: dict[str, str]) -> None:
        self._hashes = hashes

    @classmethod
    def from_keys(cls, **named_keys: str) -> KeyRing:
        """Convenience for tests and the demo: pass raw keys by name."""
        return cls({hash_key(k): name for name, k in named_keys.items()})

    @property
    def enabled(self) -> bool:
        return bool(self._hashes)

    def authenticate(self, presented: str | None) -> Principal | None:
        if not self.enabled:
            return ANONYMOUS
        if not presented:
            return None
        digest = hash_key(presented)
        match = None
        for known, name in self._hashes.items():  # no early exit: timing does not reveal which entry matched
            if hmac.compare_digest(known, digest):
                match = name
        return Principal(match) if match else None


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    name = args[0] if args else "default"
    if not _NAME.match(name):
        raise SystemExit("name must be 1-64 characters of A-Z a-z 0-9 _ . -")
    key = generate_key()
    print(f"key:  {key}")
    print(f"env:  {name}:{hash_key(key)}")


if __name__ == "__main__":  # python -m secureflow.auth [name]
    main()
