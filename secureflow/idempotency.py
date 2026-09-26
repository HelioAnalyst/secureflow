"""Idempotency keys for write endpoints.

Issuing an attestation is a blockchain transaction: it costs gas and cannot
be undone. If a client times out and retries, it must not create a second
attestation. Clients send ``Idempotency-Key: <unique string>``.

State machine for one (client, key)::

    (none) --begin--> pending --submitted(tx_hash)--> pending+tx --complete--> done
                         |                               |
                         +--release (failed before       +--(retry) resolve tx_hash on-chain:
                             broadcast)                       mined     -> complete, replay
                                                              not found -> 409 until stale,
                                                                           then retake

* retry of a ``done`` key with the same body replays the stored response
* same key with a different body is rejected (422)
* ``pending`` without a tx hash means the first request is still before
  broadcast: 409, unless it is older than ``stale_seconds`` (the process
  probably died), in which case the retry takes the key over
* ``pending`` with a tx hash means the transaction may be on-chain, so the
  caller must look it up by hash rather than send a new one

The tx hash is recorded *before* broadcast, so even a crash between
broadcast and completion can be resolved on the next retry.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .db import Database

MAX_KEY_LENGTH = 255


class IdempotencyConflict(Exception):
    """A request with this key is still being processed."""


class IdempotencyMismatch(Exception):
    """This key was already used with a different request body."""


@dataclass(frozen=True)
class Proceed:
    """The caller owns the key and should perform the operation."""


@dataclass(frozen=True)
class Replay:
    status_code: int
    body: Any


@dataclass(frozen=True)
class InDoubt:
    """A transaction was submitted under this key; resolve it by hash."""

    tx_hash: str
    stale: bool


BeginResult = Proceed | Replay | InDoubt


def fingerprint(method: str, path: str, payload: Any) -> str:
    canonical = json.dumps([method, path, payload], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


class IdempotencyStore:
    def __init__(
        self,
        db: Database,
        ttl_seconds: int = 24 * 3600,
        stale_seconds: int = 600,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._db = db
        self._ttl = ttl_seconds
        self._stale = stale_seconds
        self._clock = clock

    def begin(self, scope: str, key: str, fp: str) -> BeginResult:
        now = int(self._clock())
        with self._db.transaction() as conn:
            conn.execute("DELETE FROM idempotency WHERE created_at < ?", (now - self._ttl,))
            row = conn.execute(
                "SELECT fingerprint, state, tx_hash, status_code, body, created_at"
                " FROM idempotency WHERE scope = ? AND key = ?",
                (scope, key),
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO idempotency (scope, key, fingerprint, state, created_at)"
                    " VALUES (?, ?, ?, 'pending', ?)",
                    (scope, key, fp, now),
                )
                return Proceed()
            if row["fingerprint"] != fp:
                raise IdempotencyMismatch(key)
            if row["state"] == "done":
                return Replay(row["status_code"], json.loads(row["body"]))
            stale = now - row["created_at"] > self._stale
            if row["tx_hash"]:
                return InDoubt(row["tx_hash"], stale)
            if not stale:
                raise IdempotencyConflict(key)
            # Stuck before broadcast (the process likely died): take the key over.
            conn.execute(
                "UPDATE idempotency SET created_at = ? WHERE scope = ? AND key = ?",
                (now, scope, key),
            )
            return Proceed()

    def submitted(self, scope: str, key: str, tx_hash: str) -> None:
        """Record the signed transaction's hash just before it is broadcast."""
        with self._db.transaction() as conn:
            conn.execute(
                "UPDATE idempotency SET tx_hash = ? WHERE scope = ? AND key = ? AND state = 'pending'",
                (tx_hash, scope, key),
            )

    def retake(self, scope: str, key: str) -> None:
        """Forget a submitted-but-never-mined transaction so the operation can run again."""
        with self._db.transaction() as conn:
            conn.execute(
                "UPDATE idempotency SET tx_hash = NULL, created_at = ?"
                " WHERE scope = ? AND key = ? AND state = 'pending'",
                (int(self._clock()), scope, key),
            )

    def complete(self, scope: str, key: str, status_code: int, body: Any) -> None:
        with self._db.transaction() as conn:
            conn.execute(
                "UPDATE idempotency SET state = 'done', status_code = ?, body = ? WHERE scope = ? AND key = ?",
                (status_code, json.dumps(body), scope, key),
            )

    def release(self, scope: str, key: str) -> None:
        """Drop a pending key after a failure that definitely sent nothing."""
        with self._db.transaction() as conn:
            conn.execute("DELETE FROM idempotency WHERE scope = ? AND key = ? AND state = 'pending'", (scope, key))
