"""A small SQLite wrapper shared by the index and the idempotency store.

SQLite keeps the service single-binary: no extra container, and ``:memory:``
(the default) means tests and the mock demo leave nothing on disk. Point
``SECUREFLOW_DB`` at a file to keep the index and idempotency records across
restarts.
"""

from __future__ import annotations

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attestations (
    uid          TEXT PRIMARY KEY,
    issuer       TEXT NOT NULL,
    recipient    TEXT NOT NULL,
    data         TEXT NOT NULL,
    block_number INTEGER NOT NULL,
    log_index    INTEGER NOT NULL,
    timestamp    INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL DEFAULT 0,
    revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_att_position  ON attestations (block_number DESC, log_index DESC);
CREATE INDEX IF NOT EXISTS ix_att_issuer    ON attestations (issuer, block_number DESC, log_index DESC);
CREATE INDEX IF NOT EXISTS ix_att_recipient ON attestations (recipient, block_number DESC, log_index DESC);

CREATE TABLE IF NOT EXISTS idempotency (
    scope        TEXT NOT NULL,
    key          TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    state        TEXT NOT NULL CHECK (state IN ('pending', 'done')),
    tx_hash      TEXT,
    status_code  INTEGER,
    body         TEXT,
    created_at   INTEGER NOT NULL,
    PRIMARY KEY (scope, key)
);

-- Which API client issued each attestation through this service.
CREATE TABLE IF NOT EXISTS owners (
    uid        TEXT PRIMARY KEY,
    principal  TEXT NOT NULL
);
"""

# Tables that describe one particular chain history; wiped when the chain changes.
CHAIN_SCOPED_TABLES = ("attestations", "idempotency", "owners")


class Database:
    """One connection, serialised by a lock.

    FastAPI runs sync endpoints on a thread pool, so the connection is opened
    with ``check_same_thread=False`` and every access goes through
    :meth:`transaction`, which holds the lock and commits or rolls back.
    """

    def __init__(self, path: str = ":memory:") -> None:
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            if path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.executescript(SCHEMA)

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    def bind_identity(self, identity: str) -> bool:
        """Record which chain this database describes; wipe chain-scoped data if it changed.

        Returns True if data was wiped.
        """
        with self.transaction() as conn:
            row = conn.execute("SELECT value FROM meta WHERE key = 'identity'").fetchone()
            if row is not None and row["value"] == identity:
                return False
            for table in CHAIN_SCOPED_TABLES:
                conn.execute(f"DELETE FROM {table}")  # noqa: S608 - fixed table names
            conn.execute("DELETE FROM meta WHERE key = 'synced_to'")
            conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('identity', ?)", (identity,))
            return row is not None

    def set_owner(self, uid: str, principal: str) -> None:
        with self.transaction() as conn:
            conn.execute("INSERT OR REPLACE INTO owners (uid, principal) VALUES (?, ?)", (uid.lower(), principal))

    def get_owner(self, uid: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT principal FROM owners WHERE uid = ?", (uid.lower(),)).fetchone()
        return None if row is None else str(row["principal"])

    def get_meta(self, key: str) -> str | None:
        with self._lock:
            row = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row["value"])

    def close(self) -> None:
        with self._lock:
            self._conn.close()
