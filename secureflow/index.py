"""Event indexer: mirrors contract events into SQLite so lists are cheap.

Why: listing straight from ``eth_getLogs`` means one full scan plus one
``eth_call`` per row on every request, and public RPC providers cap the
block range a single ``eth_getLogs`` may cover. The index syncs forward in
bounded chunks, remembers how far it got, and answers list queries with an
indexed SQL query and keyset pagination.

Consistency model
-----------------
* ``GET /attestations/{uid}`` always reads the contract: verification never
  trusts the index.
* Lists sync on read, so they include everything up to
  ``latest_block - confirmations``. With ``confirmations > 0`` a chain reorg
  shallower than that depth cannot leave stale rows behind.
* If the database was built for a different chain history (another chain,
  contract, or a restarted dev chain) it is wiped and rebuilt rather than
  silently mixing data.
"""

from __future__ import annotations

import base64
import binascii
import threading
from dataclasses import dataclass
from typing import Literal

from eth_utils import to_checksum_address

from .db import Database
from .ledger import Attestation, InvalidInput, Ledger

Status = Literal["all", "valid", "revoked", "expired"]


@dataclass(frozen=True)
class Page:
    items: list[Attestation]
    next_cursor: str | None


def encode_cursor(block_number: int, log_index: int) -> str:
    return base64.urlsafe_b64encode(f"{block_number}:{log_index}".encode()).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[int, int]:
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        block, log = raw.split(":")
        return int(block), int(log)
    except (binascii.Error, UnicodeDecodeError, ValueError):
        raise InvalidInput("invalid cursor") from None


class AttestationIndex:
    def __init__(
        self,
        db: Database,
        ledger: Ledger,
        *,
        confirmations: int = 0,
        chunk_size: int = 2_000,
    ) -> None:
        if chunk_size < 1:
            raise ValueError("chunk_size must be positive")
        self._db = db
        self._ledger = ledger
        self._confirmations = confirmations
        self._chunk = chunk_size
        self._sync_lock = threading.Lock()
        self._checked_identity = False

    # -- syncing ----------------------------------------------------------

    def ensure_identity(self) -> None:
        """Wipe local chain-scoped state (index, idempotency, owners) if the chain changed.

        The identity includes the deployment block's hash, so restarting a dev
        chain and redeploying to the same address is still detected.
        """
        if self._checked_identity:
            return
        info = self._ledger.info()
        identity = f"{info.backend}:{info.chain_id}:{info.contract_address}:{self._ledger.anchor()}"
        self._db.bind_identity(identity)
        self._checked_identity = True

    @property
    def synced_to(self) -> int:
        value = self._db.get_meta("synced_to")
        return self._ledger.start_block() - 1 if value is None else int(value)

    def sync(self) -> int:
        """Pull new events up to the confirmed head. Returns the number applied."""
        with self._sync_lock:
            self.ensure_identity()
            target = self._ledger.latest_block() - self._confirmations
            applied = 0
            start = max(self.synced_to + 1, self._ledger.start_block())
            while start <= target:
                end = min(start + self._chunk - 1, target)
                events = self._ledger.events(start, end)
                with self._db.transaction() as conn:
                    for e in events:
                        if e.kind == "created":
                            conn.execute(
                                """INSERT OR IGNORE INTO attestations
                                   (uid, issuer, recipient, data, block_number, log_index, timestamp, expires_at)
                                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                                (
                                    e.uid,
                                    e.issuer,
                                    e.recipient,
                                    e.data,
                                    e.block_number,
                                    e.log_index,
                                    e.timestamp,
                                    e.expires_at,
                                ),
                            )
                        else:
                            conn.execute("UPDATE attestations SET revoked = 1 WHERE uid = ?", (e.uid,))
                    conn.execute(
                        "INSERT OR REPLACE INTO meta (key, value) VALUES ('synced_to', ?)",
                        (str(end),),
                    )
                applied += len(events)
                start = end + 1
            return applied

    # -- querying ---------------------------------------------------------

    def query(
        self,
        *,
        now: int,
        issuer: str | None = None,
        recipient: str | None = None,
        status: Status = "all",
        limit: int = 50,
        cursor: str | None = None,
    ) -> Page:
        """Newest first, keyset-paginated on (block_number, log_index)."""
        self.sync()
        where: list[str] = []
        params: list[object] = []
        if issuer:
            where.append("issuer = ?")
            params.append(to_checksum_address(issuer))
        if recipient:
            where.append("recipient = ?")
            params.append(to_checksum_address(recipient))
        if status == "revoked":
            where.append("revoked = 1")
        elif status == "expired":
            where.append("revoked = 0 AND expires_at != 0 AND expires_at <= ?")
            params.append(now)
        elif status == "valid":
            where.append("revoked = 0 AND (expires_at = 0 OR expires_at > ?)")
            params.append(now)
        if cursor:
            block, log = decode_cursor(cursor)
            where.append("(block_number, log_index) < (?, ?)")
            params += [block, log]

        sql = "SELECT * FROM attestations"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY block_number DESC, log_index DESC LIMIT ?"
        params.append(limit + 1)  # one extra row tells us whether there is a next page

        with self._db.transaction() as conn:
            rows = conn.execute(sql, params).fetchall()

        has_more = len(rows) > limit
        rows = rows[:limit]
        items = [
            Attestation(
                uid=r["uid"],
                issuer=r["issuer"],
                recipient=r["recipient"],
                data=r["data"],
                block_number=r["block_number"],
                timestamp=r["timestamp"],
                expires_at=r["expires_at"],
                revoked=bool(r["revoked"]),
            )
            for r in rows
        ]
        next_cursor = encode_cursor(rows[-1]["block_number"], rows[-1]["log_index"]) if has_more else None
        return Page(items, next_cursor)
