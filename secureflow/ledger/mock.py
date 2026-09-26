"""In-memory ledger that behaves like the contract. No chain, no keys."""

from __future__ import annotations

import bisect
import os
import threading
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import replace

from eth_utils import keccak, to_checksum_address

from .base import (
    AlreadyRevoked,
    Attestation,
    AttestationNotFound,
    InvalidInput,
    LedgerEvent,
    LedgerInfo,
    NotIssuer,
    OnSubmitted,
    TxResult,
    compute_uid,
)

# A fixed, obviously fake issuer so mock output is stable across runs.
MOCK_ISSUER = to_checksum_address("0x5ec0f10000000000000000000000000000000001")
MOCK_CHAIN_ID = 31337
ZERO_ADDRESS = "0x" + "00" * 20


def _wall_clock() -> int:
    return int(time.time())


class MockLedger:
    """One transaction per block, like an automining dev chain."""

    def __init__(self, issuer: str = MOCK_ISSUER, clock: Callable[[], int] = _wall_clock) -> None:
        self._issuer = to_checksum_address(issuer)
        self._clock = clock
        self._records: dict[str, Attestation] = {}
        self._events: list[LedgerEvent] = []
        self._block = 0
        self._count = 0
        self._lock = threading.Lock()
        self._anchor = uuid.uuid4().hex  # a fresh "chain" every time the process starts
        self._by_tx: dict[str, TxResult] = {}

    def _mine(self) -> tuple[int, int, str]:
        self._block += 1
        return self._block, self._clock(), "0x" + keccak(os.urandom(32)).hex()

    def info(self) -> LedgerInfo:
        return LedgerInfo("mock", MOCK_CHAIN_ID, self._issuer, None, self._block)

    def latest_block(self) -> int:
        return self._block

    def start_block(self) -> int:
        return 0

    def anchor(self) -> str:
        return self._anchor

    def resolve_create(self, tx_hash: str) -> TxResult | None:
        return self._by_tx.get(tx_hash)

    def create(
        self, recipient: str, data: str, expires_at: int = 0, on_submitted: OnSubmitted | None = None
    ) -> TxResult:
        recipient = to_checksum_address(recipient)
        if recipient == to_checksum_address(ZERO_ADDRESS):
            raise InvalidInput("recipient cannot be the zero address")
        with self._lock:
            now = self._clock()
            if expires_at and expires_at <= now:
                raise InvalidInput("expires_at must be in the future")
            block, ts, tx_hash = self._mine()
            if on_submitted:
                on_submitted(tx_hash)
            uid = compute_uid(self._issuer, recipient, data, block, self._count)
            self._count += 1
            self._records[uid] = Attestation(uid, self._issuer, recipient, data, block, ts, expires_at)
            self._events.append(LedgerEvent("created", uid, block, 0, self._issuer, recipient, data, expires_at, ts))
            result = TxResult(uid, tx_hash, block)
            self._by_tx[tx_hash] = result
        return result

    def get(self, uid: str) -> Attestation:
        try:
            return self._records[uid.lower()]
        except KeyError:
            raise AttestationNotFound(uid) from None

    def revoke(self, uid: str) -> TxResult:
        with self._lock:
            record = self.get(uid)
            if record.issuer != self._issuer:
                raise NotIssuer(uid)
            if record.revoked:
                raise AlreadyRevoked(uid)
            block, ts, tx_hash = self._mine()
            self._records[record.uid] = replace(record, revoked=True)
            self._events.append(LedgerEvent("revoked", record.uid, block, 0, self._issuer, timestamp=ts))
        return TxResult(record.uid, tx_hash, block)

    def events(self, from_block: int, to_block: int) -> Sequence[LedgerEvent]:
        blocks = [e.block_number for e in self._events]
        lo = bisect.bisect_left(blocks, from_block)
        hi = bisect.bisect_right(blocks, to_block)
        return self._events[lo:hi]
