"""In-memory ledger that behaves like the contract. No chain, no keys."""

from __future__ import annotations

import os
import threading
import time
from dataclasses import replace

from eth_utils import keccak, to_checksum_address

from .base import (
    AlreadyRevoked,
    Attestation,
    AttestationNotFound,
    InvalidInput,
    LedgerInfo,
    NotIssuer,
    TxResult,
    compute_uid,
)

# A fixed, obviously fake issuer so mock output is stable across runs.
MOCK_ISSUER = to_checksum_address("0x5ec0f10000000000000000000000000000000001")
MOCK_CHAIN_ID = 31337
ZERO_ADDRESS = "0x" + "00" * 20


class MockLedger:
    def __init__(self, issuer: str = MOCK_ISSUER) -> None:
        self._issuer = to_checksum_address(issuer)
        self._records: dict[str, Attestation] = {}
        self._order: list[str] = []
        self._block = 0
        self._count = 0
        self._lock = threading.Lock()

    def _mine(self) -> tuple[int, int, str]:
        self._block += 1
        return self._block, int(time.time()), "0x" + keccak(os.urandom(32)).hex()

    def info(self) -> LedgerInfo:
        return LedgerInfo("mock", MOCK_CHAIN_ID, self._issuer, None, self._block)

    def create(self, recipient: str, data: str) -> TxResult:
        recipient = to_checksum_address(recipient)
        if recipient == to_checksum_address(ZERO_ADDRESS):
            raise InvalidInput("recipient cannot be the zero address")
        with self._lock:
            block, ts, tx_hash = self._mine()
            uid = compute_uid(self._issuer, recipient, data, block, self._count)
            self._count += 1
            self._records[uid] = Attestation(uid, self._issuer, recipient, data, block, ts)
            self._order.append(uid)
        return TxResult(uid, tx_hash, block)

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
            block, _, tx_hash = self._mine()
            self._records[record.uid] = replace(record, revoked=True)
        return TxResult(record.uid, tx_hash, block)

    def list(self, *, issuer: str | None = None, recipient: str | None = None, limit: int = 50) -> list[Attestation]:
        out = []
        for uid in reversed(self._order):  # newest first
            a = self._records[uid]
            if issuer and a.issuer != to_checksum_address(issuer):
                continue
            if recipient and a.recipient != to_checksum_address(recipient):
                continue
            out.append(a)
            if len(out) >= limit:
                break
        return out
