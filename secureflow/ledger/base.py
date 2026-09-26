"""The ledger port: what the API needs from an attestation store.

Two adapters implement it:

* ``MockLedger``  - in-memory, no chain, no credentials. Default.
* ``Web3Ledger``  - talks to AttestationRegistry on any EVM JSON-RPC node.

The mock derives uids exactly as the contract does, so the two are
interchangeable from the API's point of view.

Point reads (``get``) always go to the ledger, which is the source of truth.
Lists are served from :mod:`secureflow.index`, which consumes ``events()``.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol, runtime_checkable

from eth_abi import encode
from eth_utils import keccak


@dataclass(frozen=True)
class Attestation:
    uid: str  # 0x-prefixed 32-byte hex
    issuer: str
    recipient: str
    data: str
    block_number: int
    timestamp: int
    expires_at: int = 0  # unix seconds; 0 = never
    revoked: bool = False

    def is_expired(self, now: int) -> bool:
        return self.expires_at != 0 and now >= self.expires_at

    def is_valid(self, now: int) -> bool:
        """Mirrors AttestationRegistry.isValid."""
        return not self.revoked and not self.is_expired(now)


@dataclass(frozen=True)
class LedgerEvent:
    """One contract event, in chain order. ``position`` is (block_number, log_index)."""

    kind: Literal["created", "revoked"]
    uid: str
    block_number: int
    log_index: int
    issuer: str
    # Only set for "created":
    recipient: str | None = None
    data: str | None = None
    expires_at: int = 0
    timestamp: int = 0

    @property
    def position(self) -> tuple[int, int]:
        return self.block_number, self.log_index


@dataclass(frozen=True)
class TxResult:
    uid: str
    tx_hash: str
    block_number: int


@dataclass(frozen=True)
class LedgerInfo:
    backend: str
    chain_id: int
    issuer: str
    contract_address: str | None
    latest_block: int


class LedgerError(Exception):
    """Base class for ledger failures the API maps to HTTP responses."""


class AttestationNotFound(LedgerError):
    pass


class AlreadyRevoked(LedgerError):
    pass


class NotIssuer(LedgerError):
    pass


class InvalidInput(LedgerError):
    pass


class LedgerUnavailable(LedgerError):
    """The node is unreachable or the contract is missing."""


class TransactionPending(LedgerUnavailable):
    """The transaction was (or may have been) broadcast, but its outcome is unknown.

    Retrying blindly could issue twice, so callers should look the hash up
    with ``resolve_create`` instead.
    """

    def __init__(self, tx_hash: str, reason: str) -> None:
        super().__init__(f"transaction {tx_hash} submitted but not confirmed ({reason})")
        self.tx_hash = tx_hash


OnSubmitted = Callable[[str], None]
"""Called with the transaction hash after signing and *before* broadcast."""


@runtime_checkable
class Ledger(Protocol):
    def info(self) -> LedgerInfo: ...

    def latest_block(self) -> int: ...

    def start_block(self) -> int:
        """First block that can contain events (the deployment block)."""
        ...

    def anchor(self) -> str:
        """Identifies this exact chain history (e.g. the deployment block's hash).

        Changes when a dev chain is restarted even if chain id and contract
        address are the same, so local state built against the old chain
        can be discarded.
        """
        ...

    def create(
        self, recipient: str, data: str, expires_at: int = 0, on_submitted: OnSubmitted | None = None
    ) -> TxResult: ...

    def resolve_create(self, tx_hash: str) -> TxResult | None:
        """Outcome of an earlier ``create`` by transaction hash; None if not (yet) mined."""
        ...

    def get(self, uid: str) -> Attestation: ...

    def revoke(self, uid: str) -> TxResult: ...

    def events(self, from_block: int, to_block: int) -> Sequence[LedgerEvent]:
        """All contract events in [from_block, to_block], sorted by position."""
        ...


def compute_uid(issuer: str, recipient: str, data: str, block_number: int, nonce: int) -> str:
    """Mirror of the contract's uid:
    keccak256(abi.encode(msg.sender, recipient, data, block.number, attestationCount))."""
    encoded = encode(
        ["address", "address", "string", "uint256", "uint256"],
        [issuer, recipient, data, block_number, nonce],
    )
    return "0x" + keccak(encoded).hex()
