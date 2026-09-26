"""The ledger port: what the API needs from an attestation store.

Two adapters implement it:

* ``MockLedger``  - in-memory, no chain, no credentials. Default.
* ``Web3Ledger``  - talks to AttestationRegistry on any EVM JSON-RPC node.

The mock derives uids exactly as the contract does, so the two are
interchangeable from the API's point of view.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

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
    revoked: bool = False


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


@runtime_checkable
class Ledger(Protocol):
    def info(self) -> LedgerInfo: ...

    def create(self, recipient: str, data: str) -> TxResult: ...

    def get(self, uid: str) -> Attestation: ...

    def revoke(self, uid: str) -> TxResult: ...

    def list(
        self, *, issuer: str | None = None, recipient: str | None = None, limit: int = 50
    ) -> list[Attestation]: ...


def compute_uid(issuer: str, recipient: str, data: str, block_number: int, nonce: int) -> str:
    """Mirror of the contract's uid:
    keccak256(abi.encode(msg.sender, recipient, data, block.number, attestationCount))."""
    encoded = encode(
        ["address", "address", "string", "uint256", "uint256"],
        [issuer, recipient, data, block_number, nonce],
    )
    return "0x" + keccak(encoded).hex()
