from __future__ import annotations

from ..config import Settings
from .base import (
    AlreadyRevoked,
    Attestation,
    AttestationNotFound,
    InvalidInput,
    Ledger,
    LedgerError,
    LedgerEvent,
    LedgerInfo,
    LedgerUnavailable,
    NotIssuer,
    OnSubmitted,
    TransactionPending,
    TxResult,
    compute_uid,
)
from .mock import MockLedger

__all__ = [
    "AlreadyRevoked",
    "Attestation",
    "AttestationNotFound",
    "InvalidInput",
    "Ledger",
    "LedgerError",
    "LedgerEvent",
    "LedgerInfo",
    "LedgerUnavailable",
    "MockLedger",
    "NotIssuer",
    "OnSubmitted",
    "TransactionPending",
    "TxResult",
    "build_ledger",
    "compute_uid",
]


def build_ledger(settings: Settings) -> Ledger:
    """Pick the adapter named by SECUREFLOW_BACKEND."""
    if settings.backend == "mock":
        return MockLedger()

    from .web3_ledger import Web3Ledger  # imported lazily: mock mode never touches web3 networking

    address, deployment_block = settings.resolve_deployment()
    return Web3Ledger(
        private_key=settings.private_key or "",
        contract_address=address,
        deployment_block=deployment_block,
        rpc_url=settings.rpc_url,
        tx_timeout_seconds=settings.tx_timeout_seconds,
    )
