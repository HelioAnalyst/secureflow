"""Ledger adapter for the AttestationRegistry contract on an EVM chain."""

from __future__ import annotations

import ast
import threading
from typing import Any

from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_utils import to_checksum_address
from web3 import Web3
from web3.exceptions import ContractCustomError, ContractLogicError, TimeExhausted
from web3.types import TxReceipt

from .. import contract as artifact
from .base import (
    AlreadyRevoked,
    Attestation,
    AttestationNotFound,
    InvalidInput,
    LedgerError,
    LedgerInfo,
    LedgerUnavailable,
    NotIssuer,
    TxResult,
)

GAS_MARGIN = 1.2  # headroom over eth_estimateGas

_ERRORS: dict[str, type[LedgerError]] = {
    "AttestationNotFound": AttestationNotFound,
    "AlreadyRevoked": AlreadyRevoked,
    "NotIssuer": NotIssuer,
    "ZeroRecipient": InvalidInput,
}


def _uid_bytes(uid: str) -> bytes:
    raw = Web3.to_bytes(hexstr=uid)
    if len(raw) != 32:
        raise InvalidInput("uid must be 32 bytes of hex")
    return raw


def _revert_selector(exc: Exception) -> str | None:
    """The 4-byte custom-error selector from a revert, as 0x-hex, if present."""
    if isinstance(exc, ContractCustomError) and isinstance(exc.data, str):
        return exc.data[:10].lower()
    # eth-tester (the in-process EVM used by the test suite) reports reverts as
    # TransactionFailed("execution reverted: b'...'") rather than JSON-RPC error data.
    message = str(exc)
    marker = "execution reverted: b"
    if marker in message:
        try:
            raw = ast.literal_eval(message[message.index(marker) + len(marker) - 1 :])
        except (SyntaxError, ValueError):
            return None
        if isinstance(raw, bytes) and len(raw) >= 4:
            return "0x" + raw[:4].hex()
    return None


def _translate(exc: Exception, uid: str | None = None) -> LedgerError:
    """Turn a contract revert into the matching domain error."""
    name = artifact.error_selectors().get(_revert_selector(exc) or "")
    if name == "ZeroRecipient":
        return InvalidInput("recipient cannot be the zero address")
    if name in _ERRORS:
        return _ERRORS[name](uid or name)
    return LedgerError(f"contract call reverted: {exc}")


try:  # only present when web3[tester] is installed
    from eth_tester.exceptions import TransactionFailed as _TesterRevert
except ImportError:  # pragma: no cover

    class _TesterRevert(Exception):  # type: ignore[no-redef]
        pass


_REVERTS = (ContractCustomError, ContractLogicError, _TesterRevert)


class Web3Ledger:
    """Signs transactions locally with a private key; the key never leaves the process.

    The connection is opened lazily on first use, so importing the app (and
    running tests against the mock) never needs a node.
    """

    def __init__(
        self,
        *,
        private_key: str,
        contract_address: str,
        deployment_block: int = 0,
        rpc_url: str | None = None,
        w3: Web3 | None = None,
        tx_timeout_seconds: int = 120,
    ) -> None:
        if not private_key:
            raise LedgerUnavailable("ETH_PRIVATE_KEY is required for the web3 backend")
        if w3 is None and not rpc_url:
            raise LedgerUnavailable("either rpc_url or a Web3 instance is required")
        self._account: LocalAccount = Account.from_key(private_key)
        self._address = to_checksum_address(contract_address)
        self._deployment_block = deployment_block
        self._rpc_url = rpc_url
        self._w3 = w3
        self._contract: Any = None
        self._timeout = tx_timeout_seconds
        self._tx_lock = threading.Lock()  # one in-flight nonce at a time

    # -- connection -------------------------------------------------------

    def _ready(self):
        if self._contract is not None:
            return self._contract
        if self._w3 is None:
            self._w3 = Web3(Web3.HTTPProvider(self._rpc_url, request_kwargs={"timeout": 10}))
        try:
            connected = self._w3.is_connected()
        except Exception:  # noqa: BLE001 - any transport failure means "unavailable"
            connected = False
        if not connected:
            raise LedgerUnavailable(f"cannot reach Ethereum node at {self._rpc_url}")
        if self._w3.eth.get_code(self._address) in (b"", b"\x00"):
            raise LedgerUnavailable(f"no contract deployed at {self._address}")
        self._contract = self._w3.eth.contract(address=self._address, abi=artifact.abi())
        return self._contract

    @property
    def w3(self) -> Web3:
        self._ready()
        assert self._w3 is not None
        return self._w3

    # -- transactions -----------------------------------------------------

    def _send(self, fn, uid: str | None = None) -> TxReceipt:
        w3 = self.w3
        sender = self._account.address
        with self._tx_lock:
            try:
                gas = int(fn.estimate_gas({"from": sender}) * GAS_MARGIN)
                tx = fn.build_transaction(
                    {
                        "from": sender,
                        "nonce": w3.eth.get_transaction_count(sender, "pending"),
                        "gas": gas,
                        "chainId": w3.eth.chain_id,
                    }
                )  # fee fields (EIP-1559 or legacy) are filled in from the node
            except _REVERTS as exc:
                raise _translate(exc, uid) from exc
            signed = self._account.sign_transaction(tx)
            tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        try:
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=self._timeout)
        except TimeExhausted as exc:
            raise LedgerUnavailable(f"transaction {tx_hash.hex()} not mined within {self._timeout}s") from exc
        if receipt["status"] != 1:
            raise LedgerError(f"transaction {tx_hash.hex()} reverted")
        return receipt

    # -- Ledger port ------------------------------------------------------

    def info(self) -> LedgerInfo:
        w3 = self.w3
        return LedgerInfo("web3", w3.eth.chain_id, self._account.address, self._address, w3.eth.block_number)

    def create(self, recipient: str, data: str) -> TxResult:
        contract = self._ready()
        receipt = self._send(contract.functions.createAttestation(to_checksum_address(recipient), data))
        events = contract.events.AttestationCreated().process_receipt(receipt)
        if not events:
            raise LedgerError("transaction mined but no AttestationCreated event was emitted")
        uid = "0x" + events[0]["args"]["uid"].hex()
        return TxResult(uid, "0x" + receipt["transactionHash"].hex().removeprefix("0x"), receipt["blockNumber"])

    def get(self, uid: str) -> Attestation:
        contract = self._ready()
        try:
            issuer, recipient, data, block_number, timestamp, revoked = contract.functions.getAttestation(
                _uid_bytes(uid)
            ).call()
        except _REVERTS as exc:
            raise _translate(exc, uid) from exc
        return Attestation(uid.lower(), issuer, recipient, data, block_number, timestamp, revoked)

    def revoke(self, uid: str) -> TxResult:
        contract = self._ready()
        receipt = self._send(contract.functions.revokeAttestation(_uid_bytes(uid)), uid)
        return TxResult(uid.lower(), "0x" + receipt["transactionHash"].hex().removeprefix("0x"), receipt["blockNumber"])

    def list(self, *, issuer: str | None = None, recipient: str | None = None, limit: int = 50) -> list[Attestation]:
        """Newest first, rebuilt from AttestationCreated events.

        Fine for a demo or a private chain. On a busy public chain you would
        page the block range or read from an indexer instead.
        """
        contract = self._ready()
        filters = {}
        if issuer:
            filters["issuer"] = to_checksum_address(issuer)
        if recipient:
            filters["recipient"] = to_checksum_address(recipient)
        logs = contract.events.AttestationCreated.get_logs(
            from_block=self._deployment_block, argument_filters=filters or None
        )
        uids = ["0x" + log["args"]["uid"].hex() for log in reversed(logs)][:limit]
        return [self.get(uid) for uid in uids]
