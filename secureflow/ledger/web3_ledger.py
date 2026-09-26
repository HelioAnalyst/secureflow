"""Ledger adapter for the AttestationRegistry contract on an EVM chain."""

from __future__ import annotations

import ast
import threading
from collections.abc import Sequence
from functools import lru_cache
from typing import Any

from eth_account import Account
from eth_account.signers.local import LocalAccount
from eth_typing import HexStr
from eth_utils import to_checksum_address
from web3 import Web3
from web3.exceptions import (
    ContractCustomError,
    ContractLogicError,
    TimeExhausted,
    TransactionNotFound,
    Web3RPCError,
)
from web3.types import TxReceipt

from .. import contract as artifact
from .base import (
    AlreadyRevoked,
    Attestation,
    AttestationNotFound,
    InvalidInput,
    LedgerError,
    LedgerEvent,
    LedgerInfo,
    LedgerUnavailable,
    NotIssuer,
    OnSubmitted,
    TransactionPending,
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
    raw = Web3.to_bytes(hexstr=HexStr(uid))
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
    if name == "ExpiryInPast":
        return InvalidInput("expires_at must be in the future")
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
        self._block_time = lru_cache(maxsize=4096)(self._fetch_block_time)

    # -- connection -------------------------------------------------------

    def _ready(self) -> Any:
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

    def _send(self, fn: Any, uid: str | None = None, on_submitted: OnSubmitted | None = None) -> TxReceipt:
        """Sign locally, report the hash, broadcast, and wait for the receipt.

        Failure modes are kept distinct because callers must treat them differently:
        * revert during gas estimation / node rejects the tx -> nothing was sent (domain error)
        * transport failure during broadcast, or receipt timeout -> may be on-chain
          (``TransactionPending``); the caller must resolve it by hash, never blindly resend.
        """
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
            tx_hash = _hex(signed.hash)
            if on_submitted:
                on_submitted(tx_hash)
            try:
                w3.eth.send_raw_transaction(signed.raw_transaction)
            except Web3RPCError as exc:  # the node answered and refused it: definitely not sent
                raise LedgerError(f"node rejected transaction: {exc}") from exc
            except Exception as exc:  # noqa: BLE001 - connection dropped mid-send: outcome unknown
                raise TransactionPending(tx_hash, f"broadcast failed: {type(exc).__name__}") from exc
        try:
            receipt = w3.eth.wait_for_transaction_receipt(HexStr(tx_hash), timeout=self._timeout)
        except TimeExhausted as exc:
            raise TransactionPending(tx_hash, f"not mined within {self._timeout}s") from exc
        if receipt["status"] != 1:
            raise LedgerError(f"transaction {tx_hash} reverted")
        return receipt

    # -- Ledger port ------------------------------------------------------

    def info(self) -> LedgerInfo:
        w3 = self.w3
        return LedgerInfo("web3", w3.eth.chain_id, self._account.address, self._address, w3.eth.block_number)

    def latest_block(self) -> int:
        return int(self.w3.eth.block_number)

    def start_block(self) -> int:
        return self._deployment_block

    def anchor(self) -> str:
        return _hex(self.w3.eth.get_block(self._deployment_block)["hash"])

    def create(
        self, recipient: str, data: str, expires_at: int = 0, on_submitted: OnSubmitted | None = None
    ) -> TxResult:
        contract = self._ready()
        fn = contract.functions.createAttestation(to_checksum_address(recipient), data, expires_at)
        return self._created(self._send(fn, on_submitted=on_submitted))

    def resolve_create(self, tx_hash: str) -> TxResult | None:
        """Mined -> result. Still in the mempool -> TransactionPending. Unknown to the node -> None."""
        try:
            receipt = self.w3.eth.get_transaction_receipt(HexStr(tx_hash))
        except TransactionNotFound:
            try:
                self.w3.eth.get_transaction(HexStr(tx_hash))
            except TransactionNotFound:
                return None  # never broadcast, or dropped from the mempool
            raise TransactionPending(tx_hash, "still waiting in the mempool") from None
        if receipt["status"] != 1:
            raise LedgerError(f"transaction {tx_hash} reverted")
        return self._created(receipt)

    def _created(self, receipt: TxReceipt) -> TxResult:
        events = self._ready().events.AttestationCreated().process_receipt(receipt)
        if not events:
            raise LedgerError("transaction mined but no AttestationCreated event was emitted")
        uid = "0x" + events[0]["args"]["uid"].hex()
        return TxResult(uid, _hex(receipt["transactionHash"]), receipt["blockNumber"])

    def get(self, uid: str) -> Attestation:
        contract = self._ready()
        try:
            issuer, recipient, data, block_number, timestamp, expires_at, revoked = contract.functions.getAttestation(
                _uid_bytes(uid)
            ).call()
        except _REVERTS as exc:
            raise _translate(exc, uid) from exc
        return Attestation(uid.lower(), issuer, recipient, data, block_number, timestamp, expires_at, revoked)

    def revoke(self, uid: str) -> TxResult:
        contract = self._ready()
        receipt = self._send(contract.functions.revokeAttestation(_uid_bytes(uid)), uid)
        return TxResult(uid.lower(), _hex(receipt["transactionHash"]), receipt["blockNumber"])

    def _fetch_block_time(self, block_number: int) -> int:
        return int(self.w3.eth.get_block(block_number)["timestamp"])

    def events(self, from_block: int, to_block: int) -> Sequence[LedgerEvent]:
        """Both event types in one block range, merged into chain order.

        The caller (the indexer) chooses the range, so it can page through a
        long history in chunks that stay under a node's eth_getLogs limits.
        """
        contract = self._ready()
        span = {"from_block": from_block, "to_block": to_block}
        out: list[LedgerEvent] = []
        for log in contract.events.AttestationCreated.get_logs(**span):
            args = log["args"]
            out.append(
                LedgerEvent(
                    kind="created",
                    uid="0x" + args["uid"].hex(),
                    block_number=log["blockNumber"],
                    log_index=log["logIndex"],
                    issuer=args["issuer"],
                    recipient=args["recipient"],
                    data=args["data"],
                    expires_at=args["expiresAt"],
                    timestamp=self._block_time(log["blockNumber"]),
                )
            )
        for log in contract.events.AttestationRevoked.get_logs(**span):
            out.append(
                LedgerEvent(
                    kind="revoked",
                    uid="0x" + log["args"]["uid"].hex(),
                    block_number=log["blockNumber"],
                    log_index=log["logIndex"],
                    issuer=log["args"]["issuer"],
                    timestamp=self._block_time(log["blockNumber"]),
                )
            )
        out.sort(key=lambda e: e.position)
        return out


def _hex(value: bytes) -> str:
    return "0x" + value.hex().removeprefix("0x")
