"""The Solidity contract itself, exercised through Web3Ledger on an in-process EVM."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from secureflow.api import create_app
from secureflow.ledger import (
    AlreadyRevoked,
    AttestationNotFound,
    LedgerUnavailable,
    MockLedger,
    NotIssuer,
    compute_uid,
)
from secureflow.ledger.web3_ledger import Web3Ledger
from tests.conftest import RECIPIENT


def test_uid_matches_contract_derivation(web3_ledger):
    """The mock's uid formula must be byte-for-byte the contract's."""
    first = web3_ledger.create(RECIPIENT, "payload")
    second = web3_ledger.create(RECIPIENT, "payload")
    issuer = web3_ledger.info().issuer
    assert first.uid == compute_uid(issuer, RECIPIENT, "payload", first.block_number, 0)
    assert second.uid == compute_uid(issuer, RECIPIENT, "payload", second.block_number, 1)


def test_attestation_count_increments(web3_ledger):
    web3_ledger.create(RECIPIENT, "a")
    web3_ledger.create(RECIPIENT, "b")
    contract = web3_ledger._ready()
    assert contract.functions.attestationCount().call() == 2


def test_record_fields_come_from_chain(web3_ledger):
    tx = web3_ledger.create(RECIPIENT, "data")
    record = web3_ledger.get(tx.uid)
    block = web3_ledger.w3.eth.get_block(tx.block_number)
    assert record.issuer == web3_ledger.info().issuer
    assert record.block_number == tx.block_number
    assert record.timestamp == block["timestamp"]


def test_only_issuer_can_revoke(deployed, web3_ledger):
    w3, keys, deployment = deployed
    uid = web3_ledger.create(RECIPIENT, "x").uid
    stranger = Web3Ledger(private_key=keys[1], contract_address=deployment["address"], w3=w3)
    with pytest.raises(NotIssuer):
        stranger.revoke(uid)
    web3_ledger.revoke(uid)
    with pytest.raises(AlreadyRevoked):
        web3_ledger.revoke(uid)


def test_stranger_revoke_maps_to_403(deployed, web3_ledger):
    w3, keys, deployment = deployed
    uid = web3_ledger.create(RECIPIENT, "x").uid
    stranger = Web3Ledger(private_key=keys[1], contract_address=deployment["address"], w3=w3)
    with TestClient(create_app(ledger=stranger)) as client:
        assert client.post(f"/attestations/{uid}/revoke").status_code == 403


def test_get_unknown_raises(web3_ledger):
    with pytest.raises(AttestationNotFound):
        web3_ledger.get("0x" + "00" * 32)


def test_list_filters_by_issuer(deployed, web3_ledger):
    w3, keys, deployment = deployed
    other = Web3Ledger(private_key=keys[1], contract_address=deployment["address"], w3=w3)
    mine = web3_ledger.create(RECIPIENT, "mine").uid
    other.create(RECIPIENT, "theirs")
    issuer = web3_ledger.info().issuer
    assert [a.uid for a in web3_ledger.list(issuer=issuer)] == [mine]
    assert len(web3_ledger.list()) == 2


def test_missing_contract_is_unavailable(chain):
    w3, keys = chain
    ledger = Web3Ledger(private_key=keys[0], contract_address="0x" + "12" * 20, w3=w3)
    with pytest.raises(LedgerUnavailable):
        ledger.info()


def test_unreachable_node_is_503(chain):
    _, keys = chain
    ledger = Web3Ledger(private_key=keys[0], contract_address="0x" + "12" * 20, rpc_url="http://127.0.0.1:1")
    with TestClient(create_app(ledger=ledger)) as client:
        response = client.get("/health")
    assert response.status_code == 503
    assert "cannot reach" in response.json()["detail"]


def test_constructing_web3_ledger_does_not_connect():
    # Must not raise even though nothing is listening: connection is lazy.
    Web3Ledger(private_key="0x" + "01" * 32, contract_address="0x" + "12" * 20, rpc_url="http://127.0.0.1:1")


def test_mock_uids_follow_same_formula():
    ledger = MockLedger()
    tx = ledger.create(RECIPIENT, "payload")
    assert tx.uid == compute_uid(ledger.info().issuer, RECIPIENT, "payload", tx.block_number, 0)


def test_contract_rejects_zero_recipient(web3_ledger):
    """Bypasses the API's own validation to prove the contract enforces it too."""
    from secureflow.ledger import InvalidInput

    with pytest.raises(InvalidInput, match="zero address"):
        web3_ledger.create("0x" + "00" * 20, "x")
