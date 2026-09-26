"""Indexer, idempotency store, auth and config rules, tested without HTTP."""

from __future__ import annotations

import pytest

from secureflow.auth import AuthConfigError, KeyRing, hash_key, main, parse_key_hashes
from secureflow.config import ConfigError, Settings
from secureflow.db import Database
from secureflow.idempotency import (
    IdempotencyConflict,
    IdempotencyMismatch,
    IdempotencyStore,
    InDoubt,
    Proceed,
    Replay,
)
from secureflow.index import AttestationIndex, decode_cursor, encode_cursor
from secureflow.ledger import InvalidInput, MockLedger
from tests.conftest import RECIPIENT, FakeClock

# -- index ------------------------------------------------------------------------


def test_sync_is_incremental():
    ledger = MockLedger()
    index = AttestationIndex(Database(), ledger)
    ledger.create(RECIPIENT, "a")
    assert index.sync() == 1
    assert index.sync() == 0  # nothing new
    ledger.create(RECIPIENT, "b")
    assert index.sync() == 1
    assert index.synced_to == ledger.latest_block()


def test_sync_in_chunks_matches_single_pass():
    ledger = MockLedger()
    for i in range(7):
        ledger.create(RECIPIENT, str(i))
    small = AttestationIndex(Database(), ledger, chunk_size=2)
    big = AttestationIndex(Database(), ledger, chunk_size=1000)
    assert [a.uid for a in small.query(now=0).items] == [a.uid for a in big.query(now=0).items]


def test_confirmations_hold_back_recent_blocks():
    ledger = MockLedger()
    index = AttestationIndex(Database(), ledger, confirmations=2)
    for i in range(3):
        ledger.create(RECIPIENT, str(i))
    assert len(index.query(now=0).items) == 1  # blocks 2 and 3 are not yet confirmed
    ledger.create(RECIPIENT, "3")
    ledger.create(RECIPIENT, "4")
    assert len(index.query(now=0).items) == 3


def test_index_survives_restart_with_file_db(tmp_path):
    path = str(tmp_path / "index.db")
    ledger = MockLedger()
    ledger.create(RECIPIENT, "a")
    AttestationIndex(Database(path), ledger).sync()
    reopened = AttestationIndex(Database(path), ledger)
    assert reopened.synced_to == 1
    assert len(reopened.query(now=0).items) == 1


def test_index_resets_when_pointed_at_another_chain(tmp_path):
    path = str(tmp_path / "index.db")
    first = MockLedger()
    first.create(RECIPIENT, "a")
    AttestationIndex(Database(path), first).sync()

    class OtherChain(MockLedger):
        def info(self):
            info = super().info()
            return type(info)(info.backend, 1, info.issuer, "0x" + "99" * 20, info.latest_block)

    second = OtherChain()
    assert AttestationIndex(Database(path), second).query(now=0).items == []


def test_cursor_round_trip_and_rejection():
    assert decode_cursor(encode_cursor(123, 4)) == (123, 4)
    for bad in ["", "not-base64!", encode_cursor(1, 2)[:-2] + "@@"]:
        with pytest.raises(InvalidInput):
            decode_cursor(bad)


def test_chunk_size_must_be_positive():
    with pytest.raises(ValueError):
        AttestationIndex(Database(), MockLedger(), chunk_size=0)


# -- idempotency store ------------------------------------------------------------


def test_idempotency_states():
    clock = FakeClock(start=1_000_000)
    store = IdempotencyStore(Database(), stale_seconds=600, clock=clock)
    assert store.begin("alice", "k1", "fp") == Proceed()
    with pytest.raises(IdempotencyConflict):
        store.begin("alice", "k1", "fp")  # still in flight, nothing submitted yet
    store.complete("alice", "k1", 201, {"uid": "0x1"})
    assert store.begin("alice", "k1", "fp") == Replay(201, {"uid": "0x1"})
    with pytest.raises(IdempotencyMismatch):
        store.begin("alice", "k1", "other-fp")
    assert store.begin("bob", "k1", "fp") == Proceed()  # scoped per client


def test_submitted_key_is_in_doubt_not_conflict():
    clock = FakeClock(start=1_000_000)
    store = IdempotencyStore(Database(), stale_seconds=600, clock=clock)
    store.begin("alice", "k", "fp")
    store.submitted("alice", "k", "0xabc")
    assert store.begin("alice", "k", "fp") == InDoubt("0xabc", stale=False)
    clock.advance(601)
    assert store.begin("alice", "k", "fp") == InDoubt("0xabc", stale=True)
    store.retake("alice", "k")
    with pytest.raises(IdempotencyConflict):  # retaken, fresh again, no tx yet
        store.begin("alice", "k", "fp")


def test_stale_pending_key_without_tx_is_taken_over():
    """The process died before broadcasting: the key must not be stuck for 24 h."""
    clock = FakeClock(start=1_000_000)
    store = IdempotencyStore(Database(), stale_seconds=600, clock=clock)
    store.begin("alice", "k", "fp")
    clock.advance(601)
    assert store.begin("alice", "k", "fp") == Proceed()


def test_idempotency_keys_expire():
    clock = FakeClock(start=1_000_000)
    store = IdempotencyStore(Database(), ttl_seconds=60, clock=clock)
    store.begin("alice", "k", "fp")
    store.complete("alice", "k", 201, {})
    clock.advance(61)
    assert store.begin("alice", "k", "different-body-is-fine-now") == Proceed()


def test_chain_reset_wipes_idempotency_and_owners(tmp_path):
    """Same chain id and contract address, but a restarted dev chain: nothing may carry over."""
    path = str(tmp_path / "sf.db")
    db = Database(path)
    first = MockLedger()
    AttestationIndex(db, first).ensure_identity()
    IdempotencyStore(db).begin("alice", "k", "fp")
    db.set_owner("0x" + "11" * 32, "alice")

    db2 = Database(path)
    AttestationIndex(db2, MockLedger()).ensure_identity()  # new anchor
    assert db2.get_owner("0x" + "11" * 32) is None
    assert IdempotencyStore(db2).begin("alice", "k", "other-fp") == Proceed()


# -- auth -------------------------------------------------------------------------


def test_keyring_authenticates_by_hash():
    ring = KeyRing(parse_key_hashes(f"ci:{hash_key('sf_a')}, ops:{hash_key('sf_b')}"))
    assert ring.enabled
    assert ring.authenticate("sf_a").name == "ci"
    assert ring.authenticate("sf_b").name == "ops"
    assert ring.authenticate("sf_c") is None
    assert ring.authenticate(None) is None


def test_empty_keyring_is_anonymous():
    ring = KeyRing({})
    assert not ring.enabled
    assert ring.authenticate(None).name == "anonymous"


@pytest.mark.parametrize("spec", ["nocolon", "name:short", "bad name:" + "a" * 64, ":" + "a" * 64])
def test_bad_key_specs_rejected(spec):
    with pytest.raises(AuthConfigError):
        parse_key_hashes(spec)


def test_key_generator_output_round_trips(capsys):
    main(["ci-bot"])
    lines = dict(line.split(":  ", 1) for line in capsys.readouterr().out.strip().splitlines())
    ring = KeyRing(parse_key_hashes(lines["env"]))
    assert ring.authenticate(lines["key"]).name == "ci-bot"


# -- config safety ----------------------------------------------------------------


@pytest.mark.parametrize("blank", [None, "", " ", ",", " , "])
def test_web3_backend_requires_api_keys(blank):
    with pytest.raises(ConfigError, match="SECUREFLOW_API_KEYS"):
        Settings(backend="web3", api_keys=blank).validate()


def test_malformed_api_keys_are_a_config_error():
    with pytest.raises(ConfigError, match="expected name:sha256hex"):
        Settings(backend="mock", api_keys="oops").validate()


def test_web3_backend_accepts_real_keys():
    Settings(backend="web3", api_keys=f"x:{hash_key('k')}").validate()
    Settings(backend="mock").validate()


def test_non_integer_env_is_a_config_error(monkeypatch):
    monkeypatch.setenv("SECUREFLOW_INDEX_CHUNK", "lots")
    with pytest.raises(ConfigError, match="SECUREFLOW_INDEX_CHUNK"):
        Settings.from_env()


# -- logging ----------------------------------------------------------------------


def test_json_logs_carry_request_id_and_fields(capsys):
    import json
    import logging

    from fastapi.testclient import TestClient

    from secureflow.api import create_app
    from secureflow.observability import configure_logging

    configure_logging("INFO", json_format=True)
    try:
        with TestClient(create_app(ledger=MockLedger())) as client:
            client.get("/health", headers={"X-Request-ID": "trace-1"})
        lines = [json.loads(line) for line in capsys.readouterr().err.strip().splitlines()]
        request_log = next(line for line in lines if line["msg"] == "request")
        assert request_log["request_id"] == "trace-1"
        assert request_log["route"] == "/health"
        assert request_log["status"] == 200
    finally:
        logging.getLogger("secureflow").handlers.clear()


def test_text_logs_include_request_id(capsys):
    import logging

    from secureflow.observability import configure_logging, logger

    configure_logging("INFO", json_format=False)
    try:
        logger.info("hello")
        assert "[-] secureflow: hello" in capsys.readouterr().err
    finally:
        logging.getLogger("secureflow").handlers.clear()
