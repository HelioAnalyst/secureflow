"""HTTP behaviour. Parametrised over both ledgers via the `ledger` fixture."""

from __future__ import annotations

import time

import pytest

from secureflow.ledger import LedgerUnavailable, TransactionPending
from tests.conftest import OTHER_API_KEY, OTHER_RECIPIENT, RECIPIENT

MISSING_UID = "0x" + "ab" * 32


def issue(client, data="hello", recipient=RECIPIENT, headers=None, **extra):
    response = client.post("/attestations", json={"recipient": recipient, "data": data, **extra}, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def uids(response):
    assert response.status_code == 200, response.text
    return [a["uid"] for a in response.json()["items"]]


# -- basics -----------------------------------------------------------------------


def test_health(client):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["backend"] in {"mock", "web3"}
    assert body["encryption"] is True
    assert body["auth"] is True
    assert body["issuer"].startswith("0x")


def test_issue_and_verify(client):
    created = issue(client, "Completed: Advanced Python")
    assert len(created["uid"]) == 66
    assert created["tx_hash"].startswith("0x")

    record = client.get(f"/attestations/{created['uid']}").json()
    assert record["data"] == "Completed: Advanced Python"
    assert record["recipient"] == RECIPIENT
    assert record["encrypted"] is False
    assert record["expires_at"] is None
    assert record["valid"] is True
    assert record["block_number"] == created["block_number"]


def test_identical_attestations_get_distinct_uids(client):
    assert issue(client, "same")["uid"] != issue(client, "same")["uid"]


def test_recipient_is_normalised_to_checksum(client):
    created = issue(client, recipient=RECIPIENT.lower())
    assert client.get(f"/attestations/{created['uid']}").json()["recipient"] == RECIPIENT


def test_verify_unknown_uid_is_404(client):
    assert client.get(f"/attestations/{MISSING_UID}").status_code == 404


def test_malformed_uid_is_422(client):
    assert client.get("/attestations/0x1234").status_code == 422


def test_invalid_recipient_is_422(client):
    response = client.post("/attestations", json={"recipient": "not-an-address", "data": "x"})
    assert response.status_code == 422


def test_zero_address_recipient_is_rejected(client):
    response = client.post("/attestations", json={"recipient": "0x" + "00" * 20, "data": "x"})
    assert response.status_code == 422


def test_empty_and_oversized_data_rejected(client):
    assert client.post("/attestations", json={"recipient": RECIPIENT, "data": ""}).status_code == 422
    assert client.post("/attestations", json={"recipient": RECIPIENT, "data": "x" * 4097}).status_code == 422


# -- auth -------------------------------------------------------------------------


def test_writes_require_api_key(anon_client, client):
    response = anon_client.post("/attestations", json={"recipient": RECIPIENT, "data": "x"})
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "ApiKey"

    uid = issue(client)["uid"]
    assert anon_client.post(f"/attestations/{uid}/revoke").status_code == 401


def test_wrong_api_key_rejected(anon_client):
    response = anon_client.post(
        "/attestations", json={"recipient": RECIPIENT, "data": "x"}, headers={"X-API-Key": "sf_nope"}
    )
    assert response.status_code == 401


def test_reads_are_public(anon_client, client):
    uid = issue(client)["uid"]
    assert anon_client.get(f"/attestations/{uid}").status_code == 200
    assert anon_client.get("/attestations").status_code == 200
    assert anon_client.get("/health").status_code == 200


def test_auth_off_when_no_keys_configured(client_no_crypto):
    """Only reachable by injecting a ledger; the web3 backend refuses to start without keys."""
    assert client_no_crypto.get("/health").json()["auth"] is False
    assert client_no_crypto.post("/attestations", json={"recipient": RECIPIENT, "data": "x"}).status_code == 201


# -- revoke -----------------------------------------------------------------------


def test_revoke_lifecycle(client):
    uid = issue(client)["uid"]
    assert client.post(f"/attestations/{uid}/revoke").status_code == 200

    record = client.get(f"/attestations/{uid}").json()
    assert record["revoked"] is True
    assert record["valid"] is False

    assert client.post(f"/attestations/{uid}/revoke").status_code == 409


def test_revoke_unknown_is_404(client):
    assert client.post(f"/attestations/{MISSING_UID}/revoke").status_code == 404


# -- expiry -----------------------------------------------------------------------


def test_expiry_in_past_rejected(client):
    response = client.post("/attestations", json={"recipient": RECIPIENT, "data": "x", "expires_at": 1})
    assert response.status_code == 422


def test_expiry_round_trip(client):
    expires = int(time.time()) + 3600
    uid = issue(client, expires_at=expires)["uid"]
    record = client.get(f"/attestations/{uid}").json()
    assert record["expires_at"] == expires
    assert record["expired"] is False
    assert record["valid"] is True


def test_attestation_expires(client, clock, backend):
    if backend != "mock":
        pytest.skip("time travel on the real contract is covered in test_web3_ledger")
    uid = issue(client, expires_at=clock.now + 60)["uid"]
    clock.advance(61)
    record = client.get(f"/attestations/{uid}").json()
    assert record["expired"] is True
    assert record["valid"] is False
    assert uids(client.get("/attestations", params={"status": "expired"})) == [uid]
    assert uids(client.get("/attestations", params={"status": "valid"})) == []


# -- encryption -------------------------------------------------------------------


def test_encrypted_attestation_round_trip(client):
    uid = issue(client, "secret salary band", encrypt=True)["uid"]
    record = client.get(f"/attestations/{uid}").json()
    assert record["encrypted"] is True
    assert record["data"] == "secret salary band"
    assert record["ciphertext"].startswith("sf1:")
    assert "secret" not in record["ciphertext"]


def test_encrypted_data_unreadable_without_key(client, client_no_crypto):
    uid = issue(client, "secret", encrypt=True)["uid"]
    record = client_no_crypto.get(f"/attestations/{uid}").json()
    assert record["encrypted"] is True
    assert record["data"] is None
    assert record["ciphertext"].startswith("sf1:")


def test_encrypt_without_key_is_400(client_no_crypto):
    response = client_no_crypto.post("/attestations", json={"recipient": RECIPIENT, "data": "x", "encrypt": True})
    assert response.status_code == 400


def test_plaintext_cannot_impersonate_ciphertext(client):
    response = client.post("/attestations", json={"recipient": RECIPIENT, "data": "sf1:AAAA"})
    assert response.status_code == 422


# -- idempotency ------------------------------------------------------------------


def test_idempotent_retry_replays_first_response(client):
    headers = {"Idempotency-Key": "order-42"}
    body = {"recipient": RECIPIENT, "data": "once only"}
    first = client.post("/attestations", json=body, headers=headers)
    second = client.post("/attestations", json=body, headers=headers)

    assert first.status_code == second.status_code == 201
    assert first.json() == second.json()
    assert second.headers["Idempotent-Replayed"] == "true"
    assert "Idempotent-Replayed" not in first.headers
    assert len(client.get("/attestations").json()["items"]) == 1  # only one on the ledger


def test_idempotency_key_reused_with_different_body_is_422(client):
    headers = {"Idempotency-Key": "order-43"}
    client.post("/attestations", json={"recipient": RECIPIENT, "data": "a"}, headers=headers)
    response = client.post("/attestations", json={"recipient": RECIPIENT, "data": "b"}, headers=headers)
    assert response.status_code == 422


def test_idempotency_keys_are_scoped_per_client(client):
    body = {"recipient": RECIPIENT, "data": "shared key"}
    first = client.post("/attestations", json=body, headers={"Idempotency-Key": "k"})
    other = client.post("/attestations", json=body, headers={"Idempotency-Key": "k", "X-API-Key": OTHER_API_KEY})
    assert first.json()["uid"] != other.json()["uid"]


def test_failed_request_releases_idempotency_key(client):
    """A ledger failure must not burn the key, or the client could never retry."""
    body, headers = {"recipient": RECIPIENT, "data": "retry me"}, {"Idempotency-Key": "retry-me"}
    real = client.app.state.ledger
    client.app.state.ledger = _FailingLedger()
    try:
        assert client.post("/attestations", json=body, headers=headers).status_code == 503
    finally:
        client.app.state.ledger = real
    retry = client.post("/attestations", json=body, headers=headers)
    assert retry.status_code == 201
    assert "Idempotent-Replayed" not in retry.headers


class _FailingLedger:
    def create(self, *args, **kwargs):
        raise LedgerUnavailable("node down")


# -- listing ----------------------------------------------------------------------


def test_list_newest_first_with_filters(client):
    first = issue(client, "one")["uid"]
    second = issue(client, "two", recipient=OTHER_RECIPIENT)["uid"]
    third = issue(client, "three")["uid"]

    assert uids(client.get("/attestations")) == [third, second, first]
    assert uids(client.get("/attestations", params={"recipient": RECIPIENT})) == [third, first]


def test_list_status_filter(client):
    keep = issue(client, "keep")["uid"]
    gone = issue(client, "gone")["uid"]
    client.post(f"/attestations/{gone}/revoke")
    assert uids(client.get("/attestations", params={"status": "revoked"})) == [gone]
    assert uids(client.get("/attestations", params={"status": "valid"})) == [keep]


def test_cursor_pagination_walks_everything_once(client):
    created = [issue(client, f"n{i}")["uid"] for i in range(5)]
    seen, cursor = [], None
    while True:
        params = {"limit": 2, **({"cursor": cursor} if cursor else {})}
        page = client.get("/attestations", params=params).json()
        seen += [a["uid"] for a in page["items"]]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == list(reversed(created))


def test_bad_cursor_is_422(client):
    assert client.get("/attestations", params={"cursor": "!!!"}).status_code == 422


def test_list_rejects_bad_filter(client):
    assert client.get("/attestations", params={"issuer": "nope"}).status_code == 422
    assert client.get("/attestations", params={"status": "maybe"}).status_code == 422


# -- observability ----------------------------------------------------------------


def test_request_id_generated_and_propagated(client):
    assert len(client.get("/health").headers["X-Request-ID"]) == 32
    assert client.get("/health", headers={"X-Request-ID": "trace-abc"}).headers["X-Request-ID"] == "trace-abc"
    # Values that could inject into logs are replaced, not echoed.
    assert client.get("/health", headers={"X-Request-ID": "bad id\n"}).headers["X-Request-ID"] != "bad id\n"


def test_metrics_endpoint(client):
    issue(client)
    client.get(f"/attestations/{MISSING_UID}")
    text = client.get("/metrics").text
    assert 'secureflow_attestations_total{operation="created"} 1.0' in text
    assert 'secureflow_ledger_errors_total{error="AttestationNotFound"} 1.0' in text
    assert 'route="/attestations/{uid}"' in text  # templated route, not the raw uid


# -- recovery: the double-issue scenarios ------------------------------------------


class _TimesOutAfterBroadcast:
    """Wraps a ledger: the transaction lands on-chain, but the caller sees a timeout."""

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def create(self, recipient, data, expires_at=0, on_submitted=None):
        seen = {}

        def record(tx_hash):
            seen["tx"] = tx_hash
            if on_submitted:
                on_submitted(tx_hash)

        self._inner.create(recipient, data, expires_at, on_submitted=record)
        raise TransactionPending(seen["tx"], "not mined within 120s")


def test_timeout_after_broadcast_then_retry_does_not_issue_twice(client):
    body, headers = {"recipient": RECIPIENT, "data": "exactly once"}, {"Idempotency-Key": "flaky-1"}
    real = client.app.state.ledger
    client.app.state.ledger = _TimesOutAfterBroadcast(real)
    try:
        first = client.post("/attestations", json=body, headers=headers)
    finally:
        client.app.state.ledger = real
    assert first.status_code == 503
    assert "same Idempotency-Key" in first.json()["detail"]

    retry = client.post("/attestations", json=body, headers=headers)
    assert retry.status_code == 201
    assert retry.headers["Idempotent-Replayed"] == "true"
    assert len(client.get("/attestations").json()["items"]) == 1  # still exactly one on the ledger

    again = client.post("/attestations", json=body, headers=headers)
    assert again.json() == retry.json()


def test_retry_after_expiry_passed_replays_instead_of_422(client, clock, backend):
    if backend != "mock":
        pytest.skip("needs the controllable clock")
    body = {"recipient": RECIPIENT, "data": "short", "expires_at": clock.now + 5}
    headers = {"Idempotency-Key": "late-retry"}
    first = client.post("/attestations", json=body, headers=headers)
    clock.advance(10)
    retry = client.post("/attestations", json=body, headers=headers)
    assert retry.status_code == 201
    assert retry.json() == first.json()


def test_other_client_cannot_revoke(client):
    uid = issue(client)["uid"]
    response = client.post(f"/attestations/{uid}/revoke", headers={"X-API-Key": OTHER_API_KEY})
    assert response.status_code == 403
    assert "another API client" in response.json()["detail"]
    assert client.post(f"/attestations/{uid}/revoke").status_code == 200  # the owner still can
