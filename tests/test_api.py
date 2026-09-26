"""HTTP behaviour. Parametrised over both ledgers via the `ledger` fixture."""

from __future__ import annotations

from tests.conftest import OTHER_RECIPIENT, RECIPIENT

MISSING_UID = "0x" + "ab" * 32


def issue(client, data="hello", recipient=RECIPIENT, **extra):
    response = client.post("/attestations", json={"recipient": recipient, "data": data, **extra})
    assert response.status_code == 201, response.text
    return response.json()


def test_health(client, ledger):
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["backend"] in {"mock", "web3"}
    assert body["encryption"] is True
    assert body["issuer"].startswith("0x")


def test_issue_and_verify(client):
    created = issue(client, "Completed: Advanced Python")
    assert len(created["uid"]) == 66
    assert created["tx_hash"].startswith("0x")

    record = client.get(f"/attestations/{created['uid']}").json()
    assert record["data"] == "Completed: Advanced Python"
    assert record["recipient"] == RECIPIENT
    assert record["encrypted"] is False
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


def test_revoke_lifecycle(client):
    uid = issue(client)["uid"]
    assert client.post(f"/attestations/{uid}/revoke").status_code == 200

    record = client.get(f"/attestations/{uid}").json()
    assert record["revoked"] is True
    assert record["valid"] is False

    assert client.post(f"/attestations/{uid}/revoke").status_code == 409


def test_revoke_unknown_is_404(client):
    assert client.post(f"/attestations/{MISSING_UID}/revoke").status_code == 404


def test_encrypted_attestation_round_trip(client):
    uid = issue(client, "secret salary band", encrypt=True)["uid"]
    record = client.get(f"/attestations/{uid}").json()
    assert record["encrypted"] is True
    assert record["data"] == "secret salary band"
    assert record["ciphertext"].startswith("sf1:")
    assert "secret" not in record["ciphertext"]


def test_encrypted_data_unreadable_without_key(ledger, client, client_no_crypto):
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


def test_list_newest_first_with_filters(client):
    first = issue(client, "one")["uid"]
    second = issue(client, "two", recipient=OTHER_RECIPIENT)["uid"]
    third = issue(client, "three")["uid"]

    everything = [a["uid"] for a in client.get("/attestations").json()]
    assert everything == [third, second, first]

    mine = [a["uid"] for a in client.get("/attestations", params={"recipient": RECIPIENT}).json()]
    assert mine == [third, first]

    limited = client.get("/attestations", params={"limit": 1}).json()
    assert [a["uid"] for a in limited] == [third]


def test_list_rejects_bad_filter(client):
    assert client.get("/attestations", params={"issuer": "nope"}).status_code == 422
