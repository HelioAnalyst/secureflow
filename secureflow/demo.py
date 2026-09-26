"""Walk through the whole attestation lifecycle.

python -m secureflow.demo                                  # in-process, mock ledger, nothing to set up
python -m secureflow.demo --url http://localhost:8000 \\
    --api-key sf_demo_do_not_use_in_production              # against a running API (e.g. docker compose)

The API key can also come from SECUREFLOW_API_KEY.
"""

from __future__ import annotations

import argparse
import json
import os
import time
import uuid
from typing import Any

import httpx

RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"


def _show(title: str, response: httpx.Response, *headers: str) -> Any:
    body = response.json()
    print(f"\n== {title}  [{response.request.method} {response.request.url.path} -> {response.status_code}]")
    for name in headers:
        if name in response.headers:
            print(f"   {name}: {response.headers[name]}")
    print(json.dumps(body, indent=2))
    return body


def run(client: httpx.Client) -> None:
    health = _show("Service health", client.get("/health"))

    _show(
        "Writes need an API key",
        client.post("/attestations", json={"recipient": RECIPIENT, "data": "x"}, headers={"X-API-Key": "sf_wrong"}),
    )

    body = {"recipient": RECIPIENT, "data": "Completed: Advanced Python, grade A"}
    key = {"Idempotency-Key": f"demo-{uuid.uuid4()}"}
    created = _show(
        "Issue an attestation (with an Idempotency-Key)", client.post("/attestations", json=body, headers=key)
    )
    _show(
        "Retry the same request: replayed, no second transaction",
        client.post("/attestations", json=body, headers=key),
        "Idempotent-Replayed",
    )
    uid = created["uid"]
    _show("Verify it", client.get(f"/attestations/{uid}"))

    expires = int(time.time()) + 30 * 24 * 3600
    expiring = _show(
        "Issue one that expires in 30 days",
        client.post("/attestations", json={"recipient": RECIPIENT, "data": "Visitor pass", "expires_at": expires}),
    )
    _show("Verify it: note expires_at", client.get(f"/attestations/{expiring['uid']}"))

    if health["encryption"]:
        sealed = _show(
            "Issue an encrypted attestation (only ciphertext goes on-chain)",
            client.post(
                "/attestations", json={"recipient": RECIPIENT, "data": "Salary band: confidential", "encrypt": True}
            ),
        )
        _show("Verify it: decrypted by the service", client.get(f"/attestations/{sealed['uid']}"))

    _show("Revoke the first one", client.post(f"/attestations/{uid}/revoke"))
    _show("Verify again: now invalid", client.get(f"/attestations/{uid}"))
    _show("Revoking twice is rejected", client.post(f"/attestations/{uid}/revoke"))

    page = _show("List, 2 per page (served from the index)", client.get("/attestations", params={"limit": 2}))
    if page["next_cursor"]:
        _show("Next page via cursor", client.get("/attestations", params={"limit": 2, "cursor": page["next_cursor"]}))
    _show("Only valid ones", client.get("/attestations", params={"status": "valid"}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", help="base URL of a running SecureFlow API")
    parser.add_argument("--api-key", default=os.getenv("SECUREFLOW_API_KEY"), help="key for issuing and revoking")
    args = parser.parse_args()

    if args.url:
        headers = {"X-API-Key": args.api_key} if args.api_key else {}
        with httpx.Client(base_url=args.url, timeout=60, headers=headers) as client:
            run(client)
        return

    from fastapi.testclient import TestClient

    from .api import create_app
    from .auth import KeyRing
    from .auth import generate_key as generate_api_key
    from .crypto import PayloadCipher, generate_key
    from .ledger import MockLedger

    api_key = generate_api_key()
    app = create_app(ledger=MockLedger(), cipher=PayloadCipher(generate_key()), keyring=KeyRing.from_keys(demo=api_key))
    with TestClient(app, headers={"X-API-Key": api_key}) as client:
        run(client)


if __name__ == "__main__":
    main()
