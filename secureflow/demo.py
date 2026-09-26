"""Walk through the whole attestation lifecycle.

python -m secureflow.demo                              # in-process, mock ledger, nothing to set up
python -m secureflow.demo --url http://localhost:8000  # against a running API (e.g. docker compose)
"""

from __future__ import annotations

import argparse
import json

import httpx

RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"


def _show(title: str, response: httpx.Response) -> dict | list:
    body = response.json()
    print(f"\n== {title}  [{response.request.method} {response.request.url.path} -> {response.status_code}]")
    print(json.dumps(body, indent=2))
    return body


def run(client: httpx.Client) -> None:
    health = _show("Service health", client.get("/health"))

    created = _show(
        "Issue a plaintext attestation",
        client.post("/attestations", json={"recipient": RECIPIENT, "data": "Completed: Advanced Python, grade A"}),
    )
    uid = created["uid"]
    _show("Verify it", client.get(f"/attestations/{uid}"))

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
    _show("List attestations for the recipient", client.get("/attestations", params={"recipient": RECIPIENT}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", help="base URL of a running SecureFlow API")
    args = parser.parse_args()

    if args.url:
        with httpx.Client(base_url=args.url, timeout=60) as client:
            run(client)
        return

    from fastapi.testclient import TestClient

    from .api import create_app
    from .crypto import PayloadCipher, generate_key
    from .ledger import MockLedger

    app = create_app(ledger=MockLedger(), cipher=PayloadCipher(generate_key()))
    with TestClient(app) as client:
        run(client)


if __name__ == "__main__":
    main()
