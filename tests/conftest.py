from __future__ import annotations

import time

import pytest
from eth_tester import EthereumTester
from fastapi.testclient import TestClient
from web3 import EthereumTesterProvider, Web3

from secureflow.api import create_app
from secureflow.auth import KeyRing
from secureflow.crypto import PayloadCipher, generate_key
from secureflow.deploy import deploy
from secureflow.ledger import MockLedger
from secureflow.ledger.web3_ledger import Web3Ledger

RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
OTHER_RECIPIENT = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
API_KEY = "sf_test_issuer_key"
OTHER_API_KEY = "sf_test_other_key"


class FakeClock:
    """Controllable 'now' shared by the mock ledger and the API."""

    def __init__(self, start: int | None = None) -> None:
        self.now = start if start is not None else int(time.time())

    def __call__(self) -> int:
        return self.now

    def advance(self, seconds: int) -> None:
        self.now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def chain():
    """A fresh in-process EVM (py-evm via eth-tester) per test: no node, no network."""
    tester = EthereumTester()
    w3 = Web3(EthereumTesterProvider(tester))
    keys = [k.to_hex() for k in tester.backend.account_keys]
    return w3, keys, tester


@pytest.fixture
def deployed(chain):
    w3, keys, tester = chain
    deployment = deploy(w3, keys[0])
    return w3, keys, deployment


@pytest.fixture
def web3_ledger(deployed) -> Web3Ledger:
    w3, keys, deployment = deployed
    return Web3Ledger(
        private_key=keys[0],
        contract_address=deployment["address"],
        deployment_block=deployment["block_number"],
        w3=w3,
    )


@pytest.fixture
def cipher() -> PayloadCipher:
    return PayloadCipher(generate_key())


@pytest.fixture
def keyring() -> KeyRing:
    return KeyRing.from_keys(issuer=API_KEY, other=OTHER_API_KEY)


@pytest.fixture(params=["mock", "web3"])
def backend(request) -> str:
    return request.param


@pytest.fixture
def ledger(backend, clock, request):
    """Every API test runs against both adapters: they must behave identically."""
    if backend == "mock":
        return MockLedger(clock=clock)
    return request.getfixturevalue("web3_ledger")


@pytest.fixture
def app(ledger, cipher, keyring, clock, backend):
    # The web3 ledger uses the chain's clock; keep the API's "now" on wall time there.
    return create_app(ledger=ledger, cipher=cipher, keyring=keyring, clock=clock if backend == "mock" else None)


@pytest.fixture
def client(app):
    """Authenticated as the 'issuer' key."""
    with TestClient(app, headers={"X-API-Key": API_KEY}) as c:
        yield c


@pytest.fixture
def anon_client(app):
    with TestClient(app) as c:
        yield c


@pytest.fixture
def client_no_crypto(ledger):
    with TestClient(create_app(ledger=ledger)) as c:
        yield c
