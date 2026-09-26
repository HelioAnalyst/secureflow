from __future__ import annotations

import pytest
from eth_tester import EthereumTester
from fastapi.testclient import TestClient
from web3 import EthereumTesterProvider, Web3

from secureflow.api import create_app
from secureflow.crypto import PayloadCipher, generate_key
from secureflow.deploy import deploy
from secureflow.ledger import MockLedger
from secureflow.ledger.web3_ledger import Web3Ledger

RECIPIENT = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
OTHER_RECIPIENT = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"


@pytest.fixture
def chain():
    """A fresh in-process EVM (py-evm via eth-tester) per test: no node, no network."""
    tester = EthereumTester()
    w3 = Web3(EthereumTesterProvider(tester))
    keys = [k.to_hex() for k in tester.backend.account_keys]
    return w3, keys


@pytest.fixture
def deployed(chain):
    w3, keys = chain
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


@pytest.fixture(params=["mock", "web3"])
def ledger(request):
    """Every API test runs against both adapters: they must behave identically."""
    if request.param == "mock":
        return MockLedger()
    return request.getfixturevalue("web3_ledger")


@pytest.fixture
def client(ledger, cipher):
    with TestClient(create_app(ledger=ledger, cipher=cipher)) as c:
        yield c


@pytest.fixture
def client_no_crypto(ledger):
    with TestClient(create_app(ledger=ledger)) as c:
        yield c
