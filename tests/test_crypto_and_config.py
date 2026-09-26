from __future__ import annotations

import base64
import json

import pytest

from secureflow.config import ConfigError, Settings
from secureflow.crypto import CryptoError, PayloadCipher, generate_key
from secureflow.ledger import MockLedger, build_ledger
from secureflow.ledger.web3_ledger import Web3Ledger

ALICE = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
BOB = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"


# -- crypto ---------------------------------------------------------------------


def test_round_trip():
    c = PayloadCipher(generate_key())
    assert c.decrypt(c.encrypt("héllo ✓", ALICE), ALICE) == "héllo ✓"


def test_nonce_is_random():
    c = PayloadCipher(generate_key())
    assert c.encrypt("same", ALICE) != c.encrypt("same", ALICE)


def test_key_survives_new_instance():
    """The original module generated a key at import, so nothing survived a restart."""
    key = generate_key()
    sealed = PayloadCipher(key).encrypt("persisted", ALICE)
    assert PayloadCipher(key).decrypt(sealed, ALICE) == "persisted"


def test_wrong_key_fails():
    sealed = PayloadCipher(generate_key()).encrypt("x", ALICE)
    with pytest.raises(CryptoError):
        PayloadCipher(generate_key()).decrypt(sealed, ALICE)


def test_ciphertext_bound_to_recipient():
    c = PayloadCipher(generate_key())
    with pytest.raises(CryptoError):
        c.decrypt(c.encrypt("x", ALICE), BOB)


def test_tampering_detected():
    c = PayloadCipher(generate_key())
    sealed = c.encrypt("x", ALICE)
    raw = bytearray(base64.b64decode(sealed[4:]))
    raw[-1] ^= 1
    with pytest.raises(CryptoError):
        c.decrypt("sf1:" + base64.b64encode(bytes(raw)).decode(), ALICE)


@pytest.mark.parametrize("bad", ["not base64!!", base64.b64encode(b"short").decode()])
def test_bad_keys_rejected(bad):
    with pytest.raises(CryptoError):
        PayloadCipher(bad)


# -- config ---------------------------------------------------------------------


@pytest.fixture
def clean_env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)  # no stray .env
    for var in (
        "SECUREFLOW_BACKEND",
        "ETH_RPC_URL",
        "INFURA_URL",
        "ETH_PRIVATE_KEY",
        "CONTRACT_ADDRESS",
        "SECUREFLOW_DEPLOYMENT_FILE",
        "SECUREFLOW_ENCRYPTION_KEY",
        "SECUREFLOW_API_KEYS",
        "SECUREFLOW_DB",
        "SECUREFLOW_INDEX_CONFIRMATIONS",
        "SECUREFLOW_INDEX_CHUNK",
    ):
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


def test_defaults_to_mock(clean_env):
    settings = Settings.from_env()
    assert settings.backend == "mock"
    assert isinstance(build_ledger(settings), MockLedger)


def test_unknown_backend_rejected(clean_env):
    clean_env.setenv("SECUREFLOW_BACKEND", "sqlite")
    with pytest.raises(ConfigError):
        Settings.from_env()


def test_infura_url_still_accepted(clean_env):
    clean_env.setenv("INFURA_URL", "http://legacy:7545")
    assert Settings.from_env().rpc_url == "http://legacy:7545"


def test_web3_backend_reads_deployment_file(clean_env, tmp_path):
    path = tmp_path / "deployment.json"
    path.write_text(json.dumps({"address": "0x" + "12" * 20, "block_number": 7}))
    clean_env.setenv("SECUREFLOW_BACKEND", "web3")
    clean_env.setenv("ETH_PRIVATE_KEY", "0x" + "01" * 32)
    clean_env.setenv("SECUREFLOW_DEPLOYMENT_FILE", str(path))
    ledger = build_ledger(Settings.from_env())
    assert isinstance(ledger, Web3Ledger)
    assert ledger._deployment_block == 7


def test_web3_backend_without_deployment_explains_itself(clean_env):
    clean_env.setenv("SECUREFLOW_BACKEND", "web3")
    with pytest.raises(ConfigError, match="secureflow.deploy"):
        build_ledger(Settings.from_env())


def test_importing_api_needs_nothing(clean_env):
    import importlib

    import secureflow.api

    importlib.reload(secureflow.api)  # no node, no env, no error
