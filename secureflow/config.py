"""Runtime configuration, read from environment variables (and .env if present)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

DEFAULT_DEPLOYMENT_FILE = "deployments/local.json"


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from None


class ConfigError(RuntimeError):
    """Raised when the configuration is incomplete for the selected backend."""


@dataclass(frozen=True)
class Settings:
    backend: str = "mock"  # "mock" or "web3"
    rpc_url: str = "http://127.0.0.1:8545"
    private_key: str | None = None
    contract_address: str | None = None
    deployment_file: str = DEFAULT_DEPLOYMENT_FILE
    encryption_key: str | None = None  # base64, 32 bytes
    tx_timeout_seconds: int = 120
    api_keys: str | None = None  # "name:sha256hex,name:sha256hex"
    db_path: str = ":memory:"
    index_confirmations: int = 0
    index_chunk_size: int = 2_000
    log_level: str = "INFO"
    log_json: bool = True

    @classmethod
    def from_env(cls) -> Settings:
        load_dotenv()
        backend = os.getenv("SECUREFLOW_BACKEND", "mock").strip().lower()
        if backend not in {"mock", "web3"}:
            raise ConfigError(f"SECUREFLOW_BACKEND must be 'mock' or 'web3', got {backend!r}")
        return cls(
            backend=backend,
            # INFURA_URL is accepted for compatibility with older .env files.
            rpc_url=os.getenv("ETH_RPC_URL") or os.getenv("INFURA_URL") or cls.rpc_url,
            private_key=os.getenv("ETH_PRIVATE_KEY") or None,
            contract_address=os.getenv("CONTRACT_ADDRESS") or None,
            deployment_file=os.getenv("SECUREFLOW_DEPLOYMENT_FILE", DEFAULT_DEPLOYMENT_FILE),
            encryption_key=os.getenv("SECUREFLOW_ENCRYPTION_KEY") or None,
            tx_timeout_seconds=_int("SECUREFLOW_TX_TIMEOUT", 120),
            api_keys=os.getenv("SECUREFLOW_API_KEYS") or None,
            db_path=os.getenv("SECUREFLOW_DB", ":memory:"),
            index_confirmations=_int("SECUREFLOW_INDEX_CONFIRMATIONS", 0),
            index_chunk_size=_int("SECUREFLOW_INDEX_CHUNK", 2_000),
            log_level=os.getenv("SECUREFLOW_LOG_LEVEL", "INFO").upper(),
            log_json=os.getenv("SECUREFLOW_LOG_FORMAT", "json").lower() != "text",
        )

    def validate(self) -> None:
        """Refuse configurations that would be unsafe to serve."""
        from .auth import AuthConfigError, parse_key_hashes

        try:
            keys = parse_key_hashes(self.api_keys)
        except AuthConfigError as exc:
            raise ConfigError(str(exc)) from None
        if self.backend == "web3" and not keys:  # parsed, so " " or "," can't sneak through
            raise ConfigError(
                "SECUREFLOW_API_KEYS is required with the web3 backend: without it anyone could "
                "spend the issuer's gas. Generate one with `python -m secureflow.auth`."
            )

    def resolve_deployment(self) -> tuple[str, int]:
        """Return (contract_address, deployment_block).

        CONTRACT_ADDRESS wins if set (logs are then scanned from block 0);
        otherwise the file written by ``python -m secureflow.deploy`` is used.
        """
        if self.contract_address:
            return self.contract_address, 0
        path = Path(self.deployment_file)
        if not path.is_file():
            raise ConfigError(
                f"No CONTRACT_ADDRESS set and no deployment file at {path}. Run `python -m secureflow.deploy` first."
            )
        data = json.loads(path.read_text(encoding="utf-8"))
        return data["address"], int(data.get("block_number", 0))
