"""Runtime configuration, read from environment variables (and .env if present)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

DEFAULT_DEPLOYMENT_FILE = "deployments/local.json"


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
            tx_timeout_seconds=int(os.getenv("SECUREFLOW_TX_TIMEOUT", "120")),
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
