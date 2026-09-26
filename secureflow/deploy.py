"""Deploy AttestationRegistry and record where it went.

    python -m secureflow.deploy                       # uses ETH_RPC_URL / ETH_PRIVATE_KEY
    python -m secureflow.deploy --out deployments/local.json

Writes ``{"address", "block_number", "chain_id", "tx_hash"}`` to the output
file, which the API reads when CONTRACT_ADDRESS is not set.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from eth_account import Account
from web3 import Web3

from . import contract as artifact
from .config import Settings


def deploy(w3: Web3, private_key: str) -> dict:
    account = Account.from_key(private_key)
    factory = w3.eth.contract(abi=artifact.abi(), bytecode=artifact.bytecode())
    constructor = factory.constructor()
    tx = constructor.build_transaction(
        {
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address, "pending"),
            "gas": int(constructor.estimate_gas({"from": account.address}) * 1.2),
            "chainId": w3.eth.chain_id,
        }
    )
    tx_hash = w3.eth.send_raw_transaction(account.sign_transaction(tx).raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180)
    if receipt["status"] != 1:
        raise RuntimeError(f"deployment transaction {tx_hash.hex()} reverted")
    return {
        "address": receipt["contractAddress"],
        "block_number": receipt["blockNumber"],
        "chain_id": w3.eth.chain_id,
        "tx_hash": "0x" + tx_hash.hex().removeprefix("0x"),
    }


def main() -> None:
    settings = Settings.from_env()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rpc-url", default=settings.rpc_url)
    parser.add_argument("--out", default=settings.deployment_file)
    args = parser.parse_args()

    if not settings.private_key:
        parser.error("ETH_PRIVATE_KEY is not set")
    w3 = Web3(Web3.HTTPProvider(args.rpc_url))
    if not w3.is_connected():
        parser.error(f"cannot reach Ethereum node at {args.rpc_url}")

    result = deploy(w3, settings.private_key)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"AttestationRegistry deployed at {result['address']}")
    print(f"  chain {result['chain_id']}, block {result['block_number']}, tx {result['tx_hash']}")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
