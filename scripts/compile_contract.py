"""Compile contracts/AttestationRegistry.sol into secureflow/AttestationRegistry.json.

The compiled artifact is committed to the repo, so you only need this after
changing the Solidity source.

    python scripts/compile_contract.py                 # installs solc via py-solc-x
    python scripts/compile_contract.py --solc ./solc   # use a solc binary you already have
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import solcx

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "contracts" / "AttestationRegistry.sol"
ARTIFACT = ROOT / "secureflow" / "AttestationRegistry.json"
CONTRACT = "AttestationRegistry"
SOLC_VERSION = "0.8.28"
# "paris" avoids PUSH0, so the bytecode runs on Ganache, Anvil, Hardhat,
# eth-tester and every public testnet.
EVM_VERSION = "paris"


def compile_contract(solc_binary: str | None = None) -> dict:
    standard_input = {
        "language": "Solidity",
        "sources": {SOURCE.name: {"content": SOURCE.read_text(encoding="utf-8")}},
        "settings": {
            "evmVersion": EVM_VERSION,
            "optimizer": {"enabled": True, "runs": 200},
            "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object"]}},
        },
    }
    if solc_binary:
        output = solcx.compile_standard(standard_input, solc_binary=solc_binary)
    else:
        solcx.install_solc(SOLC_VERSION)
        output = solcx.compile_standard(standard_input, solc_version=SOLC_VERSION)

    compiled = output["contracts"][SOURCE.name][CONTRACT]
    return {
        "contractName": CONTRACT,
        "compiler": {"solc": SOLC_VERSION, "evmVersion": EVM_VERSION, "optimizerRuns": 200},
        "abi": compiled["abi"],
        "bytecode": "0x" + compiled["evm"]["bytecode"]["object"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--solc", help="path to a solc binary (skips the py-solc-x download)")
    args = parser.parse_args()

    artifact = compile_contract(args.solc)
    ARTIFACT.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {ARTIFACT.relative_to(ROOT)} ({len(artifact['bytecode']) // 2 - 1} bytes of bytecode)")


if __name__ == "__main__":
    main()
