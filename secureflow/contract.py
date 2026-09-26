"""Access to the compiled AttestationRegistry artifact."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources

from eth_utils import keccak

CONTRACT_NAME = "AttestationRegistry"


@lru_cache(maxsize=1)
def artifact() -> dict:
    text = resources.files("secureflow").joinpath(f"{CONTRACT_NAME}.json").read_text(encoding="utf-8")
    return json.loads(text)


def abi() -> list[dict]:
    return artifact()["abi"]


def bytecode() -> str:
    return artifact()["bytecode"]


@lru_cache(maxsize=1)
def error_selectors() -> dict[str, str]:
    """Map 4-byte selector (0x-prefixed hex) -> custom error name."""
    selectors = {}
    for item in abi():
        if item["type"] != "error":
            continue
        signature = f"{item['name']}({','.join(i['type'] for i in item['inputs'])})"
        selectors["0x" + keccak(text=signature)[:4].hex()] = item["name"]
    return selectors
