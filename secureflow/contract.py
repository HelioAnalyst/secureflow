"""Access to the compiled AttestationRegistry artifact."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import Any, cast

from eth_utils import keccak

CONTRACT_NAME = "AttestationRegistry"


@lru_cache(maxsize=1)
def artifact() -> dict[str, Any]:
    text = resources.files("secureflow").joinpath(f"{CONTRACT_NAME}.json").read_text(encoding="utf-8")
    return cast(dict[str, Any], json.loads(text))


def abi() -> list[dict[str, Any]]:
    return cast(list[dict[str, Any]], artifact()["abi"])


def bytecode() -> str:
    return str(artifact()["bytecode"])


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
