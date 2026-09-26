"""HTTP API.

    uvicorn secureflow.api:app --reload

Routes
------
GET  /health                       backend, chain id, issuer, latest block
POST /attestations                 issue an attestation (optionally encrypted)
GET  /attestations                 list, newest first; filter by issuer/recipient
GET  /attestations/{uid}           verify one attestation
POST /attestations/{uid}/revoke    revoke (issuer only)
"""

from __future__ import annotations

from typing import Annotated

from eth_utils import is_address, to_checksum_address
from fastapi import Depends, FastAPI, HTTPException, Path, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from . import __version__
from .config import Settings
from .crypto import CryptoError, PayloadCipher, is_encrypted
from .ledger import (
    AlreadyRevoked,
    Attestation,
    AttestationNotFound,
    InvalidInput,
    Ledger,
    LedgerError,
    LedgerUnavailable,
    NotIssuer,
    build_ledger,
)

UID_PATTERN = r"^0x[0-9a-fA-F]{64}$"
MAX_DATA_BYTES = 4096


# -- schemas ------------------------------------------------------------------


def _checksum(value: str) -> str:
    if not is_address(value):
        raise ValueError("not a valid Ethereum address")
    return to_checksum_address(value)


class AttestationIn(BaseModel):
    recipient: str = Field(examples=["0x70997970C51812dc3A010C7d01b50e0d17dc79C8"])
    data: str = Field(min_length=1, examples=["Completed: Advanced Python, grade A"])
    encrypt: bool = Field(False, description="Seal `data` with AES-256-GCM before it goes on-chain.")

    @field_validator("recipient")
    @classmethod
    def _recipient(cls, v: str) -> str:
        address = _checksum(v)
        if int(address, 16) == 0:
            raise ValueError("recipient cannot be the zero address")
        return address

    @field_validator("data")
    @classmethod
    def _data_size(cls, v: str) -> str:
        if len(v.encode("utf-8")) > MAX_DATA_BYTES:
            raise ValueError(f"data must be at most {MAX_DATA_BYTES} bytes")
        return v


class TxOut(BaseModel):
    uid: str
    tx_hash: str
    block_number: int


class AttestationOut(BaseModel):
    uid: str
    issuer: str
    recipient: str
    data: str | None = Field(description="Plaintext, or null if encrypted and this service cannot decrypt it.")
    encrypted: bool
    ciphertext: str | None = Field(None, description="The on-chain value, when `data` was encrypted.")
    block_number: int
    timestamp: int
    revoked: bool
    valid: bool = Field(description="True when the attestation exists and has not been revoked.")


class HealthOut(BaseModel):
    status: str
    version: str
    backend: str
    chain_id: int
    issuer: str
    contract_address: str | None
    latest_block: int
    encryption: bool


# -- dependencies -------------------------------------------------------------


def get_ledger(request: Request) -> Ledger:
    return request.app.state.ledger


def get_cipher(request: Request) -> PayloadCipher | None:
    return request.app.state.cipher


LedgerDep = Annotated[Ledger, Depends(get_ledger)]
CipherDep = Annotated[PayloadCipher | None, Depends(get_cipher)]
Uid = Annotated[str, Path(pattern=UID_PATTERN, description="32-byte attestation uid, 0x-prefixed hex")]


# -- app ----------------------------------------------------------------------


def create_app(
    ledger: Ledger | None = None, cipher: PayloadCipher | None = None, settings: Settings | None = None
) -> FastAPI:
    """Build the app. Tests pass their own ledger/cipher; production reads env."""
    if ledger is None:
        settings = settings or Settings.from_env()
        ledger = build_ledger(settings)
    if cipher is None and settings is not None and settings.encryption_key:
        cipher = PayloadCipher(settings.encryption_key)

    app = FastAPI(
        title="SecureFlow",
        version=__version__,
        description="Issue, verify and revoke attestations on an Ethereum smart contract.",
    )
    app.state.ledger = ledger
    app.state.cipher = cipher

    @app.exception_handler(LedgerError)
    async def _ledger_error(_: Request, exc: LedgerError) -> JSONResponse:
        mapping = {
            AttestationNotFound: (status.HTTP_404_NOT_FOUND, "attestation not found"),
            AlreadyRevoked: (status.HTTP_409_CONFLICT, "attestation already revoked"),
            NotIssuer: (status.HTTP_403_FORBIDDEN, "only the issuer can revoke this attestation"),
            InvalidInput: (422, str(exc)),
            LedgerUnavailable: (status.HTTP_503_SERVICE_UNAVAILABLE, str(exc)),
        }
        code, detail = mapping.get(type(exc), (status.HTTP_502_BAD_GATEWAY, str(exc)))
        return JSONResponse(status_code=code, content={"detail": detail})

    def render(a: Attestation, cipher: PayloadCipher | None) -> AttestationOut:
        encrypted = is_encrypted(a.data)
        data: str | None = a.data
        if encrypted:
            data = None
            if cipher is not None:
                try:
                    data = cipher.decrypt(a.data, a.recipient)
                except CryptoError:
                    data = None
        return AttestationOut(
            uid=a.uid,
            issuer=a.issuer,
            recipient=a.recipient,
            data=data,
            encrypted=encrypted,
            ciphertext=a.data if encrypted else None,
            block_number=a.block_number,
            timestamp=a.timestamp,
            revoked=a.revoked,
            valid=not a.revoked,
        )

    @app.get("/health", response_model=HealthOut, tags=["meta"])
    def health(ledger: LedgerDep, cipher: CipherDep) -> HealthOut:
        info = ledger.info()
        return HealthOut(status="ok", version=__version__, encryption=cipher is not None, **info.__dict__)

    @app.post("/attestations", response_model=TxOut, status_code=status.HTTP_201_CREATED, tags=["attestations"])
    def create_attestation(body: AttestationIn, ledger: LedgerDep, cipher: CipherDep) -> TxOut:
        data = body.data
        if body.encrypt:
            if cipher is None:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST, "encryption requested but SECUREFLOW_ENCRYPTION_KEY is not configured"
                )
            data = cipher.encrypt(data, body.recipient)
        elif is_encrypted(data):
            raise HTTPException(422, "plaintext data must not start with 'sf1:'")
        result = ledger.create(body.recipient, data)
        return TxOut(**result.__dict__)

    @app.get("/attestations", response_model=list[AttestationOut], tags=["attestations"])
    def list_attestations(
        ledger: LedgerDep,
        cipher: CipherDep,
        issuer: str | None = None,
        recipient: str | None = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> list[AttestationOut]:
        for name, value in (("issuer", issuer), ("recipient", recipient)):
            if value is not None and not is_address(value):
                raise HTTPException(422, f"{name} is not a valid Ethereum address")
        return [render(a, cipher) for a in ledger.list(issuer=issuer, recipient=recipient, limit=limit)]

    @app.get("/attestations/{uid}", response_model=AttestationOut, tags=["attestations"])
    def verify_attestation(uid: Uid, ledger: LedgerDep, cipher: CipherDep) -> AttestationOut:
        return render(ledger.get(uid), cipher)

    @app.post("/attestations/{uid}/revoke", response_model=TxOut, tags=["attestations"])
    def revoke_attestation(uid: Uid, ledger: LedgerDep) -> TxOut:
        return TxOut(**ledger.revoke(uid).__dict__)

    return app


def __getattr__(name: str):
    # `uvicorn secureflow.api:app` builds the app on first access rather than
    # at import, so importing this module never needs env vars or a node.
    if name == "app":
        global app
        app = create_app()
        return app
    raise AttributeError(name)
