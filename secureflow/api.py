"""HTTP API.

    uvicorn secureflow.api:app --reload

Routes
------
GET  /health                       backend, chain id, issuer, latest block, index position
GET  /metrics                      Prometheus metrics
POST /attestations                 issue (API key; supports Idempotency-Key)
GET  /attestations                 list from the index, newest first, cursor-paginated
GET  /attestations/{uid}           verify one attestation against the contract
POST /attestations/{uid}/revoke    revoke (API key; issuer only)
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Annotated, Any

from eth_utils import is_address, to_checksum_address
from fastapi import Depends, FastAPI, Header, HTTPException, Path, Query, Request, Security, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse, Response
from fastapi.security import APIKeyHeader
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel, Field, field_validator

from . import __version__
from .auth import KeyRing, Principal, parse_key_hashes
from .config import Settings
from .crypto import CryptoError, PayloadCipher, is_encrypted
from .db import Database
from .idempotency import (
    MAX_KEY_LENGTH,
    IdempotencyConflict,
    IdempotencyMismatch,
    IdempotencyStore,
    InDoubt,
    Replay,
    fingerprint,
)
from .index import AttestationIndex, Status
from .ledger import (
    AlreadyRevoked,
    Attestation,
    AttestationNotFound,
    InvalidInput,
    Ledger,
    LedgerError,
    LedgerUnavailable,
    NotIssuer,
    TransactionPending,
    TxResult,
    build_ledger,
)
from .observability import Metrics, configure_logging, logger, request_context_middleware

app: FastAPI  # built lazily by __getattr__ below; declared for type checkers

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
    expires_at: int | None = Field(
        None, gt=0, lt=2**64, description="Unix time (seconds) after which the attestation is invalid. Omit for never."
    )

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
    expires_at: int | None = Field(description="Unix time the attestation expires, or null for never.")
    revoked: bool
    expired: bool
    valid: bool = Field(description="Exists, not revoked and not expired.")


class AttestationPage(BaseModel):
    items: list[AttestationOut]
    next_cursor: str | None = Field(description="Pass as `cursor` to fetch the next page; null on the last page.")


class HealthOut(BaseModel):
    status: str
    version: str
    backend: str
    chain_id: int
    issuer: str
    contract_address: str | None
    latest_block: int
    index_synced_to: int
    encryption: bool
    auth: bool


# -- dependencies -------------------------------------------------------------


def get_ledger(request: Request) -> Ledger:
    ledger: Ledger = request.app.state.ledger
    return ledger


def get_cipher(request: Request) -> PayloadCipher | None:
    cipher: PayloadCipher | None = request.app.state.cipher
    return cipher


def get_index(request: Request) -> AttestationIndex:
    index: AttestationIndex = request.app.state.index
    return index


def get_now(request: Request) -> int:
    clock: Callable[[], int] = request.app.state.clock
    return clock()


_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False, description="Required for issuing and revoking.")


def require_principal(request: Request, key: Annotated[str | None, Security(_api_key_header)]) -> Principal:
    keyring: KeyRing = request.app.state.keyring
    principal = keyring.authenticate(key)
    if principal is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "missing or invalid API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return principal


LedgerDep = Annotated[Ledger, Depends(get_ledger)]
CipherDep = Annotated[PayloadCipher | None, Depends(get_cipher)]
IndexDep = Annotated[AttestationIndex, Depends(get_index)]
NowDep = Annotated[int, Depends(get_now)]
PrincipalDep = Annotated[Principal, Depends(require_principal)]
Uid = Annotated[str, Path(pattern=UID_PATTERN, description="32-byte attestation uid, 0x-prefixed hex")]
IdempotencyKey = Annotated[
    str | None,
    Header(
        alias="Idempotency-Key",
        max_length=MAX_KEY_LENGTH,
        description="Unique per logical request. Retries with the same key replay the first response.",
    ),
]


def render(a: Attestation, cipher: PayloadCipher | None, now: int) -> AttestationOut:
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
        expires_at=a.expires_at or None,
        revoked=a.revoked,
        expired=a.is_expired(now),
        valid=a.is_valid(now),
    )


# -- app ----------------------------------------------------------------------

_ERROR_STATUS: dict[type[LedgerError], int] = {
    AttestationNotFound: status.HTTP_404_NOT_FOUND,
    AlreadyRevoked: status.HTTP_409_CONFLICT,
    NotIssuer: status.HTTP_403_FORBIDDEN,
    InvalidInput: 422,
    LedgerUnavailable: status.HTTP_503_SERVICE_UNAVAILABLE,
    TransactionPending: status.HTTP_503_SERVICE_UNAVAILABLE,
}
_ERROR_DETAIL: dict[type[LedgerError], str] = {
    AttestationNotFound: "attestation not found",
    AlreadyRevoked: "attestation already revoked",
    NotIssuer: "only the issuer can revoke this attestation",
}


def create_app(
    ledger: Ledger | None = None,
    cipher: PayloadCipher | None = None,
    settings: Settings | None = None,
    *,
    keyring: KeyRing | None = None,
    db: Database | None = None,
    clock: Callable[[], int] | None = None,
) -> FastAPI:
    """Build the app.

    Production calls this with nothing and everything comes from the
    environment. Tests inject a ledger, cipher, keyring and clock; any part
    left out falls back to a safe default (in-memory DB, auth off unless a
    keyring is given).
    """
    if ledger is None:
        settings = settings or Settings.from_env()
        settings.validate()
        configure_logging(settings.log_level, settings.log_json)
        ledger = build_ledger(settings)
    if cipher is None and settings is not None and settings.encryption_key:
        cipher = PayloadCipher(settings.encryption_key)
    if keyring is None:
        keyring = KeyRing(parse_key_hashes(settings.api_keys if settings else None))
    if db is None:
        db = Database(settings.db_path if settings else ":memory:")

    app = FastAPI(
        title="SecureFlow",
        version=__version__,
        description="Issue, verify and revoke attestations on an Ethereum smart contract.",
    )
    metrics = Metrics()
    app.state.ledger = ledger
    app.state.cipher = cipher
    app.state.keyring = keyring
    app.state.clock = clock or (lambda: int(time.time()))
    app.state.metrics = metrics
    app.state.index = AttestationIndex(
        db,
        ledger,
        confirmations=settings.index_confirmations if settings else 0,
        chunk_size=settings.index_chunk_size if settings else 2_000,
    )
    idempotency = IdempotencyStore(db)
    app.middleware("http")(request_context_middleware(metrics))

    @app.exception_handler(LedgerError)
    async def _ledger_error(_: Request, exc: LedgerError) -> JSONResponse:
        code = _ERROR_STATUS.get(type(exc), status.HTTP_502_BAD_GATEWAY)
        detail = _ERROR_DETAIL.get(type(exc), str(exc))
        if isinstance(exc, TransactionPending):
            detail += "; retry with the same Idempotency-Key to pick up the result without issuing twice"
        metrics.ledger_errors.labels(type(exc).__name__).inc()
        level = logging.WARNING if code >= 500 else logging.INFO
        logger.log(level, "ledger error", extra={"error": type(exc).__name__, "detail": str(exc)})
        return JSONResponse(status_code=code, content={"detail": detail})

    @app.exception_handler(IdempotencyConflict)
    async def _idem_conflict(_: Request, exc: IdempotencyConflict) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"detail": "a request with this Idempotency-Key is still in progress"},
            headers={"Retry-After": "1"},
        )

    @app.exception_handler(IdempotencyMismatch)
    async def _idem_mismatch(_: Request, exc: IdempotencyMismatch) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={"detail": "this Idempotency-Key was already used with a different request"},
        )

    @app.get("/health", response_model=HealthOut, tags=["meta"])
    def health(ledger: LedgerDep, cipher: CipherDep, index: IndexDep) -> HealthOut:
        info = ledger.info()
        return HealthOut(
            status="ok",
            version=__version__,
            encryption=cipher is not None,
            auth=keyring.enabled,
            index_synced_to=index.synced_to,
            **info.__dict__,
        )

    @app.get("/metrics", tags=["meta"], response_class=Response)
    def prometheus_metrics() -> Response:
        return Response(generate_latest(metrics.registry), media_type=CONTENT_TYPE_LATEST)

    def finish_create(result: TxResult, principal: Principal, key: str | None, replayed: bool) -> Any:
        out = TxOut(**result.__dict__)
        body = jsonable_encoder(out)
        db.set_owner(out.uid, principal.name)
        if key:
            idempotency.complete(principal.name, key, status.HTTP_201_CREATED, body)
        metrics.attestations.labels("created").inc()
        logger.info(
            "attestation created",
            extra={"uid": out.uid, "tx_hash": out.tx_hash, "principal": principal.name, "recovered": replayed},
        )
        if replayed:
            return JSONResponse(body, status.HTTP_201_CREATED, headers={"Idempotent-Replayed": "true"})
        return out

    @app.post(
        "/attestations",
        response_model=TxOut,
        status_code=status.HTTP_201_CREATED,
        tags=["attestations"],
        responses={
            401: {"description": "Missing or invalid API key"},
            409: {"description": "Same Idempotency-Key still in progress"},
            503: {"description": "Node unreachable, or transaction submitted but not yet confirmed"},
        },
    )
    def create_attestation(
        body: AttestationIn,
        ledger: LedgerDep,
        cipher: CipherDep,
        index: IndexDep,
        principal: PrincipalDep,
        now: NowDep,
        idempotency_key: IdempotencyKey = None,
    ) -> Any:
        if body.encrypt and cipher is None:
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST, "encryption requested but SECUREFLOW_ENCRYPTION_KEY is not configured"
            )
        if not body.encrypt and is_encrypted(body.data):
            raise HTTPException(422, "plaintext data must not start with 'sf1:'")

        index.ensure_identity()  # idempotency records from a previous chain must not be replayed
        scope, key = principal.name, idempotency_key
        if key:
            claim = idempotency.begin(scope, key, fingerprint("POST", "/attestations", body.model_dump()))
            if isinstance(claim, Replay):
                return JSONResponse(claim.body, claim.status_code, headers={"Idempotent-Replayed": "true"})
            if isinstance(claim, InDoubt):
                # An earlier attempt submitted a transaction: find out what happened to it.
                try:
                    resolved = ledger.resolve_create(claim.tx_hash)
                except TransactionPending:
                    raise IdempotencyConflict(key) from None
                if resolved is not None:
                    return finish_create(resolved, principal, key, replayed=True)
                if not claim.stale:
                    raise IdempotencyConflict(key)
                idempotency.retake(scope, key)  # the node has never seen it: safe to send again

        # Time-dependent validation runs after the replay check, so a retry is
        # never refused just because the clock moved past expires_at meanwhile.
        if body.expires_at is not None and body.expires_at <= now:
            if key:
                idempotency.release(scope, key)
            raise HTTPException(422, "expires_at must be in the future")

        submitted = False

        def on_submitted(tx_hash: str) -> None:
            nonlocal submitted
            if key:
                idempotency.submitted(scope, key, tx_hash)
            submitted = True

        try:
            data = cipher.encrypt(body.data, body.recipient) if body.encrypt and cipher else body.data
            result = ledger.create(body.recipient, data, body.expires_at or 0, on_submitted=on_submitted)
        except BaseException as exc:
            definitely_not_on_chain = not submitted or (
                isinstance(exc, LedgerError) and not isinstance(exc, TransactionPending)
            )
            if key and definitely_not_on_chain:
                idempotency.release(scope, key)
            raise
        return finish_create(result, principal, key, replayed=False)

    @app.get("/attestations", response_model=AttestationPage, tags=["attestations"])
    def list_attestations(
        index: IndexDep,
        cipher: CipherDep,
        now: NowDep,
        issuer: str | None = None,
        recipient: str | None = None,
        status_filter: Annotated[Status, Query(alias="status")] = "all",
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
        cursor: Annotated[str | None, Query(max_length=64)] = None,
    ) -> AttestationPage:
        for name, value in (("issuer", issuer), ("recipient", recipient)):
            if value is not None and not is_address(value):
                raise HTTPException(422, f"{name} is not a valid Ethereum address")
        page = index.query(
            now=now, issuer=issuer, recipient=recipient, status=status_filter, limit=limit, cursor=cursor
        )
        return AttestationPage(items=[render(a, cipher, now) for a in page.items], next_cursor=page.next_cursor)

    @app.get("/attestations/{uid}", response_model=AttestationOut, tags=["attestations"])
    def verify_attestation(uid: Uid, ledger: LedgerDep, cipher: CipherDep, now: NowDep) -> AttestationOut:
        return render(ledger.get(uid), cipher, now)

    @app.post(
        "/attestations/{uid}/revoke",
        response_model=TxOut,
        tags=["attestations"],
        responses={
            401: {"description": "Missing or invalid API key"},
            403: {"description": "Issued by another client or issuer"},
        },
    )
    def revoke_attestation(uid: Uid, ledger: LedgerDep, index: IndexDep, principal: PrincipalDep) -> TxOut:
        # Every client signs with the service's one key, so the contract's issuer check
        # can't tell clients apart. Enforce per-client ownership here.
        index.ensure_identity()
        owner = db.get_owner(uid)
        if owner is not None and owner != principal.name:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "attestation was issued by another API client")
        out = TxOut(**ledger.revoke(uid).__dict__)
        metrics.attestations.labels("revoked").inc()
        logger.info("attestation revoked", extra={"uid": out.uid, "tx_hash": out.tx_hash, "principal": principal.name})
        return out

    return app


def __getattr__(name: str) -> FastAPI:
    # `uvicorn secureflow.api:app` builds the app on first access rather than
    # at import, so importing this module never needs env vars or a node.
    if name == "app":
        global app
        app = create_app()
        return app
    raise AttributeError(name)
