# Changelog

## 1.1.0 — 2026-09-26

### Added
- **API-key authentication** for `POST /attestations` and `POST /attestations/{uid}/revoke` (`X-API-Key`). Keys are
  configured as SHA-256 hashes (`SECUREFLOW_API_KEYS`); `python -m secureflow.auth` generates them. The `web3` backend
  refuses to start without keys.
- **Idempotency keys** on `POST /attestations` (`Idempotency-Key`), scoped per client, with a 24 h TTL. The signed
  transaction hash is recorded before broadcast, so a retry after a timeout or crash resolves the original
  transaction on-chain instead of issuing twice.
- **Per-client revocation**: only the API client that issued an attestation can revoke it.
- **Attestation expiry**: optional `expires_at` on issue; the contract's `isValid()` and the API's `valid`/`expired`
  fields honour it.
- **Event indexer** backed by SQLite (`SECUREFLOW_DB`), with chunked sync, a confirmation depth, and state bound
  to the chain id, contract address and deployment block hash.
- `status` filter (`valid`, `revoked`, `expired`) and **cursor pagination** on `GET /attestations`.
- JSON structured logs with `X-Request-ID` propagation; `GET /metrics` for Prometheus.
- mypy `--strict`, a coverage gate (90%) and both checks in CI.

### Changed (breaking)
- `GET /attestations` returns `{"items": [...], "next_cursor": ...}` instead of a bare list.
- Contract: `createAttestation(recipient, data, expiresAt)` takes an expiry argument, `AttestationCreated` carries
  `expiresAt` instead of `blockNumber`, and the record struct gained `expiresAt`. Redeploy with
  `python -m secureflow.deploy`.
- Write endpoints need an API key whenever keys are configured.

## 1.0.0 — 2026-09-26

First public release: FastAPI service over `AttestationRegistry`, mock and web3 ledger adapters, optional AES-256-GCM
payload encryption, pytest suite on an in-process EVM, and Docker Compose stack.
