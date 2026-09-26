"""Structured logging, request IDs and Prometheus metrics."""

from __future__ import annotations

import contextvars
import json
import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable

from prometheus_client import CollectorRegistry, Counter, Histogram
from starlette.requests import Request
from starlette.responses import Response

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
_VALID_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

logger = logging.getLogger("secureflow")


class JsonFormatter(logging.Formatter):
    """One JSON object per line, ready for Loki/CloudWatch/Datadog."""

    _RESERVED = set(vars(logging.makeLogRecord({})))

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, object] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": request_id_var.get(),
        }
        payload.update({k: v for k, v in vars(record).items() if k not in self._RESERVED and not k.startswith("_")})
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


class _RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        return True


def configure_logging(level: str = "INFO", json_format: bool = True) -> None:
    handler = logging.StreamHandler()
    if json_format:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s [%(request_id)s] %(name)s: %(message)s"))
        handler.addFilter(_RequestIdFilter())
    logger.handlers[:] = [handler]
    logger.setLevel(level)
    logger.propagate = False


class Metrics:
    """Per-app registry, so tests (and multiple apps in one process) don't collide."""

    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.requests = Histogram(
            "secureflow_http_request_duration_seconds",
            "HTTP request latency",
            ["method", "route", "status"],
            registry=self.registry,
        )
        self.attestations = Counter(
            "secureflow_attestations_total",
            "Attestation lifecycle operations that reached the ledger",
            ["operation"],
            registry=self.registry,
        )
        self.ledger_errors = Counter(
            "secureflow_ledger_errors_total",
            "Ledger failures by type",
            ["error"],
            registry=self.registry,
        )


def request_context_middleware(
    metrics: Metrics,
) -> Callable[[Request, Callable[[Request], Awaitable[Response]]], Awaitable[Response]]:
    async def middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        incoming = request.headers.get("x-request-id", "")
        rid = incoming if _VALID_REQUEST_ID.match(incoming) else uuid.uuid4().hex
        token = request_id_var.set(rid)
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            response.headers["X-Request-ID"] = rid
            return response
        finally:
            elapsed = time.perf_counter() - start
            # Label by route template (/attestations/{uid}), not the raw path, to keep cardinality bounded.
            route = getattr(request.scope.get("route"), "path", "unmatched")
            metrics.requests.labels(request.method, route, str(status)).observe(elapsed)
            logger.info(
                "request",
                extra={
                    "method": request.method,
                    "route": route,
                    "status": status,
                    "duration_ms": round(elapsed * 1000, 2),
                },
            )
            request_id_var.reset(token)

    return middleware
