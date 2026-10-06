"""Connector base class: shared HTTP plumbing, retries, throttling and health.

Each vendor connector subclasses :class:`BaseConnector` and implements its own
auth + resource methods, but every one of them gets:

* exponential-backoff retries on transient failures and ``429``
* a token-bucket style client-side rate limiter (Scalefusion allows 30 req/min)
* a uniform ``health()`` contract used by the ``/health`` endpoint and by Claude
* structured audit logging of every outbound call
"""

from __future__ import annotations

import abc
import asyncio
import random
import time
from typing import Any

import httpx

from iam_agent.config import Backend
from iam_agent.core.audit import AuditLog
from iam_agent.core.errors import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    ConnectorError,
    NotFoundError,
    RateLimitError,
    TransientError,
)


class HealthStatus:
    """Result of a connector health probe."""

    __slots__ = ("backend", "checked_at", "detail", "healthy", "latency_ms", "name")

    def __init__(
        self,
        name: str,
        healthy: bool,
        backend: str,
        detail: str = "",
        latency_ms: float = 0.0,
    ) -> None:
        self.name = name
        self.healthy = healthy
        self.backend = backend
        self.detail = detail
        self.latency_ms = round(latency_ms, 1)
        self.checked_at = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "healthy": self.healthy,
            "backend": self.backend,
            "detail": self.detail,
            "latency_ms": self.latency_ms,
        }


class RateLimiter:
    """Simple sliding-window limiter. Async-safe via a lock."""

    def __init__(self, max_calls: int, period_seconds: float = 60.0) -> None:
        self.max_calls = max(1, max_calls)
        self.period = period_seconds
        self._calls: list[float] = []
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            while True:
                now = time.monotonic()
                self._calls = [t for t in self._calls if now - t < self.period]
                if len(self._calls) < self.max_calls:
                    self._calls.append(now)
                    return
                wait = self.period - (now - self._calls[0]) + 0.05
                await asyncio.sleep(max(0.0, wait))


class BaseConnector(abc.ABC):
    """Common behaviour for all five platform connectors."""

    #: Stable platform key used in actions, audit records and policy rules.
    name: str = "base"
    #: Human-readable label.
    label: str = "Base connector"

    def __init__(
        self,
        *,
        backend: Backend = "mock",
        audit: AuditLog | None = None,
        timeout: float = 30.0,
        max_retries: int = 3,
        rate_limit_per_minute: int = 0,
    ) -> None:
        self.backend = backend
        self.audit = audit
        self.timeout = timeout
        self.max_retries = max_retries
        self.limiter = RateLimiter(rate_limit_per_minute) if rate_limit_per_minute else None
        self._client: httpx.AsyncClient | None = None
        self._token: str = ""
        self._token_expires_at: float = 0.0

    # ---- lifecycle ------------------------------------------------------- #

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=False)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()
        self._client = None

    async def __aenter__(self) -> BaseConnector:
        return self

    async def __aexit__(self, *exc: Any) -> None:
        await self.aclose()

    # ---- auth ------------------------------------------------------------ #

    @abc.abstractmethod
    async def authenticate(self) -> None:
        """Obtain/refresh whatever credential the vendor needs."""

    async def ensure_authenticated(self) -> None:
        if time.time() >= self._token_expires_at - 60:
            await self.authenticate()

    # ---- health ---------------------------------------------------------- #

    @abc.abstractmethod
    async def health(self) -> HealthStatus:
        """Cheap probe used by /health and by the pre-flight workflow check."""

    # ---- HTTP ------------------------------------------------------------ #

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        data: Any = None,
        expected: tuple[int, ...] = (200, 201, 202, 204),
    ) -> Any:
        """Perform an HTTP call with retries, throttling, audit and error mapping.

        Returns parsed JSON (or ``None`` for 204/empty bodies).
        """
        await self.ensure_authenticated()

        last_error: Exception | None = None
        for attempt in range(1, self.max_retries + 1):
            if self.limiter:
                await self.limiter.acquire()

            started = time.monotonic()
            try:
                response = await self.client.request(
                    method,
                    url,
                    headers={**self._auth_headers(), **(headers or {})},
                    params=params,
                    json=json_body,
                    data=data,
                )
                elapsed = (time.monotonic() - started) * 1000
                self._log_call(method, url, response.status_code, elapsed)

                if response.status_code in expected:
                    if response.status_code == 204 or not response.content:
                        return None
                    ctype = response.headers.get("content-type", "")
                    if "json" in ctype:
                        return response.json()
                    return {"text": response.text}

                # Explicit, non-retryable failures
                if response.status_code in (401, 403):
                    self._raise_for_status(response, url)

                if response.status_code == 404:
                    raise NotFoundError(f"{method} {url} -> 404", platform=self.name)

                if response.status_code == 409:
                    raise ConflictError(self._error_text(response), platform=self.name)

                if response.status_code == 429:
                    retry_after = _parse_retry_after(response)
                    if attempt < self.max_retries:
                        await asyncio.sleep(retry_after or _backoff(attempt))
                        last_error = RateLimitError(
                            self._error_text(response), retry_after=retry_after, platform=self.name
                        )
                        continue
                    raise RateLimitError(
                        self._error_text(response), retry_after=retry_after, platform=self.name
                    )

                if response.status_code >= 500:
                    last_error = TransientError(self._error_text(response), platform=self.name)
                    if attempt < self.max_retries:
                        await asyncio.sleep(_backoff(attempt))
                        continue
                    raise last_error

                # Any other unexpected status
                raise ConnectorError(
                    f"unexpected status {response.status_code}: {self._error_text(response)}",
                    platform=self.name,
                )

            except (httpx.TimeoutException, httpx.TransportError) as exc:
                elapsed = (time.monotonic() - started) * 1000
                self._log_call(method, url, None, elapsed, error=str(exc))
                last_error = TransientError(f"{type(exc).__name__}: {exc}", platform=self.name)
                if attempt < self.max_retries:
                    await asyncio.sleep(_backoff(attempt))
                    continue
                raise last_error from exc

        # Should be unreachable, but be explicit.
        raise last_error or ConnectorError("request failed", platform=self.name)

    def _auth_headers(self) -> dict[str, str]:
        if not self._token:
            return {}
        return {"Authorization": f"Bearer {self._token}"}

    def _raise_for_status(self, response: httpx.Response, url: str) -> None:
        text = self._error_text(response)
        if response.status_code == 401:
            # Force a re-auth on the next call.
            self._token_expires_at = 0.0
            raise AuthenticationError(f"401 from {url}: {text}", platform=self.name)
        raise AuthorizationError(
            f"403 from {url}: {text}. Check that the app registration / API role grants "
            f"the permission this operation needs.",
            platform=self.name,
        )

    @staticmethod
    def _error_text(response: httpx.Response) -> str:
        try:
            body = response.json()
        except Exception:
            return response.text[:500]
        if isinstance(body, dict):
            for key_path in (
                ("error", "message"),
                ("message",),
                ("user_message",),
                ("developer_message",),
                ("error_description",),
                ("error",),
            ):
                node: Any = body
                for key in key_path:
                    node = node.get(key) if isinstance(node, dict) else None
                    if node is None:
                        break
                if isinstance(node, str) and node:
                    return node
            return str(body)[:500]
        return str(body)[:500]

    def _log_call(
        self, method: str, url: str, status_code: int | None, duration_ms: float, error: str = ""
    ) -> None:
        if self.audit:
            self.audit.api_call(
                self.name, method, url, status_code, duration_ms, error=error
            )


def _backoff(attempt: int, base: float = 0.8, cap: float = 20.0) -> float:
    """Exponential backoff with full jitter."""
    return min(cap, base * (2 ** (attempt - 1))) * (0.5 + random.random() / 2)


def _parse_retry_after(response: httpx.Response) -> float | None:
    raw = response.headers.get("Retry-After") or response.headers.get("retry-after")
    if not raw:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


class NotConfiguredError(ConnectorError):
    """Raised when a live connector lacks the credentials it needs."""

    status_code = 400
