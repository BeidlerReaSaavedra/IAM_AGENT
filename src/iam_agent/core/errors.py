"""Exceptions raised across the agent.

A single hierarchy makes it easy for the executor, the API and Claude to react
differently to a transient network blip versus a hard permission denial.
"""

from __future__ import annotations


class IAMAgentError(Exception):
    """Base class for everything raised by this package."""

    #: HTTP-ish status the REST layer should surface.
    status_code: int = 500

    def __init__(self, message: str, *, platform: str = "", details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.platform = platform
        self.details = details or {}

    def to_dict(self) -> dict:
        return {
            "error": type(self).__name__,
            "message": self.message,
            "platform": self.platform,
            "details": self.details,
        }


class ConfigurationError(IAMAgentError):
    """Missing or invalid settings."""

    status_code = 400


class ConnectorError(IAMAgentError):
    """A connector failed to complete an operation."""

    status_code = 502


class AuthenticationError(ConnectorError):
    """Credentials rejected or missing."""

    status_code = 401


class AuthorizationError(ConnectorError):
    """Authenticated but not permitted (missing Graph scope, wrong Action1 role...)."""

    status_code = 403


class NotFoundError(ConnectorError):
    """The target object does not exist."""

    status_code = 404


class ConflictError(ConnectorError):
    """The object already exists, or the state transition is not allowed."""

    status_code = 409


class RateLimitError(ConnectorError):
    """The vendor throttled us. Carries ``retry_after`` seconds when known."""

    status_code = 429

    def __init__(self, message: str, *, retry_after: float | None = None, **kwargs) -> None:
        super().__init__(message, **kwargs)
        self.retry_after = retry_after


class TransientError(ConnectorError):
    """Retryable failure (5xx, timeout, DNS)."""

    status_code = 503


class PolicyDeniedError(IAMAgentError):
    """The policy engine refused the operation outright."""

    status_code = 403


class ApprovalRequired(IAMAgentError):
    """Raised internally to signal the executor must park and wait."""

    status_code = 202

    def __init__(self, message: str, *, approval_id: str = "", **kwargs) -> None:
        super().__init__(message, **kwargs)
        self.approval_id = approval_id


class ObjectNotFoundError(NotFoundError):
    """Raised when a lookup by correlation key finds nothing."""


class AmbiguousMatchError(ConnectorError):
    """More than one candidate matched a correlation key - refuse to guess."""

    status_code = 409
