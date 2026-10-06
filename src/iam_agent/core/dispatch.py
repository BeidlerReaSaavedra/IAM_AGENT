"""Symbolic action dispatch.

An :class:`~iam_agent.core.result.Action` names an operation as
``"<platform>.<method>"`` — for example ``entra.create_user`` or
``scalefusion.wipe_device``. This module resolves that string to the actual
connector coroutine and coerces its arguments.

Why not just store a bound callable on the action?
--------------------------------------------------
Because closures are not serialisable. A run that waits three days for a human
approval has to survive a process restart, and a plan held in memory does not.
Resolving operations *symbolically* means the persisted plan is complete on its
own: reload it from disk and it still executes, with no re-planning step that
could regenerate action ids and re-open approvals that were already granted.

It also gives the policy engine a stable string to match on, so a rule like
``scalefusion.wipe_device`` is meaningful in config, in the audit log and in
Claude's tool description simultaneously.
"""

from __future__ import annotations

import inspect
from datetime import date, datetime
from typing import Any, Callable, get_type_hints

from pydantic import BaseModel

from iam_agent.connectors import ConnectorHub
from iam_agent.core.errors import IAMAgentError

#: Operations whose verb intentionally differs from the connector method name.
OPERATION_ALIASES: dict[str, str] = {
    "entra.revoke_all_sessions": "revoke_sign_in_sessions",
    "m365.remove_all_teams_memberships": "remove_all_teams_memberships",
}


class UnknownOperationError(IAMAgentError):
    """The named operation does not exist on the target connector."""

    status_code = 400


class ActionDispatcher:
    """Maps ``platform.method`` strings onto connector coroutines."""

    def __init__(self, hub: ConnectorHub) -> None:
        self.hub = hub
        self._hints: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------ #

    def split(self, operation: str) -> tuple[str, str]:
        platform, sep, method = operation.partition(".")
        if not sep or not method:
            raise UnknownOperationError(
                f"operation '{operation}' must be namespaced as '<platform>.<method>'"
            )
        return platform, OPERATION_ALIASES.get(operation, method)

    def resolve(self, operation: str) -> Callable[..., Any] | None:
        """Return the bound connector method, or ``None`` if it does not exist."""
        platform, method = self.split(operation)
        try:
            connector = self.hub.get(platform)
        except KeyError:
            return None
        return getattr(connector, method, None)

    def assert_resolvable(self, operation: str) -> None:
        if self.resolve(operation) is None:
            platform, method = self.split(operation)
            raise UnknownOperationError(
                f"operation '{operation}' cannot be resolved: platform '{platform}' has no "
                f"method '{method}'"
            )

    # ------------------------------------------------------------------ #

    def _signature_hints(self, func: Callable[..., Any]) -> dict[str, Any]:
        key = f"{getattr(func, '__module__', '')}.{getattr(func, '__qualname__', id(func))}"
        if key not in self._hints:
            try:
                hints = get_type_hints(func)
            except Exception:  # noqa: BLE001 - unresolved forward refs must not break dispatch
                hints = {}
            hints.pop("return", None)
            self._hints[key] = hints
        return self._hints[key]

    def coerce(self, func: Callable[..., Any], params: dict[str, Any]) -> dict[str, Any]:
        """Adapt JSON-round-tripped parameters back to the types the method wants.

        After a run is persisted and reloaded, ``Employee`` arrives as a dict and
        ``expires_at`` arrives as an ISO string. Rather than forcing every
        connector to defend against that, it is normalised once here.
        """
        hints = self._signature_hints(func)
        if not hints:
            return dict(params)

        signature = inspect.signature(func)
        out: dict[str, Any] = {}
        for name, value in params.items():
            expected = hints.get(name)
            out[name] = _coerce_value(value, expected, name, signature)
        return out

    async def dispatch(self, operation: str, params: dict[str, Any]) -> Any:
        """Resolve, coerce and await one operation."""
        func = self.resolve(operation)
        if func is None:
            self.assert_resolvable(operation)  # raises with a precise message
        kwargs = self.coerce(func, params)
        result = func(**kwargs)
        if inspect.isawaitable(result):
            return await result
        return result


def _coerce_value(value: Any, expected: Any, name: str, signature: inspect.Signature) -> Any:
    if expected is None or value is None:
        return value

    # Unwrap Optional[X] / X | None
    origin = getattr(expected, "__origin__", None)
    args = getattr(expected, "__args__", None)
    if args and type(None) in args:  # noqa: E721
        non_null = [a for a in args if a is not type(None)]  # noqa: E721
        if len(non_null) == 1:
            expected = non_null[0]
            origin = getattr(expected, "__origin__", None)

    if isinstance(expected, type) and issubclass(expected, BaseModel) and isinstance(value, dict):
        return expected.model_validate(value)

    if expected is datetime and isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    if expected is date and isinstance(value, str):
        try:
            return date.fromisoformat(value[:10])
        except ValueError:
            return value

    # Leave list[str] / dict[str, Any] alone: JSON already round-trips them.
    return value


__all__ = ["ActionDispatcher", "UnknownOperationError", "OPERATION_ALIASES"]
