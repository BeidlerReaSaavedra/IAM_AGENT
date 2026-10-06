"""Append-only audit trail.

Every decision, every action and every approval is written here as JSON lines so
that a security review can reconstruct exactly *who* did *what*, *when*, *why*
and *under which policy*. Secret-looking fields are redacted before writing.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any

from iam_agent.config import AuditSettings

# Redaction lives in core.redact so that the audit log, the run store and the
# approval queue cannot drift apart and leave one of them writing secrets.
from iam_agent.core.redact import redact


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _val(value: Any) -> Any:
    """Unwrap an enum to its plain value for JSON output.

    ``StrEnum`` subclasses ``str``, so an ``isinstance(value, str)`` guard would
    wrongly pass it through and leave the enum repr in the audit log.
    """
    return value.value if isinstance(value, Enum) else value


def _merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    """Combine a derived record with caller-supplied overrides.

    Every convenience wrapper derives some fields from its subject (an action, an
    approval request) *and* accepts ``**extra``. Passing both straight into
    ``record(**kwargs)`` raises ``TypeError: got multiple values for keyword``
    whenever a caller overrides a derived field - which is a legitimate thing to
    want to do. Merging first keeps the override and keeps ``record()`` simple.
    """
    return {**base, **extra}


class AuditLog:
    """Thread-safe JSON-lines writer with best-effort durability."""

    def __init__(self, settings: AuditSettings) -> None:
        self.settings = settings
        # Absolute: see RunStore. An audit log that fails to write because cwd
        # moved is worse than no audit log, because the action still happened.
        self.path = Path(settings.log_path).expanduser().resolve()
        self._ensure_directory()

    def _ensure_directory(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()

    # ---- writing --------------------------------------------------------- #

    def record(self, event: str, **fields: Any) -> dict[str, Any]:
        entry = {
            "ts": _utcnow().isoformat(),
            "event": event,
            "actor": fields.pop("actor", "iam-agent"),
            "run_id": fields.pop("run_id", None),
            "action_id": fields.pop("action_id", None),
            "platform": fields.pop("platform", None),
            "operation": fields.pop("operation", None),
            "outcome": fields.pop("outcome", None),
            "data": redact(fields) if self.settings.include_request_payloads else {},
        }
        with self._lock, self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, default=str) + "\n")
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        return entry

    # Convenience wrappers ------------------------------------------------- #

    def action_planned(self, action: Any, run_id: str = "", **extra: Any) -> None:
        self.record(
            "action_planned",
            **_merge(
                {
                    "run_id": run_id,
                    "action_id": action.id,
                    "platform": action.platform,
                    "operation": action.operation,
                    "target": action.target,
                    "risk": _val(action.risk),
                    "params": action.params,
                },
                extra,
            ),
        )

    def action_executed(self, action: Any, run_id: str = "", **extra: Any) -> None:
        self.record(
            "action_executed",
            **_merge(
                {
                    "run_id": run_id,
                    "action_id": action.id,
                    "platform": action.platform,
                    "operation": action.operation,
                    "outcome": _val(action.status),
                    "target": action.target,
                    "risk": _val(action.risk),
                    "duration_ms": action.duration_ms,
                    "error": action.error or None,
                },
                extra,
            ),
        )

    def decision(self, action: Any, decision: Any, run_id: str = "", **extra: Any) -> None:
        self.record(
            "policy_decision",
            **_merge(
                {
                    "run_id": run_id,
                    "action_id": action.id,
                    "platform": action.platform,
                    "operation": action.operation,
                    "outcome": decision.outcome,
                    "risk": _val(decision.risk),
                    "reason": decision.reason,
                    "rules": decision.applied_rules,
                    "blocked": decision.blocked_reason or None,
                },
                extra,
            ),
        )

    def approval(self, req: Any, event: str = "approval_created", **extra: Any) -> None:
        self.record(
            event,
            **_merge(
                {
                    "run_id": getattr(req, "run_id", ""),
                    "approval_id": getattr(req, "id", ""),
                    "risk": _val(getattr(req, "risk", "")),
                    "subject": getattr(req, "subject", ""),
                    "actions": getattr(req, "action_ids", []),
                },
                extra,
            ),
        )

    def workflow_event(self, event: str, run_id: str = "", **fields: Any) -> None:
        self.record(event, **_merge({"run_id": run_id}, fields))

    def api_call(
        self,
        platform: str,
        method: str,
        url: str,
        status_code: int | None,
        duration_ms: float,
        error: str = "",
        **extra: Any,
    ) -> None:
        """Low-level HTTP trace. Kept separate so it can be filtered out."""
        self.record(
            "api_call",
            **_merge(
                {
                    "platform": platform,
                    "outcome": f"http_{status_code}" if status_code else "transport_error",
                    "data": {"method": method, "url": url, "duration_ms": duration_ms, "error": error},
                },
                extra,
            ),
        )

    # ---- reading --------------------------------------------------------- #

    def tail(self, n: int = 100, *, event: str | None = None, run_id: str | None = None) -> list[dict]:
        if not self.path.exists():
            return []
        rows: list[dict] = []
        with self._lock, self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event and entry.get("event") != event:
                    continue
                if run_id and entry.get("run_id") != run_id:
                    continue
                rows.append(entry)
        return rows[-n:]

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        if not self.path.exists():
            return counts
        with self._lock, self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                key = entry.get("event", "unknown")
                counts[key] = counts.get(key, 0) + 1
        return counts
