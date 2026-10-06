"""Human-in-the-loop approval queue.

The orchestrator parks any gated action here and stops. A human (via CLI, REST
API, or by replying to Claude) approves or rejects, and the run resumes. Pending
requests expire so an abandoned offboarding can never sit half-applied forever.
"""

from __future__ import annotations

import json
import logging
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field, ValidationError

from iam_agent.config import ApprovalSettings, Settings

logger = logging.getLogger("iam_agent.approvals")
from iam_agent.core.redact import safe_json
from iam_agent.core.result import Action, RiskLevel, new_id


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


ApprovalStatus = Literal["pending", "approved", "rejected", "expired", "cancelled"]


class ApprovalRequest(BaseModel):
    """A single approval gate covering one or more related actions."""

    id: str = Field(default_factory=lambda: new_id("apv"))
    run_id: str = ""
    workflow: str = ""
    subject: str = ""

    title: str = ""
    description: str = ""
    risk: RiskLevel = RiskLevel.LOW
    reversible: bool = True

    actions: list[dict[str, Any]] = Field(default_factory=list)
    """Serialised action summaries - approvals are reviewed by humans."""
    action_ids: list[str] = Field(default_factory=list)

    status: ApprovalStatus = "pending"
    requested_at: datetime = Field(default_factory=_utcnow)
    requested_by: str = "iam-agent"
    expires_at: datetime | None = None

    decided_at: datetime | None = None
    decided_by: str = ""
    decision_comment: str = ""
    approvals: list[dict[str, Any]] = Field(default_factory=list)
    """Supports two-person integrity for critical actions."""

    required_approvals: int = 1

    @property
    def is_pending(self) -> bool:
        return self.status == "pending"

    @property
    def is_expired(self) -> bool:
        if self.status != "pending":
            return False
        return bool(self.expires_at and _utcnow() > self.expires_at)

    def effective_status(self) -> ApprovalStatus:
        return "expired" if self.is_expired else self.status

    def to_review_markdown(self) -> str:
        lines = [
            f"## 🔒 Approval `{self.id}` — {self.title}",
            f"- **Workflow:** {self.workflow}",
            f"- **Subject:** {self.subject}",
            f"- **Risk:** `{self.risk.value}` · reversible: {'yes' if self.reversible else '**NO**'}",
            f"- **Requested:** {self.requested_at.strftime('%Y-%m-%d %H:%M UTC')} by {self.requested_by}",
        ]
        if self.expires_at:
            lines.append(f"- **Expires:** {self.expires_at.strftime('%Y-%m-%d %H:%M UTC')}")
        if self.required_approvals > 1:
            lines.append(f"- **Requires {self.required_approvals} approvers (two-person integrity)**")
        if self.description:
            lines += ["", self.description]
        lines += ["", "### Actions", ""]
        for a in self.actions:
            lines.append(
                f"- `{a.get('operation')}` → **{a.get('target') or 'n/a'}** "
                f"— {a.get('description', '')} (risk `{a.get('risk')}`)"
            )
            params = a.get("params") or {}
            if params:
                lines.append(f"  - params: `{safe_json(params, limit=500)}`")
        return "\n".join(lines)


class ApprovalStore:
    """Thread-safe, file-backed approval queue."""

    def __init__(self, settings: ApprovalSettings) -> None:
        self.settings = settings
        self.path = Path(settings.storage_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._cache: dict[str, ApprovalRequest] = {}
        self.corrupt_lines = 0
        self._load()

    # ---- persistence ----------------------------------------------------- #

    def _load(self) -> None:
        """Rehydrate the queue from disk.

        A pending approval must survive a process restart: the CLI, the REST API
        and the MCP server are three separate processes that all need to see the
        same gate, and an orchestrator that loses its queue on restart strands
        every parked run for good.

        Only *corrupt lines* are skipped. Errors from our own code are re-raised
        rather than swallowed - a bare ``except: continue`` here once turned a
        missing ``import json`` into a silently empty approval queue, which is
        indistinguishable from "nothing needs approving" and therefore far worse
        than a crash.
        """
        if not self.path.exists():
            return
        skipped = 0
        with self.path.open("r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    skipped += 1
                    logger.warning("skipping malformed JSON at %s:%d", self.path, lineno)
                    continue
                try:
                    req = ApprovalRequest.model_validate(payload)
                except ValidationError:
                    skipped += 1
                    logger.warning(
                        "skipping unreadable approval at %s:%d (schema drift?)", self.path, lineno
                    )
                    continue
                self._cache[req.id] = req
        self.corrupt_lines = skipped
        if skipped:
            logger.warning("%d approval record(s) in %s could not be loaded", skipped, self.path)

    def _flush(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as fh:
            for req in sorted(self._cache.values(), key=lambda r: r.requested_at):
                fh.write(req.model_dump_json() + "\n")
        tmp.replace(self.path)

    # ---- queue operations ------------------------------------------------ #

    def create(
        self,
        *,
        actions: list[Action],
        run_id: str = "",
        workflow: str = "",
        subject: str = "",
        title: str = "",
        description: str = "",
        requested_by: str = "iam-agent",
    ) -> ApprovalRequest:
        """Create one approval covering all supplied actions."""
        with self._lock:
            risk = max((a.risk for a in actions), key=lambda r: r.rank) if actions else RiskLevel.LOW
            reversible = all(a.reversible for a in actions)

            required = 1
            if risk == RiskLevel.CRITICAL and self.settings.require_second_approver_for_critical:
                required = 2

            req = ApprovalRequest(
                run_id=run_id,
                workflow=workflow,
                subject=subject,
                title=title or f"{len(actions)} gated action(s) for {subject or workflow}",
                description=description,
                risk=risk,
                reversible=reversible,
                actions=[a.to_audit() for a in actions],
                action_ids=[a.id for a in actions],
                requested_by=requested_by,
                expires_at=_utcnow() + timedelta(minutes=self.settings.request_timeout_minutes),
                required_approvals=required,
            )
            self._cache[req.id] = req
            self._flush()
            return req

    def get(self, approval_id: str) -> ApprovalRequest | None:
        with self._lock:
            return self._cache.get(approval_id)

    def list(
        self,
        *,
        status: ApprovalStatus | None = "pending",
        run_id: str | None = None,
        include_expired: bool = False,
    ) -> list[ApprovalRequest]:
        with self._lock:
            items = list(self._cache.values())

        if run_id:
            items = [r for r in items if r.run_id == run_id]
        if status:
            items = [r for r in items if r.effective_status() == status]
        elif not include_expired:
            items = [r for r in items if r.effective_status() != "expired"]
        return sorted(items, key=lambda r: r.requested_at)

    def pending(self) -> list[ApprovalRequest]:
        return self.list(status="pending")

    def decide(
        self,
        approval_id: str,
        *,
        approve: bool,
        decided_by: str,
        comment: str = "",
    ) -> ApprovalRequest:
        """Record a decision. Critical requests need ``required_approvals`` distinct approvers."""
        with self._lock:
            req = self._cache.get(approval_id)
            if req is None:
                raise KeyError(f"unknown approval id: {approval_id}")

            if not approve:
                req.status = "rejected"
                req.decided_at = _utcnow()
                req.decided_by = decided_by
                req.decision_comment = comment
                self._flush()
                return req

            if any(a["approver"] == decided_by for a in req.approvals):
                raise ValueError(
                    f"{decided_by} has already approved {approval_id}; "
                    "two-person integrity requires a distinct second approver."
                )

            req.approvals.append(
                {"approver": decided_by, "at": _utcnow().isoformat(), "comment": comment}
            )

            if len(req.approvals) >= req.required_approvals:
                req.status = "approved"
                req.decided_at = _utcnow()
                req.decided_by = ", ".join(a["approver"] for a in req.approvals)
                req.decision_comment = comment
            self._flush()
            return req

    def cancel(self, approval_id: str, reason: str = "") -> ApprovalRequest | None:
        with self._lock:
            req = self._cache.get(approval_id)
            if req and req.status == "pending":
                req.status = "cancelled"
                req.decision_comment = reason
                req.decided_at = _utcnow()
                self._flush()
            return req

    def expire_stale(self) -> list[str]:
        """Mark timed-out requests as expired. Returns the affected IDs."""
        expired: list[str] = []
        with self._lock:
            for req in self._cache.values():
                if req.is_expired:
                    req.status = "expired"
                    req.decided_at = _utcnow()
                    expired.append(req.id)
            if expired:
                self._flush()
        return expired

    def is_approved(self, approval_id: str) -> bool:
        req = self.get(approval_id)
        return bool(req and req.effective_status() == "approved")


class ApprovalNotifier:
    """Best-effort push of new approval requests to Teams/Slack/generic webhook.

    Failures are swallowed on purpose: notification is a convenience and must
    never block or fail the security gate itself.
    """

    def __init__(self, settings: Settings) -> None:
        self.url = settings.approval.notify_webhook_url

    def notify(self, req: ApprovalRequest) -> bool:
        if not self.url:
            return False
        payload = {
            "title": f"🔒 IAM Agent approval required: {req.title}",
            "text": req.to_review_markdown(),
            "approval_id": req.id,
            "risk": req.risk.value,
            "run_id": req.run_id,
            "expires_at": req.expires_at.isoformat() if req.expires_at else None,
        }
        try:
            httpx.post(self.url, json=payload, timeout=10)
            return True
        except httpx.HTTPError:
            return False
