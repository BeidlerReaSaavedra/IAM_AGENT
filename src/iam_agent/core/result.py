"""Execution primitives: actions, plan steps, and durable run records.

Every mutation the agent performs is expressed as an :class:`Action` that is
first *planned*, then *gated* by policy, then *executed*, and finally written to
an append-only audit trail. Runs are persisted so they can be resumed after a
crash or after a human approves a pending step.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field

from iam_agent.core.redact import redact, safe_params


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


# --------------------------------------------------------------------------- #
# Status enumerations
# --------------------------------------------------------------------------- #


class ActionStatus(StrEnum):
    PLANNED = "planned"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    DRY_RUN = "dry_run"
    ROLLED_BACK = "rolled_back"


TERMINAL = {
    ActionStatus.SUCCEEDED,
    ActionStatus.FAILED,
    ActionStatus.SKIPPED,
    ActionStatus.DRY_RUN,
    ActionStatus.REJECTED,
    ActionStatus.EXPIRED,
    ActionStatus.ROLLED_BACK,
}

# Statuses that count as "done without error" for progress reporting.
OK_STATUSES = {ActionStatus.SUCCEEDED, ActionStatus.DRY_RUN, ActionStatus.SKIPPED}


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


# --------------------------------------------------------------------------- #
# Action
# --------------------------------------------------------------------------- #


class Action(BaseModel):
    """One atomic, auditable operation against one platform.

    ``operation`` is a stable verb understood by the matching connector, e.g.
    ``entra.create_user`` or ``scalefusion.wipe_device``.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str = Field(default_factory=lambda: new_id("act"))
    operation: str
    platform: str
    description: str = ""

    params: dict[str, Any] = Field(default_factory=dict)
    target: str = ""
    """Human-readable subject, e.g. the user's UPN or a device name."""

    risk: RiskLevel = RiskLevel.LOW
    reversible: bool = True
    idempotency_key: str = ""
    """Set this to make re-runs collapse into a single effect."""

    # Populated at execution time
    status: ActionStatus = ActionStatus.PLANNED
    result: dict[str, Any] = Field(default_factory=dict)
    error: str = ""
    approval_id: str = ""
    started_at: datetime | None = None
    completed_at: datetime | None = None
    attempts: int = 0

    # Rollback support: an optional inverse action, planned up-front.
    compensating_action: "Action | None" = None

    # Not serialised - the callable the executor runs.
    executor: Callable[..., Any] | None = Field(default=None, exclude=True)

    @property
    def duration_ms(self) -> float | None:
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds() * 1000
        return None

    @property
    def needs_approval(self) -> bool:
        return self.status == ActionStatus.PLANNED and bool(self.approval_id)

    def mark(self, status: ActionStatus, **result: Any) -> None:
        self.status = status
        if result:
            self.result = {**self.result, **result}
        if status in TERMINAL:
            self.completed_at = _utcnow()

    def to_audit(self) -> dict[str, Any]:
        """Serialise for audit, approvals and persistence.

        ``params`` and ``result`` are scrubbed: an onboarding action legitimately
        carries the new hire's initial password and a TAP action carries the pass
        itself, and neither may reach disk or a review document.
        """
        return {
            "action_id": self.id,
            "operation": self.operation,
            "platform": self.platform,
            "target": self.target,
            "description": self.description,
            "risk": self.risk.value,
            "status": self.status.value,
            "params": safe_params(self.params),
            "result": safe_params(self.result),
            "error": self.error,
            "approval_id": self.approval_id,
            "idempotency_key": self.idempotency_key,
            "attempts": self.attempts,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


Action.model_rebuild()


# --------------------------------------------------------------------------- #
# Plan / steps
# --------------------------------------------------------------------------- #


class StepStatus(StrEnum):
    PENDING = "pending"
    BLOCKED_ON_APPROVAL = "blocked_on_approval"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


class PlanStep(BaseModel):
    """A named phase of a workflow containing one or more actions."""

    order: int
    name: str
    description: str = ""
    platform: str = ""
    actions: list[Action] = Field(default_factory=list)

    # Dependency control
    depends_on: list[str] = Field(default_factory=list)
    """Names of steps that must complete first."""
    continue_on_error: bool = False
    enabled: bool = True
    requires_approval: bool = False

    status: StepStatus = StepStatus.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    notes: str = ""

    @property
    def risk(self) -> RiskLevel:
        """Highest risk contained in the step - steps inherit their worst action."""
        if not self.actions:
            return RiskLevel.LOW
        return max((a.risk for a in self.actions), key=lambda r: r.rank)

    @property
    def is_complete(self) -> bool:
        """True when the step finished *successfully*.

        Deliberately excludes FAILED: the executor uses this to decide whether a
        dependent step may run, and a step downstream of a failure must not.
        """
        return self.status in (StepStatus.DONE, StepStatus.SKIPPED)

    @property
    def is_terminal(self) -> bool:
        """True when the step will not change again, whatever the outcome.

        The run-level roll-up needs this rather than :attr:`is_complete`: a run
        containing a failed step is finished, and reporting it as still running
        hides the failure from every caller.
        """
        return self.status in (StepStatus.DONE, StepStatus.FAILED, StepStatus.SKIPPED)

    def summary(self) -> dict[str, Any]:
        return {
            "order": self.order,
            "name": self.name,
            "platform": self.platform,
            "status": self.status.value,
            "risk": self.risk.value,
            "requires_approval": self.requires_approval,
            "actions": [
                {
                    "id": a.id,
                    "operation": a.operation,
                    "description": a.description or a.operation,
                    "target": a.target,
                    "risk": a.risk.value,
                    "status": a.status.value,
                    "error": a.error,
                }
                for a in self.actions
            ],
        }


class ExecutionPlan(BaseModel):
    """An ordered, dependency-aware set of steps for one workflow run."""

    id: str = Field(default_factory=lambda: new_id("plan"))
    workflow: str
    subject: str
    """Who the plan is about (name / UPN)."""
    created_at: datetime = Field(default_factory=_utcnow)
    steps: list[PlanStep] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    """Things the planner inferred - surfaced to Claude and to approvers."""
    warnings: list[str] = Field(default_factory=list)

    def add(self, step: PlanStep) -> PlanStep:
        if not step.order:
            step.order = len(self.steps) + 1
        self.steps.append(step)
        self.steps.sort(key=lambda s: s.order)
        return step

    def step(self, name: str) -> PlanStep | None:
        return next((s for s in self.steps if s.name == name), None)

    @property
    def all_actions(self) -> list[Action]:
        return [a for s in self.steps for a in s.actions]

    @property
    def max_risk(self) -> RiskLevel:
        actions = self.all_actions
        if not actions:
            return RiskLevel.LOW
        return max((a.risk for a in actions), key=lambda r: r.rank)

    def needs_approval(self) -> bool:
        return any(s.requires_approval for s in self.steps) or any(
            a.approval_id for a in self.all_actions
        )

    def progress(self) -> dict[str, int]:
        counts = {"pending": 0, "running": 0, "done": 0, "failed": 0, "blocked": 0, "skipped": 0}
        for s in self.steps:
            if s.status == StepStatus.DONE:
                counts["done"] += 1
            elif s.status == StepStatus.FAILED:
                counts["failed"] += 1
            elif s.status == StepStatus.RUNNING:
                counts["running"] += 1
            elif s.status == StepStatus.BLOCKED_ON_APPROVAL:
                counts["blocked"] += 1
            elif s.status == StepStatus.SKIPPED:
                counts["skipped"] += 1
            else:
                counts["pending"] += 1
        counts["total"] = len(self.steps)
        return counts

    def to_markdown(self) -> str:
        """Human/approver-readable rendering of the plan."""
        lines = [
            f"# Plan `{self.id}` — {self.workflow}",
            f"**Subject:** {self.subject}  ",
            f"**Created:** {self.created_at.isoformat()}  ",
            f"**Max risk:** {self.max_risk.value}  ",
            f"**Approval required:** {'yes' if self.needs_approval() else 'no'}",
            "",
        ]
        if self.assumptions:
            lines += ["### Assumptions", *[f"- {a}" for a in self.assumptions], ""]
        if self.warnings:
            lines += ["### Warnings", *[f"- ⚠️ {w}" for w in self.warnings], ""]

        lines.append("### Steps")
        for s in self.steps:
            flag = " 🔒" if s.requires_approval else ""
            lines.append(f"\n**{s.order}. {s.name}** — `{s.platform}` · risk `{s.risk.value}`{flag}")
            if s.description:
                lines.append(f"   {s.description}")
            for a in s.actions:
                state = s.status.value if a.status == ActionStatus.PLANNED else a.status.value
                lines.append(f"   - [{state}] `{a.operation}` → {a.target or 'n/a'}")
                if a.error:
                    lines.append(f"     - error: {a.error}")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Run record (persisted, resumable)
# --------------------------------------------------------------------------- #


class RunStatus(StrEnum):
    CREATED = "created"
    PLANNED = "planned"
    AWAITING_APPROVAL = "awaiting_approval"
    RUNNING = "running"
    PARTIALLY_BLOCKED = "partially_blocked"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RunRecord(BaseModel):
    """Durable state of one workflow execution."""

    id: str = Field(default_factory=lambda: new_id("run"))
    workflow: str
    subject: str
    correlation_key: str = ""
    status: RunStatus = RunStatus.CREATED

    requested_by: str = "system"
    reason: str = ""

    plan: ExecutionPlan | None = None
    created_at: datetime = Field(default_factory=_utcnow)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    updated_at: datetime = Field(default_factory=_utcnow)

    approvals: list[str] = Field(default_factory=list)
    """Approval IDs consumed by this run."""
    events: list[dict[str, Any]] = Field(default_factory=list)
    context: dict[str, Any] = Field(default_factory=dict)
    """Snapshot of the IdentitySnapshot summary the plan was built from."""

    def log_event(self, event: str, **data: Any) -> None:
        self.events.append({"at": _utcnow().isoformat(), "event": event, **data})
        self.updated_at = _utcnow()

    @property
    def is_finished(self) -> bool:
        return self.status in (RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED)

    def recompute_status(self) -> None:
        if self.plan is None:
            return
        # Never roll a run back out of a terminal state.
        if self.status in (RunStatus.FAILED, RunStatus.CANCELLED, RunStatus.COMPLETED):
            return
        steps = [s for s in self.plan.steps if s.enabled]
        if not steps:
            self.status = RunStatus.COMPLETED
            return
        if any(s.status == StepStatus.BLOCKED_ON_APPROVAL for s in steps):
            self.status = RunStatus.AWAITING_APPROVAL
        elif any(s.status == StepStatus.RUNNING for s in steps):
            self.status = RunStatus.RUNNING
        elif all(s.is_terminal for s in steps):
            # Everything has settled. A run with failures is FAILED unless every
            # failing step was explicitly marked continue_on_error, in which case
            # the workflow author decided those failures are tolerable.
            failed = [s for s in steps if s.status == StepStatus.FAILED]
            if failed and not all(s.continue_on_error for s in failed):
                self.status = RunStatus.FAILED
            else:
                self.status = RunStatus.COMPLETED
        self.updated_at = _utcnow()

    def summary(self) -> dict[str, Any]:
        return {
            "run_id": self.id,
            "workflow": self.workflow,
            "subject": self.subject,
            "status": self.status.value,
            "requested_by": self.requested_by,
            "reason": self.reason,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "progress": self.plan.progress() if self.plan else {},
            "max_risk": self.plan.max_risk.value if self.plan else None,
            "needs_approval": self.plan.needs_approval() if self.plan else False,
        }


# --------------------------------------------------------------------------- #
# Persistence
# --------------------------------------------------------------------------- #


class RunStore:
    """Tiny JSON-lines + per-run-file store. No external database required.

    Swap this for Postgres/DynamoDB in larger deployments by re-implementing the
    four methods below.
    """

    def __init__(self, directory: str | Path = "data/runs") -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def _path(self, run_id: str) -> Path:
        # run ids are generated by us; guard against traversal anyway.
        safe = "".join(c for c in run_id if c.isalnum() or c in "_-")
        return self.directory / f"{safe}.json"

    def save(self, run: RunRecord) -> RunRecord:
        run.updated_at = _utcnow()
        # model_dump() alone is not enough: Action.params holds raw credentials
        # and pydantic has no reason to know that. Scrub on the way to disk.
        payload = redact(run.model_dump(mode="json", exclude_none=True))
        tmp = self._path(run.id).with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        tmp.replace(self._path(run.id))
        return run

    def get(self, run_id: str) -> RunRecord | None:
        path = self._path(run_id)
        if not path.exists():
            return None
        return RunRecord.model_validate(json.loads(path.read_text(encoding="utf-8")))

    def list(self, *, workflow: str | None = None, limit: int = 100) -> list[RunRecord]:
        runs: list[RunRecord] = []
        for path in sorted(self.directory.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
            try:
                run = RunRecord.model_validate(json.loads(path.read_text(encoding="utf-8")))
            except Exception:  # noqa: BLE001 - a corrupt record must not break listing
                continue
            if workflow and run.workflow != workflow:
                continue
            runs.append(run)
            if len(runs) >= limit:
                break
        return runs

    def find_by_correlation(self, correlation_key: str, workflow: str) -> list[RunRecord]:
        return [
            r
            for r in self.list(limit=1000)
            if r.correlation_key == correlation_key and r.workflow == workflow
        ]
