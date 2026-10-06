"""The orchestrator: the single entry point every interface calls into.

MCP tools, REST routes, the CLI and the autonomous Claude agent all funnel
through :class:`Orchestrator`. That is deliberate - it means there is exactly one
place where a plan is built, gated by policy, approved, executed, audited and
persisted, so no interface can bypass the safety layer.
"""

from __future__ import annotations

import asyncio
from datetime import date, datetime
from typing import Any

from iam_agent.config import Settings, get_settings
from iam_agent.connectors import ConnectorHub, get_hub
from iam_agent.core.approval import ApprovalNotifier, ApprovalRequest, ApprovalStore
from iam_agent.core.audit import AuditLog
from iam_agent.core.errors import IAMAgentError, NotFoundError
from iam_agent.core.models import DriftReport, Employee, IdentitySnapshot, LifecycleState
from iam_agent.core.policy import DEFAULT_RULES, PolicyEngine
from iam_agent.core.reconcile import Reconciler
from iam_agent.core.result import (
    Action,
    PlanStep,
    RiskLevel,
    ActionStatus,
    ExecutionPlan,
    RunRecord,
    RunStatus,
    RunStore,
    StepStatus,
)
from iam_agent.core.executor import Executor, RollbackManager
from iam_agent.workflows.base import WorkflowContext
from iam_agent.workflows.registry import WorkflowRegistry


class Orchestrator:
    """Coordinates connectors, workflows, policy, approvals and audit."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        hub: ConnectorHub | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.audit = audit or AuditLog(self.settings.audit)
        self.hub = hub or get_hub(self.settings, self.audit)
        self.policy = PolicyEngine(self.settings, DEFAULT_RULES)
        self.approvals = ApprovalStore(self.settings.approval)
        self.notifier = ApprovalNotifier(self.settings)
        self.runs = RunStore(self.settings.audit.run_store_path)
        self.workflows = WorkflowRegistry(self.hub, self.settings)
        self.reconciler = Reconciler(self.hub, self.settings)
        self.executor = Executor(
            hub=self.hub,
            settings=self.settings,
            policy=self.policy,
            approvals=self.approvals,
            audit=self.audit,
            runs=self.runs,
            notifier=self.notifier,
        )
        self.rollback = RollbackManager(self.executor)

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #

    async def status(self) -> dict[str, Any]:
        """Everything an operator (or Claude) needs to understand current posture."""
        health = await self.hub.health_report()
        return {
            "settings": self.settings.describe(),
            "health": health,
            "mock_estate": self.hub.store.stats() if self.hub.store else None,
            "pending_approvals": len(self.approvals.pending()),
            "active_runs": len([r for r in self.runs.list(limit=200) if not r.is_finished]),
            "audit_events": self.audit.stats(),
            "workflows": self.workflows.keys(),
        }

    async def preflight(self) -> dict[str, Any]:
        """Connectivity + configuration check across all five platforms."""
        statuses = await self.hub.health()
        problems: list[str] = []
        for name, status in statuses.items():
            if not status.healthy:
                problems.append(f"{name}: {status.detail}")

        configuration_notes = []
        if not self.settings.entra.primary_domain:
            configuration_notes.append(
                "IAM_ENTRA_PRIMARY_DOMAIN is unset - UPNs will be derived from the supplied email domain."
            )
        if self.settings.active_directory.enabled and not self.settings.active_directory.use_ssl:
            configuration_notes.append(
                "On-prem AD is configured without LDAPS; password writes will be refused."
            )
        if self.settings.action1.region == "north_america" and self.settings.environment == "production":
            configuration_notes.append(
                "Action1 is pointed at the North America region while the tenant appears to be EU."
            )

        return {
            "ok": not problems,
            "mode": self.settings.effective_mode(),
            "connectors": {n: s.to_dict() for n, s in statuses.items()},
            "problems": problems,
            "configuration_notes": configuration_notes,
        }

    # ------------------------------------------------------------------ #
    # Identity lookups
    # ------------------------------------------------------------------ #

    async def get_identity(self, identifier: str) -> IdentitySnapshot:
        """Full cross-platform picture of one person."""
        snapshot = await self.reconciler.snapshot(identifier)
        if not snapshot.directories:
            raise NotFoundError(
                f"no identity matched '{identifier}' in Entra ID or on-premises AD",
                platform="entra",
            )
        self.audit.workflow_event("identity_snapshot", subject=identifier,
                                  platforms=list(snapshot.directories),
                                  devices=len(snapshot.devices))
        return snapshot

    async def find_people(self, query: str, *, limit: int = 25) -> list[dict[str, Any]]:
        """Fuzzy search across Entra and AD."""
        results = await asyncio.gather(
            self.hub.entra.search_users(query),
            self.hub.active_directory.search_users(query),
            return_exceptions=True,
        )
        merged: dict[str, dict[str, Any]] = {}
        for result in results:
            if isinstance(result, BaseException):
                continue
            for user in result:
                key = user.email or user.upn or user.external_id
                entry = merged.setdefault(
                    key,
                    {
                        "identifier": user.email or user.upn,
                        "display_name": user.display_name,
                        "username": user.username,
                        "department": user.department,
                        "job_title": user.job_title,
                        "enabled": user.enabled,
                        "platforms": [],
                    },
                )
                entry["platforms"].append(user.platform)
                entry["enabled"] = entry["enabled"] or user.enabled
        return list(merged.values())[:limit]

    async def audit_estate(self, *, limit: int = 200) -> DriftReport:
        """Estate-wide drift sweep.

        Named ``audit_estate`` rather than ``audit`` because ``self.audit`` is the
        :class:`AuditLog` instance - an instance attribute would shadow the method.
        """
        report = await self.reconciler.audit_fleet(limit=limit)
        self.audit.workflow_event(
            "drift_audit", findings=len(report.findings),
            critical=len(report.by_severity().get("critical", [])),
        )
        return report

    # ------------------------------------------------------------------ #
    # Workflow execution
    # ------------------------------------------------------------------ #

    def annotate_plan(self, run: RunRecord) -> RunRecord:
        """Mark, ahead of time, which steps will gate on a human.

        The planner only knows the *shape* of the work; whether it needs a human
        is a policy question. Without this pass a dry-run plan reports
        ``needs_approval == False`` for an offboarding that will in fact park on
        four approvals, which is exactly the wrong thing to tell an operator.

        Purely advisory: :class:`~iam_agent.core.executor.Executor` re-evaluates
        policy per action at execution time and never consults these flags, so
        annotating cannot weaken a gate.
        """
        plan = run.plan
        if plan is None:
            return run

        gated = 0
        blocked_ops: list[str] = []
        for step in plan.steps:
            if not step.enabled:
                continue
            step_gated = False
            for action in step.actions:
                decision = self.policy.evaluate(action)
                if decision.requires_approval:
                    step_gated = True
                elif not decision.allowed:
                    blocked_ops.append(f"{action.operation}: {decision.blocked_reason}")
            if step_gated:
                step.requires_approval = True
                gated += 1

        if gated:
            plan.assumptions.append(
                f"{gated} of {len([s for s in plan.steps if s.enabled])} steps will require "
                f"human approval in {self.settings.approval.default_mode} mode."
            )
        for message in blocked_ops:
            if message not in plan.warnings:
                plan.warnings.append(f"policy will skip this action — {message}")
        return run

    async def build_plan(
        self,
        workflow: str,
        employee: Employee,
        *,
        options: dict[str, Any] | None = None,
        requested_by: str = "system",
        reason: str = "",
        with_snapshot: bool = True,
    ) -> tuple[RunRecord, WorkflowContext]:
        """Plan a workflow without executing it."""
        snapshot: IdentitySnapshot | None = None
        if with_snapshot:
            needle = employee.email or employee.upn or employee.username or employee.employee_id
            if needle:
                try:
                    snapshot = await self.reconciler.snapshot(needle)
                except Exception:  # noqa: BLE001 - a brand-new hire has no snapshot yet
                    snapshot = None

        if snapshot and snapshot.employee.email and not employee.email:
            employee.email = snapshot.employee.email
        if snapshot and snapshot.entra:
            # Adopt the authoritative lifecycle state unless the caller overrode it.
            if employee.lifecycle_state == LifecycleState.PRE_HIRE and workflow == "offboarding":
                employee.lifecycle_state = LifecycleState.LEAVER

        ctx = WorkflowContext(
            employee=employee,
            hub=self.hub,
            settings=self.settings,
            snapshot=snapshot,
            requested_by=requested_by,
            reason=reason,
            options=dict(options or {}),
        )

        impl = self.workflows.get(workflow)
        plan: ExecutionPlan = await impl.plan(ctx)
        plan.assumptions = list(dict.fromkeys(plan.assumptions + ctx.assumptions))
        plan.warnings = list(dict.fromkeys(plan.warnings + ctx.warnings))

        run = RunRecord(
            workflow=workflow,
            subject=ctx.subject_label,
            correlation_key=employee.correlation_key,
            requested_by=requested_by,
            reason=reason,
            plan=plan,
            context={
                "summary": snapshot.summary() if snapshot else None,
                "resolved": _safe_resolved(ctx),
                "options": {k: v for k, v in (options or {}).items() if k != "password"},
            },
        )
        run.status = RunStatus.PLANNED
        # Annotate before the audit event so the recorded needs_approval is the
        # real answer, not the planner's guess.
        self.annotate_plan(run)
        run.log_event("plan_built", steps=len(plan.steps), actions=len(plan.all_actions))
        self.runs.save(run)
        self.audit.workflow_event(
            "plan_built", run_id=run.id, workflow=workflow, subject=run.subject,
            steps=len(plan.steps), actions=len(plan.all_actions),
            max_risk=plan.max_risk.value, needs_approval=plan.needs_approval(),
        )
        return run, ctx

    async def run_workflow(
        self,
        workflow: str,
        employee: Employee,
        *,
        options: dict[str, Any] | None = None,
        requested_by: str = "system",
        reason: str = "",
        execute: bool = True,
    ) -> RunRecord:
        """Plan and (optionally) execute a workflow end to end."""
        run, _ctx = await self.build_plan(
            workflow,
            employee,
            options=options,
            requested_by=requested_by,
            reason=reason,
        )

        if not execute:
            return run

        if self.settings.effective_mode() == "dry_run":
            return await self.executor.plan_only(run)
        return await self.executor.execute(run)

    async def run_adhoc(
        self,
        actions: list[Action],
        *,
        subject: str,
        requested_by: str = "agent",
        reason: str = "",
        execute: bool = True,
    ) -> RunRecord:
        """Run one or more targeted actions outside a named workflow.

        Used for incident response ("disable this account *now*") and for the
        granular MCP tools. These still get a plan, a policy evaluation, an
        approval gate when required and a full audit record - the gate is not
        bypassable just because the request did not come from a playbook.
        """
        plan = ExecutionPlan(workflow="adhoc", subject=subject)
        plan.add(
            PlanStep(
                order=1,
                name="adhoc_actions",
                platform=actions[0].platform if actions else "all",
                description=reason or "Ad-hoc action requested by an operator or the agent.",
                actions=actions,
                continue_on_error=False,
            )
        )
        run = RunRecord(
            workflow="adhoc",
            subject=subject,
            requested_by=requested_by,
            reason=reason,
            plan=plan,
        )
        run.status = RunStatus.PLANNED
        self.annotate_plan(run)
        run.log_event("adhoc_plan_built", actions=len(actions))
        self.runs.save(run)
        self.audit.workflow_event(
            "adhoc_plan_built", run_id=run.id, subject=subject,
            operations=[a.operation for a in actions],
        )
        if not execute:
            return run
        if self.settings.effective_mode() == "dry_run":
            return await self.executor.plan_only(run)
        return await self.executor.execute(run)

    def build_action(
        self,
        operation: str,
        *,
        description: str = "",
        target: str = "",
        risk: RiskLevel | None = None,
        reversible: bool = True,
        **params: Any,
    ) -> Action:
        """Create a single validated action for :meth:`run_adhoc`.

        Resolving the operation here means a typo surfaces immediately with a
        precise message instead of failing halfway through a run.
        """
        self.executor.dispatcher.assert_resolvable(operation)
        act = Action(
            operation=operation,
            platform=operation.split(".", 1)[0],
            description=description or operation,
            target=target,
            params=params,
            reversible=reversible,
            idempotency_key=f"{operation}:{target}",
        )
        if risk is not None:
            act.risk = risk
        return act

    async def resume_run(self, run_id: str, *, approver: str = "api") -> RunRecord:
        run = self.runs.get(run_id)
        if run is None:
            raise NotFoundError(f"no run with id '{run_id}'", platform="orchestrator")
        return await self.executor.resume(run, approver=approver)

    async def cancel_run(self, run_id: str, reason: str = "") -> RunRecord:
        run = self.runs.get(run_id)
        if run is None:
            raise NotFoundError(f"no run with id '{run_id}'", platform="orchestrator")
        if run.is_finished:
            raise IAMAgentError(f"run {run_id} already finished ({run.status.value})", platform="orchestrator")
        run.status = RunStatus.CANCELLED
        run.completed_at = datetime.now()
        run.log_event("cancelled", reason=reason)
        for approval_id in run.approvals:
            self.approvals.cancel(approval_id, reason)
        if run.plan:
            for step in run.plan.steps:
                if step.status in (StepStatus.PENDING, StepStatus.BLOCKED_ON_APPROVAL):
                    step.status = StepStatus.SKIPPED
        self.runs.save(run)
        self.audit.workflow_event("run_cancelled", run_id=run_id, reason=reason)
        return run

    async def rollback_run(self, run_id: str) -> dict[str, Any]:
        run = self.runs.get(run_id)
        if run is None:
            raise NotFoundError(f"no run with id '{run_id}'", platform="orchestrator")
        return await self.rollback.rollback(run)

    # ------------------------------------------------------------------ #
    # Approvals
    # ------------------------------------------------------------------ #

    def list_approvals(self, *, status: str | None = "pending") -> list[ApprovalRequest]:
        self.approvals.expire_stale()
        return self.approvals.list(status=status)  # type: ignore[arg-type]

    def get_approval(self, approval_id: str) -> ApprovalRequest:
        request = self.approvals.get(approval_id)
        if request is None:
            raise NotFoundError(f"no approval '{approval_id}'", platform="orchestrator")
        return request

    async def decide_approval(
        self,
        approval_id: str,
        *,
        approve: bool,
        decided_by: str,
        comment: str = "",
        resume: bool = True,
    ) -> dict[str, Any]:
        """Approve or reject, then continue the parked run."""
        request = self.get_approval(approval_id)
        updated = self.approvals.decide(
            approval_id, approve=approve, decided_by=decided_by, comment=comment
        )
        self.audit.approval(
            updated,
            event="approval_approved" if approve else "approval_rejected",
            decided_by=decided_by,
            comment=comment,
        )

        outcome: dict[str, Any] = {
            "approval_id": approval_id,
            "status": updated.effective_status(),
            "required_approvals": updated.required_approvals,
            "approvals_recorded": len(updated.approvals),
            "fully_approved": updated.effective_status() == "approved",
        }

        if resume and updated.run_id and approve and updated.effective_status() == "approved":
            run = await self.resume_run(updated.run_id, approver=decided_by)
            outcome["run_id"] = run.id
            outcome["run_status"] = run.status.value
            outcome["progress"] = run.plan.progress() if run.plan else {}
        elif resume and updated.run_id and not approve:
            run = self.runs.get(updated.run_id)
            if run:
                run.status = RunStatus.CANCELLED
                run.log_event("cancelled_by_rejection", approval_id=approval_id, by=decided_by)
                if run.plan:
                    for step in run.plan.steps:
                        if step.status == StepStatus.BLOCKED_ON_APPROVAL:
                            step.status = StepStatus.SKIPPED
                self.runs.save(run)
                outcome["run_id"] = run.id
                outcome["run_status"] = run.status.value
        return outcome

    # ------------------------------------------------------------------ #
    # Runs
    # ------------------------------------------------------------------ #

    def get_run(self, run_id: str) -> RunRecord:
        run = self.runs.get(run_id)
        if run is None:
            raise NotFoundError(f"no run '{run_id}'", platform="orchestrator")
        return run

    def list_runs(self, *, workflow: str | None = None, limit: int = 50) -> list[RunRecord]:
        return self.runs.list(workflow=workflow, limit=limit)

    def run_detail(self, run_id: str) -> dict[str, Any]:
        run = self.get_run(run_id)
        plan = run.plan
        return {
            **run.summary(),
            "reason": run.reason,
            "events": run.events[-40:],
            "plan": {
                "id": plan.id if plan else None,
                "max_risk": plan.max_risk.value if plan else None,
                "needs_approval": plan.needs_approval() if plan else False,
                "assumptions": plan.assumptions if plan else [],
                "warnings": plan.warnings if plan else [],
                "steps": [s.summary() for s in plan.steps] if plan else [],
            },
            "pending_approvals": [
                a.to_dict() if hasattr(a, "to_dict") else a
                for a in self.approvals.list(status="pending", run_id=run_id)
            ],
        }

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    async def aclose(self) -> None:
        await self.hub.aclose()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _safe_resolved(ctx: WorkflowContext) -> dict[str, Any]:
    """Strip secrets before persisting the planning context."""
    return {k: v for k, v in ctx.resolved.items() if not k.startswith("_")}
