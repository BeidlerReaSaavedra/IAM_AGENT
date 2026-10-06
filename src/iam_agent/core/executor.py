"""Plan executor: the only component allowed to mutate production state.

Flow for every action in a plan
-------------------------------
1. :meth:`PolicyEngine.evaluate` classifies risk and decides the gate.
2. ``blocked``  → the action is skipped with a recorded reason.
3. ``approval_required`` → an :class:`ApprovalRequest` is created, the action is
   parked, the step becomes ``blocked_on_approval`` and the run stops there.
4. ``auto`` → the action runs (or is simulated in dry-run), then is audited.

The executor is *resumable*: call :meth:`resume` after approvals land and it
picks up exactly where it stopped, skipping anything already terminal. That is
what makes the hybrid mode practical - an offboarding can span days of human
review without losing its place or double-applying a step.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

from iam_agent.config import Settings
from iam_agent.connectors import ConnectorHub
from iam_agent.core.approval import ApprovalNotifier, ApprovalStore
from iam_agent.core.audit import AuditLog
from iam_agent.core.dispatch import ActionDispatcher
from iam_agent.core.errors import IAMAgentError, PolicyDeniedError
from iam_agent.core.policy import PolicyEngine
from iam_agent.core.result import (
    Action,
    ActionStatus,
    ExecutionPlan,
    PlanStep,
    RunRecord,
    RunStatus,
    RunStore,
    StepStatus,
)

#: Signature of the function bound to an action at plan time.
Handler = Callable[..., Awaitable[Any]]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Executor:
    """Runs execution plans under policy control."""

    def __init__(
        self,
        *,
        hub: ConnectorHub,
        settings: Settings,
        policy: PolicyEngine,
        approvals: ApprovalStore,
        audit: AuditLog,
        runs: RunStore,
        notifier: ApprovalNotifier | None = None,
        dispatcher: ActionDispatcher | None = None,
    ) -> None:
        self.hub = hub
        self.settings = settings
        self.policy = policy
        self.approvals = approvals
        self.audit = audit
        self.runs = runs
        self.notifier = notifier or ApprovalNotifier(settings)
        # Operations are resolved symbolically so a persisted plan stays runnable
        # after a restart, with no re-planning and therefore no duplicate approvals.
        self.dispatcher = dispatcher or ActionDispatcher(hub)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #

    async def plan_only(self, run: RunRecord) -> RunRecord:
        """Evaluate a plan without executing anything (dry-run report)."""
        assert run.plan is not None, "run has no plan"
        for step in run.plan.steps:
            for action in step.actions:
                decision = self.policy.evaluate(action)
                self.audit.decision(action, decision, run_id=run.id)
                self.audit.action_planned(action, run_id=run.id)
                if not decision.allowed:
                    action.mark(ActionStatus.SKIPPED, reason=decision.blocked_reason)
                elif decision.requires_approval:
                    action.status = ActionStatus.PLANNED
            step.status = StepStatus.PENDING
        run.status = RunStatus.PLANNED
        run.log_event("planned", mode="dry_run", actions=len(run.plan.all_actions))
        return self.runs.save(run)

    async def execute(self, run: RunRecord) -> RunRecord:
        """Execute a run, stopping at the first approval gate it cannot pass."""
        assert run.plan is not None, "run has no plan"

        if run.started_at is None:
            run.started_at = _utcnow()
        run.status = RunStatus.RUNNING
        self.runs.save(run)
        self.audit.workflow_event("run_started", run_id=run.id, workflow=run.workflow, subject=run.subject)

        crashed = False
        try:
            await self._walk(run)
        except Exception as exc:  # noqa: BLE001 - a run must always leave a record
            crashed = True
            run.status = RunStatus.FAILED
            run.log_event("executor_error", error=f"{type(exc).__name__}: {exc}")
            self.audit.workflow_event(
                "run_error", run_id=run.id, error=f"{type(exc).__name__}: {exc}"
            )
        finally:
            # A crash must not be laundered into "running" by the step-status roll-up.
            if not crashed:
                run.recompute_status()
            if run.is_finished:
                run.completed_at = _utcnow()
            self.runs.save(run)
            self.audit.workflow_event(
                "run_state", run_id=run.id, status=run.status.value, progress=run.plan.progress()
            )
        return run

    async def resume(self, run: RunRecord, *, approver: str = "resumed") -> RunRecord:
        """Continue a run whose approvals have now been granted."""
        assert run.plan is not None
        expired = self.approvals.expire_stale()
        if expired:
            self.audit.workflow_event("approvals_expired", ids=expired)

        unblocked = 0
        for step in run.plan.steps:
            if step.status != StepStatus.BLOCKED_ON_APPROVAL:
                continue
            for action in step.actions:
                if action.status != ActionStatus.PLANNED or not action.approval_id:
                    continue
                request = self.approvals.get(action.approval_id)
                if request is None:
                    continue
                status = request.effective_status()
                if status == "approved":
                    # Keep approval_id as the evidence trail and mark the action as
                    # cleared. Without this the policy engine re-gates the very same
                    # action on the next pass and the run loops forever.
                    action.status = ActionStatus.APPROVED
                    unblocked += 1
                    self.audit.workflow_event(
                        "approval_consumed",
                        run_id=run.id,
                        approval_id=request.id,
                        action_id=action.id,
                        approver=approver,
                    )
                elif status in ("rejected", "expired", "cancelled"):
                    action.mark(
                        ActionStatus.REJECTED if status == "rejected" else ActionStatus.EXPIRED,
                        reason=f"approval {status} by/after {request.decided_by or request.expires_at}",
                    )

        run.log_event("resumed", unblocked=unblocked)
        if unblocked:
            run.status = RunStatus.RUNNING
        return await self.execute(run)

    # ------------------------------------------------------------------ #
    # Internals
    # ------------------------------------------------------------------ #

    async def _walk(self, run: RunRecord) -> None:
        assert run.plan is not None
        plan = run.plan

        for step in self._ordered_steps(plan):
            if not step.enabled:
                step.status = StepStatus.SKIPPED
                continue

            if not self._dependencies_met(plan, step):
                step.notes = "skipped: an upstream dependency did not complete"
                step.status = StepStatus.SKIPPED
                continue

            if step.status in (StepStatus.DONE, StepStatus.SKIPPED):
                continue

            step.status = StepStatus.RUNNING
            step.started_at = _utcnow()
            self.audit.workflow_event("step_started", run_id=run.id, step=step.name)

            outcome = await self._run_step(run, step)

            if outcome is StepStatus.BLOCKED_ON_APPROVAL:
                step.status = StepStatus.BLOCKED_ON_APPROVAL
                run.status = RunStatus.AWAITING_APPROVAL
                run.log_event("awaiting_approval", step=step.name)
                self.audit.workflow_event(
                    "step_blocked", run_id=run.id, step=step.name,
                    approvals=[a.approval_id for a in step.actions if a.approval_id],
                )
                self.runs.save(run)
                return  # stop the walk; resume() continues later

            step.completed_at = _utcnow()
            step.status = outcome
            self.audit.workflow_event(
                "step_finished", run_id=run.id, step=step.name, status=step.status.value
            )

            if step.status == StepStatus.FAILED and not step.continue_on_error:
                run.log_event("step_failed_halt", step=step.name)
                run.status = RunStatus.FAILED
                self.runs.save(run)
                return
            self.runs.save(run)

    def _ordered_steps(self, plan: ExecutionPlan) -> list[PlanStep]:
        """Topological-ish order: honour ``order`` first, then dependencies."""
        remaining = list(plan.steps)
        done: set[str] = set()
        ordered: list[PlanStep] = []
        while remaining:
            ready = [
                s
                for s in remaining
                if all(dep in done or not plan.step(dep) for dep in s.depends_on)
            ]
            if not ready:  # cycle - fall back to declared order
                ready = [min(remaining, key=lambda s: s.order)]
            batch = sorted(ready, key=lambda s: s.order)
            for step in batch:
                ordered.append(step)
                done.add(step.name)
                remaining.remove(step)
        return ordered

    def _dependencies_met(self, plan: ExecutionPlan, step: PlanStep) -> bool:
        for name in step.depends_on:
            dep = plan.step(name)
            if dep is None:
                continue
            if dep.status == StepStatus.FAILED:
                return False
            if not dep.is_complete and dep.enabled:
                # Dependency not reached yet - only valid if ordering is wrong.
                return dep.status in (StepStatus.DONE, StepStatus.SKIPPED)
        return True

    def _is_cleared(self, action: Action) -> bool:
        """True when a human approval has already been granted for this action.

        Checked against the live approval record rather than a flag alone, so a
        request that expired or was withdrawn between passes is never honoured.
        """
        if action.status == ActionStatus.APPROVED:
            return bool(action.approval_id) and self.approvals.is_approved(action.approval_id)
        return bool(action.approval_id) and self.approvals.is_approved(action.approval_id)

    async def _run_step(self, run: RunRecord, step: PlanStep) -> StepStatus:
        """Run every action in a step and report the step's resulting status."""
        assert run.plan is not None
        blocked_actions: list[Action] = []
        failed = False

        # Pass 1: policy evaluation for everything not already terminal.
        for action in step.actions:
            if action.status in (
                ActionStatus.SUCCEEDED,
                ActionStatus.DRY_RUN,
                ActionStatus.SKIPPED,
                ActionStatus.REJECTED,
                ActionStatus.EXPIRED,
            ):
                continue
            if action.status == ActionStatus.RUNNING:
                continue

            # A human already signed this one off - execute without re-gating.
            if self._is_cleared(action):
                await self._apply(run, action)
                if action.status == ActionStatus.FAILED:
                    failed = True
                continue

            decision = self.policy.evaluate(action)
            self.audit.decision(action, decision, run_id=run.id)

            if not decision.allowed:
                action.mark(ActionStatus.SKIPPED, reason=decision.blocked_reason)
                self.audit.action_executed(action, run_id=run.id, outcome="blocked_by_policy")
                continue

            if decision.requires_approval:
                blocked_actions.append(action)
                continue

            await self._apply(run, action)
            if action.status == ActionStatus.FAILED:
                failed = True

        # Pass 2: create one approval covering everything gated in this step.
        if blocked_actions:
            request = self.approvals.create(
                actions=blocked_actions,
                run_id=run.id,
                workflow=run.workflow,
                subject=run.subject,
                title=f"{step.name} — {run.subject}",
                description=step.description,
                requested_by=run.requested_by,
            )
            for action in blocked_actions:
                action.approval_id = request.id
                self.audit.action_planned(action, run_id=run.id, approval_id=request.id)
            run.approvals.append(request.id)
            self.audit.approval(request, run_id=run.id)
            self.notifier.notify(request)
            return StepStatus.BLOCKED_ON_APPROVAL

        return StepStatus.FAILED if failed else StepStatus.DONE

    async def _apply(self, run: RunRecord, action: Action) -> None:
        """Execute one action (or simulate it) and record the outcome."""
        if self.settings.global_dry_run:
            action.mark(
                ActionStatus.DRY_RUN,
                simulated=True,
                reason="global dry-run: nothing was written to any platform",
            )
            self.audit.action_executed(action, run_id=run.id, outcome="dry_run")
            return

        action.status = ActionStatus.RUNNING
        action.started_at = _utcnow()
        action.attempts += 1
        self.audit.action_executed(action, run_id=run.id, outcome="running")

        try:
            if action.executor is not None:
                # Explicitly bound handlers win (used for verification closures).
                result = await action.executor(**action.params)
            else:
                result = await self.dispatcher.dispatch(action.operation, action.params)
            payload = result if isinstance(result, dict) else {"result": result}
            action.mark(ActionStatus.SUCCEEDED, **payload)
            self.audit.action_executed(action, run_id=run.id, outcome="succeeded")
        except PolicyDeniedError as exc:
            action.mark(ActionStatus.SKIPPED, reason=str(exc))
            action.error = str(exc)
            self.audit.action_executed(action, run_id=run.id, outcome="policy_denied")
        except IAMAgentError as exc:
            action.mark(ActionStatus.FAILED, **exc.to_dict())
            action.error = exc.message
            self.audit.action_executed(action, run_id=run.id, outcome="failed", error=exc.message)
        except Exception as exc:  # noqa: BLE001
            action.mark(ActionStatus.FAILED, error=f"{type(exc).__name__}: {exc}")
            action.error = str(exc)
            self.audit.action_executed(action, run_id=run.id, outcome="failed", error=str(exc))


class RollbackManager:
    """Best-effort compensation for a partially applied run.

    Only actions that declared a ``compensating_action`` can be undone; the
    manager walks the plan backwards so later changes are reverted first.
    """

    def __init__(self, executor: Executor) -> None:
        self.executor = executor

    async def rollback(self, run: RunRecord) -> dict[str, Any]:
        assert run.plan is not None
        reverted: list[str] = []
        skipped: list[str] = []

        for step in reversed(run.plan.steps):
            for action in reversed(step.actions):
                if action.status != ActionStatus.SUCCEEDED:
                    continue
                compensation = action.compensating_action
                if compensation is None or not action.reversible:
                    skipped.append(f"{action.operation}:{action.target}")
                    continue
                compensation.status = ActionStatus.PLANNED
                await self.executor._apply(run, compensation)
                if compensation.status == ActionStatus.SUCCEEDED:
                    action.status = ActionStatus.ROLLED_BACK
                    reverted.append(action.operation)
                else:
                    skipped.append(f"{action.operation}:rollback_failed")

        run.log_event("rollback", reverted=reverted, skipped=skipped)
        self.executor.audit.workflow_event(
            "rollback", run_id=run.id, reverted=reverted, skipped=skipped
        )
        self.executor.runs.save(run)
        return {"reverted": reverted, "skipped": skipped}
