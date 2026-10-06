"""Workflow framework: declarative playbooks that build executable plans.

A workflow is a *pure planner*. It reads state, decides what should happen, and
returns an :class:`ExecutionPlan`. It never writes anything itself - the
:class:`~iam_agent.core.executor.Executor` does that, behind the policy gate.

That separation is deliberate:

* the plan can be shown to a human for approval **before** anything happens
* the same planner can be driven by Claude, by the REST API, by a cron job or by
  a webhook, with identical behaviour
* planning is cheap and safe, so it can be re-run any time to see what *would*
  happen (``dry_run``)
"""

from __future__ import annotations

import abc
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, ClassVar

from iam_agent.config import Settings
from iam_agent.connectors import ConnectorHub
from iam_agent.core.models import Employee, IdentitySnapshot
from iam_agent.core.result import Action, ExecutionPlan, PlanStep, RiskLevel

Handler = Callable[..., Awaitable[Any]]


@dataclass
class WorkflowContext:
    """Everything a planner may look at.

    ``resolved`` accumulates identifiers discovered during planning (e.g. the
    Entra object id created in step 1) so later steps can reference them.
    Because planning happens before execution, values that only exist after a
    write are represented as *late-bound* placeholders the executor fills in.
    """

    employee: Employee
    hub: ConnectorHub
    settings: Settings
    snapshot: IdentitySnapshot | None = None
    requested_by: str = "system"
    reason: str = ""
    options: dict[str, Any] = field(default_factory=dict)
    resolved: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)

    # ---- option helpers --------------------------------------------------- #

    def opt(self, key: str, default: Any = None) -> Any:
        value = self.options.get(key, default)
        return default if value is None else value

    def flag(self, key: str, default: bool = False) -> bool:
        return bool(self.options.get(key, default))

    # ---- identity helpers -------------------------------------------------- #

    @property
    def entra_id(self) -> str:
        """Best-known Entra object id for the subject."""
        if self.snapshot and self.snapshot.entra:
            return self.snapshot.entra.external_id
        ref = self.employee.identity_for("entra")
        return ref.external_id if ref else (self.employee.upn or self.employee.email)

    @property
    def ad_identifier(self) -> str:
        if self.snapshot and self.snapshot.on_prem:
            return self.snapshot.on_prem.dn or self.snapshot.on_prem.external_id
        return self.employee.username or self.employee.email

    @property
    def subject_label(self) -> str:
        return self.employee.full_name or self.employee.email or self.employee.employee_id or "unknown"

    def note(self, message: str) -> None:
        self.warnings.append(message)

    def assume(self, message: str) -> None:
        self.assumptions.append(message)


def action(
    operation: str,
    platform: str,
    executor: Handler | None = None,
    *,
    description: str = "",
    target: str = "",
    risk: RiskLevel | None = None,
    reversible: bool = True,
    idempotency_key: str = "",
    compensating: Action | None = None,
    **params: Any,
) -> Action:
    """Build an :class:`Action` targeting ``<platform>.<method>``.

    ``executor`` is accepted for readability at the call site - it names the
    connector method being invoked - but it is deliberately **not** bound onto
    the action. Dispatch is resolved symbolically at run time from the
    ``operation`` string (see :mod:`iam_agent.core.dispatch`).

    That is what makes a plan durable: a run parked for three days waiting on a
    human approval can be reloaded from disk in a fresh process and still
    execute, without re-planning and without re-opening approvals that were
    already granted. ``params`` are passed to the resolved method as keyword
    arguments, so their names must match its signature.
    """
    act = Action(
        operation=operation,
        platform=platform,
        description=description or operation,
        params=dict(params),
        target=target,
        reversible=reversible,
        idempotency_key=idempotency_key or f"{operation}:{target}",
        compensating_action=compensating,
    )
    if risk is not None:
        act.risk = risk
    return act


def step(
    order: int,
    name: str,
    platform: str,
    *actions: Action,
    description: str = "",
    depends_on: list[str] | None = None,
    continue_on_error: bool = False,
    requires_approval: bool = False,
    enabled: bool = True,
) -> PlanStep:
    return PlanStep(
        order=order,
        name=name,
        platform=platform,
        description=description,
        actions=[a for a in actions if a is not None],
        depends_on=depends_on or [],
        continue_on_error=continue_on_error,
        requires_approval=requires_approval,
        enabled=enabled,
    )


class Workflow(abc.ABC):
    """Base class for every playbook."""

    #: Stable identifier used by the registry, API and CLI.
    key: str = "workflow"
    #: One-line description shown to Claude and in the API index.
    summary: str = ""
    #: Longer guidance - included in the MCP tool description so Claude knows
    #: when to pick this workflow.
    guidance: str = ""
    #: Which platforms the workflow touches (used for pre-flight health checks).
    platforms: tuple[str, ...] = ()
    #: Options the caller may override, with defaults. Documented for Claude.
    #: ClassVar, not an instance attribute: subclasses replace it wholesale and
    #: nothing mutates it in place, but the annotation makes that a rule rather
    #: than a coincidence - a future `self.options_schema[...] = ...` would
    #: otherwise leak into every other instance of the class.
    options_schema: ClassVar[dict[str, Any]] = {}

    def __init__(self, hub: ConnectorHub, settings: Settings) -> None:
        self.hub = hub
        self.settings = settings

    @abc.abstractmethod
    async def plan(self, ctx: WorkflowContext) -> ExecutionPlan:
        """Build the execution plan for this workflow."""

    # ---- helpers available to subclasses --------------------------------- #

    def new_plan(self, ctx: WorkflowContext) -> ExecutionPlan:
        return ExecutionPlan(
            workflow=self.key,
            subject=ctx.subject_label,
            assumptions=list(ctx.assumptions),
            warnings=list(ctx.warnings),
        )

    async def health_gate(self, ctx: WorkflowContext) -> list[str]:
        """Return a list of platforms that are unhealthy, if any."""
        statuses = await self.hub.health()
        unhealthy = []
        for platform in self.platforms:
            status = statuses.get(platform)
            if status and not status.healthy:
                unhealthy.append(f"{platform}: {status.detail}")
        return unhealthy

    def describe(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "summary": self.summary,
            "guidance": self.guidance,
            "platforms": list(self.platforms),
            "options": self.options_schema,
        }


__all__ = [
    "Action",
    "ExecutionPlan",
    "PlanStep",
    "RiskLevel",
    "Workflow",
    "WorkflowContext",
    "action",
    "step",
]
