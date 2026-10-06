"""Run and step status roll-up semantics.

Two properties that look redundant and are not:

* ``PlanStep.is_complete`` — finished *successfully*. The executor uses it to
  decide whether a dependent step may run, so FAILED must not count.
* ``PlanStep.is_terminal`` — will not change again. The run roll-up uses it, so
  FAILED must count.

Getting these the wrong way round produces two distinct, nasty failures: a run
that sits in ``running`` forever after a step fails (invisible to every caller),
or a step that executes despite its dependency having failed. Both are covered
here because both have happened.
"""

from __future__ import annotations

import pytest

from iam_agent.core.result import (
    ExecutionPlan,
    PlanStep,
    RunRecord,
    RunStatus,
    StepStatus,
)


def _run_with(steps: list[tuple[StepStatus, bool]]) -> RunRecord:
    """Build a run whose steps have the given (status, continue_on_error) pairs."""
    plan = ExecutionPlan(
        workflow="test",
        subject="someone",
        steps=[
            PlanStep(
                order=i,
                name=f"step{i}",
                platform="entra",
                status=status,
                continue_on_error=continue_on_error,
            )
            for i, (status, continue_on_error) in enumerate(steps, start=1)
        ],
    )
    run = RunRecord(workflow="test", subject="someone", plan=plan)
    run.status = RunStatus.RUNNING
    return run


@pytest.mark.parametrize(
    "statuses, expected",
    [
        ([StepStatus.DONE, StepStatus.DONE], RunStatus.COMPLETED),
        ([StepStatus.DONE, StepStatus.SKIPPED], RunStatus.COMPLETED),
        ([StepStatus.SKIPPED, StepStatus.SKIPPED], RunStatus.COMPLETED),
        # The regression: a failed step used to leave the run in RUNNING forever,
        # because the roll-up only settled when every step was is_complete.
        ([StepStatus.DONE, StepStatus.FAILED], RunStatus.FAILED),
        ([StepStatus.FAILED], RunStatus.FAILED),
        ([StepStatus.DONE, StepStatus.FAILED, StepStatus.DONE], RunStatus.FAILED),
        # Still in flight.
        ([StepStatus.DONE, StepStatus.RUNNING], RunStatus.RUNNING),
        ([StepStatus.PENDING, StepStatus.PENDING], RunStatus.RUNNING),
        ([StepStatus.DONE, StepStatus.BLOCKED_ON_APPROVAL], RunStatus.AWAITING_APPROVAL),
        ([StepStatus.FAILED, StepStatus.BLOCKED_ON_APPROVAL], RunStatus.AWAITING_APPROVAL),
    ],
)
def test_roll_up(statuses: list[StepStatus], expected: RunStatus) -> None:
    run = _run_with([(s, False) for s in statuses])
    run.recompute_status()
    assert run.status == expected


def test_tolerated_failures_still_complete_the_run() -> None:
    """A workflow author who marks a step continue_on_error accepts its failure."""
    run = _run_with([(StepStatus.FAILED, True), (StepStatus.DONE, False)])
    run.recompute_status()
    assert run.status == RunStatus.COMPLETED


def test_one_intolerant_failure_fails_the_whole_run() -> None:
    """Mixed tolerance: a single non-tolerated failure is enough."""
    run = _run_with([(StepStatus.FAILED, True), (StepStatus.FAILED, False)])
    run.recompute_status()
    assert run.status == RunStatus.FAILED


def test_disabled_steps_do_not_hold_the_run_open() -> None:
    plan = ExecutionPlan(
        workflow="test",
        subject="someone",
        steps=[
            PlanStep(order=1, name="done", platform="entra", status=StepStatus.DONE),
            PlanStep(order=2, name="off", platform="entra", status=StepStatus.PENDING, enabled=False),
        ],
    )
    run = RunRecord(workflow="test", subject="someone", plan=plan)
    run.status = RunStatus.RUNNING
    run.recompute_status()
    assert run.status == RunStatus.COMPLETED


def test_run_without_plan_does_not_crash() -> None:
    run = RunRecord(workflow="test", subject="someone")
    run.recompute_status()
    assert run.status == RunStatus.CREATED


@pytest.mark.parametrize("status", [StepStatus.DONE, StepStatus.SKIPPED])
def test_is_complete_means_success(status: StepStatus) -> None:
    step = PlanStep(order=1, name="s", platform="entra", status=status)
    assert step.is_complete is True
    assert step.is_terminal is True


@pytest.mark.parametrize("status", [StepStatus.FAILED])
def test_failed_is_terminal_but_not_complete(status: StepStatus) -> None:
    """The distinction the executor depends on: dependents must not run."""
    step = PlanStep(order=1, name="s", platform="entra", status=status)
    assert step.is_complete is False, "a failed step must block its dependents"
    assert step.is_terminal is True, "but the run roll-up must treat it as settled"


@pytest.mark.parametrize("status", [StepStatus.PENDING, StepStatus.RUNNING, StepStatus.BLOCKED_ON_APPROVAL])
def test_unsettled_steps_are_neither(status: StepStatus) -> None:
    step = PlanStep(order=1, name="s", platform="entra", status=status)
    assert step.is_complete is False
    assert step.is_terminal is False


@pytest.mark.parametrize(
    "terminal_status", [RunStatus.COMPLETED, RunStatus.FAILED, RunStatus.CANCELLED]
)
def test_terminal_runs_are_never_rolled_back(terminal_status: RunStatus) -> None:
    """Recomputation must not resurrect a finished run - e.g. on a late resume."""
    run = _run_with([(StepStatus.PENDING, False)])
    run.status = terminal_status
    run.recompute_status()
    assert run.status == terminal_status
