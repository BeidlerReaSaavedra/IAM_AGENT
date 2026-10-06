"""Persistence and cross-process resume.

The CLI, the REST API and the MCP server are three separate processes that must
all see the same parked run and the same approval gate. If the approval queue or
the run store does not survive a restart, every run parked at a gate is stranded
forever - so this is a correctness requirement, not a convenience.

Each test here builds a *second* Orchestrator to stand in for a second process.
That is the part the earlier suites missed: constructing a fresh object over the
same files is what exercises rehydration, including the ``coerce()`` path that
turns stored JSON back into pydantic models and datetimes.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from conftest import approve_everything
from iam_agent.core.approval import ApprovalStore
from iam_agent.core.models import Employee, Manager
from iam_agent.core.orchestrator import Orchestrator
from iam_agent.core.result import RunRecord, RunStatus, RunStore


def _hire(**overrides) -> Employee:
    base = dict(
        employee_id="EMP-8001",
        first_name="Aina",
        last_name="Serra",
        department="Ventas",
        job_title="Account Executive",
        hire_date=date(2026, 11, 15),
        manager=Manager(email="lferra@contoso-balears.example"),
    )
    base.update(overrides)
    return Employee(**base)


def test_approval_queue_survives_a_new_store_instance(settings):
    """A pending gate must still be pending after the process that created it exits."""
    from iam_agent.core.result import Action, RiskLevel

    first = ApprovalStore(settings.approval)
    store_run = RunRecord(workflow="onboarding", subject="Aina Serra")

    request = first.create(
        actions=[
            Action(
                operation="entra.create_user",
                platform="entra",
                description="Create the user",
                target="aserra@contoso-balears.example",
                risk=RiskLevel.MEDIUM,
                params={"employee": _hire(), "password": "Sup3r-Canary"},
            )
        ],
        run_id=store_run.id,
        workflow="onboarding",
        subject="Aina Serra",
        title="entra_identity — Aina Serra",
        requested_by="persistence-test",
    )
    assert request.id
    assert Path(settings.approval.storage_path).exists()

    # A brand-new store over the same file == a new process.
    second = ApprovalStore(settings.approval)
    assert second.corrupt_lines == 0
    pending = second.list(status="pending")
    assert [r.id for r in pending] == [request.id], (
        "the queue did not rehydrate - a parked run would be stranded after a restart"
    )
    assert pending[0].title == request.title
    assert pending[0].run_id == store_run.id


def test_run_store_round_trips_a_parked_run(settings):
    """A run saved mid-flight must reload with its plan, params and statuses intact."""
    store = RunStore(settings.audit.run_store_path)

    run = RunRecord(
        workflow="onboarding",
        subject="Aina Serra",
        requested_by="persistence-test",
        reason="round-trip",
    )
    run.status = RunStatus.AWAITING_APPROVAL
    run.log_event("test_event", detail="value")
    store.save(run)

    reloaded = store.get(run.id)
    assert reloaded is not None
    assert reloaded.id == run.id
    assert reloaded.status == RunStatus.AWAITING_APPROVAL
    assert reloaded.workflow == "onboarding"
    assert reloaded.events, "event history must survive the round-trip"
    assert reloaded.created_at.tzinfo is not None, "datetimes must come back timezone-aware"


async def test_second_orchestrator_can_approve_a_run_parked_by_the_first(settings):
    """The real scenario: park in one process, approve in another, and finish."""
    first = Orchestrator(settings)
    run = await first.run_workflow(
        "onboarding", _hire(), requested_by="process-1", reason="cross-process"
    )
    assert run.status == RunStatus.AWAITING_APPROVAL
    parked_id = run.id
    first_pending = first.list_approvals(status="pending")
    assert first_pending, "the run should have parked on a gate"

    # Simulate process 1 exiting and process 2 starting against the same files.
    second = Orchestrator(settings)
    assert second is not first
    second_pending = second.list_approvals(status="pending")
    assert [r.id for r in second_pending] == [r.id for r in first_pending], (
        "the second process must see exactly the gates the first one left behind"
    )

    reloaded = second.get_run(parked_id)
    assert reloaded is not None
    assert reloaded.status == RunStatus.AWAITING_APPROVAL

    rounds = await approve_everything(second)
    assert rounds > 0
    finished = second.get_run(parked_id)
    assert finished.status == RunStatus.COMPLETED, finished.status

    await first.aclose()
    await second.aclose()


async def test_no_secret_survives_the_round_trip(settings):
    """Rehydration must not resurrect a credential that redaction removed on write."""
    orchestrator = Orchestrator(settings)
    await orchestrator.run_workflow(
        "onboarding",
        _hire(),
        options={"password": "Sup3r-Canary"},
        requested_by="persistence-test",
    )
    run_dir = Path(settings.audit.run_store_path)
    blobs = [p.read_text(encoding="utf-8") for p in run_dir.rglob("*") if p.is_file()]
    assert blobs, "expected at least one persisted run"
    for blob in blobs:
        assert "Sup3r-Canary" not in blob
        assert json.loads(blob), "persisted runs must be valid JSON"

    approvals_blob = Path(settings.approval.storage_path).read_text(encoding="utf-8")
    assert "Sup3r-Canary" not in approvals_blob
    await orchestrator.aclose()


def test_corrupt_line_is_skipped_without_losing_the_rest(settings, tmp_path):
    """One unreadable record must not take the whole queue down with it."""
    from iam_agent.core.result import Action, RiskLevel

    store = ApprovalStore(settings.approval)
    good = store.create(
        actions=[
            Action(
                operation="entra.disable_user",
                platform="entra",
                description="disable",
                target="x",
                risk=RiskLevel.HIGH,
            )
        ],
        run_id="run_good",
        workflow="offboarding",
        subject="Good Record",
        title="step",
        requested_by="t",
    )

    path = Path(settings.approval.storage_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines.insert(0, "{ this is not json")
    lines.insert(1, '{"id": "apv_broken", "risk": "not-a-real-risk"}')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    reloaded = ApprovalStore(settings.approval)
    assert reloaded.corrupt_lines == 2, "both bad lines should be reported, not silently dropped"
    assert [r.id for r in reloaded.list(status=None)] == [good.id]
