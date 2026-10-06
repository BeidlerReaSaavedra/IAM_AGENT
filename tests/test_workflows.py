"""End-to-end workflow tests in hybrid (approval_required) execution mode.

These are the acceptance criteria in executable form: a joiner gets provisioned
everywhere, a leaver loses access everywhere while keeping their data, and a mover
changes department without anything destructive happening to them.

Each test drives the real orchestrator against the simulator and clears every
approval gate with a distinct human identity, so the two-person rule for critical
actions is exercised rather than bypassed.
"""

from __future__ import annotations

from datetime import date

import pytest

from conftest import approve_everything
from iam_agent.connectors.mock.store import get_mock_store
from iam_agent.core.models import Employee, Manager
from iam_agent.core.orchestrator import Orchestrator
from iam_agent.core.result import RunStatus

DOMAIN = "contoso-balears.example"
MANAGER = f"lferra@{DOMAIN}"
LEAVER = f"bsola@{DOMAIN}"
MOVER = f"nserra@{DOMAIN}"


def _hire(**overrides) -> Employee:
    base = dict(
        employee_id="EMP-8001",
        first_name="Aina",
        last_name="Serra",
        department="Ventas",
        job_title="Account Executive",
        hire_date=date(2026, 11, 15),
        manager=Manager(email=MANAGER),
    )
    base.update(overrides)
    return Employee(**base)


async def _run_to_completion(orch: Orchestrator, run) -> tuple[object, int]:
    rounds = await approve_everything(orch)
    return orch.get_run(run.id), rounds


def _operations(run) -> list[str]:
    return [a.operation for step in run.plan.steps if step.enabled for a in step.actions]


# --------------------------------------------------------------------------- #
# Onboarding
# --------------------------------------------------------------------------- #


async def test_onboarding_provisions_across_all_platforms(orchestrator):
    store = get_mock_store()
    run = await orchestrator.run_workflow(
        "onboarding", _hire(), requested_by="hr", reason="new starter"
    )
    assert run.status == RunStatus.AWAITING_APPROVAL, "a write must gate before it runs"

    finished, rounds = await _run_to_completion(orchestrator, run)
    assert finished.status == RunStatus.COMPLETED, finished.status
    assert rounds == 5, "onboarding gates on five steps in approval_required mode"

    user = store.find_user(email=f"aserra@{DOMAIN}")
    assert user is not None, "the Entra account should exist"
    assert user["account_enabled"] is True
    assert user["department"] == "Ventas"

    ops = _operations(finished)
    assert "entra.create_user" in ops
    assert "active_directory.create_user" in ops, "on-prem account must be created too"
    assert "entra.assign_license" in ops
    assert "entra.add_group_member" in ops
    assert "m365.add_team_member" in ops
    assert "entra.create_temporary_access_pass" in ops, "day-one sign-in must be bootstrapped"


async def test_onboarding_derives_department_defaults(orchestrator):
    store = get_mock_store()
    run = await orchestrator.run_workflow(
        "onboarding", _hire(department="Finanzas", job_title="Controller"), requested_by="hr"
    )
    await _run_to_completion(orchestrator, run)

    user = store.find_user(email=f"aserra@{DOMAIN}")
    groups = {
        g["display_name"]
        for g in store.groups.values()
        if user["id"] in g.get("members", [])
    }
    assert "Finanzas-All" in groups
    assert "All-Employees" in groups


async def test_onboarding_folds_diacritics_in_the_logon_name(orchestrator):
    """Catalan and Spanish names are the norm; the logon must still be ASCII."""
    store = get_mock_store()
    run = await orchestrator.run_workflow(
        "onboarding",
        _hire(employee_id="EMP-8002", first_name="Miquel", last_name="Àngel Camps",
              department="IT", job_title="Tècnic"),
        requested_by="hr",
    )
    await _run_to_completion(orchestrator, run)

    upns = [u["user_principal_name"] for u in store.users.values()]
    assert any("@" in u and all(ord(c) < 128 for c in u) for u in upns), upns
    created = [u for u in upns if "camps" in u.lower()]
    assert created, f"no account derived from 'Àngel Camps': {upns}"


async def test_dry_run_writes_nothing(dry_run_orchestrator):
    """`global_dry_run` routes to plan_only: the run stays PLANNED and nothing is written.

    Even with ``execute=True``. The flag is a master kill switch, so it wins over
    the caller's intent - see also ``test_global_dry_run_overrides_the_approval_mode``.
    """
    store = get_mock_store()
    before = len(store.users)
    run = await dry_run_orchestrator.run_workflow(
        "onboarding", _hire(), requested_by="hr", execute=True
    )
    assert run.status == RunStatus.PLANNED
    assert len(store.users) == before, "dry run must not create anything"
    assert store.find_user(email=f"aserra@{DOMAIN}") is None
    # No gate was raised either: nothing was attempted, so nothing needs signing.
    assert dry_run_orchestrator.list_approvals(status="pending") == []


# --------------------------------------------------------------------------- #
# Offboarding
# --------------------------------------------------------------------------- #


async def test_offboarding_revokes_access_and_preserves_data(orchestrator):
    store = get_mock_store()
    leaver = Employee(first_name="", last_name="", email=LEAVER)
    run = await orchestrator.run_workflow(
        "offboarding", leaver, requested_by="hr", reason="resignation"
    )
    finished, rounds = await _run_to_completion(orchestrator, run)

    assert finished.status == RunStatus.COMPLETED, finished.status
    assert rounds >= 10, "critical steps need two distinct approvers each"

    user = store.find_user(email=LEAVER)
    assert user is not None, "the account must be disabled, not deleted"
    assert user["account_enabled"] is False

    mailbox = store.mailboxes.get(LEAVER) or next(
        (m for m in store.mailboxes.values() if m.get("primary_smtp") == LEAVER), None
    )
    assert mailbox is not None
    assert mailbox["mailbox_type"] == "shared", "data must be preserved as a shared mailbox"
    assert mailbox.get("hidden_from_gal") is True
    # Litigation hold is a legal measure applied on request, not automatically:
    # it blocks purge indefinitely and consumes storage. Asserted separately below.
    assert mailbox.get("litigation_hold") is False


async def test_litigation_hold_is_applied_when_requested(orchestrator):
    """The option exists for investigations and legal requests, so it must work."""
    store = get_mock_store()
    run = await orchestrator.run_workflow(
        "offboarding",
        Employee(first_name="", last_name="", email=LEAVER),
        options={"litigation_hold": True},
        requested_by="legal",
        reason="under investigation",
    )
    ops = _operations(run)
    assert "m365.set_litigation_hold" in ops, "the hold must be planned when requested"

    await _run_to_completion(orchestrator, run)
    mailbox = store.mailboxes.get(LEAVER) or next(
        (m for m in store.mailboxes.values() if m.get("primary_smtp") == LEAVER), None
    )
    assert mailbox is not None
    assert mailbox.get("litigation_hold") is True


async def test_offboarding_strips_group_memberships(orchestrator):
    store = get_mock_store()
    run = await orchestrator.run_workflow(
        "offboarding", Employee(first_name="", last_name="", email=LEAVER),
        requested_by="hr", reason="resignation",
    )
    await _run_to_completion(orchestrator, run)

    leaver = store.find_user(email=LEAVER)
    still_member = [
        g["display_name"] for g in store.groups.values() if leaver["id"] in g.get("members", [])
    ]
    assert still_member == [], f"leaver still holds group memberships: {still_member}"


async def test_offboarding_never_hard_deletes_the_ad_account(orchestrator):
    """`allow_hard_delete` defaults to false and the workflow must respect it."""
    run = await orchestrator.run_workflow(
        "offboarding", Employee(first_name="", last_name="", email=LEAVER),
        requested_by="hr", reason="resignation",
    )
    finished, _ = await _run_to_completion(orchestrator, run)
    assert "active_directory.delete_user" not in _operations(finished)
    assert "active_directory.disable_user" in _operations(finished)


async def test_offboarding_releases_licences_last(orchestrator):
    """Releasing a licence before preserving the mailbox would destroy the data."""
    run = await orchestrator.run_workflow(
        "offboarding", Employee(first_name="", last_name="", email=LEAVER),
        requested_by="hr", reason="resignation",
    )
    steps = [s.name for s in run.plan.steps if s.enabled]
    mailbox_at = next(i for i, n in enumerate(steps) if "mailbox" in n)
    licence_at = next(i for i, n in enumerate(steps) if "license" in n)
    assert mailbox_at < licence_at, steps


async def test_rejecting_an_approval_cancels_without_writing(orchestrator):
    store = get_mock_store()
    before = len(store.users)
    run = await orchestrator.run_workflow(
        "onboarding", _hire(), requested_by="hr", reason="mistaken request"
    )
    assert run.status == RunStatus.AWAITING_APPROVAL

    pending = orchestrator.list_approvals(status="pending")
    result = await orchestrator.decide_approval(
        pending[0].id, approve=False, decided_by="hr@corp.local", comment="not after all"
    )
    assert result["status"] == "rejected"
    assert orchestrator.get_run(run.id).status == RunStatus.CANCELLED
    assert len(store.users) == before, "a rejected run must not have created anything"


# --------------------------------------------------------------------------- #
# Transfer
# --------------------------------------------------------------------------- #


async def test_transfer_is_delta_only_and_changes_nothing_destructive(orchestrator):
    before = await orchestrator.get_identity(MOVER)
    assert before.entra is not None and before.entra.enabled

    run = await orchestrator.run_workflow(
        "transfer",
        Employee(first_name="", last_name="", email=MOVER,
                 department="Finanzas", job_title="Responsable de Control"),
        requested_by="hr",
        reason="internal promotion",
    )
    finished, rounds = await _run_to_completion(orchestrator, run)
    assert finished.status == RunStatus.COMPLETED, finished.status
    assert rounds > 0

    after = await orchestrator.get_identity(MOVER)
    # Nothing destructive: a department change is not a security incident.
    assert after.entra.enabled is True, "a mover must not be disabled"
    assert after.on_prem is None or after.on_prem.enabled is True
    ops = _operations(finished)
    for forbidden in (
        "entra.disable_user",
        "active_directory.disable_user",
        "entra.revoke_sign_in_sessions",
        "scalefusion.wipe_device",
        "scalefusion.retire_device",
        "entra.delete_user",
        "entra.remove_all_licenses",
    ):
        assert forbidden not in ops, f"a transfer must never {forbidden}"

    assert after.employee.department == "Finanzas"


async def test_transfer_swaps_the_department_group(orchestrator):
    run = await orchestrator.run_workflow(
        "transfer",
        Employee(first_name="", last_name="", email=MOVER, department="Finanzas"),
        requested_by="hr",
    )
    finished, _ = await _run_to_completion(orchestrator, run)
    assert finished.status == RunStatus.COMPLETED, finished.status

    after = await orchestrator.get_identity(MOVER)
    names = {g.display_name for g in after.group_memberships.get("entra", [])}
    assert "Finanzas-All" in names
    assert "Ventas-All" not in names
    # Baseline membership is protected from removal by a transfer.
    assert "All-Employees" in names


async def test_transfer_swaps_licences_atomically(orchestrator):
    """The regression: a tier change used to add the new SKU and keep the old one.

    The plan summary claimed the old licence had been released, so nothing
    downstream noticed - a permanent, silent cost leak on every internal move.
    """
    store = get_mock_store()
    before = await orchestrator.get_identity(MOVER)
    old_licences = set(before.entra.license_skus)
    assert old_licences, "the fixture mover should hold a licence to begin with"
    seats_before = {k: v["consumed"] for k, v in store.license_skus.items()}

    run = await orchestrator.run_workflow(
        "transfer",
        Employee(first_name="", last_name="", email=MOVER, department="Finanzas"),
        requested_by="hr",
    )
    finished, _ = await _run_to_completion(orchestrator, run)
    assert finished.status == RunStatus.COMPLETED

    # Exactly one licence action, carrying both halves.
    licence_actions = [
        a for a in finished.plan.all_actions if a.operation == "entra.assign_license"
    ]
    assert len(licence_actions) == 1
    params = licence_actions[0].params
    assert params.get("sku_part_numbers"), "should add the target tier"
    assert params.get("remove_sku_part_numbers"), "should release the superseded tier"

    after = await orchestrator.get_identity(MOVER)
    new_licences = after.entra.license_skus
    assert len(new_licences) == len(set(new_licences)), f"duplicated SKUs: {new_licences}"
    assert not (old_licences & set(new_licences)), (
        f"the superseded licence was never released: {old_licences} -> {new_licences}"
    )

    # Seat accounting must move, not just grow.
    seats_after = {k: v["consumed"] for k, v in store.license_skus.items()}
    assert seats_after != seats_before, "seat consumption should have changed"


async def test_transfer_does_not_touch_devices(orchestrator):
    before = await orchestrator.get_identity(MOVER)
    devices_before = {(d.external_id, d.state.value, d.assigned_email) for d in before.devices}

    run = await orchestrator.run_workflow(
        "transfer",
        Employee(first_name="", last_name="", email=MOVER, department="Finanzas"),
        requested_by="hr",
    )
    await _run_to_completion(orchestrator, run)

    after = await orchestrator.get_identity(MOVER)
    devices_after = {(d.external_id, d.state.value, d.assigned_email) for d in after.devices}
    assert devices_before == devices_after


# --------------------------------------------------------------------------- #
# Cross-workflow invariants
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("workflow", ["onboarding", "offboarding", "transfer"])
async def test_every_write_gates_before_it_runs(orchestrator, workflow):
    """In approval_required mode nothing may execute before a human signs it."""
    if workflow == "onboarding":
        subject = _hire()
    elif workflow == "offboarding":
        subject = Employee(first_name="", last_name="", email=LEAVER)
    else:
        subject = Employee(first_name="", last_name="", email=MOVER, department="Finanzas")

    run = await orchestrator.run_workflow(workflow, subject, requested_by="hr")
    assert run.status == RunStatus.AWAITING_APPROVAL
    assert orchestrator.list_approvals(status="pending"), "a gate must exist"


@pytest.mark.parametrize("workflow", ["onboarding", "offboarding", "transfer"])
async def test_plans_advertise_their_own_gates(orchestrator, workflow):
    """A plan that says 'no approval needed' and then parks is worse than useless."""
    if workflow == "onboarding":
        subject = _hire()
    elif workflow == "offboarding":
        subject = Employee(first_name="", last_name="", email=LEAVER)
    else:
        subject = Employee(first_name="", last_name="", email=MOVER, department="Finanzas")

    run, _ctx = await orchestrator.build_plan(workflow, subject, requested_by="hr")
    assert run.plan.needs_approval() is True
    assert any(s.requires_approval for s in run.plan.steps)


async def test_deferred_deletion_with_nothing_eligible_says_so(orchestrator):
    """A housekeeping job that finds nothing must report that, not silently no-op."""
    run, _ctx = await orchestrator.build_plan(
        "deferred_deletion",
        Employee(first_name="", last_name="", email=LEAVER),
        requested_by="cron",
    )
    assert run.plan is not None
    assert run.plan.assumptions, "the plan should explain why there is nothing to do"
