"""Secret-leak regression tests.

An onboarding action legitimately carries the new hire's initial password, and a
TAP action carries the pass itself. Those values pass through three durable
sinks: the audit log, the persisted run record and the approval queue. These
tests assert that none of the three ever writes the raw value.

A plaintext password on disk in ``data/`` is a worse outcome than a failed
onboarding, so this is treated as a hard requirement rather than a nice-to-have.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from iam_agent.config import Settings
from iam_agent.connectors.mock.store import get_mock_store
from iam_agent.core.models import Employee, Manager
from iam_agent.core.orchestrator import Orchestrator
from iam_agent.core.redact import REDACTED, is_secret_field, redact, safe_params

CANARY = "Sup3r-Secret-Canary!xyz"
TAP_CANARY = "999-888-777"


@pytest.fixture
def isolated_workspace(tmp_path, monkeypatch):
    """Point every durable sink at a throwaway directory."""
    monkeypatch.chdir(tmp_path)
    get_mock_store(reseed=True)
    return tmp_path


def _new_hire(**overrides) -> Employee:
    base = dict(
        employee_id="EMP-9001",
        first_name="Prova",
        last_name="Secret",
        department="IT",
        job_title="Analista",
        hire_date=date(2026, 11, 1),
        manager=Manager(email="lferra@contoso-balears.example"),
    )
    base.update(overrides)
    return Employee(**base)


async def test_password_never_reaches_any_persisted_file(isolated_workspace):
    orch = Orchestrator(
        Settings(
            global_dry_run=False,
            approval={"default_mode": "approval_required", "autonomous_max_risk": "low"},
            audit={"log_path": "data/audit.jsonl", "run_store_path": "data/runs"},
        )
    )
    try:
        run = await orch.run_workflow(
            "onboarding",
            _new_hire(),
            options={"password": CANARY},
            requested_by="security-test",
            reason="leak test",
        )
        # Walk the whole approval chain so every sink is written to.
        for _ in range(20):
            pending = orch.list_approvals(status="pending")
            if not pending:
                break
            request = pending[0]
            await orch.decide_approval(
                request.id,
                approve=True,
                decided_by=f"approver{len(request.approvals) + 1}@corp.local",
                comment="leak test",
            )
        assert orch.get_run(run.id).status.value in ("completed", "awaiting_approval")

        written = list(Path("data").rglob("*"))
        assert written, "expected the test to have produced audit/run/approval files"

        offenders: list[str] = []
        for path in written:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            if CANARY in text:
                offenders.append(str(path))
        assert not offenders, f"initial password leaked into: {offenders}"
    finally:
        await orch.aclose()


async def test_tap_value_never_reaches_disk(isolated_workspace):
    orch = Orchestrator(
        Settings(
            global_dry_run=False,
            approval={"default_mode": "autonomous", "autonomous_max_risk": "critical"},
        )
    )
    try:
        snapshot = await orch.reconciler.snapshot("lferra@contoso-balears.example")
        user = snapshot.entra
        assert user is not None

        run = await orch.run_adhoc(
            [
                orch.build_action(
                    "entra.create_temporary_access_pass",
                    description="issue TAP",
                    target=user.upn,
                    user_id=user.external_id,
                    lifetime_minutes=60,
                    one_time=True,
                )
            ],
            subject=user.upn,
            requested_by="security-test",
        )
        action = run.plan.all_actions[0] if run.plan else None
        assert action is not None
        tap = action.result.get("temporaryAccessPass")
        assert tap, "the simulated TAP should have been returned to the caller"

        for path in Path("data").rglob("*"):
            if path.is_file():
                assert tap not in path.read_text(encoding="utf-8", errors="replace"), (
                    f"TAP value leaked into {path}"
                )
    finally:
        await orch.aclose()


def test_employee_repr_hides_the_password():
    employee = _new_hire(password=CANARY)
    assert CANARY not in repr(employee)
    assert CANARY not in str(employee)
    assert CANARY not in json.dumps(employee.model_dump(mode="json"), default=str)


def test_redaction_is_recursive_and_key_based():
    payload = {
        "user": {"password": CANARY, "name": "visible"},
        "nested": [{"client_secret": CANARY, "ok": True}],
        "list_of_scalars": [1, 2, 3],
        "TemporaryAccessPass": TAP_CANARY,
    }
    scrubbed = redact(payload)
    text = json.dumps(scrubbed, default=str)
    assert CANARY not in text
    assert TAP_CANARY not in text
    assert scrubbed["user"]["name"] == "visible"
    assert scrubbed["nested"][0]["ok"] is True
    assert scrubbed["user"]["password"] == REDACTED


@pytest.mark.parametrize(
    "field",
    ["password", "client_secret", "api_key", "apiKey", "TemporaryAccessPass", "unicodePwd", "authorization"],
)
def test_secret_field_detection(field: str):
    assert is_secret_field(field), field


@pytest.mark.parametrize("field", ["username", "department", "target", "operation", "risk"])
def test_normal_fields_are_not_over_redacted(field: str):
    assert not is_secret_field(field), field


def test_safe_params_compacts_embedded_models():
    """A reviewer should see who is being created, not a 900-char repr."""
    employee = _new_hire(password=CANARY)
    params = {"employee": employee, "password": CANARY, "must_change": True}
    safe = safe_params(params)

    assert safe["password"] == REDACTED
    assert CANARY not in json.dumps(safe, default=str)
    assert isinstance(safe["employee"], dict)
    assert safe["employee"]["first_name"] == "Prova"
    assert safe["must_change"] is True
