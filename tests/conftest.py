"""Shared pytest fixtures.

Every test runs against the in-memory simulator with a freshly reseeded estate,
inside a throwaway working directory, so no test can touch a real platform or
leave state behind for the next one.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from iam_agent.config import Settings, get_settings
from iam_agent.connectors import reset_hub
from iam_agent.connectors.mock.store import get_mock_store
from iam_agent.core.approval import ApprovalStore
from iam_agent.core.audit import AuditLog
from iam_agent.core.orchestrator import Orchestrator
from iam_agent.core.result import RunStore


@pytest.fixture(autouse=True)
def _clean_environment(tmp_path, monkeypatch):
    """Isolate each test: fresh CWD, fresh settings cache, fresh estate."""
    monkeypatch.chdir(tmp_path)
    # Never let a stray .env in the repo influence a test run.
    for key in list(os.environ):
        if key.startswith("IAM_"):
            monkeypatch.delenv(key, raising=False)
    get_settings.cache_clear()
    reset_hub()
    get_mock_store(reseed=True)
    yield
    get_settings.cache_clear()
    reset_hub()


@pytest.fixture
def store():
    return get_mock_store(reseed=True)


@pytest.fixture
def settings(tmp_path) -> Settings:
    """Approval-required posture, writing into the temp workspace."""
    return Settings(
        environment="development",
        global_dry_run=False,
        approval={
            "default_mode": "approval_required",
            "autonomous_max_risk": "low",
            "storage_path": str(tmp_path / "data" / "approvals.jsonl"),
            "request_timeout_minutes": 60,
        },
        audit={
            "log_path": str(tmp_path / "data" / "audit.jsonl"),
            "run_store_path": str(tmp_path / "data" / "runs"),
        },
    )


@pytest.fixture
def dry_run_settings(tmp_path) -> Settings:
    return Settings(
        global_dry_run=True,
        approval={"storage_path": str(tmp_path / "data" / "approvals.jsonl")},
        audit={
            "log_path": str(tmp_path / "data" / "audit.jsonl"),
            "run_store_path": str(tmp_path / "data" / "runs"),
        },
    )


@pytest.fixture
def orchestrator(settings) -> Orchestrator:
    return Orchestrator(settings)


@pytest.fixture
def dry_run_orchestrator(dry_run_settings) -> Orchestrator:
    return Orchestrator(dry_run_settings)


async def approve_everything(
    orch: Orchestrator,
    *,
    max_rounds: int = 40,
    decide: bool = True,
    approver_prefix: str = "approver",
    comment: str = "approved by test",
) -> int:
    """Drive a parked run to completion by approving each gate in turn.

    Critical actions require two distinct approvers, so the approver identity
    changes on every call - which is also what exercises the two-person rule.
    """
    rounds = 0
    while rounds < max_rounds:
        pending = orch.list_approvals(status="pending")
        if not pending:
            break
        request = pending[0]
        decided_by = f"{approver_prefix}{len(request.approvals) + 1}@corp.local"
        outcome = await orch.decide_approval(
            request.id, approve=decide, decided_by=decided_by, comment=comment
        )
        rounds += 1
        if outcome.get("run_status") in ("completed", "failed", "cancelled"):
            break
    return rounds
