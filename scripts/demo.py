#!/usr/bin/env python3
"""End-to-end demonstration against the simulator.

Runs a joiner through onboarding, shows the approval gates a human would see,
approves them with distinct identities, and then reports the resulting estate —
followed by the same person leaving.

Safe by construction: it forces the mock backend and a temporary working
directory, so it cannot touch a real tenant no matter what is in your .env.

    python scripts/demo.py
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import tempfile
from datetime import date
from pathlib import Path

# Point state at a scratch directory *before* importing anything that reads
# settings, and force the simulator regardless of the ambient environment.
_SCRATCH = Path(tempfile.mkdtemp(prefix="iam-agent-demo-"))
os.chdir(_SCRATCH)
os.environ["IAM_GLOBAL_DRY_RUN"] = "false"
os.environ["IAM_APPROVAL__DEFAULT_MODE"] = "approval_required"
os.environ["IAM_MOCK__PERSIST"] = "true"
for var in list(os.environ):
    if var.startswith(("IAM_ENTRA_", "IAM_M365_", "IAM_AD_", "IAM_ACTION1_", "IAM_SCALEFUSION_")):
        if "BACKEND" in var or var.endswith("_ENABLED"):
            os.environ[var] = "false"

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from iam_agent.config import Settings, get_settings  # noqa: E402
from iam_agent.connectors.mock.store import get_mock_store  # noqa: E402
from iam_agent.core.models import Employee, Manager  # noqa: E402
from iam_agent.core.orchestrator import Orchestrator  # noqa: E402

DOMAIN = "contoso-balears.example"
BAR = "─" * 74


def head(title: str) -> None:
    print(f"\n{BAR}\n{title}\n{BAR}")


async def approve_all(orch: Orchestrator, pool: list[str]) -> int:
    """Clear every pending gate, using a distinct approver for each signature.

    Critical actions need two distinct approvers, so the pool rotates rather than
    reusing one identity — which is exactly what a real two-person rule demands.
    """
    rounds = 0
    for _ in range(60):
        pending = orch.list_approvals(status="pending")
        if not pending:
            break
        request = pending[0]
        already = len(request.approvals)
        approver = pool[min(already, len(pool) - 1)]
        need = request.required_approvals
        print(
            f"  ↪ [{request.risk.value:<8}] {request.title}"
            f"  ({already + 1}/{need} approver{'s' if need > 1 else ''})  →  {approver}"
        )
        await orch.decide_approval(
            request.id, approve=True, decided_by=approver, comment="demo"
        )
        rounds += 1
    return rounds


async def main() -> int:
    get_settings.cache_clear()
    settings = get_settings()
    get_mock_store(reseed=True)
    orch = Orchestrator(settings)

    head("0 · Posture")
    preflight = await orch.preflight()
    print(f"  mode            : {preflight['mode']}")
    print(f"  live platforms  : {preflight['live_platforms'] or 'none — simulator only'}")
    print(f"  simulated       : {', '.join(preflight['simulated_platforms'])}")
    print(f"  problems        : {preflight['problems'] or 'none'}")
    assert preflight["live_platforms"] == [], "the demo must not touch a real tenant"

    head("1 · The estate before we start")
    status = await orch.status()
    estate = status.get("mock_estate", {})
    print(f"  Entra users    : {estate.get('entra_users')}")
    print(f"  Entra groups   : {estate.get('entra_groups')}")
    print(f"  mailboxes      : {estate.get('mailboxes')}")
    print(f"  Teams          : {estate.get('teams')}")
    print(f"  Action1 PCs    : {estate.get('action1_endpoints')}")
    print(f"  Scalefusion    : {estate.get('scalefusion_devices')}")

    # ------------------------------------------------------------------ #
    hire = Employee(
        employee_id="EMP-9001",
        first_name="Aina",
        last_name="Serra Ferrer",
        email=f"aserraferrer@{DOMAIN}",
        department="Ventas",
        job_title="Account Executive",
        office_location="Palma de Mallorca",
        hire_date=date.today(),
        manager=Manager(email=f"lferra@{DOMAIN}"),
    )

    head("2 · Onboarding — plan")
    run = await orch.run_workflow("onboarding", hire, requested_by="hr-demo", reason="new starter")
    print(f"  run      : {run.id}")
    print(f"  status   : {run.status.value}")
    print(f"  max risk : {run.plan.max_risk.value}")
    for step in run.plan.steps:
        if not step.enabled:
            continue
        gate = "GATE" if step.requires_approval else "    "
        print(f"  {gate} {step.order:>2}. {step.name:<20} {len(step.actions)} action(s)")
    for note in run.plan.assumptions:
        print(f"  · assumption: {note}")

    head("3 · Onboarding — clearing the gates")
    rounds = await approve_all(orch, [f"approver{i}@{DOMAIN}" for i in range(1, 4)])
    finished = orch.get_run(run.id)
    progress = finished.plan.progress()
    print(f"\n  approval rounds : {rounds}")
    print(f"  final status    : {finished.status.value}")
    print(f"  progress        : {progress['done']}/{progress['total']} done")

    head("4 · What the joiner now has")
    identity = await orch.get_identity(hire.email)
    print(f"  name        : {identity.employee.full_name}")
    print(f"  logon       : {identity.employee.suggested_username()}")
    print(f"  upn         : {identity.entra.upn if identity.entra else '—'}")
    print(f"  enabled     : Entra {identity.entra.enabled if identity.entra else '?'} · "
          f"AD {identity.on_prem.enabled if identity.on_prem else 'n/a'}")
    print(f"  licences    : {identity.entra.license_skus if identity.entra else []}")
    groups = [g.display_name for g in identity.group_memberships.get("entra", [])]
    print(f"  groups      : {', '.join(groups)}")
    print(f"  devices     : {[d.device_name for d in identity.devices] or 'none yet'}")

    head("5 · Offboarding — the same person, six months on")
    leaver_run = await orch.run_workflow(
        "offboarding",
        Employee(first_name="", last_name="", email=hire.email),
        requested_by="hr-demo",
        reason="resignation",
    )
    print(f"  run    : {leaver_run.id}")
    print(f"  status : {leaver_run.status.value}")
    for step in leaver_run.plan.steps:
        if step.enabled and step.requires_approval:
            print(f"  GATE {step.order:>2}. {step.name}")

    rounds = await approve_all(orch, [f"approver{i}@{DOMAIN}" for i in range(1, 4)])
    leaver = orch.get_run(leaver_run.id)
    print(f"\n  approval rounds : {rounds}")
    print(f"  final status    : {leaver.status.value}")

    head("6 · What offboarding left behind")
    after = await orch.get_identity(hire.email)
    print(f"  enabled Entra   : {after.entra.enabled if after.entra else '?'}")
    print(f"  enabled AD      : {after.on_prem.enabled if after.on_prem else 'n/a'}")
    print(f"  groups          : {[g.display_name for g in after.group_memberships.get('entra', [])]}")
    for mailbox in after.mailboxes:
        print(f"  mailbox         : {mailbox.mailbox_type} · hidden={mailbox.hidden_from_gal} "
              f"· hold={mailbox.litigation_hold}")
    for device in after.devices:
        print(f"  device          : {device.device_name} → {device.state.value}")

    head("7 · Drift across the estate")
    report = await orch.audit_estate(limit=25)
    print(f"  findings : {len(report.findings)}")
    for finding in report.findings[:8]:
        print(f"   · [{finding.severity}] {finding.subject}: {finding.description}")

    head("8 · Audit trail")
    tail = orch.audit.tail(6)
    for entry in reversed(tail):
        print(f"  {entry.get('ts', '')[:19]}  {entry.get('event', '')}")

    await orch.aclose()
    print(f"\n{BAR}\nDemo complete — no live tenant was contacted, and the\nscratch state is discarded on exit.\n{BAR}")
    return 0


if __name__ == "__main__":
    try:
        code = asyncio.run(main())
    finally:
        # Leave nothing behind: the demo is a demo, not a fixture.
        shutil.rmtree(_SCRATCH, ignore_errors=True)
    raise SystemExit(code)
