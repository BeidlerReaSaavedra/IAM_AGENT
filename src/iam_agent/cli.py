"""Command-line interface.

The console script declared in ``pyproject.toml`` (``iam-agent``). It is the
operator's entry point for everything the API and MCP server also expose: check
the posture, plan a lifecycle change, review what it will do, approve it, and
read the audit trail afterwards.

Two things the CLI is deliberately strict about, because it is the surface most
likely to be used from a shell history or a cron job:

* **Approval identity.** ``--approver`` is required for every decision and is
  written to the immutable audit log. It refuses ``claude``/``agent``/``system``
  so an AI cannot launder its own write through a CLI flag.
* **Nothing executes by default.** ``iam-agent onboard`` *plans* and shows you
  the plan. Add ``--execute`` to actually run it.
"""

from __future__ import annotations

import asyncio
import json
from datetime import date, datetime
from typing import Any

import typer
from rich.console import Console
from rich.markdown import Markdown
from rich.table import Table

from iam_agent import __version__
from iam_agent.config import Settings, get_settings
from iam_agent.core.errors import IAMAgentError
from iam_agent.core.models import Employee, Manager
from iam_agent.core.orchestrator import Orchestrator

app = typer.Typer(
    name="iam-agent",
    help="Identity & endpoint lifecycle automation across Entra ID, M365, AD, Action1 and Scalefusion.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
err_console = Console(stderr=True)

_FORBIDDEN_APPROVERS = {"claude", "agent", "ai", "system", "api", "anonymous"}


# --------------------------------------------------------------------------- #
# Plumbing
# --------------------------------------------------------------------------- #


def _settings() -> Settings:
    return get_settings()


def _orch() -> Orchestrator:
    return Orchestrator(_settings())


def _run(coro):
    """Run an async orchestrator call, reporting domain errors as clean exits."""
    async def _wrapper():
        orch = _orch()
        try:
            return await coro(orch)
        finally:
            await orch.aclose()

    try:
        return asyncio.run(_wrapper())
    except IAMAgentError as exc:
        err_console.print(f"[red]{type(exc).__name__}:[/red] {exc}")
        raise typer.Exit(code=exc.status_code or 1) from None
    except KeyboardInterrupt:
        err_console.print("[yellow]interrupted[/yellow]")
        raise typer.Exit(code=130) from None


def _employee(
    *,
    identifier: str = "",
    employee_id: str = "",
    first_name: str = "",
    last_name: str = "",
    department: str = "",
    job_title: str = "",
    manager_email: str = "",
    hire_date: str = "",
    leave_date: str = "",
    reason: str = "",
) -> Employee:
    """Build an Employee from CLI flags, tolerating a bare identifier.

    ``first_name`` and ``last_name`` are the only fields on :class:`Employee`
    without a default, so they must always be supplied - even as empty strings.
    The previous version dropped every empty value, which made both natural
    invocations fail with a pydantic ValidationError:

        iam-agent onboard "Aina Serra"      # no name flags at all
        iam-agent offboard nserra           # looked up by username

    For the second case an empty name is correct: the workflow resolves the
    person from the directory. For the first, the identifier *is* the name, so
    split it - first token as given name, the rest as surname, which keeps
    composite Spanish and Catalan surnames ("Miquel Àngel Camps") intact.
    """
    if identifier and "@" not in identifier and " " in identifier.strip():
        if not first_name and not last_name:
            given, _, rest = identifier.strip().partition(" ")
            first_name = first_name or given
            last_name = last_name or rest.strip()

    # Required fields stay in the dict even when empty.
    kwargs: dict[str, Any] = {
        "first_name": first_name,
        "last_name": last_name,
    }
    optional: dict[str, Any] = {
        "employee_id": employee_id,
        "department": department,
        "job_title": job_title,
        "termination_reason": reason,
    }
    if "@" in identifier:
        optional["email"] = identifier
    elif identifier and not (first_name or last_name):
        # A single token that is not a name: treat it as a logon name to resolve.
        optional["username"] = identifier
    if manager_email:
        optional["manager"] = Manager(email=manager_email)
    if hire_date:
        optional["hire_date"] = _parse_date(hire_date, "hire-date")
    if leave_date:
        optional["leave_date"] = _parse_date(leave_date, "leave-date")
    kwargs.update({k: v for k, v in optional.items() if v not in ("", None)})
    return Employee(**kwargs)


def _parse_date(value: str, flag: str) -> date:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        err_console.print(f"[red]--{flag} must be YYYY-MM-DD[/red] (got {value!r})")
        raise typer.Exit(code=2) from exc


def _check_approver(name: str) -> str:
    if name.strip().lower() in _FORBIDDEN_APPROVERS:
        err_console.print(
            "[red]refusing approver identity "
            f"{name!r}[/red] — approvals must be attributable to a real human; "
            "this value is written to the immutable audit log."
        )
        raise typer.Exit(code=2)
    return name.strip()


def _print_plan(plan: Any) -> None:
    console.print(Markdown(plan.to_markdown()))


def _print_run(run: Any) -> None:
    table = Table(title=f"Run {run.id}", show_header=False, box=None)
    table.add_row("workflow", run.workflow)
    table.add_row("subject", run.subject)
    table.add_row("status", f"[bold]{run.status.value}[/bold]")
    # progress() lives on the plan, not on the run; a run with no plan yet has none.
    progress = run.plan.progress() if run.plan else {}
    if progress:
        table.add_row(
            "progress",
            f"{progress.get('done', 0)}/{progress.get('total', 0)} done · "
            f"{progress.get('blocked', 0)} blocked · {progress.get('failed', 0)} failed · "
            f"{progress.get('skipped', 0)} skipped",
        )
    if run.plan:
        table.add_row("max risk", run.plan.max_risk.value)
        gates = [s.name for s in run.plan.steps if s.requires_approval]
        if gates:
            table.add_row("approval gates", ", ".join(gates))
    console.print(table)


def _print_pending(orch: Orchestrator) -> None:
    pending = orch.list_approvals(status="pending")
    if not pending:
        return
    table = Table(title="Awaiting human approval")
    for col in ("approval id", "step", "subject", "risk", "approvers"):
        table.add_column(col)
    for request in pending:
        table.add_row(
            request.id,
            request.title,
            request.subject,
            request.risk.value,
            f"{len(request.approvals)}/{request.required_approvals}",
        )
    console.print(table)
    console.print(
        "[dim]review one with "
        "[bold]iam-agent approvals show <id>[/bold], then "
        "[bold]iam-agent approvals decide <id> --approve --approver you@corp[/bold][/dim]"
    )


# --------------------------------------------------------------------------- #
# Status & discovery
# --------------------------------------------------------------------------- #


@app.command()
def version() -> None:
    """Print the version and exit."""
    console.print(f"iam-agent {__version__}")


@app.command()
def status() -> None:
    """Show connector health and the current safety posture."""

    async def _do(orch: Orchestrator) -> dict[str, Any]:
        return await orch.status()

    report = _run(_do)
    settings_block = report.get("settings") or {}
    health_block = report.get("health") or {}
    mode = settings_block.get("effective_mode", "?")

    table = Table(title=f"IAM Agent posture — {mode}")
    table.add_column("platform")
    table.add_column("healthy")
    table.add_column("backend")
    table.add_column("detail")
    for name, info in (health_block.get("connectors") or {}).items():
        backend = str(info.get("backend", ""))
        # A simulated backend must be impossible to miss: pointing a lifecycle
        # agent at the mock while believing it is live is a real failure mode.
        badge = "[green]live[/green]" if backend == "live" else "[yellow]SIMULATED[/yellow]"
        table.add_row(
            name,
            "[green]yes[/green]" if info.get("healthy") else "[red]no[/red]",
            badge,
            str(info.get("detail", ""))[:64],
        )
    console.print(table)

    console.print(
        f"[bold]execution mode:[/bold] {mode}   "
        f"[bold]approval policy:[/bold] {settings_block.get('approval_mode', '?')}   "
        f"[bold]autonomous ceiling:[/bold] {settings_block.get('autonomous_max_risk', '?')}"
    )
    console.print(
        f"[bold]pending approvals:[/bold] {report.get('pending_approvals', 0)}   "
        f"[bold]active runs:[/bold] {report.get('active_runs', 0)}   "
        f"[bold]audit events:[/bold] {sum((report.get('audit_events') or {}).values())}"
    )
    if settings_block.get("global_dry_run"):
        console.print("[yellow]global dry-run is ON: nothing will be written to any platform.[/yellow]")
    if report.get("mock_estate"):
        console.print(
            f"[yellow]running against the simulator[/yellow] [dim]{report['mock_estate']}[/dim]"
        )


@app.command()
def preflight() -> None:
    """Verify credentials and connectivity before doing anything else."""

    async def _do(orch: Orchestrator) -> dict[str, Any]:
        return await orch.preflight()

    report = _run(_do)
    for name, info in (report.get("connectors") or {}).items():
        mark = "[green]✔[/green]" if info.get("healthy") else "[red]✘[/red]"
        backend = str(info.get("backend", ""))
        badge = "[green]live[/green]" if backend == "live" else "[yellow]SIMULATED[/yellow]"
        console.print(
            f"{mark} [bold]{name}[/bold] {badge} "
            f"{info.get('detail', '')} [dim]({info.get('latency_ms', 0)} ms)[/dim]"
        )
    for note in report.get("configuration_notes") or []:
        console.print(f"[cyan]ℹ[/cyan] {note}")
    for problem in report.get("problems") or []:
        console.print(f"[red]✘[/red] {problem}")
    ok = report.get("ok", True)
    console.print(
        "[green]preflight OK[/green]" if ok else "[red]preflight FAILED[/red]"
        f" [dim](mode: {report.get('mode')})[/dim]"
    )
    if not ok:
        raise typer.Exit(code=1)


@app.command()
def workflows() -> None:
    """List the available lifecycle playbooks."""
    orch = _orch()
    for wf in orch.workflows.describe_all():
        console.print(f"[bold]{wf['key']}[/bold] — {wf['summary']}")
        console.print(f"  [dim]platforms: {', '.join(wf['platforms'])}[/dim]")
        console.print(Markdown(f"> {wf['guidance']}"))


@app.command()
def find(
    query: str = typer.Argument(..., help="Name, e-mail, UPN, username or employee id."),
    limit: int = typer.Option(20, help="Maximum matches."),
) -> None:
    """Search every connected directory for a person."""

    async def _do(orch: Orchestrator) -> list[dict[str, Any]]:
        return await orch.find_people(query, limit=limit)

    results = _run(_do)
    if not results:
        console.print(f"[yellow]no match for {query!r}[/yellow]")
        raise typer.Exit(code=1)
    table = Table(title=f"{len(results)} match(es) for {query!r}")
    for col in ("identifier", "name", "username", "department", "job title", "enabled", "platforms"):
        table.add_column(col)
    for hit in results:
        enabled = hit.get("enabled")
        table.add_row(
            str(hit.get("identifier", "")),
            str(hit.get("display_name", "")),
            str(hit.get("username", "")),
            str(hit.get("department", "")),
            str(hit.get("job_title", "")),
            "" if enabled is None else ("[green]yes[/green]" if enabled else "[red]no[/red]"),
            ",".join(hit.get("platforms") or []),
        )
    console.print(table)


@app.command()
def identity(identifier: str = typer.Argument(..., help="E-mail, UPN, username or id.")) -> None:
    """Show one person's complete estate: accounts, groups, licences, devices."""

    async def _do(orch: Orchestrator):
        return await orch.get_identity(identifier)

    snapshot = _run(_do)
    console.print(Markdown(snapshot.to_markdown()))


@app.command()
def drift(
    identifier: str = typer.Option("", help="One person. Omit to audit the whole estate."),
    limit: int = typer.Option(200, help="How many people to audit (estate mode)."),
) -> None:
    """Report configuration drift between Entra ID, on-prem AD and the consoles."""

    async def _do(orch: Orchestrator) -> Any:
        if identifier:
            _snapshot, findings = await orch.reconciler.detect_drift_for(identifier)
            return findings
        report = await orch.audit_estate(limit=limit)
        return report.findings

    findings = _run(_do)
    if not findings:
        console.print("[green]no drift detected[/green]")
        return
    table = Table(title=f"{len(findings)} drift finding(s)")
    for col in ("severity", "subject", "category", "finding", "recommended action", "platforms"):
        table.add_column(col, overflow="fold")
    colour = {"critical": "red", "high": "yellow", "medium": "cyan", "low": "dim"}
    for finding in findings:
        severity = str(finding.severity)
        table.add_row(
            f"[{colour.get(severity, 'white')}]{severity}[/]",
            finding.subject,
            finding.category,
            finding.description,
            finding.recommended_action,
            ", ".join(finding.platforms or []) or "—",
        )
    console.print(table)
    raise typer.Exit(code=1 if any(str(f.severity) in ("critical", "high") for f in findings) else 0)


@app.command()
def devices(
    console_name: str = typer.Option("all", "--console", help="all | action1 | scalefusion"),
    owner: str = typer.Option("", help="Filter by owner e-mail."),
    ownership: str = typer.Option("", help="Filter by corporate | byod."),
    limit: int = typer.Option(100, help="Maximum rows."),
) -> None:
    """List endpoints from Action1 (PCs) and Scalefusion (mobile)."""

    async def _do(orch: Orchestrator) -> list[Any]:
        found: list[Any] = []
        if console_name in ("all", "action1"):
            found += (
                await orch.hub.action1.find_endpoints_by_owner(owner)
                if owner
                else await orch.hub.action1.list_endpoints()
            )
        if console_name in ("all", "scalefusion"):
            found += (
                await orch.hub.scalefusion.find_devices_by_user(owner)
                if owner
                else await orch.hub.scalefusion.list_devices()
            )
        return found

    found = _run(_do)
    if ownership:
        found = [d for d in found if d.ownership.value == ownership.lower()]
    found = found[:limit]
    table = Table(title=f"{len(found)} device(s)")
    for col in ("console", "device", "serial", "owner", "state", "ownership", "os", "online", "compliance"):
        table.add_column(col)
    for device in found:
        table.add_row(
            device.platform_console,
            device.device_name or device.model or "—",
            device.serial_number or "—",
            device.assigned_email or "[yellow]unassigned[/yellow]",
            device.state.value,
            # BYOD is highlighted: it changes what offboarding is allowed to do.
            (
                f"[magenta]{device.ownership.value}[/magenta]"
                if device.ownership.value == "byod"
                else device.ownership.value
            ),
            f"{device.os_name} {device.os_version}".strip() or "—",
            "[green]yes[/green]" if device.online else "[dim]no[/dim]",
            device.compliance or "—",
        )
    console.print(table)


# --------------------------------------------------------------------------- #
# Lifecycle
# --------------------------------------------------------------------------- #


def _lifecycle_command(
    name: str,
    workflow: str,
    help_text: str,
) -> None:
    """Register a plan/execute command for one workflow."""

    def command(
        identifier: str = typer.Argument("", help="E-mail, UPN, username or employee id."),
        employee_id: str = typer.Option("", "--employee-id", help="HR employee id."),
        first_name: str = typer.Option("", "--first-name", help="Given name."),
        last_name: str = typer.Option("", "--last-name", help="Family name."),
        department: str = typer.Option("", "--department", help="Department."),
        job_title: str = typer.Option("", "--job-title", help="Job title."),
        manager_email: str = typer.Option("", "--manager", help="Manager e-mail."),
        hire_date: str = typer.Option("", "--hire-date", help="YYYY-MM-DD."),
        leave_date: str = typer.Option("", "--leave-date", help="YYYY-MM-DD."),
        reason: str = typer.Option("", "--reason", help="Why this is happening (audit log)."),
        execute: bool = typer.Option(
            False, "--execute", help="Actually run it. Without this flag the command only plans."
        ),
        option: list[str] = typer.Option(
            [], "--option", "-o", help="Workflow option as key=value. Repeatable."
        ),
        as_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON."),
    ) -> None:
        options = _parse_options(option)
        employee = _employee(
            identifier=identifier,
            employee_id=employee_id,
            first_name=first_name,
            last_name=last_name,
            department=department,
            job_title=job_title,
            manager_email=manager_email,
            hire_date=hire_date,
            leave_date=leave_date,
            reason=reason,
        )

        async def _plan_only(orch: Orchestrator) -> Any:
            run, _ctx = await orch.build_plan(
                workflow, employee, options=options, requested_by="cli", reason=reason
            )
            return run

        async def _execute(orch: Orchestrator) -> Any:
            return await orch.run_workflow(
                workflow,
                employee,
                options=options,
                requested_by="cli",
                reason=reason,
                execute=True,
            )

        run = _run(_execute if execute else _plan_only)
        if as_json:
            console.print_json(json.dumps(run.model_dump(mode="json", exclude_none=True)))
            return
        if not execute:
            console.print("[bold cyan]DRY RUN[/bold cyan] — nothing was executed.\n")
        _print_run(run)
        if run.plan:
            _print_plan(run.plan)

        async def _show_pending(orch: Orchestrator) -> None:
            _print_pending(orch)

        _run(_show_pending)
        if run.status.value == "awaiting_approval":
            raise typer.Exit(code=3)

    command.__doc__ = help_text
    app.command(name=name)(command)


def _parse_options(pairs: list[str]) -> dict[str, Any]:
    options: dict[str, Any] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep:
            err_console.print(f"[red]--option must be key=value[/red] (got {pair!r})")
            raise typer.Exit(code=2)
        if value.lower() in ("true", "false"):
            options[key] = value.lower() == "true"
        elif value.isdigit():
            options[key] = int(value)
        elif value.startswith("[") and value.endswith("]"):
            try:
                options[key] = json.loads(value)
            except json.JSONDecodeError:
                options[key] = [v.strip() for v in value[1:-1].split(",") if v.strip()]
        else:
            options[key] = value
    return options


_lifecycle_command(
    "onboard",
    "onboarding",
    "Plan (or with --execute, run) a joiner's full provisioning across all five platforms.",
)
_lifecycle_command(
    "offboard",
    "offboarding",
    "Plan (or with --execute, run) a leaver's revoke-first offboarding.",
)
_lifecycle_command(
    "transfer",
    "transfer",
    "Plan (or with --execute, run) a mover's delta-only department change.",
)
_lifecycle_command(
    "purge",
    "deferred_deletion",
    "Delete Entra objects for leavers whose retention window has expired.",
)


# --------------------------------------------------------------------------- #
# Approvals
# --------------------------------------------------------------------------- #


approvals_app = typer.Typer(help="Review and decide the human-in-the-loop gates.", no_args_is_help=True)
app.add_typer(approvals_app, name="approvals")


@approvals_app.command("list")
def approvals_list(
    approval_status: str = typer.Option("pending", "--status", help="pending | approved | rejected | expired | all"),
) -> None:
    """List approval requests."""
    orch = _orch()
    items = orch.list_approvals(status=None if approval_status == "all" else approval_status)
    if not items:
        console.print(f"[green]no {approval_status} approvals[/green]")
        return
    table = Table(title=f"{len(items)} {approval_status} approval(s)")
    for col in ("id", "step", "subject", "workflow", "risk", "signed", "expires"):
        table.add_column(col)
    for request in items:
        table.add_row(
            request.id,
            request.title,
            request.subject,
            request.workflow,
            request.risk.value,
            f"{len(request.approvals)}/{request.required_approvals}",
            request.expires_at.strftime("%Y-%m-%d %H:%M UTC") if request.expires_at else "—",
        )
    console.print(table)


@approvals_app.command("show")
def approvals_show(approval_id: str = typer.Argument(..., help="Approval id (apv_…).")) -> None:
    """Render the review document a human should read before deciding."""
    orch = _orch()
    try:
        request = orch.get_approval(approval_id)
    except KeyError:
        err_console.print(f"[red]no approval with id {approval_id!r}[/red]")
        raise typer.Exit(code=1) from None
    console.print(Markdown(request.to_review_markdown()))


@approvals_app.command("decide")
def approvals_decide(
    approval_id: str = typer.Argument(..., help="Approval id (apv_…)."),
    approve: bool = typer.Option(False, "--approve/--reject", help="Grant or refuse."),
    approver: str = typer.Option(..., "--approver", help="Your identity, e.g. you@corp. Required."),
    comment: str = typer.Option("", "--comment", help="Free text for the audit log."),
    wait: bool = typer.Option(True, "--wait/--no-wait", help="Resume the run after deciding."),
) -> None:
    """Approve or reject a gate, then resume the run."""
    human = _check_approver(approver)

    async def _do(orch: Orchestrator) -> dict[str, Any]:
        return await orch.decide_approval(
            approval_id, approve=approve, decided_by=human, comment=comment
        )

    try:
        result = _run(_do)
    except ValueError as exc:
        err_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=1) from None

    verb = "approved" if approve else "rejected"
    console.print(f"[bold]{verb}[/bold] {approval_id} by {human}")
    if result.get("message"):
        console.print(f"[yellow]{result['message']}[/yellow]")
    if not result.get("fully_approved"):
        console.print(
            f"[yellow]still needs "
            f"{result['required_approvals'] - result['approvals_recorded']} more distinct approver(s)[/yellow]"
        )
        return

    run_id = result.get("run_id")
    if not run_id or not wait:
        return

    async def _finish(orch: Orchestrator) -> Any:
        return orch.get_run(run_id)

    run = _run(_finish)
    _print_run(run)
    async def _pending(orch: Orchestrator) -> None:
        _print_pending(orch)
    _run(_pending)
    if run.status.value == "awaiting_approval":
        raise typer.Exit(code=3)
    if run.status.value == "failed":
        raise typer.Exit(code=1)


# --------------------------------------------------------------------------- #
# Runs
# --------------------------------------------------------------------------- #


runs_app = typer.Typer(help="Inspect, resume, cancel and roll back runs.", no_args_is_help=True)
app.add_typer(runs_app, name="runs")


@runs_app.command("list")
def runs_list(
    workflow: str = typer.Option("", help="Filter by workflow key."),
    limit: int = typer.Option(25, help="Maximum rows."),
) -> None:
    """List recent runs."""
    orch = _orch()
    runs = orch.list_runs(workflow=workflow or None, limit=limit)
    if not runs:
        console.print("[green]no runs recorded[/green]")
        return
    table = Table(title=f"{len(runs)} run(s)")
    for col in ("id", "workflow", "subject", "status", "progress", "risk", "created"):
        table.add_column(col)
    for run in runs:
        progress = run.plan.progress() if run.plan else {}
        table.add_row(
            run.id,
            run.workflow,
            run.subject,
            run.status.value,
            f"{progress.get('done', 0)}/{progress.get('total', 0)}",
            run.plan.max_risk.value if run.plan else "—",
            run.created_at.strftime("%Y-%m-%d %H:%M"),
        )
    console.print(table)


@runs_app.command("show")
def runs_show(run_id: str = typer.Argument(...), as_json: bool = typer.Option(False, "--json")) -> None:
    """Show one run in full."""

    async def _do(orch: Orchestrator) -> dict[str, Any]:
        return orch.run_detail(run_id)

    detail = _run(_do)
    if as_json:
        console.print_json(json.dumps(detail, default=str))
        return
    # run_detail() spreads RunRecord.summary() at the top level, so the id lives
    # under "run_id" and there is no nested "run" object.
    console.print(
        Markdown(f"# Run `{detail.get('run_id')}` — {detail.get('workflow')} · {detail.get('status')}")
    )
    orch = _orch()
    _print_run(orch.get_run(run_id))
    plan = detail.get("plan") or {}
    for note in plan.get("assumptions") or []:
        console.print(f"[cyan]ℹ assumption:[/cyan] {note}")
    for warn in plan.get("warnings") or []:
        console.print(f"[yellow]⚠ {warn}[/yellow]")
    steps = Table(title="Steps")
    for col in ("#", "step", "platform", "status", "risk", "gate"):
        steps.add_column(col)
    for st in plan.get("steps") or []:
        steps.add_row(
            str(st.get("order")),
            st.get("name", ""),
            st.get("platform", ""),
            st.get("status", ""),
            st.get("risk", ""),
            "🔒" if st.get("requires_approval") else "",
        )
    console.print(steps)
    for approval in detail.get("pending_approvals") or []:
        console.print(f"[yellow]awaiting approval:[/yellow] {approval.get('id')} — {approval.get('title')}")
    for event in detail.get("events") or []:
        console.print(f"[dim]{str(event.get('ts', ''))[:19]} {event.get('event')}[/dim]")


@runs_app.command("resume")
def runs_resume(
    run_id: str = typer.Argument(...),
    approver: str = typer.Option(..., "--approver", help="Who is resuming this run."),
) -> None:
    """Resume a parked run once its approvals are in place."""

    async def _do(orch: Orchestrator) -> Any:
        return await orch.resume_run(run_id, approver=_check_approver(approver))

    run = _run(_do)
    _print_run(run)
    if run.plan:
        _print_plan(run.plan)
    if run.status.value == "awaiting_approval":
        raise typer.Exit(code=3)


@runs_app.command("cancel")
def runs_cancel(run_id: str = typer.Argument(...), reason: str = typer.Option("", help="Why.")) -> None:
    """Cancel a run."""

    async def _do(orch: Orchestrator):
        return await orch.cancel_run(run_id, reason)

    _print_run(_run(_do))


@runs_app.command("rollback")
def runs_rollback(run_id: str = typer.Argument(...)) -> None:
    """Run the compensating actions for everything already applied."""

    async def _do(orch: Orchestrator) -> dict[str, Any]:
        return await orch.rollback_run(run_id)

    result = _run(_do)
    console.print_json(json.dumps(result, default=str))


# --------------------------------------------------------------------------- #
# Audit & server
# --------------------------------------------------------------------------- #


@app.command()
def audit(
    count: int = typer.Option(50, "-n", help="How many entries."),
    event: str = typer.Option("", help="Filter by event name."),
    run_id: str = typer.Option("", help="Filter by run id."),
    as_json: bool = typer.Option(False, "--json", help="Raw JSON lines."),
) -> None:
    """Read the append-only audit log."""
    orch = _orch()
    entries = orch.audit.tail(count, event=event or None, run_id=run_id or None)
    if as_json:
        for entry in entries:
            console.print_json(json.dumps(entry, default=str))
        return
    table = Table(title=f"last {len(entries)} audit entries")
    for col in ("timestamp", "event", "actor", "detail"):
        table.add_column(col, overflow="fold")
    for entry in entries:
        detail = {k: v for k, v in entry.items() if k not in ("timestamp", "event", "actor", "run_id")}
        table.add_row(
            str(entry.get("timestamp", ""))[:19],
            str(entry.get("event", "")),
            str(entry.get("actor", "")),
            json.dumps(detail, ensure_ascii=False, default=str)[:110],
        )
    console.print(table)
    stats = orch.audit.stats()
    if stats:
        console.print(f"[dim]totals: {stats}[/dim]")


@app.command()
def serve(
    host: str = typer.Option("", help="Bind address. Defaults to settings (0.0.0.0)."),
    port: int = typer.Option(0, help="Port. Defaults to settings (8000)."),
    reload: bool = typer.Option(False, "--reload", help="Auto-reload on change (development)."),
) -> None:
    """Start the REST control plane."""
    import uvicorn

    cfg = _settings().api
    uvicorn.run(
        "iam_agent.api.app:app",
        host=host or cfg.host,
        port=port or cfg.port,
        reload=reload,
    )


@app.command()
def mcp(
    transport: str = typer.Option("stdio", help="stdio | streamable-http | sse"),
) -> None:
    """Start the MCP server so Claude Code / Claude Desktop can drive it."""
    import os

    from iam_agent.mcp_server.server import main as mcp_main

    os.environ.setdefault("IAM_MCP_TRANSPORT", transport)
    mcp_main()


@app.command()
def agent(
    prompt: str = typer.Argument("", help="What you want done. Omit for interactive mode."),
    max_turns: int = typer.Option(0, help="Override the configured turn budget."),
    plan_only: bool = typer.Option(False, help="Force read-only: no write may execute."),
    approver: str = typer.Option("", help="Identity used when you approve interactively."),
) -> None:
    """Run the autonomous Claude agent over the same tool surface."""
    from iam_agent.agent.loop import AgentLoop

    cfg = _settings()
    if not cfg.claude.api_key:
        err_console.print(
            "[red]no IAM_CLAUDE_API_KEY set.[/red] Configure it, or use the MCP server / CLI, "
            "which need no model API key."
        )
        raise typer.Exit(code=2)

    loop = AgentLoop(
        settings=cfg,
        max_turns=max_turns or None,
        plan_only=plan_only,
        approver=approver or "operator",
    )
    try:
        asyncio.run(loop.run(prompt))
    except KeyboardInterrupt:
        console.print("\n[yellow]interrupted[/yellow]")
        raise typer.Exit(code=130) from None


if __name__ == "__main__":
    app()
