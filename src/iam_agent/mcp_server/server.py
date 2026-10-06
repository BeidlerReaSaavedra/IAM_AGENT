"""MCP server: exposes the IAM Agent to Claude as a set of tools.

Tool design
-----------
The surface is deliberately **high level**. Claude gets ``onboard_employee`` and
``offboard_employee`` rather than sixty raw Graph/Action1/Scalefusion endpoints,
because:

* a raw endpoint surface invites Claude to improvise a sequence, and the
  ordering of an offboarding is a security property, not a preference;
* every tool here routes through the same policy gate, approval queue and audit
  log, so there is no privileged path;
* the playbooks encode institutional knowledge (licence before mailbox, disable
  at the authoritative source, never wipe BYOD) that a model should not have to
  rediscover each time.

Granular tools do exist (``disable_user``, ``lock_device``, ``revoke_sessions``)
for incident response, and they are gated identically.

**Reads are always allowed. Writes return an approval request instead of
executing.** That is the contract Claude must understand, and it is stated in the
server instructions so it does not try to "retry" a gated action.
"""

from __future__ import annotations

import json
import os
from datetime import date
from typing import Any, Literal, cast

from mcp.server.mcpserver import MCPServer

from iam_agent import __version__
from iam_agent.config import Settings, get_settings
from iam_agent.core.models import DeviceOwnership, Employee, EmploymentType, LifecycleState, Manager
from iam_agent.core.orchestrator import Orchestrator

INSTRUCTIONS = """\
You are operating an IAM and Unified Endpoint Management agent for a company that
uses Microsoft Entra ID, Microsoft 365, an on-premises Active Directory, Action1
(RMM for PCs and servers) and Scalefusion (MDM for mobile devices).

How this server behaves - read this carefully:

1. READ tools always work and never change anything. Use them freely to
   investigate before acting. `get_identity` gives you the complete picture of a
   person across all five platforms in one call - prefer it over several narrow
   lookups.

2. WRITE tools are gated by a policy engine. In the default hybrid posture a
   write does NOT execute: it returns a `run_id` plus an `approval_id` and the
   run parks in `awaiting_approval`. This is correct behaviour, not an error. Do
   not retry the tool. Instead show the human what is being proposed (use
   `show_approval`) and ask them to approve it. Once they do, call
   `decide_approval`, which resumes the run automatically.

3. `plan_workflow` builds a plan and executes nothing. Use it whenever you want
   to show someone the consequences before committing - it is free and safe.

4. Destructive operations (device wipe, device retire, account deletion) are
   classified `critical` and require TWO distinct approvers. Tell the user this
   up front rather than letting them discover it on the second call.

5. BYOD devices are never fully wiped - only the work profile is removed. Do not
   attempt to override this; it is enforced in two places.

6. Always run `iam_status` first in a session. It tells you which platforms are
   live versus simulated, the current execution mode, and whether approvals are
   already pending. Acting without this is how you end up surprised.

7. If `audit_estate` reports findings, treat `critical` and `high` as urgent.
   Each finding carries a `recommended_action` - surface it verbatim rather than
   inventing your own remediation.

Report honestly. If a step was skipped, blocked or failed, say so explicitly and
give the reason. Never imply an action succeeded when the run is still awaiting
approval.
"""


def _json(value: Any) -> str:
    return json.dumps(value, default=str, ensure_ascii=False, indent=2)


def _date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


# --------------------------------------------------------------------------- #
# Server + shared state
# --------------------------------------------------------------------------- #

_server: MCPServer | None = None
_orchestrator: Orchestrator | None = None


def get_orchestrator() -> Orchestrator:
    """One orchestrator per process, shared by every tool call."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator(get_settings())
    return _orchestrator


def build_server(settings: Settings | None = None) -> MCPServer:
    """Construct the MCP server and register every tool."""
    global _server, _orchestrator
    if settings is not None:
        _orchestrator = Orchestrator(settings)

    server = MCPServer(
        name="iam-agent",
        title="IAM & Endpoint Lifecycle Agent",
        description=(
            "Identity and endpoint lifecycle automation across Microsoft Entra ID, "
            "Microsoft 365, on-premises Active Directory, Action1 RMM and Scalefusion MDM."
        ),
        instructions=INSTRUCTIONS,
        version=__version__,
    )
    _server = server
    _register_tools(server)
    return server


def _register_tools(server: MCPServer) -> None:
    # ======================================================================= #
    # STATUS & PREFLIGHT
    # ======================================================================= #

    @server.tool(
        name="iam_status",
        description=(
            "Current posture of the IAM agent: which of the five platforms are live vs "
            "simulated, the execution mode (dry_run / approval_required / autonomous), "
            "connector health and latency, how many approvals are pending, how many runs "
            "are in flight, and the audit event counts. ALWAYS call this first in a session."
        ),
    )
    async def iam_status() -> str:
        return _json(await get_orchestrator().status())

    @server.tool(
        name="iam_preflight",
        description=(
            "Connectivity and configuration check across Entra ID, M365, on-prem AD, "
            "Action1 and Scalefusion. Returns per-connector health plus a list of "
            "configuration problems and advisories (for example: AD without LDAPS means "
            "password writes will be refused). Run this before a bulk operation."
        ),
    )
    async def iam_preflight() -> str:
        return _json(await get_orchestrator().preflight())

    # ======================================================================= #
    # IDENTITY READS
    # ======================================================================= #

    @server.tool(
        name="find_people",
        description=(
            "Fuzzy search for people across Entra ID and on-premises Active Directory by "
            "name, email or username. Returns up to `limit` matches with the platforms "
            "each was found in. Use this to resolve a human-typed name into a canonical "
            "identifier before calling get_identity."
        ),
    )
    async def find_people(query: str, limit: int = 25) -> str:
        return _json(await get_orchestrator().find_people(query, limit=limit))

    @server.tool(
        name="get_identity",
        description=(
            "The complete cross-platform picture of ONE person: their Entra and on-prem AD "
            "objects, every device managed by Action1 and Scalefusion, mailbox state and "
            "size, group memberships per directory, plus any reconciliation warnings. "
            "This is the single best tool for understanding who someone is and what they "
            "have access to. Accepts an email, UPN, username or Entra object id."
        ),
    )
    async def get_identity(identifier: str) -> str:
        snapshot = await get_orchestrator().get_identity(identifier)
        return _json(
            {
                "summary": snapshot.summary(),
                "employee": snapshot.employee.model_dump(mode="json", exclude_none=True),
                "devices": [d.model_dump(mode="json", exclude={"raw"}) for d in snapshot.devices],
                "mailboxes": [m.model_dump(mode="json") for m in snapshot.mailboxes],
                "groups": {
                    platform: [g.display_name for g in groups]
                    for platform, groups in snapshot.group_memberships.items()
                },
                "warnings": snapshot.warnings,
            }
        )

    @server.tool(
        name="get_user_access",
        description=(
            "Focused access review for one person: Entra group memberships, Microsoft Team "
            "memberships, directory role assignments (Global Admin, User Admin, etc.), "
            "assigned licence SKUs and MFA registration state. Use this to answer 'what can "
            "this person actually do?' without pulling their whole identity snapshot."
        ),
    )
    async def get_user_access(identifier: str) -> str:
        orch = get_orchestrator()
        snapshot = await orch.get_identity(identifier)
        entra = snapshot.entra
        roles, teams = [], []
        if entra:
            try:
                roles = await orch.hub.entra.get_user_roles(entra.external_id)
            except Exception as exc:
                roles = [{"error": str(exc)}]
            try:
                teams = [
                    t.get("displayName") for t in await orch.hub.m365.find_user_teams(entra.external_id)
                ]
            except Exception as exc:
                teams = [{"error": str(exc)}]
        return _json(
            {
                "identifier": identifier,
                "display_name": snapshot.employee.full_name,
                "entra": {
                    "object_id": entra.external_id if entra else None,
                    "upn": entra.upn if entra else None,
                    "enabled": entra.enabled if entra else None,
                    "license_skus": entra.license_skus if entra else [],
                    "mfa_registered": entra.mfa_registered if entra else None,
                    "last_sign_in": entra.last_sign_in.isoformat() if entra and entra.last_sign_in else None,
                    "on_premises_sync": entra.on_premises_sync if entra else None,
                },
                "directory_roles": roles,
                "entra_groups": [g.display_name for g in snapshot.group_memberships.get("entra", [])],
                "teams": teams,
                "on_prem_groups": [
                    g.display_name for g in snapshot.group_memberships.get("active_directory", [])
                ],
                "on_prem": {
                    "dn": snapshot.on_prem.dn if snapshot.on_prem else None,
                    "enabled": snapshot.on_prem.enabled if snapshot.on_prem else None,
                },
            }
        )

    @server.tool(
        name="audit_estate",
        description=(
            "Estate-wide drift and risk audit across all five platforms. Detects orphaned "
            "accounts (enabled past their leave date), Entra/on-prem sync gaps, devices "
            "still bound to leavers, licences wasted on leavers, mailboxes never converted "
            "to shared, unpatched endpoints and unowned assets. Every finding carries a "
            "severity and a recommended_action. Use this for the weekly hygiene review."
        ),
    )
    async def audit_estate(limit: int = 200) -> str:
        report = await get_orchestrator().audit_estate(limit=limit)
        return _json(
            {
                "generated_at": report.generated_at.isoformat(),
                "is_clean": report.is_clean,
                "counts": {sev: len(items) for sev, items in report.by_severity().items()},
                "findings": [f.model_dump(mode="json") for f in report.findings],
            }
        )

    @server.tool(
        name="list_drift_for_user",
        description=(
            "Drift findings for ONE person rather than the whole estate - the same checks "
            "as audit_estate but scoped, and paired with their identity snapshot. Useful "
            "right before an offboarding to see what is already inconsistent."
        ),
    )
    async def list_drift_for_user(identifier: str) -> str:
        snapshot, findings = await get_orchestrator().reconciler.detect_drift_for(identifier)
        return _json(
            {
                "identity": snapshot.summary(),
                "findings": [f.model_dump(mode="json") for f in findings],
            }
        )

    # ======================================================================= #
    # DEVICE READS
    # ======================================================================= #

    @server.tool(
        name="list_devices",
        description=(
            "Inventory of managed endpoints. `console` selects the source: 'action1' for "
            "PCs/servers, 'scalefusion' for mobiles/kiosks, or 'all' for both. Optionally "
            "filter by `owner` (email or name), `state` and `ownership` (corporate/byod). "
            "Returns patch/compliance posture, last seen time and assignment."
        ),
    )
    async def list_devices(
        console: str = "all",
        owner: str = "",
        state: str = "",
        ownership: str = "",
        limit: int = 100,
    ) -> str:
        orch = get_orchestrator()
        devices = []
        if console in ("all", "action1"):
            if owner:
                devices += await orch.hub.action1.find_endpoints_by_owner(owner)
            else:
                devices += await orch.hub.action1.list_endpoints()
        if console in ("all", "scalefusion"):
            if owner:
                devices += await orch.hub.scalefusion.find_devices_by_user(owner)
            else:
                devices += await orch.hub.scalefusion.list_devices()

        if state:
            devices = [d for d in devices if d.state.value == state]
        if ownership:
            devices = [d for d in devices if d.ownership.value == ownership]

        return _json(
            {
                "count": len(devices[:limit]),
                "devices": [
                    {
                        "console": d.platform_console,
                        "id": d.external_id,
                        "name": d.device_name,
                        "platform": d.device_platform.value,
                        "os": f"{d.os_name} {d.os_version}".strip(),
                        "state": d.state.value,
                        "online": d.online,
                        "ownership": d.ownership.value,
                        "assigned_to": d.assigned_email or d.assigned_user,
                        "missing_updates": d.missing_updates,
                        "critical_vulnerabilities": d.critical_vulnerabilities,
                        "compliance": d.compliance,
                        "last_seen": d.last_seen.isoformat() if d.last_seen else None,
                        "asset_tag": d.asset_tag,
                        "serial_number": d.serial_number,
                    }
                    for d in devices[:limit]
                ],
            }
        )

    @server.tool(
        name="get_device",
        description=(
            "Full detail for one managed endpoint, including the vendor's raw payload. "
            "`console` is 'action1' or 'scalefusion'. For Scalefusion mobile devices this "
            "also pulls battery level, installed applications and the last known locations."
        ),
    )
    async def get_device(console: str, device_id: str) -> str:
        orch = get_orchestrator()
        if console == "action1":
            device = await orch.hub.action1.get_endpoint(device_id)
            if not device:
                return _json({"error": f"no Action1 endpoint '{device_id}'"})
            return _json(device.model_dump(mode="json"))
        if console == "scalefusion":
            device = await orch.hub.scalefusion.get_device(device_id)
            if not device:
                return _json({"error": f"no Scalefusion device '{device_id}'"})
            extra = {
                "battery": await orch.hub.scalefusion.get_device_battery(device_id),
                "apps": await orch.hub.scalefusion.get_device_apps(device_id),
                "location": await orch.hub.scalefusion.get_device_location(device_id),
            }
            return _json({**device.model_dump(mode="json"), **extra})
        return _json({"error": "console must be 'action1' or 'scalefusion'"})

    @server.tool(
        name="list_device_profiles",
        description=(
            "Scalefusion device profiles and device groups, and Action1 endpoint groups and "
            "available automations. You need these ids/names to apply a profile, move a "
            "device between groups, or launch an automation."
        ),
    )
    async def list_device_profiles() -> str:
        orch = get_orchestrator()
        return _json(
            {
                "scalefusion": {
                    "device_profiles": await orch.hub.scalefusion.list_device_profiles(),
                    "device_groups": await orch.hub.scalefusion.list_device_groups(),
                },
                "action1": {
                    "endpoint_groups": await orch.hub.action1.list_endpoint_groups(),
                    "automations": await orch.hub.action1.list_automations(),
                },
            }
        )

    # ======================================================================= #
    # DIRECTORY READS
    # ======================================================================= #

    @server.tool(
        name="list_groups",
        description=(
            "List groups. `platform` is 'entra' (cloud security/M365 groups), "
            "'active_directory' (on-prem), 'm365_teams' (Teams) or 'all'. Useful to find "
            "the exact group name to pass to grant_access."
        ),
    )
    async def list_groups(platform: str = "entra", search: str = "") -> str:
        orch = get_orchestrator()
        out: dict[str, Any] = {}
        if platform in ("all", "entra"):
            out["entra"] = [g.model_dump(mode="json", exclude={"raw"}) for g in await orch.hub.entra.list_groups()]
        if platform in ("all", "active_directory"):
            out["active_directory"] = [
                g.model_dump(mode="json", exclude={"raw"}) for g in await orch.hub.active_directory.list_groups()
            ]
        if platform in ("all", "m365_teams"):
            out["teams"] = await orch.hub.m365.list_teams()
        if search:
            needle = search.lower()
            out = {
                key: [g for g in value if needle in json.dumps(g, default=str).lower()]
                for key, value in out.items()
            }
        return _json(out)

    @server.tool(
        name="list_licences",
        description=(
            "Microsoft 365 licence inventory: SKU part numbers, product names, seats "
            "enabled, consumed and available. Check this BEFORE onboarding to confirm "
            "there is a free seat for the SKU you intend to assign."
        ),
    )
    async def list_licences() -> str:
        return _json({"skus": await get_orchestrator().hub.m365.list_skus()})

    # ======================================================================= #
    # LIFECYCLE (gated writes)
    # ======================================================================= #

    @server.tool(
        name="plan_workflow",
        description=(
            "Build a workflow plan and execute NOTHING. Returns the full ordered plan: every "
            "step, every action, its risk level, whether it needs approval, plus the "
            "planner's assumptions and warnings. Use this to show a human exactly what will "
            "happen before committing. `workflow` is 'onboarding', 'offboarding', 'transfer' "
            "or 'deferred_deletion'."
        ),
    )
    async def plan_workflow(workflow: str, employee: dict[str, Any], options: dict[str, Any] | None = None) -> str:
        emp = _employee_from_dict(employee)
        run, _ctx = await get_orchestrator().build_plan(
            workflow, emp, options=options or {}, requested_by="claude", reason="plan preview"
        )
        assert run.plan is not None
        return _json(
            {
                "run_id": run.id,
                "workflow": workflow,
                "executed": False,
                "max_risk": run.plan.max_risk.value,
                "needs_approval": run.plan.needs_approval(),
                "markdown": run.plan.to_markdown(),
                "plan": {
                    "assumptions": run.plan.assumptions,
                    "warnings": run.plan.warnings,
                    "steps": [s.summary() for s in run.plan.steps],
                },
            }
        )

    @server.tool(
        name="onboard_employee",
        description=(
            "Provision a NEW person across all five platforms: create the Entra ID identity, "
            "stamp HR attributes and the reporting line, assign M365 licences, grant "
            "department groups and Teams, create or verify the on-premises AD account, issue "
            "a Temporary Access Pass for MFA registration, prepare their PC in Action1 and "
            "bind their mobile in Scalefusion. Idempotent - re-running fills gaps only. "
            "Returns a run_id; under the default posture the run parks awaiting approval. "
            "Pass `password` only if HR supplied one, otherwise a compliant one is generated. "
            "Set `execute=false` for a preview identical to plan_workflow."
        ),
    )
    async def onboard_employee(
        employee: dict[str, Any],
        options: dict[str, Any] | None = None,
        reason: str = "",
        execute: bool = True,
    ) -> str:
        emp = _employee_from_dict(employee)
        run = await get_orchestrator().run_workflow(
            "onboarding", emp, options=options or {}, requested_by="claude",
            reason=reason or "Onboarding requested via Claude", execute=execute,
        )
        return _json(_run_payload(run, get_orchestrator()))

    @server.tool(
        name="offboard_employee",
        description=(
            "Revoke a LEAVER across all five platforms in the correct security order: revoke "
            "sessions, disable at the authoritative source, strip directory roles, remove all "
            "group and Teams memberships, contain the PC via Action1, lock then release the "
            "mobile via Scalefusion, convert the mailbox to shared with manager access, remove "
            "licences and clean up on-prem AD. Irreversible actions (wipe, retire, delete) are "
            "ALWAYS gated and need TWO approvers. BYOD devices are never fully wiped. "
            "Key options: emergency=true for same-day hostile termination (quarantines "
            "endpoints), litigation_hold=true for legal, retain_mailbox=true (default), "
            "wipe_mobile, retire_mobile, delete_after_days (0 = never delete). "
            "Requires an identifier (email/username/object id) in the employee dict."
        ),
    )
    async def offboard_employee(
        employee: dict[str, Any],
        options: dict[str, Any] | None = None,
        reason: str = "",
        execute: bool = True,
    ) -> str:
        orch = get_orchestrator()
        emp = _employee_from_dict(employee)

        # Offboarding works from what actually exists, not from what the caller typed.
        needle = emp.email or emp.upn or emp.username or emp.employee_id
        if needle:
            try:
                snapshot = await orch.reconciler.snapshot(needle)
                if snapshot.directories:
                    merged = snapshot.employee
                    if emp.leave_date:
                        merged.leave_date = emp.leave_date
                    if emp.termination_reason:
                        merged.termination_reason = emp.termination_reason
                    if emp.lifecycle_state != LifecycleState.PRE_HIRE:
                        merged.lifecycle_state = emp.lifecycle_state
                    else:
                        merged.lifecycle_state = LifecycleState.LEAVER
                    if emp.manager and emp.manager.email and not merged.manager:
                        merged.manager = emp.manager
                    emp = merged
            except Exception:
                pass
        emp.lifecycle_state = LifecycleState.LEAVER

        run = await orch.run_workflow(
            "offboarding", emp, options=options or {}, requested_by="claude",
            reason=reason or "Offboarding requested via Claude", execute=execute,
        )
        return _json(_run_payload(run, orch))

    @server.tool(
        name="transfer_employee",
        description=(
            "Move someone between departments or roles as a DELTA, not as an offboard+onboard: "
            "it computes which groups, Teams and licences the target role needs versus what "
            "they have, then applies only the difference. The account is never disabled, "
            "sessions are never revoked and devices are never wiped, so the person keeps "
            "working throughout. Licence changes add before removing to avoid a service gap. "
            "Options: target_department, target_title, target_licenses, new_manager, "
            "remove_old_groups (default true), reprofile_mobile (default true)."
        ),
    )
    async def transfer_employee(
        employee: dict[str, Any],
        options: dict[str, Any] | None = None,
        reason: str = "",
        execute: bool = True,
    ) -> str:
        orch = get_orchestrator()
        emp = _employee_from_dict(employee)
        needle = emp.email or emp.upn or emp.username or emp.employee_id
        if needle:
            try:
                snapshot = await orch.reconciler.snapshot(needle)
                if snapshot.directories:
                    merged = snapshot.employee
                    if emp.department:
                        merged.department = emp.department
                    if emp.job_title:
                        merged.job_title = emp.job_title
                    emp = merged
            except Exception:
                pass
        run = await orch.run_workflow(
            "transfer", emp, options=options or {}, requested_by="claude",
            reason=reason or "Internal transfer requested via Claude", execute=execute,
        )
        return _json(_run_payload(run, orch))

    # ======================================================================= #
    # TARGETED OPERATIONS (gated writes, incident response)
    # ======================================================================= #

    @server.tool(
        name="disable_user",
        description=(
            "Disable ONE account. With `both_directories=true` (default) it disables in "
            "on-premises Active Directory AND Entra ID, because if the account is Entra "
            "Connect-synced, disabling only in the cloud gets reverted at the next sync. "
            "With `revoke_sessions=true` (default) it also revokes all Entra refresh tokens, "
            "which kills existing sessions within minutes. This is the tool to reach for "
            "during a security incident."
        ),
    )
    async def disable_user(
        identifier: str,
        reason: str = "",
        both_directories: bool = True,
        revoke_sessions: bool = True,
        execute: bool = True,
    ) -> str:
        orch = get_orchestrator()
        snapshot = await orch.reconciler.snapshot(identifier)
        entra = snapshot.entra
        ad = snapshot.on_prem
        actions = []
        if revoke_sessions and entra:
            actions.append(
                orch.build_action(
                    "entra.revoke_all_sessions",
                    description="Revoke all Entra refresh tokens to kill live sessions",
                    target=entra.upn or identifier,
                    user_id=entra.external_id,
                )
            )
        if both_directories and ad:
            actions.append(
                orch.build_action(
                    "active_directory.disable_user",
                    description="Disable at the authoritative source (on-premises AD)",
                    target=ad.dn or identifier,
                    identifier=ad.dn or ad.external_id,
                    reason=reason,
                )
            )
        if entra:
            actions.append(
                orch.build_action(
                    "entra.disable_user",
                    description="Disable the Entra ID account",
                    target=entra.upn or identifier,
                    user_id=entra.external_id,
                    reason=reason,
                )
            )
        if not actions:
            return _json({"error": f"no account matched '{identifier}'"})
        run = await orch.run_adhoc(
            actions, subject=snapshot.employee.full_name or identifier,
            requested_by="claude", reason=reason or "Manual disable via Claude", execute=execute,
        )
        return _json(_run_payload(run, orch))

    @server.tool(
        name="revoke_sessions",
        description=(
            "Revoke every Entra ID refresh token for a user, invalidating all existing "
            "sessions within minutes without disabling the account. Use when credentials may "
            "be compromised but the person still needs to work - they will simply be prompted "
            "to sign in again (and re-authenticate with MFA)."
        ),
    )
    async def revoke_sessions(identifier: str, reason: str = "", execute: bool = True) -> str:
        orch = get_orchestrator()
        snapshot = await orch.reconciler.snapshot(identifier)
        if not snapshot.entra:
            return _json({"error": f"no Entra account matched '{identifier}'"})
        run = await orch.run_adhoc(
            [
                orch.build_action(
                    "entra.revoke_all_sessions",
                    description="Revoke all sign-in sessions",
                    target=snapshot.entra.upn or identifier,
                    user_id=snapshot.entra.external_id,
                )
            ],
            subject=snapshot.employee.full_name or identifier,
            requested_by="claude", reason=reason or "Session revocation via Claude", execute=execute,
        )
        return _json(_run_payload(run, orch))

    @server.tool(
        name="lock_device",
        description=(
            "Remotely lock a Scalefusion-managed device. `message` is shown on the lock "
            "screen. Reversible with unlock_device. Use when a device is lost or when the "
            "owner has left but the hardware has not been recovered."
        ),
    )
    async def lock_device(device_id: str, message: str = "", reason: str = "", execute: bool = True) -> str:
        orch = get_orchestrator()
        device = await orch.hub.scalefusion.get_device(device_id)
        if not device:
            return _json({"error": f"no Scalefusion device '{device_id}'"})
        run = await orch.run_adhoc(
            [
                orch.build_action(
                    "scalefusion.lock_device",
                    description=f"Lock {device.device_name}",
                    target=device.device_name or device_id,
                    device_id=device.external_id,
                    message=message,
                )
            ],
            subject=device.device_name or device_id,
            requested_by="claude", reason=reason or "Device lock via Claude", execute=execute,
        )
        return _json(_run_payload(run, orch))

    @server.tool(
        name="wipe_device",
        description=(
            "IRREVERSIBLE. Factory-wipe a Scalefusion device. `retention=true` removes ONLY "
            "the work profile and preserves personal data - this is forced automatically for "
            "BYOD devices and a full wipe of a BYOD device will be REFUSED. Classified "
            "critical: requires two distinct approvers and cannot run in autonomous mode."
        ),
    )
    async def wipe_device(
        device_id: str, retention: bool = False, reason: str = "", execute: bool = True
    ) -> str:
        orch = get_orchestrator()
        device = await orch.hub.scalefusion.get_device(device_id)
        if not device:
            return _json({"error": f"no Scalefusion device '{device_id}'"})
        if device.ownership == DeviceOwnership.BYOD and not retention:
            return _json(
                {
                    "refused": True,
                    "device": device.device_name,
                    "ownership": "byod",
                    "reason": (
                        "This is a BYOD device. A full factory wipe would destroy personal "
                        "data. Call again with retention=true to remove only the work profile, "
                        "or use retire_device to unenrol it."
                    ),
                }
            )
        run = await orch.run_adhoc(
            [
                orch.build_action(
                    "scalefusion.wipe_device",
                    description=(
                        f"{'Work-profile-only wipe' if retention else 'Factory wipe'} of {device.device_name}"
                    ),
                    target=device.device_name or device_id,
                    reversible=False,
                    device_id=device.external_id,
                    retention=retention,
                )
            ],
            subject=device.device_name or device_id,
            requested_by="claude", reason=reason or "Device wipe via Claude", execute=execute,
        )
        return _json(_run_payload(run, orch))

    @server.tool(
        name="grant_access",
        description=(
            "Grant a user membership of an Entra group, a Microsoft Team, a licence SKU or a "
            "directory role. `kind` is one of 'group', 'team', 'license', 'role'. Names are "
            "resolved to ids automatically. Directory roles are high-risk and always gated."
        ),
    )
    async def grant_access(
        identifier: str, kind: str, value: str, reason: str = "", execute: bool = True
    ) -> str:
        orch = get_orchestrator()
        snapshot = await orch.reconciler.snapshot(identifier)
        if not snapshot.entra:
            return _json({"error": f"no Entra account matched '{identifier}'"})
        uid = snapshot.entra.external_id
        target = snapshot.entra.upn or identifier

        if kind == "group":
            act = orch.build_action(
                "entra.add_group_member", description=f"Add to group '{value}'",
                target=f"{target} -> {value}", group_id=value, user_id=uid,
            )
        elif kind == "team":
            act = orch.build_action(
                "m365.add_team_member", description=f"Add to Team '{value}'",
                target=f"{target} -> {value}", team_id=value, user_id=uid,
            )
        elif kind == "license":
            act = orch.build_action(
                "entra.assign_license", description=f"Assign licence '{value}'",
                target=f"{target} -> {value}", user_id=uid, sku_part_numbers=[value],
            )
        elif kind == "role":
            act = orch.build_action(
                "entra.grant_role", description=f"Grant directory role '{value}'",
                target=f"{target} -> {value}", role_id=value, user_id=uid,
            )
        else:
            return _json({"error": "kind must be one of: group, team, license, role"})

        run = await orch.run_adhoc(
            [act], subject=snapshot.employee.full_name or identifier,
            requested_by="claude", reason=reason or f"Grant {kind} via Claude", execute=execute,
        )
        return _json(_run_payload(run, orch))

    @server.tool(
        name="revoke_access",
        description=(
            "Revoke a user's membership of an Entra group, a Microsoft Team, or a directory "
            "role. `kind` is 'group', 'team' or 'role'. For removing ALL groups and ALL Teams "
            "at once, use offboard_employee instead - it also handles the ordering."
        ),
    )
    async def revoke_access(
        identifier: str, kind: str, value: str, reason: str = "", execute: bool = True
    ) -> str:
        orch = get_orchestrator()
        snapshot = await orch.reconciler.snapshot(identifier)
        if not snapshot.entra:
            return _json({"error": f"no Entra account matched '{identifier}'"})
        uid = snapshot.entra.external_id
        target = snapshot.entra.upn or identifier

        if kind == "group":
            act = orch.build_action(
                "entra.remove_group_member", description=f"Remove from group '{value}'",
                target=f"{target} -> {value}", group_id=value, user_id=uid,
            )
        elif kind == "team":
            act = orch.build_action(
                "m365.remove_team_member", description=f"Remove from Team '{value}'",
                target=f"{target} -> {value}", team_id=value, user_id=uid,
            )
        elif kind == "role":
            act = orch.build_action(
                "entra.revoke_role", description=f"Revoke directory role '{value}'",
                target=f"{target} -> {value}", role_id=value, user_id=uid,
            )
        else:
            return _json({"error": "kind must be one of: group, team, role"})

        run = await orch.run_adhoc(
            [act], subject=snapshot.employee.full_name or identifier,
            requested_by="claude", reason=reason or f"Revoke {kind} via Claude", execute=execute,
        )
        return _json(_run_payload(run, orch))

    @server.tool(
        name="issue_temporary_access_pass",
        description=(
            "Create a one-time Temporary Access Pass (TAP) for a user so they can sign in and "
            "register MFA without a password. Returns the pass value - hand it to the user or "
            "their manager over a trusted channel, never by email to a personal address. "
            "`lifetime_minutes` defaults to 480."
        ),
    )
    async def issue_temporary_access_pass(
        identifier: str, lifetime_minutes: int = 480, reason: str = "", execute: bool = True
    ) -> str:
        orch = get_orchestrator()
        snapshot = await orch.reconciler.snapshot(identifier)
        if not snapshot.entra:
            return _json({"error": f"no Entra account matched '{identifier}'"})
        run = await orch.run_adhoc(
            [
                orch.build_action(
                    "entra.create_temporary_access_pass",
                    description="Issue a one-time Temporary Access Pass",
                    target=snapshot.entra.upn or identifier,
                    user_id=snapshot.entra.external_id,
                    lifetime_minutes=lifetime_minutes,
                    one_time=True,
                )
            ],
            subject=snapshot.employee.full_name or identifier,
            requested_by="claude", reason=reason or "TAP issued via Claude", execute=execute,
        )
        payload = _run_payload(run, orch)
        # Surface the pass value only once it actually executed.
        for step_result in payload["plan"]["steps"]:
            for act in step_result["actions"]:
                if act.get("result", {}).get("temporaryAccessPass"):
                    payload["temporary_access_pass"] = act["result"]["temporaryAccessPass"]
        return _json(payload)

    @server.tool(
        name="run_endpoint_automation",
        description=(
            "Launch a pre-existing Action1 automation against specific endpoints. The "
            "automation must already be defined in the Action1 console - this tool cannot "
            "create one. High risk: an automation may execute scripts on endpoints. Use "
            "list_device_profiles to discover automation ids and names."
        ),
    )
    async def run_endpoint_automation(
        automation: str, endpoint_ids: list[str], reason: str = "", execute: bool = True
    ) -> str:
        orch = get_orchestrator()
        run = await orch.run_adhoc(
            [
                orch.build_action(
                    "action1.run_automation",
                    description=f"Launch Action1 automation '{automation}'",
                    target=", ".join(endpoint_ids),
                    automation_id=automation,
                    endpoint_ids=endpoint_ids,
                )
            ],
            subject=automation, requested_by="claude",
            reason=reason or "Automation launched via Claude", execute=execute,
        )
        return _json(_run_payload(run, orch))

    # ======================================================================= #
    # APPROVALS
    # ======================================================================= #

    @server.tool(
        name="list_pending_approvals",
        description=(
            "All approval requests currently waiting on a human, with their risk level, how "
            "many approvers are required, when they expire and which run they belong to. "
            "Critical actions need TWO distinct approvers. Approvals expire after the "
            "configured timeout, which abandons the parked run safely."
        ),
    )
    async def list_pending_approvals() -> str:
        orch = get_orchestrator()
        pending = orch.list_approvals(status="pending")
        return _json(
            {
                "count": len(pending),
                "approvals": [
                    {
                        "approval_id": a.id,
                        "run_id": a.run_id,
                        "workflow": a.workflow,
                        "title": a.title,
                        "subject": a.subject,
                        "risk": a.risk.value,
                        "reversible": a.reversible,
                        "required_approvals": a.required_approvals,
                        "approvals_so_far": len(a.approvals),
                        "action_count": len(a.action_ids),
                        "requested_at": a.requested_at.isoformat(),
                        "expires_at": a.expires_at.isoformat() if a.expires_at else None,
                    }
                    for a in pending
                ],
            }
        )

    @server.tool(
        name="show_approval",
        description=(
            "Render one approval request as a human-readable review document: what is being "
            "proposed, every action with its target and parameters, the risk classification "
            "and whether the action is reversible. Show this to the user BEFORE asking them to "
            "approve. Secrets are redacted."
        ),
    )
    async def show_approval(approval_id: str) -> str:
        try:
            request = get_orchestrator().get_approval(approval_id)
        except Exception as exc:
            return _json({"error": str(exc)})
        return _json(
            {
                "approval_id": request.id,
                "status": request.effective_status(),
                "risk": request.risk.value,
                "required_approvals": request.required_approvals,
                "approvals_recorded": len(request.approvals),
                "markdown": request.to_review_markdown(),
            }
        )

    @server.tool(
        name="decide_approval",
        description=(
            "Approve or reject a pending request. On approval the parked run RESUMES "
            "automatically and continues to the next gate. Critical actions need two distinct "
            "`decided_by` identities - the second call from a different approver completes it. "
            "On rejection the run is cancelled and nothing further is applied. Never invent a "
            "`decided_by`: it must be the real human who authorised this, because it is "
            "written to the immutable audit log."
        ),
    )
    async def decide_approval(
        approval_id: str, approve: bool, decided_by: str, comment: str = ""
    ) -> str:
        if not decided_by or decided_by.strip().lower() in ("claude", "agent", "ai", "system"):
            return _json(
                {
                    "error": "decided_by must be a real human identity (e.g. an email or "
                    "domain account). An AI agent cannot approve its own privileged action."
                }
            )
        try:
            return _json(
                await get_orchestrator().decide_approval(
                    approval_id, approve=approve, decided_by=decided_by.strip(), comment=comment
                )
            )
        except ValueError as exc:
            return _json({"error": str(exc), "hint": "two-person integrity requires a distinct approver"})
        except Exception as exc:
            return _json({"error": str(exc)})

    # ======================================================================= #
    # RUNS
    # ======================================================================= #

    @server.tool(
        name="list_runs",
        description=(
            "Recent workflow runs with their status and progress. Filter by `workflow`. "
            "Useful to answer 'what did the agent do this week?' and to find a parked run "
            "that needs resuming."
        ),
    )
    async def list_runs(workflow: str = "", limit: int = 25) -> str:
        runs = get_orchestrator().list_runs(workflow=workflow or None, limit=limit)
        return _json({"count": len(runs), "runs": [r.summary() for r in runs]})

    @server.tool(
        name="get_run",
        description=(
            "Full detail of one run: every step and action with its status and error, the "
            "planner's assumptions and warnings, the event timeline, and any approval still "
            "blocking it. Use this to explain to a user exactly what happened and what is "
            "outstanding."
        ),
    )
    async def get_run(run_id: str) -> str:
        try:
            return _json(get_orchestrator().run_detail(run_id))
        except Exception as exc:
            return _json({"error": str(exc)})

    @server.tool(
        name="cancel_run",
        description=(
            "Cancel a run that is parked awaiting approval. Steps already applied are NOT "
            "undone - use rollback_run for that. Any outstanding approval request is "
            "cancelled with it."
        ),
    )
    async def cancel_run(run_id: str, reason: str = "") -> str:
        try:
            run = await get_orchestrator().cancel_run(run_id, reason)
            return _json(run.summary())
        except Exception as exc:
            return _json({"error": str(exc)})

    @server.tool(
        name="rollback_run",
        description=(
            "Best-effort compensation for a partially applied run: walks the plan backwards "
            "and applies each action's inverse where one was declared and the action is "
            "reversible. Returns what was reverted and what could NOT be - irreversible "
            "actions (wipes, deletions) are reported as skipped, never pretended to succeed."
        ),
    )
    async def rollback_run(run_id: str) -> str:
        try:
            return _json(await get_orchestrator().rollback_run(run_id))
        except Exception as exc:
            return _json({"error": str(exc)})

    # ======================================================================= #
    # AUDIT
    # ======================================================================= #

    @server.tool(
        name="read_audit_log",
        description=(
            "Read the append-only audit trail: policy decisions, executed actions, approvals "
            "and API calls, with secrets redacted. Filter by `event` (e.g. 'action_executed', "
            "'policy_decision', 'approval_approved') or by `run_id`. Use this to answer 'who "
            "authorised this and when?'."
        ),
    )
    async def read_audit_log(n: int = 50, event: str = "", run_id: str = "") -> str:
        entries = get_orchestrator().audit.tail(
            n, event=event or None, run_id=run_id or None
        )
        return _json({"count": len(entries), "entries": entries})

    @server.tool(
        name="list_workflows",
        description=(
            "Describe every available workflow: its key, summary, when to use it, which "
            "platforms it touches and the options it accepts with their defaults. Call this "
            "if you are unsure which workflow fits a request or what an option does."
        ),
    )
    async def list_workflows() -> str:
        orch = get_orchestrator()
        return _json({"workflows": orch.workflows.describe_all()})


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _employee_from_dict(data: dict[str, Any]) -> Employee:
    """Build an Employee from a loosely-typed dict supplied by the model.

    Claude will send whatever the user gave it, in whatever shape. This tolerates
    common aliases (``name`` for first/last, ``manager_email``, ``skus`` for
    ``licenses``) instead of erroring on a naming mismatch.
    """
    data = dict(data or {})

    # "full name" -> first/last
    if "name" in data and "first_name" not in data:
        parts = str(data.pop("name")).split(" ", 1)
        data["first_name"] = parts[0]
        data["last_name"] = parts[1] if len(parts) > 1 else ""
    if "fullName" in data and "first_name" not in data:
        parts = str(data.pop("fullName")).split(" ", 1)
        data["first_name"] = parts[0]
        data["last_name"] = parts[1] if len(parts) > 1 else ""

    aliases = {
        "firstname": "first_name", "givenname": "first_name", "given_name": "first_name",
        "lastname": "last_name", "surname": "last_name", "familyname": "last_name",
        "fullname": "display_name", "displayname": "display_name",
        "mail": "email", "upn": "upn", "userprincipalname": "upn",
        "employeeid": "employee_id", "workerid": "worker_id", "id": "employee_id",
        "title": "job_title", "jobtitle": "job_title", "position": "job_title",
        "dept": "department", "unit": "department",
        "location": "office_location", "office": "office_location", "city": "office_location",
        "phone": "mobile_phone", "mobile": "mobile_phone", "mobilephone": "mobile_phone",
        "startdate": "hire_date", "hiredate": "hire_date", "start_date": "hire_date",
        "enddate": "leave_date", "leavedate": "leave_date", "lastday": "leave_date",
        "last_working_day": "leave_date", "termination_date": "leave_date",
        "type": "employment_type", "employmenttype": "employment_type",
        "skus": "license_skus", "licenses": "license_skus",
        "state": "lifecycle_state", "status": "lifecycle_state",
        "samaccountname": "username", "sam": "username", "login": "username",
    }
    normalised: dict[str, Any] = {}
    for key, value in data.items():
        normalised[aliases.get(key.lower().replace("_", ""), key)] = value

    # manager may arrive as a plain string
    manager_raw = normalised.pop("manager", None) or normalised.pop("manager_email", None)
    if isinstance(manager_raw, str) and manager_raw:
        normalised["manager"] = Manager(
            email=manager_raw if "@" in manager_raw else "",
            display_name=manager_raw if "@" not in manager_raw else "",
        )
    elif isinstance(manager_raw, dict):
        normalised["manager"] = Manager.model_validate(manager_raw)

    for key in ("hire_date", "leave_date"):
        normalised[key] = _date(normalised.get(key))

    if normalised.get("employment_type"):
        try:
            normalised["employment_type"] = EmploymentType(str(normalised["employment_type"]).lower())
        except ValueError:
            normalised.pop("employment_type")

    if normalised.get("lifecycle_state"):
        try:
            normalised["lifecycle_state"] = LifecycleState(str(normalised["lifecycle_state"]).lower())
        except ValueError:
            normalised.pop("lifecycle_state")

    normalised.setdefault("first_name", "")
    normalised.setdefault("last_name", "")

    # Drop anything the model invented that Employee does not accept.
    allowed = set(Employee.model_fields)
    unknown = {k: v for k, v in normalised.items() if k not in allowed}
    clean = {k: v for k, v in normalised.items() if k in allowed}
    employee = Employee.model_validate(clean)
    if unknown:
        employee.attributes.update({"ignored_fields": sorted(unknown)})
    return employee


def _run_payload(run: Any, orch: Orchestrator) -> dict[str, Any]:
    """Consistent response shape for every gated write tool."""
    assert run.plan is not None
    pending = orch.approvals.list(status="pending", run_id=run.id)
    payload: dict[str, Any] = {
        "run_id": run.id,
        "workflow": run.workflow,
        "subject": run.subject,
        "status": run.status.value,
        "progress": run.plan.progress(),
        "max_risk": run.plan.max_risk.value,
        "assumptions": run.plan.assumptions,
        "warnings": run.plan.warnings,
        "plan": {
            "steps": [
                {**s.summary(), "actions": [
                    {**a, "result": _result_for(run, a)} for a in s.summary()["actions"]
                ]}
                for s in run.plan.steps
            ],
        },
        "markdown": run.plan.to_markdown(),
    }
    if pending:
        payload["awaiting_approval"] = [
            {
                "approval_id": a.id,
                "title": a.title,
                "risk": a.risk.value,
                "required_approvals": a.required_approvals,
                "approvals_so_far": len(a.approvals),
                "expires_at": a.expires_at.isoformat() if a.expires_at else None,
                "action_count": len(a.action_ids),
            }
            for a in pending
        ]
        payload["next_step"] = (
            f"Call show_approval with approval_id '{pending[0].id}' to present this to the "
            "user, then decide_approval once they have authorised it. Do NOT retry the "
            "workflow tool - that would create a duplicate run."
        )
    elif run.status.value == "completed":
        payload["next_step"] = "The run completed. Use get_run for the full record."
    elif run.status.value == "failed":
        payload["next_step"] = "The run failed. Inspect the per-action errors below and report them honestly."
    return payload


def _result_for(run: Any, action_summary: dict[str, Any]) -> dict[str, Any]:
    for act in run.plan.all_actions:
        if act.id == action_summary.get("id"):
            return act.result or {}
    return {}


#: MCPServer.run() dispatches on a Literal, so an arbitrary string from the
#: environment would not match any overload - and a typo would surface as an
#: opaque error from inside the library rather than at the boundary.
_MCP_TRANSPORTS = ("stdio", "sse", "streamable-http")


def main() -> None:
    """stdio entrypoint for Claude Desktop / Claude Code."""
    requested = os.environ.get("IAM_MCP_TRANSPORT", "stdio")
    if requested not in _MCP_TRANSPORTS:
        raise SystemExit(
            f"IAM_MCP_TRANSPORT={requested!r} is not one of {', '.join(_MCP_TRANSPORTS)}"
        )
    server = build_server()
    server.run(transport=cast(Literal["stdio", "sse", "streamable-http"], requested))


if __name__ == "__main__":
    main()
