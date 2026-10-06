"""FastAPI control plane.

Three kinds of consumer:

* **A dashboard or script** driving onboarding/offboarding over HTTP.
* **Webhooks** from Scalefusion (device enrolled/unenrolled) and from an HR
  system (joiner/leaver events) so lifecycle changes start without a human.
* **The approval UI.** ``GET /approvals`` + ``POST /approvals/{id}/decision`` is
  all a minimal approver front-end needs; ``GET /approvals/{id}/review`` returns
  a ready-to-render Markdown document.

Auth is a shared bearer token when ``IAM_API_API_TOKEN`` is set. Read endpoints
are open in development so the whole thing is explorable, but the token is
required for anything that writes once configured.
"""

from __future__ import annotations

import hmac
import json
from contextlib import asynccontextmanager
from datetime import date
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from iam_agent import __version__
from iam_agent.config import Settings, get_settings
from iam_agent.core.errors import IAMAgentError
from iam_agent.core.models import LifecycleState, Manager
from iam_agent.core.orchestrator import Orchestrator
_orchestrator: Orchestrator | None = None


def get_orch() -> Orchestrator:
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = Orchestrator(get_settings())
    return _orchestrator


def set_orchestrator(orch: Orchestrator | None) -> None:
    """Override the singleton - used by tests."""
    global _orchestrator
    _orchestrator = orch


# --------------------------------------------------------------------------- #
# Request / response schemas
# --------------------------------------------------------------------------- #


class EmployeeIn(BaseModel):
    """Deliberately permissive: the same shape Claude sends over MCP."""

    model_config = {"extra": "allow"}

    employee_id: str = ""
    first_name: str = ""
    last_name: str = ""
    display_name: str = ""
    email: str = ""
    upn: str = ""
    username: str = ""
    department: str = ""
    job_title: str = ""
    company: str = ""
    office_location: str = ""
    country: str = "ES"
    mobile_phone: str = ""
    hire_date: date | None = None
    leave_date: date | None = None
    employment_type: str = "full_time"
    lifecycle_state: str = "pre_hire"
    manager_email: str = ""
    license_skus: list[str] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    teams: list[str] = Field(default_factory=list)
    termination_reason: str = ""


class WorkflowRequest(BaseModel):
    employee: EmployeeIn
    options: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    requested_by: str = "api"
    execute: bool = True


class DecisionRequest(BaseModel):
    approve: bool
    decided_by: str
    comment: str = ""


class AdhocRequest(BaseModel):
    """A targeted operation outside any named playbook."""

    operation: str = Field(description="'<platform>.<method>', e.g. 'entra.disable_user'")
    params: dict[str, Any] = Field(default_factory=dict)
    target: str = ""
    description: str = ""
    subject: str = ""
    reason: str = ""
    requested_by: str = "api"
    reversible: bool = True
    execute: bool = True


class HRWebhookEvent(BaseModel):
    """Joiner/mover/leaver event from an HR system or identity governance feed."""

    event_type: Literal["joiner", "mover", "leaver"]
    employee: EmployeeIn
    reason: str = ""
    requested_by: str = "hr-webhook"
    options: dict[str, Any] = Field(default_factory=dict)
    execute: bool = True


# --------------------------------------------------------------------------- #
# Auth dependency
# --------------------------------------------------------------------------- #


def _settings_of(request: Request) -> Settings:
    """Settings the app was actually built with.

    Not ``get_settings()``: that is an lru_cached process global, so a
    dependency reading it would silently authenticate against *default* settings
    while the app runs with a token configured. That mismatch means the token is
    never enforced - a real bypass, not a cosmetic one.
    """
    return request.app.state.settings


async def require_token(
    request: Request,
    authorization: str | None = Header(default=None),
) -> str:
    """Enforce the shared bearer token when one is configured."""
    expected = _settings_of(request).api.api_token
    if not expected:
        return "anonymous"
    if not authorization:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing Authorization header")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(token.strip(), expected):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "invalid API token")
    return "bearer"


# --------------------------------------------------------------------------- #
# App
# --------------------------------------------------------------------------- #


@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.settings = getattr(app.state, "settings", None) or get_settings()
    orch = get_orch()
    # Expire stale approvals on boot so a restart cannot resurrect a timed-out gate.
    expired = orch.approvals.expire_stale()
    if expired:
        orch.audit.workflow_event("startup_expired_approvals", ids=expired)
    yield
    await orch.aclose()


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or get_settings()
    app = FastAPI(
        title="IAM Agent",
        version=__version__,
        description=(
            "Identity and endpoint lifecycle automation across Microsoft Entra ID, "
            "Microsoft 365, on-premises Active Directory, Action1 RMM and Scalefusion MDM."
        ),
        lifespan=lifespan,
    )
    app.state.settings = cfg
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.api.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.exception_handler(IAMAgentError)
    async def _iam_errors(_request: Request, exc: IAMAgentError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=exc.to_dict())

    _register_routes(app)
    return app


def _register_routes(app: FastAPI) -> None:  # noqa: C901
    # ------------------------------------------------------------------ #
    # Health & posture
    # ------------------------------------------------------------------ #

    @app.get("/health", tags=["system"])
    async def health() -> dict[str, Any]:
        orch = get_orch()
        orch = get_orch()
        report = await orch.hub.health_report()
        return {
            "status": "ok" if report["healthy"] else "degraded",
            "version": __version__,
            "mode": orch.settings.effective_mode(),
            "enabled": orch.hub.enabled_platforms(),
            "healthy": report["healthy"],
            "platforms": report["connectors"],
        }

    @app.get("/status", tags=["system"])
    async def status_endpoint() -> dict[str, Any]:
        return await get_orch().status()

    @app.get("/preflight", tags=["system"])
    async def preflight() -> dict[str, Any]:
        return await get_orch().preflight()

    @app.get("/workflows", tags=["system"])
    async def workflows() -> dict[str, Any]:
        return {"workflows": get_orch().workflows.describe_all()}

    # ------------------------------------------------------------------ #
    # Identity
    # ------------------------------------------------------------------ #

    @app.get("/people/search", tags=["identity"])
    async def search_people(q: str, limit: int = 25) -> dict[str, Any]:
        return {"results": await get_orch().find_people(q, limit=limit)}

    @app.get("/people/{identifier}/identity", tags=["identity"])
    async def identity(identifier: str) -> dict[str, Any]:
        snapshot = await get_orch().get_identity(identifier)
        return {
            "summary": snapshot.summary(),
            "employee": snapshot.employee.model_dump(mode="json", exclude_none=True),
            "devices": [d.model_dump(mode="json", exclude={"raw"}) for d in snapshot.devices],
            "mailboxes": [m.model_dump(mode="json") for m in snapshot.mailboxes],
            "groups": {
                platform: [g.model_dump(mode="json", exclude={"raw"}) for g in groups]
                for platform, groups in snapshot.group_memberships.items()
            },
            "warnings": snapshot.warnings,
        }

    @app.get("/people/{identifier}/access", tags=["identity"])
    async def access(identifier: str) -> dict[str, Any]:
        orch = get_orch()
        snapshot = await orch.get_identity(identifier)
        entra = snapshot.entra
        roles = await orch.hub.entra.get_user_roles(entra.external_id) if entra else []
        teams = (
            [t.get("displayName") for t in await orch.hub.m365.find_user_teams(entra.external_id)]
            if entra
            else []
        )
        return {
            "identifier": identifier,
            "entra_groups": [g.display_name for g in snapshot.group_memberships.get("entra", [])],
            "on_prem_groups": [
                g.display_name for g in snapshot.group_memberships.get("active_directory", [])
            ],
            "teams": teams,
            "directory_roles": roles,
            "licences": entra.license_skus if entra else [],
            "mfa_registered": entra.mfa_registered if entra else None,
            "enabled": {"entra": entra.enabled if entra else None,
                        "on_prem": snapshot.on_prem.enabled if snapshot.on_prem else None},
        }

    @app.get("/people/{identifier}/drift", tags=["identity"])
    async def drift(identifier: str) -> dict[str, Any]:
        snapshot, findings = await get_orch().reconciler.detect_drift_for(identifier)
        return {
            "identity": snapshot.summary(),
            "findings": [f.model_dump(mode="json") for f in findings],
        }

    @app.get("/audit/drift", tags=["identity"])
    async def estate_drift(limit: int = 200) -> dict[str, Any]:
        report = await get_orch().audit_estate(limit=limit)
        return {
            "generated_at": report.generated_at.isoformat(),
            "is_clean": report.is_clean,
            "counts": {sev: len(items) for sev, items in report.by_severity().items()},
            "findings": [f.model_dump(mode="json") for f in report.findings],
        }

    # ------------------------------------------------------------------ #
    # Devices & directories
    # ------------------------------------------------------------------ #

    @app.get("/devices", tags=["devices"])
    async def devices(
        console: Literal["all", "action1", "scalefusion"] = "all",
        owner: str = "",
        state: str = "",
        ownership: str = "",
        limit: int = 200,
    ) -> dict[str, Any]:
        orch = get_orch()
        found = []
        if console in ("all", "action1"):
            found += (
                await orch.hub.action1.find_endpoints_by_owner(owner)
                if owner
                else await orch.hub.action1.list_endpoints()
            )
        if console in ("all", "scalefusion"):
            found += (
                await orch.hub.scalefusion.find_devices_by_user(owner)
                if owner
                else await orch.hub.scalefusion.list_devices()
            )
        if state:
            found = [d for d in found if d.state.value == state]
        if ownership:
            found = [d for d in found if d.ownership.value == ownership]
        return {
            "count": len(found[:limit]),
            "devices": [d.model_dump(mode="json", exclude={"raw"}) for d in found[:limit]],
        }

    @app.get("/groups", tags=["directory"])
    async def groups(
        platform: Literal["entra", "active_directory", "m365_teams", "all"] = "entra",
    ) -> dict[str, Any]:
        orch = get_orch()
        out: dict[str, Any] = {}
        if platform in ("all", "entra"):
            out["entra"] = [
                g.model_dump(mode="json", exclude={"raw"}) for g in await orch.hub.entra.list_groups()
            ]
        if platform in ("all", "active_directory"):
            out["active_directory"] = [
                g.model_dump(mode="json", exclude={"raw"})
                for g in await orch.hub.active_directory.list_groups()
            ]
        if platform in ("all", "m365_teams"):
            out["teams"] = await orch.hub.m365.list_teams()
        return out

    @app.get("/licences", tags=["directory"])
    async def licences() -> dict[str, Any]:
        return {"skus": await get_orch().hub.m365.list_skus()}

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    @app.post("/workflows/{workflow}/plan", tags=["lifecycle"])
    async def plan_workflow(workflow: str, body: WorkflowRequest) -> dict[str, Any]:
        run, _ctx = await get_orch().build_plan(
            workflow,
            _employee_from_request(body.employee),
            options=body.options,
            requested_by=body.requested_by,
            reason=body.reason,
        )
        assert run.plan is not None
        return {
            "run_id": run.id,
            "executed": False,
            "markdown": run.plan.to_markdown(),
            "max_risk": run.plan.max_risk.value,
            "needs_approval": run.plan.needs_approval(),
            "approval_gates": sum(1 for st in run.plan.steps if st.requires_approval),
            "steps": [st.summary() for st in run.plan.steps],
            "assumptions": run.plan.assumptions,
            "warnings": run.plan.warnings,
        }

    @app.post("/workflows/{workflow}/run", tags=["lifecycle"])
    async def run_workflow(workflow: str, body: WorkflowRequest) -> dict[str, Any]:
        orch = get_orch()
        employee = _employee_from_request(body.employee)

        # Offboarding and transfer reason from live state, not from the request body.
        if workflow in ("offboarding", "transfer"):
            needle = employee.email or employee.upn or employee.username or employee.employee_id
            if needle:
                try:
                    snapshot = await orch.reconciler.snapshot(needle)
                    if snapshot.directories:
                        merged = snapshot.employee
                        for field_name in (
                            "leave_date", "termination_reason", "department", "job_title"
                        ):
                            value = getattr(employee, field_name, None)
                            if value:
                                setattr(merged, field_name, value)
                        if employee.manager and employee.manager.email and not merged.manager:
                            merged.manager = employee.manager
                        employee = merged
                except IAMAgentError:
                    pass
            if workflow == "offboarding":
                employee.lifecycle_state = LifecycleState.LEAVER

        run = await orch.run_workflow(
            workflow,
            employee,
            options=body.options,
            requested_by=body.requested_by,
            reason=body.reason,
            execute=body.execute,
        )
        return _run_response(run)

    @app.post("/actions/adhoc", tags=["lifecycle"])
    async def adhoc(body: AdhocRequest) -> dict[str, Any]:
        orch = get_orch()
        action = orch.build_action(
            body.operation,
            description=body.description,
            target=body.target,
            reversible=body.reversible,
            **body.params,
        )
        run = await orch.run_adhoc(
            [action],
            subject=body.subject or body.target or body.operation,
            requested_by=body.requested_by,
            reason=body.reason,
            execute=body.execute,
        )
        return _run_response(run)

    # ------------------------------------------------------------------ #
    # Runs
    # ------------------------------------------------------------------ #

    @app.get("/runs", tags=["runs"])
    async def list_runs(workflow: str = "", limit: int = 50) -> dict[str, Any]:
        runs = get_orch().list_runs(workflow=workflow or None, limit=limit)
        return {"count": len(runs), "runs": [r.summary() for r in runs]}

    @app.get("/runs/{run_id}", tags=["runs"])
    async def get_run(run_id: str) -> dict[str, Any]:
        return get_orch().run_detail(run_id)

    @app.get("/runs/{run_id}/markdown", tags=["runs"], response_class=PlainTextResponse)
    async def run_markdown(run_id: str) -> str:
        run = get_orch().get_run(run_id)
        if run.plan is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "run has no plan")
        return run.plan.to_markdown()

    @app.post("/runs/{run_id}/resume", tags=["runs"])
    async def resume_run(run_id: str, approver: str = "api") -> dict[str, Any]:
        return _run_response(await get_orch().resume_run(run_id, approver=approver))

    @app.post("/runs/{run_id}/cancel", tags=["runs"])
    async def cancel_run(run_id: str, reason: str = "") -> dict[str, Any]:
        return get_orch().cancel_run(run_id, reason).model_dump(mode="json", exclude={"plan"})

    @app.post("/runs/{run_id}/rollback", tags=["runs"])
    async def rollback_run(run_id: str) -> dict[str, Any]:
        return await get_orch().rollback_run(run_id)

    # ------------------------------------------------------------------ #
    # Approvals
    # ------------------------------------------------------------------ #

    @app.get("/approvals", tags=["approvals"])
    async def list_approvals(
        approval_status: Literal["pending", "approved", "rejected", "expired", "all"] = "pending",
    ) -> dict[str, Any]:
        orch = get_orch()
        requested = None if approval_status == "all" else approval_status
        items = orch.list_approvals(status=requested)
        return {
            "count": len(items),
            "approvals": [
                {
                    "approval_id": a.id,
                    "run_id": a.run_id,
                    "workflow": a.workflow,
                    "title": a.title,
                    "subject": a.subject,
                    "risk": a.risk.value,
                    "reversible": a.reversible,
                    "status": a.effective_status(),
                    "required_approvals": a.required_approvals,
                    "approvals_recorded": len(a.approvals),
                    "action_count": len(a.action_ids),
                    "requested_at": a.requested_at.isoformat(),
                    "expires_at": a.expires_at.isoformat() if a.expires_at else None,
                }
                for a in items
            ],
        }

    @app.get("/approvals/{approval_id}", tags=["approvals"])
    async def get_approval(approval_id: str) -> dict[str, Any]:
        request = get_orch().get_approval(approval_id)
        return request.model_dump(mode="json")

    @app.get("/approvals/{approval_id}/review", tags=["approvals"], response_class=PlainTextResponse)
    async def approval_review(approval_id: str) -> str:
        return get_orch().get_approval(approval_id).to_review_markdown()

    @app.post("/approvals/{approval_id}/decision", tags=["approvals"])
    async def decide(approval_id: str, body: DecisionRequest, _token: str = Depends(require_token)) -> dict[str, Any]:
        if body.decided_by.strip().lower() in ("", "api", "system", "claude", "agent"):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "decided_by must identify a real human; it is written to the immutable audit log.",
            )
        try:
            return await get_orch().decide_approval(
                approval_id,
                approve=body.approve,
                decided_by=body.decided_by.strip(),
                comment=body.comment,
            )
        except ValueError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc

    # ------------------------------------------------------------------ #
    # Audit
    # ------------------------------------------------------------------ #

    @app.get("/audit", tags=["audit"])
    async def audit_log(n: int = 100, event: str = "", run_id: str = "") -> dict[str, Any]:
        orch = get_orch()
        return {
            "count": n,
            "totals": orch.audit.stats(),
            "entries": orch.audit.tail(n, event=event or None, run_id=run_id or None),
        }

    # ------------------------------------------------------------------ #
    # Webhooks
    # ------------------------------------------------------------------ #

    @app.post("/webhooks/hr", tags=["webhooks"])
    async def hr_webhook(
        request: Request, body: HRWebhookEvent, x_hub_signature: str | None = Header(default=None)
    ) -> dict[str, Any]:
        """Joiner/mover/leaver events from an HR system.

        Signed with HMAC-SHA256 over the raw body when
        ``IAM_API_HR_WEBHOOK_SECRET`` is configured; unsigned requests are
        rejected in that case, because an unauthenticated leaver event is a
        denial-of-service vector against your own staff.
        """
        settings = _settings_of(request)
        secret = settings.api.hr_webhook_secret
        if secret:
            raw = await request.body()
            expected = hmac.new(secret.encode(), raw, "sha256").hexdigest()
            provided = (x_hub_signature or "").removeprefix("sha256=").strip()
            if not hmac.compare_digest(expected, provided):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid webhook signature")

        mapping = {"joiner": "onboarding", "mover": "transfer", "leaver": "offboarding"}
        workflow = mapping[body.event_type]
        orch = get_orch()
        employee = _employee_from_request(body.employee)
        if workflow == "offboarding":
            employee.lifecycle_state = LifecycleState.LEAVER
            if not employee.leave_date:
                employee.leave_date = date.today()

        run = await orch.run_workflow(
            workflow,
            employee,
            options=body.options,
            requested_by=body.requested_by,
            reason=body.reason or f"HR webhook: {body.event_type}",
            execute=body.execute,
        )
        return _run_response(run)

    @app.post("/webhooks/scalefusion", tags=["webhooks"])
    async def scalefusion_webhook(
        request: Request, x_scalefusion_signature: str | None = Header(default=None)
    ) -> dict[str, Any]:
        """Device lifecycle events (enrolled, unenrolled, lost, locked...).

        Scalefusion signs the body with the secret configured under
        *Integrations → Webhooks*. An ``device_enrolled`` event with a known
        owner can auto-start onboarding of that handset.
        """
        settings = _settings_of(request)
        secret = settings.api.scalefusion_webhook_secret
        raw = await request.body()
        if secret:
            expected = hmac.new(secret.encode(), raw, "sha256").hexdigest()
            if not hmac.compare_digest(expected, (x_scalefusion_signature or "").strip()):
                raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid webhook signature")

        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "body is not valid JSON") from None

        event = str(payload.get("event") or payload.get("event_type") or "").lower()
        device_id = str(payload.get("device_id") or payload.get("id") or "")
        owner = str(payload.get("user_email") or payload.get("email") or "")

        orch = get_orch()
        orch.audit.workflow_event(
            "scalefusion_webhook", event=event, device_id=device_id, owner=owner
        )

        result: dict[str, Any] = {"received": True, "event": event, "device_id": device_id, "owner": owner}

        if event in ("device_enrolled", "device_activated") and owner:
            # Bind a freshly enrolled handset to its owner and apply the standard profile.
            actions = [
                orch.build_action(
                    "scalefusion.assign_device_user",
                    description=f"Bind newly enrolled device to {owner}",
                    target=device_id,
                    device_id=device_id,
                    user_email=owner,
                    user_name="",
                )
            ]
            profile = settings.scalefusion.device_profile_id
            if profile:
                actions.append(
                    orch.build_action(
                        "scalefusion.apply_device_profile",
                        description=f"Apply the standard profile to {device_id}",
                        target=device_id,
                        profile_id=profile,
                        device_ids=[device_id],
                    )
                )
            run = await orch.run_adhoc(
                actions, subject=owner, requested_by="scalefusion-webhook",
                reason=f"auto-enrolment on '{event}'",
            )
            result["run_id"] = run.id
            result["run_status"] = run.status.value

        elif event == "device_lost" and device_id:
            run = await orch.run_adhoc(
                [
                    orch.build_action(
                        "scalefusion.lock_device",
                        description="Auto-lock a device reported lost",
                        target=device_id,
                        device_id=device_id,
                        message="This device has been reported lost. Please contact IT.",
                    )
                ],
                subject=device_id, requested_by="scalefusion-webhook", reason="device_lost event",
            )
            result["run_id"] = run.id
            result["run_status"] = run.status.value

        return result


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _employee_from_request(data: EmployeeIn):
    """Convert the API schema into a domain Employee, tolerating extra fields."""
    from iam_agent.core.models import Employee

    payload = data.model_dump(exclude_none=True)
    manager_email = payload.pop("manager_email", "")
    extras = {k: v for k, v in payload.items() if k not in Employee.model_fields}
    clean = {k: v for k, v in payload.items() if k in Employee.model_fields}
    if manager_email:
        clean["manager"] = Manager(email=manager_email)
    employee = Employee.model_validate(clean)
    if extras:
        employee.attributes.update(extras)
    return employee


def _run_response(run: Any) -> dict[str, Any]:
    assert run.plan is not None
    orch = get_orch()
    pending = orch.approvals.list(status="pending", run_id=run.id)
    payload = run.summary()
    payload.update(
        {
            "assumptions": run.plan.assumptions,
            "warnings": run.plan.warnings,
            "markdown": run.plan.to_markdown(),
            "steps": [st.summary() for st in run.plan.steps],
        }
    )
    if pending:
        payload["awaiting_approval"] = [
            {
                "approval_id": a.id,
                "title": a.title,
                "risk": a.risk.value,
                "required_approvals": a.required_approvals,
                "approvals_recorded": len(a.approvals),
                "expires_at": a.expires_at.isoformat() if a.expires_at else None,
                "review_url": f"/approvals/{a.id}/review",
            }
            for a in pending
        ]
    return payload


app = create_app()
