"""Onboarding playbook: from HR record to a fully provisioned, managed endpoint.

Ordering rationale
------------------
The sequence is not arbitrary. Each phase unlocks the next:

1. **preflight** — fail fast and cheap. If the UPN already exists, if no licence
   is available, or if a connector is unhealthy, we learn it before writing.
2. **entra_identity** — the Entra object is the anchor; its UPN is the join key
   every later phase resolves against.
3. **m365_licensing** — licences must be attached *before* the mailbox and
   OneDrive exist, otherwise the services never provision.
4. **groups_and_teams** — membership after licensing, so the user can actually
   open what they are added to.
5. **onprem_ad** — created *after* Entra when there is no sync, or only verified
   when Entra Connect owns the object (writing to a synced object in the cloud
   would be reverted within 30 minutes).
6. **authentication** — a Temporary Access Pass is issued only once the account
   exists and has something to access.
7. **endpoint_provisioning** — Action1 prepares the PC: joiner group, baseline
   automation, patch compliance.
8. **mobile_enrollment** — Scalefusion binds the phone to the identity and
   applies the department profile.
9. **verification** — reconcile across all five platforms and report what is
   genuinely true, not what we intended.

Phases 2-8 depend on phase 1 succeeding; 7 and 8 depend on 2. Everything that
mutates state is gated by the policy engine according to the active mode.
"""

from __future__ import annotations

from datetime import UTC
from typing import Any, ClassVar

from iam_agent.config import Settings
from iam_agent.connectors import ConnectorHub
from iam_agent.core.models import Device, Employee, EmploymentType
from iam_agent.core.reconcile import Reconciler
from iam_agent.core.result import ExecutionPlan, RiskLevel
from iam_agent.workflows.base import Workflow, WorkflowContext, action, step


class OnboardingWorkflow(Workflow):
    key = "onboarding"
    summary = "Provision a new hire across Entra ID, M365, on-prem AD, Action1 and Scalefusion."
    guidance = (
        "Use for a new employee, contractor or intern starting work. Requires at minimum a first "
        "name, last name and either an email address or a department. Optionally accepts hire_date, "
        "job_title, manager email, license SKUs, group names, and device serial numbers/asset tags. "
        "The workflow creates the identity, assigns licences, grants group and Teams membership, "
        "creates or verifies the on-premises account, issues a Temporary Access Pass, prepares the "
        "PC in Action1 and binds the mobile device in Scalefusion. It is idempotent: re-running it "
        "for someone already provisioned will skip what exists and only fill the gaps."
    )
    platforms = ("entra", "m365", "active_directory", "action1", "scalefusion")
    options_schema: ClassVar[dict[str, Any]] = {
        "password": "Initial password. Generated when omitted (never logged).",
        "licenses": "List of SKU part numbers, e.g. ['ENTERPRISEPACK']. Defaults to config.",
        "groups": "Extra Entra group names to add beyond the department defaults.",
        "teams": "Team names to join.",
        "device_serials": "Serial numbers / asset tags of devices to bind.",
        "create_on_prem_account": "Force-create in AD even if Entra Connect syncs (default False).",
        "issue_tap": "Issue a Temporary Access Pass (default True).",
        "tap_lifetime_minutes": "TAP validity, default 480.",
        "run_endpoint_automation": "Launch the Action1 onboarding automation (default True).",
        "skip_mobile": "Skip the Scalefusion phase (default False).",
        "skip_endpoint": "Skip the Action1 phase (default False).",
        "contractor_expiry": "Set an AD account expiry date for contractors (default True).",
    }

    def __init__(self, hub: ConnectorHub, settings: Settings) -> None:
        super().__init__(hub, settings)
        self.reconciler = Reconciler(hub, settings)

    # ------------------------------------------------------------------ #

    async def plan(self, ctx: WorkflowContext) -> ExecutionPlan:
        employee = ctx.employee

        # Resolve the UPN domain: explicit config > the employee's own email
        # domain > the tenant's default verified domain. Without this a hire
        # supplied by HR as just a name would get an empty UPN and every later
        # step would target "n/a".
        domain = self.settings.entra.primary_domain or _domain_of(employee.email)
        if not domain:
            try:
                domain = await self.hub.entra.get_default_domain()
            except Exception:
                domain = ""
            if domain:
                ctx.assume(f"No domain configured; inferred the tenant default '{domain}' for the UPN.")
        if not domain:
            ctx.note(
                "could not determine a UPN domain - set IAM_ENTRA_PRIMARY_DOMAIN or supply the "
                "employee's email address"
            )

        upn = employee.suggested_upn(domain)
        if not employee.email:
            employee.email = upn
        username = employee.suggested_username(domain)
        if not employee.username:
            employee.username = username
        password = ctx.opt("password") or _generate_password()

        plan = self.new_plan(ctx)

        # Resolve the department defaults once, up front.
        department = (employee.department or "").strip()
        licence_skus = (
            ctx.opt("licenses")
            or employee.license_skus
            or self.settings.m365.default_license_skus
            or _default_licenses_for(department)
        )
        group_names = list(dict.fromkeys(_default_groups_for(department) + list(ctx.opt("groups") or [])))
        team_names = list(dict.fromkeys(_default_teams_for(department) + list(ctx.opt("teams") or [])))

        if not employee.first_name or not employee.last_name:
            ctx.note("first_name and last_name are required for a proper displayName")
        if employee.employment_type == EmploymentType.CONTRACTOR and not employee.leave_date:
            ctx.assume("Contractor without a leave date: no account expiry will be set.")

        # Devices discovered in the snapshot, plus any explicitly requested.
        known_devices = list(ctx.snapshot.devices) if ctx.snapshot else []
        requested_serials = [s.lower() for s in (ctx.opt("device_serials") or [])]
        for assignment in employee.devices:
            for value in (assignment.serial_number, assignment.asset_tag, assignment.device_name):
                if value:
                    requested_serials.append(value.lower())

        # ---------------------------------------------------------------- #
        # 1. Preflight (read-only)
        # ---------------------------------------------------------------- #
        preflight_actions = [
            action(
                "entra.get_user", "entra", self.hub.entra.get_user,
                description=f"Check whether {upn} already exists in Entra",
                target=upn, risk=RiskLevel.LOW,
                identifier=upn,
            ),
            action(
                "active_directory.get_user", "active_directory", self.hub.active_directory.get_user,
                description=f"Check whether {username} already exists on-premises",
                target=username, risk=RiskLevel.LOW,
                identifier=username,
            ),
            action(
                "m365.list_skus", "m365", self.hub.m365.list_skus,
                description="Confirm licence availability before assigning",
                target="tenant", risk=RiskLevel.LOW,
            ),
            action(
                "entra.list_groups", "entra", self.hub.entra.list_groups,
                description="Resolve the department groups that will be granted",
                target=department or "tenant", risk=RiskLevel.LOW,
            ),
        ]
        if not ctx.flag("skip_endpoint"):
            preflight_actions.append(
                action(
                    "action1.list_endpoints", "action1", self.hub.action1.list_endpoints,
                    description="Inventory Action1 endpoints reachable for this hire",
                    target="fleet", risk=RiskLevel.LOW,
                )
            )
        if not ctx.flag("skip_mobile"):
            preflight_actions.append(
                action(
                    "scalefusion.list_devices", "scalefusion", self.hub.scalefusion.list_devices,
                    description="Inventory Scalefusion devices reachable for this hire",
                    target="fleet", risk=RiskLevel.LOW,
                )
            )

        plan.add(
            step(
                1, "preflight", "all", *preflight_actions,
                description="Verify identity is new, licences are available and every connector is reachable.",
                continue_on_error=True,
            )
        )

        # ---------------------------------------------------------------- #
        # 2. Entra identity
        # ---------------------------------------------------------------- #
        # The reporting line may arrive as an Entra object id (from an HR feed) or
        # just as an email (from a human typing it into Claude). Resolve both.
        manager_id = (employee.manager.entra_id if employee.manager else "") or ""
        if not manager_id and employee.manager and employee.manager.email:
            try:
                manager_user = await self.hub.entra.get_user(employee.manager.email)
                if manager_user:
                    manager_id = manager_user.external_id
                    employee.manager.entra_id = manager_id
                    if not employee.manager.display_name:
                        employee.manager.display_name = manager_user.display_name
                else:
                    ctx.note(
                        f"manager '{employee.manager.email}' does not exist in Entra; "
                        "the reporting line will be left unset"
                    )
            except Exception as exc:
                ctx.note(f"could not resolve manager '{employee.manager.email}': {exc}")
        create_actions = [
            action(
                "entra.create_user", "entra", self.hub.entra.create_user,
                description=f"Create the Entra ID user object for {employee.full_name}",
                target=upn, risk=RiskLevel.MEDIUM, reversible=False,
                idempotency_key=f"entra.create_user:{upn}",
                employee=employee, password=password,
            ),
            action(
                "entra.update_user", "entra", self.hub.entra.update_user,
                description="Stamp HR attributes (hire date, employee type, location, usage location)",
                target=upn, risk=RiskLevel.LOW,
                user_id=upn,
                attributes=_hr_attributes(employee, ctx),
            ),
        ]
        if manager_id:
            create_actions.append(
                action(
                    "entra.set_manager", "entra", self.hub.entra.set_manager,
                    description="Wire the reporting line so approvals and notifications route correctly",
                    target=upn, risk=RiskLevel.LOW,
                    user_id=upn, manager_id=manager_id,
                )
            )
        else:
            ctx.note(f"no manager supplied for {employee.full_name}; reporting line left unset")

        plan.add(
            step(
                2, "entra_identity", "entra", *create_actions,
                description="Create and enrich the Entra ID user object - the anchor identity.",
                depends_on=["preflight"],
            )
        )

        # ---------------------------------------------------------------- #
        # 3. M365 licensing
        # ---------------------------------------------------------------- #
        if licence_skus:
            plan.add(
                step(
                    3, "m365_licensing", "m365",
                    action(
                        "entra.assign_license", "entra", self.hub.entra.assign_license,
                        description=f"Assign {', '.join(licence_skus)} so Exchange/Teams/OneDrive provision",
                        target=upn, risk=RiskLevel.MEDIUM,
                        user_id=upn, sku_part_numbers=list(licence_skus),
                        compensating=action(
                            "entra.remove_all_licenses", "entra", self.hub.entra.remove_all_licenses,
                            description="Rollback: remove licences", target=upn,
                            user_id=upn,
                        ),
                    ),
                    action(
                        "m365.get_mailbox", "m365", self.hub.m365.get_mailbox,
                        description="Verify the mailbox provisioned after licensing",
                        target=upn, risk=RiskLevel.LOW,
                        identifier=upn,
                    ),
                    description="Licences must be attached before services exist.",
                    depends_on=["entra_identity"],
                    continue_on_error=True,
                )
            )
        else:
            ctx.note("no licence SKUs resolved; mailbox, Teams and OneDrive will not provision")

        # ---------------------------------------------------------------- #
        # 4. Groups & Teams
        # ---------------------------------------------------------------- #
        membership_actions = [
            action(
                "entra.add_group_member", "entra", self.hub.entra.add_group_member,
                description=f"Add to Entra group '{name}'",
                target=f"{upn} -> {name}", risk=RiskLevel.MEDIUM,
                group_id=name, user_id=upn,
                compensating=action(
                    "entra.remove_group_member", "entra", self.hub.entra.remove_group_member,
                    description=f"Rollback: remove from {name}", target=f"{upn} -> {name}",
                    group_id=name, user_id=upn,
                ),
            )
            for name in group_names
        ]
        membership_actions += [
            action(
                "m365.add_team_member", "m365", self.hub.m365.add_team_member,
                description=f"Add to Microsoft Team '{name}'",
                target=f"{upn} -> {name}", risk=RiskLevel.MEDIUM,
                team_id=name, user_id=upn,
            )
            for name in team_names
        ]
        if membership_actions:
            plan.add(
                step(
                    4, "groups_and_teams", "entra+m365", *membership_actions,
                    description="Grant the department baseline access.",
                    depends_on=["entra_identity"],
                    continue_on_error=True,
                )
            )

        # ---------------------------------------------------------------- #
        # 5. On-premises Active Directory
        # ---------------------------------------------------------------- #
        synced = bool(ctx.snapshot and ctx.snapshot.entra and ctx.snapshot.entra.on_premises_sync)
        force_create = ctx.flag("create_on_prem_account")

        if synced and not force_create:
            ctx.assume(
                "Entra reports this object as sync-managed; the on-premises account is expected to "
                "appear via Entra Connect. AD creation is skipped to avoid a conflicting object."
            )
            ad_actions = [
                action(
                    "active_directory.get_user", "active_directory", self.hub.active_directory.get_user,
                    description="Verify the synced account has landed on-premises",
                    target=username, risk=RiskLevel.LOW, identifier=username,
                )
            ]
        else:
            ad_actions = [
                action(
                    "active_directory.create_user", "active_directory", self.hub.active_directory.create_user,
                    description=f"Create the on-premises AD account in {self.hub.active_directory.users_container}",
                    target=username, risk=RiskLevel.MEDIUM, reversible=False,
                    employee=employee, password=password,
                ),
                action(
                    "active_directory.set_password", "active_directory", self.hub.active_directory.set_password,
                    description="Set the initial password over LDAPS and force a change at first logon",
                    target=username, risk=RiskLevel.HIGH,
                    identifier=username, password=password, must_change=True,
                ),
            ]
            for name in group_names:
                ad_actions.append(
                    action(
                        "active_directory.add_group_member", "active_directory",
                        self.hub.active_directory.add_group_member,
                        description=f"Add to on-prem group '{name}'",
                        target=f"{username} -> {name}", risk=RiskLevel.MEDIUM,
                        group_dn=name, member_dn=username,
                    )
                )
            if employee.employment_type in (
                EmploymentType.CONTRACTOR, EmploymentType.INTERN
            ) and employee.leave_date and ctx.flag("contractor_expiry", True):
                from datetime import datetime, time

                expiry = datetime.combine(employee.leave_date, time(23, 59), tzinfo=UTC)
                ad_actions.append(
                    action(
                        "active_directory.set_account_expiry", "active_directory",
                        self.hub.active_directory.set_account_expiry,
                        description=f"Expire the account on {employee.leave_date.isoformat()} "
                        f"({employee.employment_type.value})",
                        target=username, risk=RiskLevel.MEDIUM,
                        identifier=username, expires_at=expiry,
                    )
                )

        plan.add(
            step(
                5, "onprem_ad", "active_directory", *ad_actions,
                description="Create or verify the on-premises account (LDAPS required for password writes).",
                depends_on=["entra_identity"],
                continue_on_error=True,
            )
        )

        # ---------------------------------------------------------------- #
        # 6. Authentication / MFA bootstrap
        # ---------------------------------------------------------------- #
        if ctx.flag("issue_tap", True) and employee.require_mfa_registration:
            plan.add(
                step(
                    6, "authentication", "entra",
                    action(
                        "entra.create_temporary_access_pass", "entra",
                        self.hub.entra.create_temporary_access_pass,
                        description="Issue a one-time Temporary Access Pass so the user can register MFA",
                        target=upn, risk=RiskLevel.MEDIUM,
                        user_id=upn,
                        lifetime_minutes=int(ctx.opt("tap_lifetime_minutes", 480)),
                        one_time=True,
                    ),
                    description="Bootstrap strong authentication before the first working day.",
                    depends_on=["entra_identity"],
                    continue_on_error=True,
                )
            )

        # ---------------------------------------------------------------- #
        # 7. Endpoint provisioning (Action1)
        # ---------------------------------------------------------------- #
        if not ctx.flag("skip_endpoint"):
            endpoint_devices = [d for d in known_devices if d.platform_console == "action1"]
            endpoint_devices += _match_devices_by_serial(known_devices, requested_serials, "action1")
            endpoint_ids = list(dict.fromkeys(d.external_id for d in endpoint_devices if d.external_id))

            endpoint_actions = []
            joiner_group = self.settings.action1.joiner_group_id or "New Joiners"
            if endpoint_ids:
                endpoint_actions.append(
                    action(
                        "action1.add_endpoints_to_group", "action1",
                        self.hub.action1.add_endpoints_to_group,
                        description=f"Add {len(endpoint_ids)} endpoint(s) to the '{joiner_group}' group",
                        target=", ".join(d.device_name for d in endpoint_devices) or "endpoints",
                        risk=RiskLevel.LOW,
                        group_id=joiner_group, endpoint_ids=endpoint_ids,
                    )
                )
            else:
                ctx.note(
                    "no Action1 endpoint matched this hire - the PC is either not yet agent-installed "
                    "or its serial was not supplied. Endpoint provisioning will be skipped."
                )

            automation = self.settings.action1.onboarding_automation_id
            if automation and endpoint_ids and ctx.flag("run_endpoint_automation", True):
                endpoint_actions.append(
                    action(
                        "action1.run_automation", "action1", self.hub.action1.run_automation,
                        description=f"Launch the '{automation}' automation to build the workstation",
                        target=", ".join(d.device_name for d in endpoint_devices),
                        risk=RiskLevel.HIGH,
                        automation_id=automation, endpoint_ids=endpoint_ids,
                    )
                )

            if endpoint_actions:
                plan.add(
                    step(
                        7, "endpoint_provisioning", "action1", *endpoint_actions,
                        description="Prepare the PC: joiner group, baseline build, patch compliance.",
                        depends_on=["entra_identity"],
                        continue_on_error=True,
                    )
                )

        # ---------------------------------------------------------------- #
        # 8. Mobile enrolment (Scalefusion)
        # ---------------------------------------------------------------- #
        if not ctx.flag("skip_mobile"):
            mobile_devices = [d for d in known_devices if d.platform_console == "scalefusion"]
            mobile_devices += _match_devices_by_serial(known_devices, requested_serials, "scalefusion")
            mobile_devices = _dedupe(mobile_devices)

            profile = (
                self.settings.scalefusion.device_profile_id
                or _default_profile_for(department, mobile_devices)
            )
            group = self.settings.scalefusion.device_group_id or "Corporativo-Móviles"

            mobile_actions = []
            for device in mobile_devices:
                if employee.email:
                    mobile_actions.append(
                        action(
                            "scalefusion.assign_device_user", "scalefusion",
                            self.hub.scalefusion.assign_device_user,
                            description=f"Bind {device.device_name} to {employee.email}",
                            target=device.device_name or device.external_id,
                            risk=RiskLevel.LOW,
                            device_id=device.external_id,
                            user_email=employee.email,
                            user_name=employee.full_name,
                        )
                    )
                if profile:
                    mobile_actions.append(
                        action(
                            "scalefusion.apply_device_profile", "scalefusion",
                            self.hub.scalefusion.apply_device_profile,
                            description=f"Apply profile '{profile}' to {device.device_name}",
                            target=device.device_name or device.external_id,
                            risk=RiskLevel.MEDIUM,
                            profile_id=profile, device_ids=[device.external_id],
                        )
                    )
                mobile_actions.append(
                    action(
                        "scalefusion.add_device_to_group", "scalefusion",
                        self.hub.scalefusion.add_device_to_group,
                        description=f"Move {device.device_name} into '{group}'",
                        target=device.device_name or device.external_id,
                        risk=RiskLevel.LOW,
                        group_id=group, device_ids=[device.external_id],
                    )
                )

            if mobile_actions:
                plan.add(
                    step(
                        8, "mobile_enrollment", "scalefusion", *mobile_actions,
                        description="Bind the mobile device to the identity and apply the department profile.",
                        depends_on=["entra_identity"],
                        continue_on_error=True,
                    )
                )
            elif requested_serials or employee.devices:
                ctx.note(
                    "no Scalefusion device matched the supplied serials - the handset may not be "
                    "enrolled yet. Mobile enrolment will be skipped."
                )

        # ---------------------------------------------------------------- #
        # 9. Welcome / lifecycle workflow
        # ---------------------------------------------------------------- #
        joiner_workflow = ctx.opt("lifecycle_workflow_id") or ""
        if joiner_workflow:
            plan.add(
                step(
                    9, "lifecycle_workflow", "entra",
                    action(
                        "entra.run_lifecycle_workflow", "entra",
                        self.hub.entra.run_lifecycle_workflow,
                        description=f"Trigger Entra Lifecycle Workflow '{joiner_workflow}' (welcome email, TAP)",
                        target=upn, risk=RiskLevel.MEDIUM,
                        workflow_id=joiner_workflow, user_ids=[upn],
                    ),
                    description="Delegate the communication steps to Entra ID Governance.",
                    depends_on=["entra_identity", "m365_licensing"],
                    continue_on_error=True,
                )
            )

        # ---------------------------------------------------------------- #
        # 10. Verification (read-only)
        # ---------------------------------------------------------------- #
        plan.add(
            step(
                10, "verification", "all",
                action(
                    "entra.get_user", "entra", self.hub.entra.get_user,
                    description="Confirm the Entra account exists, is enabled and carries the licences",
                    target=upn, risk=RiskLevel.LOW, identifier=upn,
                ),
                action(
                    "active_directory.get_user", "active_directory", self.hub.active_directory.get_user,
                    description="Confirm the on-premises account state",
                    target=username, risk=RiskLevel.LOW, identifier=username,
                ),
                action(
                    "m365.get_mailbox", "m365", self.hub.m365.get_mailbox,
                    description="Confirm the mailbox is live", target=upn, risk=RiskLevel.LOW,
                    identifier=upn,
                ),
                description="Re-read every platform and confirm the intended end state was reached.",
                depends_on=["entra_identity"],
                continue_on_error=True,
            )
        )

        # Surface planner findings into the plan for reviewers and for Claude.
        plan.assumptions = list(dict.fromkeys(plan.assumptions + ctx.assumptions))
        plan.warnings = list(dict.fromkeys(plan.warnings + ctx.warnings))
        ctx.resolved.update(
            {
                "upn": upn,
                "username": username,
                "licenses": licence_skus,
                "groups": group_names,
                "teams": team_names,
                "endpoint_ids": [d.external_id for d in known_devices if d.platform_console == "action1"],
                "mobile_ids": [d.external_id for d in known_devices if d.platform_console == "scalefusion"],
                # Deliberately NOT included in any audit-visible plan field.
            }
        )
        ctx.resolved["_password"] = password
        return plan


# --------------------------------------------------------------------------- #
# Planning helpers
# --------------------------------------------------------------------------- #

_DEPARTMENT_DEFAULTS: dict[str, dict[str, list[str]]] = {
    "IT": {
        "licenses": ["ENTERPRISEPACK", "EMS"],
        "groups": ["IT-All", "All-Employees", "MFA-Required"],
        "teams": ["IT Operations"],
    },
    "Ventas": {
        "licenses": ["O365_BUSINESS_PREMIUM"],
        "groups": ["Ventas-All", "All-Employees", "MDM-Enrolled"],
        "teams": ["Comercial"],
    },
    "Finanzas": {
        "licenses": ["ENTERPRISEPACK"],
        "groups": ["Finanzas-All", "All-Employees"],
        "teams": ["Finance"],
    },
    "RRHH": {
        "licenses": ["ENTERPRISEPACK"],
        "groups": ["RRHH-All", "All-Employees"],
        "teams": ["People"],
    },
    "Marketing": {
        "licenses": ["O365_BUSINESS_PREMIUM"],
        "groups": ["Marketing-All", "All-Employees"],
        "teams": ["Marketing"],
    },
}


def _defaults_for(department: str) -> dict[str, list[str]]:
    if not department:
        return {"licenses": [], "groups": ["All-Employees"], "teams": []}
    for key, value in _DEPARTMENT_DEFAULTS.items():
        if department.lower() == key.lower():
            return value
    return {"licenses": ["ENTERPRISEPACK"], "groups": ["All-Employees"], "teams": []}


def _default_licenses_for(department: str) -> list[str]:
    return _defaults_for(department)["licenses"]


def _default_groups_for(department: str) -> list[str]:
    return _defaults_for(department)["groups"]


def _default_teams_for(department: str) -> list[str]:
    return _defaults_for(department)["teams"]


def _default_profile_for(department: str, devices: list[Device]) -> str:
    """Pick a Scalefusion profile: kiosk for warehouse/frontline, standard otherwise."""
    if any("kiosk" in (d.raw.get("mdm_mode") or "").lower() for d in devices):
        return "Kiosk-Warehouse"
    if department and department.lower() in ("logistica", "almacen", "warehouse", "tienda", "retail"):
        return "Kiosk-Warehouse"
    return "Standard-Android-Work"


def _hr_attributes(employee: Employee, ctx: WorkflowContext) -> dict[str, Any]:
    attrs: dict[str, Any] = {
        "jobTitle": employee.job_title,
        "department": employee.department,
        "companyName": employee.company,
        "officeLocation": employee.office_location,
        "country": employee.country,
        "employeeId": employee.employee_id,
        "employeeType": employee.employment_type.value,
        "mobilePhone": employee.mobile_phone,
        "usageLocation": employee.country or "ES",
        "preferredLanguage": ctx.opt("locale", "es-ES"),
    }
    if employee.hire_date:
        from datetime import datetime, time

        attrs["employeeHireDate"] = datetime.combine(
            employee.hire_date, time(9, 0), tzinfo=UTC
        ).isoformat()
    return {k: v for k, v in attrs.items() if v not in (None, "")}


def _match_devices_by_serial(
    devices: list[Device], serials: list[str], console: str
) -> list[Device]:
    if not serials:
        return []
    out = []
    for device in devices:
        if device.platform_console != console:
            continue
        haystack = " ".join(
            [device.serial_number, device.asset_tag, device.device_name, device.imei]
        ).lower()
        if any(s and s in haystack for s in serials):
            out.append(device)
    return out


def _dedupe(devices: list[Device]) -> list[Device]:
    seen: set[tuple[str, str]] = set()
    out = []
    for device in devices:
        key = (device.platform_console, device.external_id)
        if key in seen:
            continue
        seen.add(key)
        out.append(device)
    return out


def _domain_of(email: str) -> str:
    return email.split("@")[-1].lower() if email and "@" in email else ""


def _generate_password() -> str:
    """A policy-satisfying throwaway password.

    The user is always forced to change it at first sign-in, and the value is
    excluded from every serialised model so it cannot reach the audit log.
    """
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    specials = "!@#$%^&*_-+=?"
    while True:
        core = "".join(secrets.choice(alphabet) for _ in range(14))
        candidate = f"Ia-{core}{secrets.choice(specials)}{secrets.choice(string.digits)}"
        if (
            any(c.isupper() for c in candidate)
            and any(c.islower() for c in candidate)
            and any(c.isdigit() for c in candidate)
            and any(c in specials for c in candidate)
        ):
            return candidate
