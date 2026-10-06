"""Transfer (mover) playbook: internal moves, promotions and role changes.

A move is *not* an offboarding followed by an onboarding. Revoking everything
and re-granting it would drop the user out of Teams mid-conversation, unbind
their devices and cost a licence swap. Instead this workflow computes the
**delta** between the current entitlements and the target role, then:

* removes what the old department granted and the new one does not
* adds what the new department requires
* keeps anything that overlaps untouched
* never disables the account, never wipes a device

It also handles the two mover cases that are easy to get wrong: a licence
upgrade/downgrade (which needs ``removeLicenses`` and ``addLicenses`` in a single
Graph call to avoid a gap), and re-pointing the reporting line.
"""

from __future__ import annotations

from typing import Any, ClassVar

from iam_agent.config import Settings
from iam_agent.connectors import ConnectorHub
from iam_agent.core.result import ExecutionPlan, RiskLevel
from iam_agent.workflows.base import Workflow, WorkflowContext, action, step
from iam_agent.workflows.onboarding import (
    _default_groups_for,
    _default_licenses_for,
    _default_teams_for,
)


class TransferWorkflow(Workflow):
    key = "transfer"
    summary = "Move an employee between departments or roles, adjusting access as a delta."
    guidance = (
        "Use for internal moves, promotions, department changes or contract-to-permanent conversions. "
        "Requires the person's identifier plus the target department and/or job_title. Optionally "
        "accepts a new manager email, target license SKUs and an effective_date. The workflow diffs "
        "current entitlements against the target role and applies only the delta - it never disables "
        "the account, never revokes sessions and never touches devices, so the person keeps working "
        "throughout. Licence changes are applied in a single Graph call to avoid any service gap."
    )
    platforms = ("entra", "m365", "active_directory", "scalefusion")
    options_schema: ClassVar[dict[str, Any]] = {
        "target_department": "The department being moved into (required unless target_title given).",
        "target_title": "New job title.",
        "target_licenses": "Explicit SKU list; defaults to the target department's baseline.",
        "target_groups": "Explicit extra groups to add.",
        "remove_old_groups": "Revoke the old department's groups (default True).",
        "new_manager": "Email of the new manager; re-points the reporting line.",
        "effective_date": "ISO date the change takes effect (default today).",
        "reprofile_mobile": "Apply the new department's device profile (default True).",
    }

    def __init__(self, hub: ConnectorHub, settings: Settings) -> None:
        super().__init__(hub, settings)

    async def plan(self, ctx: WorkflowContext) -> ExecutionPlan:
        employee = ctx.employee
        snapshot = ctx.snapshot
        entra_user = snapshot.entra if snapshot else None
        plan = self.new_plan(ctx)

        current_department = (entra_user.department if entra_user else "") or employee.department
        target_department = ctx.opt("target_department") or employee.department or current_department
        current_title = (entra_user.job_title if entra_user else "") or employee.job_title
        target_title = ctx.opt("target_title") or employee.job_title

        identifier = (entra_user.external_id if entra_user else "") or employee.upn or employee.email
        ad_identifier = (
            (snapshot.on_prem.dn or snapshot.on_prem.external_id)
            if snapshot and snapshot.on_prem
            else employee.username or employee.email
        )

        if current_department.lower() == target_department.lower() and current_title == target_title:
            ctx.assume(
                "Target department and title match the current ones; this plan will only refresh "
                "attributes and reconcile membership."
            )

        # ---- compute the delta ----------------------------------------- #
        current_groups = {
            g.display_name
            for g in ((snapshot.group_memberships.get("entra") or []) if snapshot else [])
        }
        target_groups = set(_default_groups_for(target_department)) | set(ctx.opt("target_groups") or [])
        old_groups = set(_default_groups_for(current_department))

        to_add = sorted(target_groups - current_groups)
        to_remove = (
            sorted((old_groups - target_groups) & current_groups)
            if ctx.flag("remove_old_groups", True)
            else []
        )
        protected = {"All-Employees", "MFA-Required", "MDM-Enrolled"}
        to_remove = [g for g in to_remove if g not in protected]

        current_licenses = set(entra_user.license_skus) if entra_user else set()
        target_licenses = set(
            ctx.opt("target_licenses") or _default_licenses_for(target_department) or current_licenses
        )
        license_delta = sorted(target_licenses - current_licenses)
        license_drop = sorted(current_licenses - target_licenses)

        current_teams: set[str] = set()
        target_teams = set(_default_teams_for(target_department))
        old_teams = set(_default_teams_for(current_department))

        # Resolve actual Teams membership at plan time (cheap read).
        try:
            user_teams = await self.hub.m365.find_user_teams(identifier)
            current_teams = {t.get("displayName", "") for t in user_teams}
        except Exception:
            ctx.note("could not enumerate current Teams membership; Team changes will be additive only")

        teams_to_add = sorted(target_teams - current_teams)
        teams_to_remove = (
            sorted((old_teams - target_teams) & current_teams)
            if ctx.flag("remove_old_groups", True)
            else []
        )

        ctx.assume(
            f"Delta: +groups {to_add or 'none'}, -groups {to_remove or 'none'}, "
            f"+teams {teams_to_add or 'none'}, -teams {teams_to_remove or 'none'}, "
            f"+licences {license_delta or 'none'}, -licences {license_drop or 'none'}"
        )

        # ---------------------------------------------------------------- #
        # 1. Preflight
        # ---------------------------------------------------------------- #
        plan.add(
            step(
                1, "preflight", "all",
                action(
                    "entra.get_user", "entra", self.hub.entra.get_user,
                    description="Capture the current state before the move",
                    target=identifier, risk=RiskLevel.LOW, identifier=identifier,
                ),
                action(
                    "entra.get_user_groups", "entra", self.hub.entra.get_user_groups,
                    description="Enumerate current group membership to compute the delta",
                    target=identifier, risk=RiskLevel.LOW, user_id=identifier,
                ),
                action(
                    "m365.list_skus", "m365", self.hub.m365.list_skus,
                    description="Confirm the target licences have free seats",
                    target="tenant", risk=RiskLevel.LOW,
                ),
                description="Read the current entitlements so only the difference is applied.",
                continue_on_error=True,
            )
        )

        # ---------------------------------------------------------------- #
        # 2. Attributes
        # ---------------------------------------------------------------- #
        attributes: dict[str, Any] = {
            "department": target_department,
            "jobTitle": target_title,
        }
        effective = ctx.opt("effective_date")
        if effective:
            ctx.assume(f"Move recorded as effective {effective}")
        if ctx.opt("new_manager") or (employee.manager and employee.manager.entra_id):
            attributes["employeeType"] = employee.employment_type.value
        attributes = {k: v for k, v in attributes.items() if v not in (None, "")}

        attribute_actions = [
            action(
                "entra.update_user", "entra", self.hub.entra.update_user,
                description=f"Update department to '{target_department}' and title to '{target_title}'",
                target=identifier, risk=RiskLevel.LOW,
                user_id=identifier, attributes=attributes,
            ),
            action(
                "active_directory.update_user", "active_directory",
                self.hub.active_directory.update_user,
                description="Mirror the department and title on-premises",
                target=ad_identifier, risk=RiskLevel.LOW,
                identifier=ad_identifier,
                attributes={
                    "department": target_department,
                    "title": target_title,
                },
            ),
        ]
        new_manager = ctx.opt("new_manager")
        manager_id = ""
        if new_manager:
            try:
                manager_user = await self.hub.entra.get_user(new_manager)
                manager_id = manager_user.external_id if manager_user else ""
            except Exception:
                ctx.note(f"could not resolve new manager '{new_manager}'")
        elif employee.manager and employee.manager.entra_id:
            manager_id = employee.manager.entra_id

        if manager_id:
            attribute_actions.append(
                action(
                    "entra.set_manager", "entra", self.hub.entra.set_manager,
                    description="Re-point the reporting line to the new manager",
                    target=identifier, risk=RiskLevel.LOW,
                    user_id=identifier, manager_id=manager_id,
                )
            )

        plan.add(
            step(
                2, "attributes", "entra+ad", *attribute_actions,
                description="Update the organisational attributes in both directories.",
                depends_on=["preflight"],
            )
        )

        # ---------------------------------------------------------------- #
        # 3. Licence change (single call: add and remove together)
        # ---------------------------------------------------------------- #
        if license_delta or license_drop:
            # One action, one Graph call, both halves.
            #
            # Two separate actions would need an ordering guarantee the executor
            # does not provide inside a step, and a failure between them strands
            # the person holding both SKUs - a silent, permanent licence leak.
            #
            # The previous `remove_all_licenses` fallback was worse still: it
            # strips every licence including the one just granted. That is why it
            # was gated on `not license_delta` - which in turn meant that a tier
            # *change*, the common case, never released anything at all while the
            # plan's own summary claimed it had.
            plan.add(
                step(
                    3, "licence_change", "entra",
                    action(
                        "entra.assign_license", "entra", self.hub.entra.assign_license,
                        description=(
                            f"Add {license_delta or 'nothing'} and release "
                            f"{license_drop or 'nothing'} in a single assignLicense call, "
                            "so there is no service gap and no superseded SKU left behind."
                        ),
                        target=identifier, risk=RiskLevel.MEDIUM,
                        user_id=identifier,
                        sku_part_numbers=license_delta,
                        remove_sku_part_numbers=license_drop,
                    ),
                    description="Licence moves must be atomic to avoid losing Exchange/Teams mid-day.",
                    depends_on=["attributes"],
                    continue_on_error=True,
                )
            )

        # ---------------------------------------------------------------- #
        # 4. Group delta
        # ---------------------------------------------------------------- #
        group_actions = [
            action(
                "entra.add_group_member", "entra", self.hub.entra.add_group_member,
                description=f"Grant the new department group '{name}'",
                target=f"{identifier} -> {name}", risk=RiskLevel.MEDIUM,
                group_id=name, user_id=identifier,
                compensating=action(
                    "entra.remove_group_member", "entra", self.hub.entra.remove_group_member,
                    description=f"Rollback: remove from {name}",
                    target=f"{identifier} -> {name}", group_id=name, user_id=identifier,
                ),
            )
            for name in to_add
        ] + [
            action(
                "entra.remove_group_member", "entra", self.hub.entra.remove_group_member,
                description=f"Revoke the superseded group '{name}'",
                target=f"{identifier} -> {name}", risk=RiskLevel.MEDIUM,
                group_id=name, user_id=identifier,
                compensating=action(
                    "entra.add_group_member", "entra", self.hub.entra.add_group_member,
                    description=f"Rollback: restore {name}",
                    target=f"{identifier} -> {name}", group_id=name, user_id=identifier,
                ),
            )
            for name in to_remove
        ] + [
            action(
                "active_directory.add_group_member", "active_directory",
                self.hub.active_directory.add_group_member,
                description=f"Mirror '{name}' on-premises",
                target=f"{ad_identifier} -> {name}", risk=RiskLevel.MEDIUM,
                group_dn=name, member_dn=ad_identifier,
            )
            for name in to_add
        ]

        if group_actions:
            plan.add(
                step(
                    4, "group_delta", "entra+ad", *group_actions,
                    description="Apply only the group difference; overlapping memberships are untouched.",
                    depends_on=["attributes"],
                    continue_on_error=True,
                )
            )

        # ---------------------------------------------------------------- #
        # 5. Teams delta
        # ---------------------------------------------------------------- #
        team_actions = [
            action(
                "m365.add_team_member", "m365", self.hub.m365.add_team_member,
                description=f"Join the Team '{name}'",
                target=f"{identifier} -> {name}", risk=RiskLevel.MEDIUM,
                team_id=name, user_id=identifier,
            )
            for name in teams_to_add
        ] + [
            action(
                "m365.remove_team_member", "m365", self.hub.m365.remove_team_member,
                description=f"Leave the Team '{name}'",
                target=f"{identifier} -> {name}", risk=RiskLevel.MEDIUM,
                team_id=name, user_id=identifier,
            )
            for name in teams_to_remove
        ]
        if team_actions:
            plan.add(
                step(
                    5, "teams_delta", "m365", *team_actions,
                    description="Adjust Teams membership to the new department.",
                    depends_on=["attributes"],
                    continue_on_error=True,
                )
            )

        # ---------------------------------------------------------------- #
        # 6. Device re-profiling
        # ---------------------------------------------------------------- #
        if ctx.flag("reprofile_mobile", True) and snapshot:
            mobiles = snapshot.mobile_devices()
            profile_actions = []
            for device in mobiles:
                profile_actions.append(
                    action(
                        "scalefusion.apply_device_profile", "scalefusion",
                        self.hub.scalefusion.apply_device_profile,
                        description=(
                            f"Re-profile {device.device_name} for {target_department} "
                            "(e.g. leave kiosk mode when moving out of the warehouse)"
                        ),
                        target=device.device_name or device.external_id,
                        risk=RiskLevel.MEDIUM,
                        profile_id=_profile_for_department(target_department, device),
                        device_ids=[device.external_id],
                    )
                )
            if profile_actions:
                plan.add(
                    step(
                        6, "device_reprofile", "scalefusion", *profile_actions,
                        description="Devices follow the role; they are never wiped during a transfer.",
                        depends_on=["attributes"],
                        continue_on_error=True,
                    )
                )

        # ---------------------------------------------------------------- #
        # 7. Verification
        # ---------------------------------------------------------------- #
        plan.add(
            step(
                7, "verification", "all",
                action(
                    "entra.get_user", "entra", self.hub.entra.get_user,
                    description="Confirm the new department, title and licences",
                    target=identifier, risk=RiskLevel.LOW, identifier=identifier,
                ),
                action(
                    "entra.get_user_groups", "entra", self.hub.entra.get_user_groups,
                    description="Confirm the resulting group membership",
                    target=identifier, risk=RiskLevel.LOW, user_id=identifier,
                ),
                description="Verify the move landed as intended.",
                depends_on=["attributes"],
                continue_on_error=True,
            )
        )

        plan.assumptions = list(dict.fromkeys(plan.assumptions + ctx.assumptions))
        plan.warnings = list(dict.fromkeys(plan.warnings + ctx.warnings))
        ctx.resolved.update(
            {
                "identifier": identifier,
                "from_department": current_department,
                "to_department": target_department,
                "groups_added": to_add,
                "groups_removed": to_remove,
                "teams_added": teams_to_add,
                "teams_removed": teams_to_remove,
                "licenses_added": license_delta,
                "licenses_removed": license_drop,
            }
        )
        return plan


def _profile_for_department(department: str, device: Any) -> str:
    frontline = {"logistica", "almacen", "warehouse", "tienda", "retail", "operaciones"}
    if department and department.lower() in frontline:
        return "Kiosk-Warehouse"
    if str(device.os_name).lower().startswith(("ios", "ipad")):
        return "iOS-Supervised"
    return "Standard-Android-Work"
