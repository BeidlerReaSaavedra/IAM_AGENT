"""Offboarding playbook: revoke fast, preserve evidence, delete last.

Why this order
--------------
Offboarding is a race against an ex-employee's still-valid sessions, so the
phases are ordered by *time to revoke access*, not by convenience:

1. **preflight** — snapshot everything first. Once you disable an account you
   lose the ability to enumerate what it had access to, and you need the device
   list, the role list and the mailbox size before you act.
2. **immediate_lockdown** — revoke refresh tokens, then disable at the
   **authoritative source**. If the account is Entra Connect-synced, on-prem AD
   is authoritative: disabling only in the cloud gets reverted at the next sync.
   Both are disabled here so the state holds either way.
3. **revoke_privileged_access** — directory roles and privileged groups. An
   enabled-but-disabled account can still hold a Global Admin role assignment
   that matters the moment anyone re-enables it.
4. **remove_memberships** — all groups and all Teams.
5. **endpoint_containment** — Action1: move to the leaver group, quarantine or
   run the offboarding automation. Contains the PC even if nobody logs in again.
6. **mobile_containment** — Scalefusion: lock the handset and apply the
   restrictive leaver profile. This is reversible and immediate.
7. **mailbox_continuity** — litigation hold, convert to shared, hide from the
   GAL, grant the manager FullAccess. Must happen **before** licence removal,
   because a shared mailbox is what keeps the mail accessible without a licence.
8. **mobile_release** — unassign the user, then wipe/retire. Split from phase 6
   because a wipe is irreversible and needs its own approval; BYOD devices are
   *never* fully wiped, only the work profile is removed.
9. **license_removal** — recovers the seat for the next hire.
10. **ad_cleanup** — expire the password, set an account expiry, move to the
    leaver OU. The object is kept for audit; it is not deleted.
11. **verification** — reconcile across all five platforms and prove nothing is
    left behind.
12. **scheduled_deletion** — the only truly destructive phase, and it is
    disabled unless ``delete_after_days`` is set. Entra keeps deleted users
    recoverable for 30 days, which is the real safety net.

Every irreversible phase (wipe, retire, delete) is ``critical`` risk and will
always require human approval, in every execution mode.
"""

from __future__ import annotations

from datetime import UTC, date, datetime, time, timedelta
from typing import Any, ClassVar

from iam_agent.config import Settings
from iam_agent.connectors import ConnectorHub
from iam_agent.core.models import Device, DeviceOwnership
from iam_agent.core.reconcile import Reconciler
from iam_agent.core.result import ExecutionPlan, RiskLevel
from iam_agent.workflows.base import Workflow, WorkflowContext, action, step


class OffboardingWorkflow(Workflow):
    key = "offboarding"
    summary = (
        "Revoke a leaver's access across Entra ID, M365, on-prem AD, Action1 and Scalefusion, "
        "preserving data and releasing licences."
    )
    guidance = (
        "Use when an employee, contractor or intern is leaving. Requires an identifier (email, "
        "username or employee id) and ideally a leave_date. The workflow disables accounts at the "
        "authoritative source, revokes privileged roles and all group/Teams memberships, contains "
        "the PC via Action1, locks and then releases the mobile device via Scalefusion, converts the "
        "mailbox to shared with manager access, removes licences and cleans up on-prem AD. "
        "Irreversible actions (device wipe, device retire, account deletion) are ALWAYS gated behind "
        "human approval regardless of execution mode. BYOD devices are never fully wiped - only the "
        "work profile is removed. Set emergency=True for a same-day hostile termination: it skips "
        "deferred phases and quarantines endpoints immediately."
    )
    platforms = ("entra", "m365", "active_directory", "action1", "scalefusion")
    options_schema: ClassVar[dict[str, Any]] = {
        "emergency": "Hostile/same-day termination. Quarantines endpoints immediately (default False).",
        "retain_mailbox": "Convert to shared mailbox instead of removing (default True).",
        "mailbox_delegate": "Email of the person who should get mailbox access (defaults to the manager).",
        "litigation_hold": "Place the mailbox on hold for legal reasons (default False).",
        "forward_mail_to": "Optional address to forward incoming mail to.",
        "wipe_mobile": "Wipe corporate mobile devices (default True). Never applies to BYOD.",
        "retire_mobile": "Retire/unenrol the device after wiping (default True).",
        "delete_after_days": "Delete the Entra object after N days. 0/omitted = never delete.",
        "revoke_sessions": "Revoke all Entra sign-in sessions (default True).",
        "run_offboarding_automation": "Launch the Action1 offboarding automation (default True).",
        "quarantine_endpoints": "Network-isolate endpoints (default only when emergency=True).",
        "skip_ad_cleanup": "Skip the on-premises AD cleanup phase (default False).",
    }

    def __init__(self, hub: ConnectorHub, settings: Settings) -> None:
        super().__init__(hub, settings)
        self.reconciler = Reconciler(hub, settings)

    # ------------------------------------------------------------------ #

    async def plan(self, ctx: WorkflowContext) -> ExecutionPlan:
        employee = ctx.employee
        snapshot = ctx.snapshot
        entra_user = snapshot.entra if snapshot else None
        ad_user = snapshot.on_prem if snapshot else None

        # Identifier resolution: prefer object ids when we already know them,
        # because a disabled/renamed account may no longer resolve by UPN.
        entra_id = (entra_user.external_id if entra_user else "") or employee.upn or employee.email
        ad_id = (
            (ad_user.dn or ad_user.external_id) if ad_user else ""
        ) or employee.username or employee.email
        subject = employee.full_name or entra_id
        label = employee.email or subject

        emergency = ctx.flag("emergency")
        plan = self.new_plan(ctx)

        synced = bool(entra_user and entra_user.on_premises_sync)
        if synced:
            ctx.assume(
                "The account is Entra Connect-synced, so on-premises AD is the source of authority. "
                "Both sides are disabled to make the state hold regardless of sync timing."
            )

        # Devices, split by console and by ownership (BYOD is treated differently).
        devices: list[Device] = list(snapshot.devices) if snapshot else []
        endpoints = [d for d in devices if d.platform_console == "action1"]
        mobiles = [d for d in devices if d.platform_console == "scalefusion"]
        corporate_mobiles = [d for d in mobiles if d.ownership != DeviceOwnership.BYOD]
        byod_mobiles = [d for d in mobiles if d.ownership == DeviceOwnership.BYOD]

        if byod_mobiles:
            ctx.assume(
                f"{len(byod_mobiles)} BYOD device(s) detected. These will only be unenrolled/"
                "work-profile-wiped - personal data is never touched."
            )

        # Privileged roles discovered in the snapshot.
        roles: list[dict[str, Any]] = []
        if entra_user:
            try:
                roles = await self.hub.entra.get_user_roles(entra_user.external_id)
            except Exception:
                ctx.note("could not enumerate Entra directory roles; revoke_privileged_access will be skipped")
        if roles:
            ctx.note(
                f"{subject} holds {len(roles)} directory role(s): "
                + ", ".join(r.get("displayName", "?") for r in roles)
            )

        # Who inherits the mailbox: explicit option > HR manager > Entra manager link.
        delegate = ctx.opt("mailbox_delegate") or ""
        if not delegate and employee.manager:
            delegate = employee.manager.email
        if not delegate and entra_user:
            manager_ref = entra_user.raw.get("manager")
            if isinstance(manager_ref, dict):
                delegate = manager_ref.get("mail", "") or ""
            if not delegate and entra_user.manager_id:
                try:
                    manager_user = await self.hub.entra.get_user(entra_user.manager_id)
                    delegate = (manager_user.email if manager_user else "") or ""
                except Exception:
                    delegate = ""

        # ---------------------------------------------------------------- #
        # 1. Preflight (read-only, must succeed)
        # ---------------------------------------------------------------- #
        preflight = [
            action(
                "entra.get_user", "entra", self.hub.entra.get_user,
                description=f"Snapshot {label} in Entra before any change is made",
                target=label, risk=RiskLevel.LOW, identifier=entra_id,
            ),
            action(
                "entra.get_user_roles", "entra", self.hub.entra.get_user_roles,
                description="Enumerate privileged directory roles that must be revoked",
                target=label, risk=RiskLevel.LOW, user_id=entra_id,
            ),
            action(
                "entra.get_sign_in_activity", "entra", self.hub.entra.get_sign_in_activity,
                description="Record the last sign-in for the incident timeline",
                target=label, risk=RiskLevel.LOW, user_id=entra_id,
            ),
            action(
                "m365.get_mailbox", "m365", self.hub.m365.get_mailbox,
                description="Capture mailbox type and size before conversion",
                target=label, risk=RiskLevel.LOW, identifier=entra_id,
            ),
            action(
                "action1.find_endpoints_by_owner", "action1", self.hub.action1.find_endpoints_by_owner,
                description="Find every PC this person owns in Action1",
                target=label, risk=RiskLevel.LOW, owner=label,
            ),
            action(
                "scalefusion.find_devices_by_user", "scalefusion", self.hub.scalefusion.find_devices_by_user,
                description="Find every mobile device bound to this person in Scalefusion",
                target=label, risk=RiskLevel.LOW, user=label,
            ),
        ]
        if ad_user:
            preflight.append(
                action(
                    "active_directory.get_user", "active_directory", self.hub.active_directory.get_user,
                    description="Snapshot the on-premises account and its group memberships",
                    target=ad_id, risk=RiskLevel.LOW, identifier=ad_id,
                )
            )

        plan.add(
            step(
                1, "preflight", "all", *preflight,
                description="Capture the complete access picture before revoking anything.",
                continue_on_error=True,
            )
        )

        # ---------------------------------------------------------------- #
        # 2. Immediate lockdown
        # ---------------------------------------------------------------- #
        lockdown = []
        if ctx.flag("revoke_sessions", True):
            lockdown.append(
                action(
                    "entra.revoke_all_sessions", "entra", self.hub.entra.revoke_sign_in_sessions,
                    description="Revoke all refresh tokens - kills existing sessions within minutes",
                    target=label, risk=RiskLevel.CRITICAL, reversible=False,
                    user_id=entra_id,
                )
            )

        if ad_user and ad_user.enabled:
            lockdown.append(
                action(
                    "active_directory.disable_user", "active_directory",
                    self.hub.active_directory.disable_user,
                    description="Disable at the authoritative source (on-premises AD)",
                    target=ad_id, risk=RiskLevel.HIGH,
                    identifier=ad_id,
                    reason=f"offboarding {employee.leave_date or 'effective immediately'} - {ctx.reason}",
                    compensating=action(
                        "active_directory.enable_user", "active_directory",
                        self.hub.active_directory.enable_user,
                        description="Rollback: re-enable the AD account", target=ad_id, identifier=ad_id,
                    ),
                )
            )
        elif ad_user:
            ctx.assume("On-premises account is already disabled; skipping AD disable.")

        if entra_user and entra_user.enabled:
            lockdown.append(
                action(
                    "entra.disable_user", "entra", self.hub.entra.disable_user,
                    description="Disable the Entra account so cloud SSO and all federated apps stop",
                    target=label, risk=RiskLevel.HIGH,
                    user_id=entra_id,
                    reason=f"offboarding {employee.leave_date or 'effective immediately'} - {ctx.reason}",
                    compensating=action(
                        "entra.enable_user", "entra", self.hub.entra.enable_user,
                        description="Rollback: re-enable the Entra account", target=label, user_id=entra_id,
                    ),
                )
            )
        elif entra_user:
            ctx.assume("Entra account is already disabled; skipping Entra disable.")

        if not lockdown:
            ctx.note("both accounts already disabled - lockdown phase is a no-op")

        plan.add(
            step(
                2, "immediate_lockdown", "entra+ad", *lockdown,
                description="Cut access first. Everything else can wait; this cannot.",
                depends_on=["preflight"],
            )
        )

        # ---------------------------------------------------------------- #
        # 3. Revoke privileged access
        # ---------------------------------------------------------------- #
        if roles:
            role_actions = [
                action(
                    "entra.revoke_role", "entra", self.hub.entra.revoke_role,
                    description=f"Remove the '{role.get('displayName')}' directory role",
                    target=f"{label} / {role.get('displayName')}", risk=RiskLevel.HIGH,
                    role_id=role.get("id", ""), user_id=entra_id,
                    compensating=action(
                        "entra.grant_role", "entra", self.hub.entra.grant_role,
                        description=f"Rollback: restore '{role.get('displayName')}'",
                        target=label, role_id=role.get("id", ""), user_id=entra_id,
                    ),
                )
                for role in roles
            ]
            plan.add(
                step(
                    3, "revoke_privileged_access", "entra", *role_actions,
                    description="Strip directory roles - an enabled role assignment survives a re-enable.",
                    depends_on=["immediate_lockdown"],
                )
            )

        # ---------------------------------------------------------------- #
        # 4. Remove memberships
        # ---------------------------------------------------------------- #
        membership_actions = [
            action(
                "entra.remove_all_group_memberships", "entra",
                self.hub.entra.remove_all_group_memberships,
                description="Remove from every Entra group (dynamic groups are skipped automatically)",
                target=label, risk=RiskLevel.HIGH,
                user_id=entra_id,
            ),
            action(
                "m365.remove_all_teams_memberships", "m365",
                self.hub.m365.remove_all_teams_memberships,
                description="Remove from every Microsoft Team",
                target=label, risk=RiskLevel.HIGH,
                user_id=entra_id,
            ),
        ]
        if ad_user:
            for group in (snapshot.group_memberships.get("active_directory") if snapshot else []) or []:
                membership_actions.append(
                    action(
                        "active_directory.remove_group_member", "active_directory",
                        self.hub.active_directory.remove_group_member,
                        description=f"Remove from on-prem group '{group.display_name}'",
                        target=f"{ad_id} -> {group.display_name}", risk=RiskLevel.HIGH,
                        group_dn=group.dn or group.display_name, member_dn=ad_id,
                    )
                )

        plan.add(
            step(
                4, "remove_memberships", "entra+m365+ad", *membership_actions,
                description="Drop every group, Team and on-prem membership.",
                depends_on=["immediate_lockdown"],
                continue_on_error=True,
            )
        )

        # ---------------------------------------------------------------- #
        # 5. Endpoint containment (Action1)
        # ---------------------------------------------------------------- #
        endpoint_actions = []
        leaver_group = self.settings.action1.leaver_group_id or "Leavers"
        endpoint_ids = [d.external_id for d in endpoints if d.external_id]

        if endpoints:
            endpoint_actions.append(
                action(
                    "action1.add_endpoints_to_group", "action1",
                    self.hub.action1.add_endpoints_to_group,
                    description=f"Move {len(endpoint_ids)} endpoint(s) into the '{leaver_group}' group",
                    target=", ".join(d.device_name for d in endpoints),
                    risk=RiskLevel.LOW,
                    group_id=leaver_group, endpoint_ids=endpoint_ids,
                )
            )
            if emergency or ctx.flag("quarantine_endpoints"):
                for device in endpoints:
                    endpoint_actions.append(
                        action(
                            "action1.quarantine_endpoint", "action1",
                            self.hub.action1.quarantine_endpoint,
                            description=f"Network-isolate {device.device_name} (emergency termination)",
                            target=device.device_name, risk=RiskLevel.HIGH,
                            endpoint_id=device.external_id,
                        )
                    )
            automation = self.settings.action1.offboarding_automation_id
            if automation and ctx.flag("run_offboarding_automation", True):
                endpoint_actions.append(
                    action(
                        "action1.run_automation", "action1", self.hub.action1.run_automation,
                        description=f"Launch '{automation}' to remove profiles, certificates and local accounts",
                        target=", ".join(d.device_name for d in endpoints),
                        risk=RiskLevel.HIGH,
                        automation_id=automation, endpoint_ids=endpoint_ids,
                    )
                )
        else:
            ctx.note("no Action1 endpoint is assigned to this person; endpoint containment skipped")

        if endpoint_actions:
            plan.add(
                step(
                    5, "endpoint_containment", "action1", *endpoint_actions,
                    description="Contain the PC(s) even if nobody ever logs in again.",
                    depends_on=["immediate_lockdown"],
                    continue_on_error=True,
                )
            )

        # ---------------------------------------------------------------- #
        # 6. Mobile containment (reversible part of Scalefusion)
        # ---------------------------------------------------------------- #
        contain_actions = []
        leaver_profile = self.settings.scalefusion.leaver_device_profile_id or "Leaver-Restricted"
        for device in mobiles:
            contain_actions.append(
                action(
                    "scalefusion.lock_device", "scalefusion", self.hub.scalefusion.lock_device,
                    description=f"Lock {device.device_name} so it cannot be used if it is still in the field",
                    target=device.device_name or device.external_id, risk=RiskLevel.HIGH,
                    device_id=device.external_id,
                    message=f"This device has been locked by IT as part of offboarding. Contact {delegate or 'IT'}.",
                    compensating=action(
                        "scalefusion.unlock_device", "scalefusion", self.hub.scalefusion.unlock_device,
                        description=f"Rollback: unlock {device.device_name}",
                        target=device.device_name, device_id=device.external_id,
                    ),
                )
            )
            contain_actions.append(
                action(
                    "scalefusion.apply_device_profile", "scalefusion",
                    self.hub.scalefusion.apply_device_profile,
                    description=f"Apply the restrictive '{leaver_profile}' profile to {device.device_name}",
                    target=device.device_name or device.external_id, risk=RiskLevel.MEDIUM,
                    profile_id=leaver_profile, device_ids=[device.external_id],
                )
            )

        if contain_actions:
            plan.add(
                step(
                    6, "mobile_containment", "scalefusion", *contain_actions,
                    description="Lock and restrict every handset immediately. All of this is reversible.",
                    depends_on=["immediate_lockdown"],
                    continue_on_error=True,
                )
            )
        elif mobiles:
            ctx.note("mobile devices found but containment actions could not be planned")
        else:
            ctx.note("no Scalefusion device is bound to this person; mobile phases skipped")

        # ---------------------------------------------------------------- #
        # 7. Mailbox continuity (must precede licence removal)
        # ---------------------------------------------------------------- #
        mailbox_actions = []
        if ctx.flag("litigation_hold") or employee.employment_type.value == "vip":
            mailbox_actions.append(
                action(
                    "m365.set_litigation_hold", "m365", self.hub.m365.set_litigation_hold,
                    description="Place the mailbox on litigation hold (preserves everything, blocks purge)",
                    target=label, risk=RiskLevel.HIGH, reversible=False,
                    identifier=entra_id, enabled=True,
                )
            )

        if ctx.flag("retain_mailbox", True):
            mailbox_actions.append(
                action(
                    "m365.hide_from_gal", "m365", self.hub.m365.hide_from_gal,
                    description="Hide from the Global Address List",
                    target=label, risk=RiskLevel.LOW,
                    identifier=entra_id, hidden=True,
                )
            )
            if delegate:
                mailbox_actions.append(
                    action(
                        "m365.grant_mailbox_permission", "m365", self.hub.m365.grant_mailbox_permission,
                        description=f"Grant {delegate} FullAccess so work in progress is not lost",
                        target=f"{label} -> {delegate}", risk=RiskLevel.MEDIUM,
                        identifier=entra_id, grantee=delegate, rights="FullAccess",
                    )
                )
            else:
                ctx.note("no mailbox delegate resolved - set the manager or mailbox_delegate explicitly")

            if ctx.opt("forward_mail_to"):
                mailbox_actions.append(
                    action(
                        "m365.set_mailbox_forwarding", "m365", self.hub.m365.set_mailbox_forwarding,
                        description=f"Forward incoming mail to {ctx.opt('forward_mail_to')}",
                        target=label, risk=RiskLevel.MEDIUM,
                        identifier=entra_id, forward_to=ctx.opt("forward_mail_to"), keep_copy=True,
                    )
                )

            mailbox_actions.append(
                action(
                    "m365.convert_mailbox_to_shared", "m365", self.hub.m365.convert_mailbox_to_shared,
                    description="Convert to a shared mailbox - keeps the data without consuming a licence",
                    target=label, risk=RiskLevel.MEDIUM, reversible=False,
                    identifier=entra_id,
                )
            )
        else:
            ctx.assume("retain_mailbox=False: the mailbox will be removed with the licence and lost.")

        if mailbox_actions:
            plan.add(
                step(
                    7, "mailbox_continuity", "m365", *mailbox_actions,
                    description="Preserve the mail and hand it over before the licence goes away.",
                    depends_on=["immediate_lockdown"],
                    continue_on_error=True,
                )
            )

        # ---------------------------------------------------------------- #
        # 8. Mobile release (irreversible - separate step, always gated)
        # ---------------------------------------------------------------- #
        release_actions = []
        for device in mobiles:
            release_actions.append(
                action(
                    "scalefusion.unassign_device_user", "scalefusion",
                    self.hub.scalefusion.unassign_device_user,
                    description=f"Detach {device.device_name} from {label}",
                    target=device.device_name or device.external_id, risk=RiskLevel.MEDIUM,
                    device_id=device.external_id,
                )
            )

        for device in corporate_mobiles:
            if ctx.flag("wipe_mobile", True):
                release_actions.append(
                    action(
                        "scalefusion.wipe_device", "scalefusion", self.hub.scalefusion.wipe_device,
                        description=f"Factory-wipe the corporate device {device.device_name}",
                        target=device.device_name or device.external_id,
                        risk=RiskLevel.CRITICAL, reversible=False,
                        device_id=device.external_id, retention=False,
                    )
                )
            if ctx.flag("retire_mobile", True):
                release_actions.append(
                    action(
                        "scalefusion.retire_device", "scalefusion", self.hub.scalefusion.retire_device,
                        description=f"Retire/unenrol {device.device_name} and return it to the asset pool",
                        target=device.device_name or device.external_id,
                        risk=RiskLevel.CRITICAL, reversible=False,
                        device_id=device.external_id,
                    )
                )

        for device in byod_mobiles:
            if ctx.flag("wipe_mobile", True):
                release_actions.append(
                    action(
                        "scalefusion.wipe_device", "scalefusion", self.hub.scalefusion.wipe_device,
                        description=(
                            f"BYOD {device.device_name}: remove the WORK PROFILE only - "
                            "personal data is preserved"
                        ),
                        target=device.device_name or device.external_id,
                        risk=RiskLevel.HIGH, reversible=False,
                        device_id=device.external_id, retention=True,
                    )
                )
            release_actions.append(
                action(
                    "scalefusion.retire_device", "scalefusion", self.hub.scalefusion.retire_device,
                    description=f"Unenrol the BYOD device {device.device_name} from management",
                    target=device.device_name or device.external_id,
                    risk=RiskLevel.HIGH, reversible=False,
                    device_id=device.external_id,
                )
            )

        if release_actions:
            plan.add(
                step(
                    8, "mobile_release", "scalefusion", *release_actions,
                    description=(
                        "Detach and release the devices. Wipe and retire are irreversible and always "
                        "require explicit human approval."
                    ),
                    depends_on=["mobile_containment"] if contain_actions else ["immediate_lockdown"],
                    requires_approval=True,
                )
            )

        # ---------------------------------------------------------------- #
        # 9. Licence removal (after mailbox conversion)
        # ---------------------------------------------------------------- #
        plan.add(
            step(
                9, "license_removal", "entra",
                action(
                    "entra.remove_all_licenses", "entra", self.hub.entra.remove_all_licenses,
                    description="Release every licence SKU back to the tenant pool",
                    target=label, risk=RiskLevel.HIGH,
                    user_id=entra_id,
                    compensating=action(
                        "entra.assign_license", "entra", self.hub.entra.assign_license,
                        description="Rollback: restore licences",
                        target=label, user_id=entra_id,
                        sku_part_numbers=list(entra_user.license_skus) if entra_user else [],
                    ),
                ),
                description="Only safe once the mailbox has been converted to shared.",
                depends_on=["mailbox_continuity"] if mailbox_actions else ["immediate_lockdown"],
                continue_on_error=True,
            )
        )

        # ---------------------------------------------------------------- #
        # 10. On-prem AD cleanup
        # ---------------------------------------------------------------- #
        if not ctx.flag("skip_ad_cleanup") and ad_user:
            ad_cleanup = [
                action(
                    "active_directory.expire_password", "active_directory",
                    self.hub.active_directory.expire_password,
                    description="Force the password to expire so cached credentials stop working",
                    target=ad_id, risk=RiskLevel.MEDIUM,
                    identifier=ad_id,
                ),
                action(
                    "active_directory.update_user", "active_directory",
                    self.hub.active_directory.update_user,
                    description="Record the leaver reason in the AD description attribute",
                    target=ad_id, risk=RiskLevel.LOW,
                    identifier=ad_id,
                    attributes={
                        "description": f"[leaver] {employee.leave_date or 'immediate'} - {ctx.reason}"[:1024]
                    },
                ),
            ]
            leave = employee.leave_date or date.today()
            ad_cleanup.append(
                action(
                    "active_directory.set_account_expiry", "active_directory",
                    self.hub.active_directory.set_account_expiry,
                    description=f"Set the AD account to expire on {leave.isoformat()}",
                    target=ad_id, risk=RiskLevel.MEDIUM,
                    identifier=ad_id,
                    expires_at=datetime.combine(leave, time(23, 59), tzinfo=UTC),
                )
            )
            if self.settings.active_directory.disabled_ou:
                ad_cleanup.append(
                    action(
                        "active_directory.move_user", "active_directory",
                        self.hub.active_directory.move_user,
                        description=f"Move the object to {self.settings.active_directory.disabled_ou}",
                        target=ad_id, risk=RiskLevel.MEDIUM,
                        identifier=ad_id, target_ou=self.settings.active_directory.disabled_ou,
                    )
                )

            plan.add(
                step(
                    10, "ad_cleanup", "active_directory", *ad_cleanup,
                    description="Harden and park the on-premises object. It is kept for audit, never deleted.",
                    depends_on=["immediate_lockdown"],
                    continue_on_error=True,
                )
            )

        # ---------------------------------------------------------------- #
        # 11. Verification (read-only)
        # ---------------------------------------------------------------- #
        plan.add(
            step(
                11, "verification", "all",
                action(
                    "entra.get_user", "entra", self.hub.entra.get_user,
                    description="Confirm the Entra account is disabled and holds no licences",
                    target=label, risk=RiskLevel.LOW, identifier=entra_id,
                ),
                action(
                    "entra.get_user_roles", "entra", self.hub.entra.get_user_roles,
                    description="Confirm no privileged role assignment remains",
                    target=label, risk=RiskLevel.LOW, user_id=entra_id,
                ),
                action(
                    "active_directory.get_user", "active_directory", self.hub.active_directory.get_user,
                    description="Confirm the on-premises account is disabled and parked",
                    target=ad_id, risk=RiskLevel.LOW, identifier=ad_id,
                ),
                action(
                    "m365.get_mailbox", "m365", self.hub.m365.get_mailbox,
                    description="Confirm the mailbox is shared, hidden and delegated",
                    target=label, risk=RiskLevel.LOW, identifier=entra_id,
                ),
                action(
                    "action1.find_endpoints_by_owner", "action1", self.hub.action1.find_endpoints_by_owner,
                    description="Confirm no PC is still assigned to the leaver",
                    target=label, risk=RiskLevel.LOW, owner=label,
                ),
                action(
                    "scalefusion.find_devices_by_user", "scalefusion",
                    self.hub.scalefusion.find_devices_by_user,
                    description="Confirm no handset is still bound to the leaver",
                    target=label, risk=RiskLevel.LOW, user=label,
                ),
                description="Prove the end state instead of assuming it.",
                depends_on=["immediate_lockdown"],
                continue_on_error=True,
            )
        )

        # ---------------------------------------------------------------- #
        # 12. Scheduled deletion (opt-in, destructive)
        # ---------------------------------------------------------------- #
        delete_after = int(ctx.opt("delete_after_days", 0) or 0)
        if delete_after > 0:
            delete_on = (employee.leave_date or date.today()) + timedelta(days=delete_after)
            plan.add(
                step(
                    12, "scheduled_deletion", "entra",
                    action(
                        "entra.delete_user", "entra", self.hub.entra.delete_user,
                        description=(
                            f"Delete the Entra object on {delete_on.isoformat()} "
                            f"({delete_after} days after the leave date). Recoverable for 30 days."
                        ),
                        target=label, risk=RiskLevel.CRITICAL, reversible=False,
                        user_id=entra_id,
                    ),
                    description=(
                        "Deferred destruction. Do NOT run this on the last working day - the retention "
                        "window exists so a mistake can still be undone."
                    ),
                    depends_on=["verification"],
                    requires_approval=True,
                    enabled=delete_on <= date.today(),
                )
            )
            if delete_on > date.today():
                ctx.assume(
                    f"scheduled_deletion is planned but DISABLED until {delete_on.isoformat()}. "
                    "Re-run the workflow on or after that date, or use the 'deferred_deletion' job."
                )

        plan.assumptions = list(dict.fromkeys(plan.assumptions + ctx.assumptions))
        plan.warnings = list(dict.fromkeys(plan.warnings + ctx.warnings))
        ctx.resolved.update(
            {
                "entra_id": entra_id,
                "ad_id": ad_id,
                "endpoint_ids": endpoint_ids,
                "mobile_ids": [d.external_id for d in mobiles],
                "byod_mobile_ids": [d.external_id for d in byod_mobiles],
                "roles_revoked": [r.get("displayName") for r in roles],
                "mailbox_delegate": delegate,
            }
        )
        return plan


class DeferredDeletionWorkflow(Workflow):
    """Sweeps for leavers whose retention window has elapsed and deletes them.

    Runs unattended on a schedule; the destructive action is still ``critical``
    risk, so under the default hybrid mode it produces an approval request
    rather than deleting anything on its own.
    """

    key = "deferred_deletion"
    summary = "Delete Entra objects for leavers whose retention window has expired."
    guidance = (
        "Housekeeping workflow. Scans Entra for accounts that are disabled with an "
        "employeeLeaveDateTime older than the configured retention period, and plans their deletion. "
        "Because deletion is critical-risk it always produces an approval request. Use it on a weekly "
        "schedule to keep the directory clean without ever deleting anything unattended."
    )
    platforms = ("entra",)
    options_schema: ClassVar[dict[str, Any]] = {
        "retention_days": "Days after the leave date before deletion is eligible (default 30).",
        "limit": "Maximum number of users to consider (default 50).",
    }

    def __init__(self, hub: ConnectorHub, settings: Settings) -> None:
        super().__init__(hub, settings)

    async def plan(self, ctx: WorkflowContext) -> ExecutionPlan:
        plan = self.new_plan(ctx)
        retention = int(ctx.opt("retention_days", 30))
        limit = int(ctx.opt("limit", 50))
        cutoff = datetime.now(UTC) - timedelta(days=retention)

        disabled = await self.hub.entra.list_users(only_enabled=False, top=limit)
        eligible = []
        for user in disabled:
            leave = (user.raw or {}).get("employeeLeaveDateTime")
            if not leave:
                continue
            try:
                leave_dt = datetime.fromisoformat(str(leave).replace("Z", "+00:00"))
            except ValueError:
                continue
            if leave_dt < cutoff:
                eligible.append((user, leave_dt))

        if not eligible:
            ctx.assume(
                f"no disabled account has a leave date older than {retention} days; nothing to delete"
            )
            plan.warnings = list(ctx.warnings)
            plan.assumptions = list(ctx.assumptions)
            return plan

        actions = [
            action(
                "entra.delete_user", "entra", self.hub.entra.delete_user,
                description=(
                    f"Delete {user.display_name} (left {leave_dt.date().isoformat()}, "
                    f"{retention}-day retention elapsed)"
                ),
                target=user.upn or user.email,
                risk=RiskLevel.CRITICAL,
                reversible=False,
                user_id=user.external_id,
            )
            for user, leave_dt in eligible
        ]
        plan.add(
            step(
                1, "delete_expired_leavers", "entra", *actions,
                description=f"{len(actions)} account(s) past the {retention}-day retention window.",
                requires_approval=True,
            )
        )
        plan.assumptions = list(ctx.assumptions)
        plan.warnings = list(ctx.warnings)
        return plan
