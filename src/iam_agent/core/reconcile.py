"""Cross-platform reconciliation and drift detection.

This is what turns five separate consoles into one coherent picture. Given a
person (by email, username or employee id), it fans out to every connector,
correlates the results, and reports inconsistencies:

* enabled in Entra but disabled on-prem (or vice versa) → sync gap
* an orphaned account with a leave date in the past but still enabled
* devices still enrolled to someone who has left
* a leaver who still holds directory roles or licences
* a mailbox that never got converted / hidden after offboarding

Findings carry a ``recommended_action`` so Claude (or a human) can act on them
directly rather than re-deriving the reasoning.
"""

from __future__ import annotations

import asyncio
from datetime import date, datetime, timedelta, timezone
from typing import Any

from iam_agent.config import Settings
from iam_agent.connectors import ConnectorHub
from iam_agent.core.models import (
    Device,
    DeviceState,
    DirectoryUser,
    DriftFinding,
    DriftReport,
    Employee,
    IdentityRef,
    IdentitySnapshot,
    LifecycleState,
    MailboxInfo,
)


def _safe(value: Any) -> Any:
    """Never let one connector's failure hide the rest of the picture."""
    if isinstance(value, BaseException):
        return None
    return value


class Reconciler:
    """Builds :class:`IdentitySnapshot` objects and diffs them for drift."""

    def __init__(self, hub: ConnectorHub, settings: Settings | None = None) -> None:
        self.hub = hub
        self.settings = settings or hub.settings

    # ------------------------------------------------------------------ #
    # Snapshot building
    # ------------------------------------------------------------------ #

    async def snapshot(
        self,
        identifier: str,
        *,
        include_devices: bool = True,
        include_groups: bool = True,
    ) -> IdentitySnapshot:
        """Gather everything known about one person across all five platforms.

        Failures are collected as warnings instead of aborting: a partial picture
        is far more useful to an operator than an exception.
        """
        warnings: list[str] = []
        employee = Employee(first_name="", last_name="")
        directories: dict[str, DirectoryUser] = {}

        entra_task = asyncio.create_task(self._guard(self.hub.entra.get_user(identifier), warnings, "entra"))
        ad_task = asyncio.create_task(
            self._guard(self.hub.active_directory.get_user(identifier), warnings, "active_directory")
        )

        entra_user = _safe(await entra_task)
        ad_user = _safe(await ad_task)

        if entra_user:
            directories["entra"] = entra_user
        if ad_user:
            directories["active_directory"] = ad_user

        if not directories:
            warnings.append(f"no directory record matched '{identifier}' in Entra or on-prem AD")
            return IdentitySnapshot(employee=employee, warnings=warnings)

        primary = entra_user or ad_user
        assert primary is not None
        employee = self._to_employee(primary, entra_user, ad_user)

        # Devices --------------------------------------------------------- #
        devices: list[Device] = []
        if include_devices:
            needles = {n for n in (employee.email, primary.username, employee.full_name) if n}
            device_tasks = []
            for needle in needles:
                device_tasks.append(
                    asyncio.create_task(
                        self._guard(self.hub.action1.find_endpoints_by_owner(needle), warnings, "action1")
                    )
                )
                device_tasks.append(
                    asyncio.create_task(
                        self._guard(
                            self.hub.scalefusion.find_devices_by_user(needle), warnings, "scalefusion"
                        )
                    )
                )
            results = await asyncio.gather(*device_tasks, return_exceptions=True)
            seen: set[tuple[str, str]] = set()
            for result in results:
                found = _safe(result) or []
                for device in found:
                    key = (device.platform_console, device.external_id)
                    if key not in seen:
                        seen.add(key)
                        devices.append(device)

        # Mailbox --------------------------------------------------------- #
        mailboxes: list[MailboxInfo] = []
        mailbox = _safe(
            await self._guard(self.hub.m365.get_mailbox(primary.external_id), warnings, "m365.mailbox")
        )
        if mailbox:
            mailboxes.append(mailbox)

        # Groups ---------------------------------------------------------- #
        memberships: dict[str, list] = {}
        if include_groups:
            if entra_user:
                groups = _safe(
                    await self._guard(
                        self.hub.entra.get_user_groups(entra_user.external_id), warnings, "entra.groups"
                    )
                )
                memberships["entra"] = groups or []
            if ad_user:
                ad_groups = _safe(
                    await self._guard(
                        self.hub.active_directory.get_user_groups(ad_user.external_id),
                        warnings,
                        "ad.groups",
                    )
                )
                memberships["active_directory"] = ad_groups or []

        # Identities ------------------------------------------------------ #
        identities = []
        if entra_user:
            identities.append(
                IdentityRef(
                    platform="entra",
                    external_id=entra_user.external_id,
                    display_name=entra_user.display_name,
                    extra={"upn": entra_user.upn},
                )
            )
        if ad_user:
            identities.append(
                IdentityRef(
                    platform="active_directory",
                    external_id=ad_user.external_id,
                    display_name=ad_user.display_name,
                    extra={"dn": ad_user.dn, "sam": ad_user.username},
                )
            )
        for device in devices:
            identities.append(
                IdentityRef(
                    platform=device.platform_console,
                    external_id=device.external_id,
                    display_name=device.device_name,
                )
            )
        employee.identities = identities
        employee.devices = [d.to_assignment() for d in devices]

        return IdentitySnapshot(
            employee=employee,
            directories=directories,
            devices=devices,
            mailboxes=mailboxes,
            group_memberships=memberships,
            warnings=warnings,
        )

    async def _guard(self, coro: Any, warnings: list[str], label: str) -> Any:
        """Await a connector call, converting failures into a warning."""
        try:
            return await coro
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"{label}: {type(exc).__name__}: {exc}")
            return None

    def _to_employee(
        self,
        primary: DirectoryUser,
        entra_user: DirectoryUser | None,
        ad_user: DirectoryUser | None,
    ) -> Employee:
        """Merge directory views into one Employee, preferring Entra."""
        src = entra_user or primary
        raw = src.raw or {}

        hire = raw.get("employeeHireDate") or raw.get("employee_hire_date")
        leave = raw.get("employeeLeaveDateTime") or raw.get("employee_leave_date_time")

        state = LifecycleState.ACTIVE
        if not src.enabled:
            state = LifecycleState.LEAVER
        elif leave and _as_date(leave) and _as_date(leave) < date.today():
            # Enabled with a leave date already passed: still ACTIVE by flag but
            # the drift detector will call this out as an orphan.
            state = LifecycleState.ACTIVE

        manager_email = ""
        if isinstance(raw.get("manager"), dict):
            manager_email = raw["manager"].get("mail", "") or ""

        display_parts = (src.display_name or "").split(" ")
        first_name = src.first_name or (display_parts[0] if display_parts else "")
        last_name = src.last_name or (" ".join(display_parts[1:]) if len(display_parts) > 1 else "")

        return Employee(
            employee_id=src.employee_id,
            first_name=first_name,
            last_name=last_name,
            display_name=src.display_name,
            email=src.email,
            username=src.username,
            upn=src.upn,
            department=src.department,
            job_title=src.job_title,
            company=src.company,
            office_location=str(raw.get("officeLocation") or raw.get("office_location") or ""),
            country=str(raw.get("country") or ""),
            lifecycle_state=state,
            hire_date=_as_date(hire),
            leave_date=_as_date(leave),
            manager=_manager_model(manager_email, src.manager_id),
            license_skus=src.license_skus,
            attributes={
                "on_premises_sync": src.on_premises_sync,
                "ad_dn": ad_user.dn if ad_user else "",
                "ad_enabled": ad_user.enabled if ad_user else None,
                "entra_enabled": entra_user.enabled if entra_user else None,
                "last_sign_in": src.last_sign_in.isoformat() if src.last_sign_in else None,
                "mfa_registered": src.mfa_registered,
            },
        )

    # ------------------------------------------------------------------ #
    # Drift detection
    # ------------------------------------------------------------------ #

    async def detect_drift_for(self, identifier: str) -> tuple[IdentitySnapshot, list[DriftFinding]]:
        snapshot = await self.snapshot(identifier)
        return snapshot, self.analyze(snapshot)

    def analyze(self, snapshot: IdentitySnapshot) -> list[DriftFinding]:
        """Pure function over a snapshot - easy to unit test."""
        findings: list[DriftFinding] = []
        employee = snapshot.employee
        entra = snapshot.entra
        ad = snapshot.on_prem
        who = employee.full_name or employee.email or "unknown"

        # 1. Entra <-> AD sync gap ----------------------------------------- #
        if entra and ad and entra.enabled != ad.enabled:
            if entra.on_premises_sync:
                findings.append(
                    DriftFinding(
                        severity="high",
                        category="sync_gap",
                        subject=who,
                        platforms=["entra", "active_directory"],
                        description=(
                            f"Entra says accountEnabled={entra.enabled} but on-prem AD says "
                            f"enabled={ad.enabled}, and the account is sync-managed. The "
                            "authoritative source is on-prem; Entra Connect will revert your change."
                        ),
                        recommended_action=(
                            "Apply the state change in Active Directory (source of authority) and "
                            "let Entra Connect propagate it, or run a delta sync manually."
                        ),
                    )
                )
            else:
                findings.append(
                    DriftFinding(
                        severity="medium",
                        category="state_mismatch",
                        subject=who,
                        platforms=["entra", "active_directory"],
                        description=(
                            f"Cloud-only flag disagrees with on-prem (entra={entra.enabled}, ad={ad.enabled}) "
                            "but the account is not sync-managed - these are two independent objects."
                        ),
                        recommended_action="Confirm which object the user actually signs in with.",
                    )
                )

        # 2. Orphan: enabled with a past leave date ------------------------- #
        if employee.leave_date and employee.leave_date < date.today():
            days_over = (date.today() - employee.leave_date).days
            if entra and entra.enabled:
                findings.append(
                    DriftFinding(
                        severity="critical",
                        category="orphaned_access",
                        subject=who,
                        platforms=["entra"],
                        description=(
                            f"Leave date {employee.leave_date.isoformat()} is {days_over} day(s) in the "
                            "past but the Entra account is still ENABLED."
                        ),
                        recommended_action=(
                            "Run the offboarding workflow immediately. Last sign-in: "
                            f"{entra.last_sign_in.isoformat() if entra.last_sign_in else 'unknown'}."
                        ),
                    )
                )
            if ad and ad.enabled:
                findings.append(
                    DriftFinding(
                        severity="critical",
                        category="orphaned_access",
                        subject=who,
                        platforms=["active_directory"],
                        description=f"On-prem AD account still enabled {days_over} day(s) after the leave date.",
                        recommended_action="Disable the AD account and move it to the leaver OU.",
                    )
                )

        # 3. Devices still bound to a leaver -------------------------------- #
        if employee.is_leaver() or (employee.leave_date and employee.leave_date < date.today()):
            for device in snapshot.devices:
                if device.state in (DeviceState.WIPED, DeviceState.RETIRED, DeviceState.UNMANAGED):
                    continue
                findings.append(
                    DriftFinding(
                        severity="high",
                        category="stale_device",
                        subject=f"{who} / {device.device_name}",
                        platforms=[device.platform_console],
                        description=(
                            f"{device.device_name} ({device.device_platform.value}) is still enrolled and "
                            f"assigned, state={device.state.value}."
                        ),
                        recommended_action=(
                            "Retire the device (corporate) or unenrol the work profile (BYOD) "
                            "and remove it from the user's device group."
                            if device.ownership.value == "byod"
                            else "Lock, wipe if unrecovered, then retire the device."
                        ),
                    )
                )

        # 4. Licences still assigned to a leaver ---------------------------- #
        if employee.is_leaver() and entra and entra.license_skus:
            findings.append(
                DriftFinding(
                    severity="medium",
                    category="wasted_licence",
                    subject=who,
                    platforms=["entra", "m365"],
                    description=f"Leaver still consumes {len(entra.license_skus)} licence SKU(s): {entra.license_skus}.",
                    recommended_action=(
                        "Convert the mailbox to shared first (so mail is retained without a licence), "
                        "then remove all licences."
                    ),
                )
            )

        # 5. Mailbox not converted after offboarding ------------------------ #
        if employee.is_leaver() and snapshot.mailboxes:
            for mailbox in snapshot.mailboxes:
                if mailbox.mailbox_type == "user" and not mailbox.hidden_from_gal:
                    findings.append(
                        DriftFinding(
                            severity="medium",
                            category="mailbox_state",
                            subject=f"{who} / {mailbox.email}",
                            platforms=["m365"],
                            description=(
                                "Mailbox is still a licensed user mailbox and visible in the GAL "
                                "after offboarding."
                            ),
                            recommended_action=(
                                "Convert to shared mailbox, hide from the GAL, grant the manager "
                                "FullAccess, then remove the licence."
                            ),
                        )
                    )

        # 6. Group memberships left behind ---------------------------------- #
        if employee.is_leaver():
            for platform, groups in snapshot.group_memberships.items():
                if groups:
                    names = [g.display_name for g in groups][:10]
                    findings.append(
                        DriftFinding(
                            severity="high",
                            category="residual_access",
                            subject=who,
                            platforms=[platform],
                            description=f"Still a member of {len(groups)} group(s): {names}",
                            recommended_action="Remove all group and Teams memberships.",
                        )
                    )

        # 7. Unpatched endpoints -------------------------------------------- #
        for device in snapshot.devices:
            if device.missing_updates >= 10 or device.critical_vulnerabilities > 0:
                findings.append(
                    DriftFinding(
                        severity="high" if device.critical_vulnerabilities else "medium",
                        category="endpoint_risk",
                        subject=f"{who} / {device.device_name}",
                        platforms=[device.platform_console],
                        description=(
                            f"{device.missing_updates} missing update(s) and "
                            f"{device.critical_vulnerabilities} critical vulnerability/ies."
                        ),
                        recommended_action="Run the Action1 patching automation for this endpoint.",
                    )
                )

        # 8. No MFA on an active account ------------------------------------ #
        if entra and entra.enabled and entra.mfa_registered is False:
            findings.append(
                DriftFinding(
                    severity="high",
                    category="weak_authentication",
                    subject=who,
                    platforms=["entra"],
                    description="Account is enabled but has no strong authentication method registered.",
                    recommended_action=(
                        "Issue a Temporary Access Pass and require MFA registration before first use."
                    ),
                )
            )

        # 9. Dormant account ------------------------------------------------- #
        if entra and entra.enabled and entra.last_sign_in:
            idle = datetime.now(timezone.utc) - entra.last_sign_in
            if idle > timedelta(days=90):
                findings.append(
                    DriftFinding(
                        severity="medium",
                        category="dormant_account",
                        subject=who,
                        platforms=["entra"],
                        description=f"Enabled but no sign-in for {idle.days} day(s).",
                        recommended_action="Confirm with the manager whether the account is still required.",
                    )
                )

        # 10. Unowned devices ----------------------------------------------- #
        for device in snapshot.devices:
            if not device.assigned_email and not device.assigned_user:
                findings.append(
                    DriftFinding(
                        severity="medium",
                        category="unowned_asset",
                        subject=device.device_name,
                        platforms=[device.platform_console],
                        description="Device is managed but has no assigned owner.",
                        recommended_action="Assign an owner or retire the device.",
                    )
                )

        # Sort by severity so the worst findings surface first.
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda f: order.get(f.severity, 4))
        return findings

    # ------------------------------------------------------------------ #
    # Fleet-wide sweep
    # ------------------------------------------------------------------ #

    async def audit_fleet(
        self,
        *,
        include_unowned_devices: bool = True,
        limit: int = 200,
    ) -> DriftReport:
        """Sweep every enabled directory user and report estate-wide drift.

        Used by the scheduled reconciliation job and by the ``audit`` CLI
        command. Concurrency is bounded to stay inside vendor rate limits.
        """
        findings: list[DriftFinding] = []

        users = _safe(await self._guard(self.hub.entra.list_users(only_enabled=None, top=limit), [], "entra.list")) or []
        semaphore = asyncio.Semaphore(4)

        async def one(user: DirectoryUser) -> list[DriftFinding]:
            async with semaphore:
                snapshot = await self.snapshot(user.external_id, include_devices=True, include_groups=False)
                return self.analyze(snapshot)

        results = await asyncio.gather(*(one(u) for u in users), return_exceptions=True)
        for result in results:
            if isinstance(result, list):
                findings.extend(result)

        if include_unowned_devices:
            endpoints = _safe(await self._guard(self.hub.action1.list_endpoints(), [], "action1.list")) or []
            mobiles = _safe(await self._guard(self.hub.scalefusion.list_devices(), [], "scalefusion.list")) or []
            for device in list(endpoints) + list(mobiles):
                if not device.assigned_email and not device.assigned_user:
                    findings.append(
                        DriftFinding(
                            severity="medium",
                            category="unowned_asset",
                            subject=device.device_name or device.external_id,
                            platforms=[device.platform_console],
                            description=(
                                f"Managed device with no owner "
                                f"({device.device_platform.value}, state={device.state.value}, "
                                f"missing_updates={device.missing_updates})."
                            ),
                            recommended_action="Assign an owner or retire the device.",
                        )
                    )

        return DriftReport(findings=findings)


def _as_date(value: Any) -> date | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(text[:10])
        except ValueError:
            return None


def _manager_model(email: str, entra_id: str):
    from iam_agent.core.models import Manager

    if not email and not entra_id:
        return None
    return Manager(email=email, entra_id=entra_id)
