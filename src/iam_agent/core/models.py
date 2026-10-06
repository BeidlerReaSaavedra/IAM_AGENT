"""Domain models shared by every connector, workflow and interface.

The agent never talks about "an Entra user" or "a Scalefusion device" directly:
it works with these normalised objects and each connector maps them onto its own
vendor schema. That is what makes a single onboarding playbook able to drive
five different platforms.
"""

from __future__ import annotations

import hashlib
import unicodedata
from datetime import UTC, date, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _utcnow() -> datetime:
    return datetime.now(UTC)


def normalize_logon(value: str) -> str:
    """Fold a name into a safe Windows logon token.

    ``Núria Serra`` → ``nuria``: strip diacritics, drop anything that is not
    ``[a-z0-9._-]``, lowercase. Empty input yields an empty string so callers can
    fall back to their own default.
    """
    if not value:
        return ""
    decomposed = unicodedata.normalize("NFKD", value)
    ascii_only = "".join(c for c in decomposed if not unicodedata.combining(c))
    cleaned = "".join(c if (c.isalnum() or c in "._-") else "" for c in ascii_only.lower())
    return cleaned.strip("._-")


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class LifecycleState(StrEnum):
    """Canonical employment state driving every workflow decision."""

    PRE_HIRE = "pre_hire"
    ACTIVE = "active"
    ON_LEAVE = "on_leave"
    TRANSFERRING = "transferring"
    LEAVER = "leaver"
    OFFBOARDED = "offboarded"


class EmploymentType(StrEnum):
    FULL_TIME = "full_time"
    PART_TIME = "part_time"
    CONTRACTOR = "contractor"
    INTERN = "intern"
    SERVICE_ACCOUNT = "service_account"
    VIP = "vip"


class DevicePlatform(StrEnum):
    WINDOWS = "windows"
    MACOS = "macos"
    LINUX = "linux"
    ANDROID = "android"
    IOS = "ios"
    IPADOS = "ipados"
    CHROMEOS = "chromeos"
    UNKNOWN = "unknown"


class DeviceOwnership(StrEnum):
    CORPORATE = "corporate"
    BYOD = "byod"
    UNKNOWN = "unknown"


class DeviceState(StrEnum):
    ENROLLED = "enrolled"
    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    LOST = "lost"
    PENDING_WIPE = "pending_wipe"
    WIPED = "wiped"
    RETIRED = "retired"
    UNMANAGED = "unmanaged"


class AccessState(StrEnum):
    ENABLED = "enabled"
    DISABLED = "disabled"
    PENDING = "pending"
    QUARANTINED = "quarantined"
    DELETED = "deleted"


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #


class IdentityRef(BaseModel):
    """A handle to a user object inside one specific platform."""

    model_config = ConfigDict(frozen=True)

    platform: str
    """One of: entra, m365, active_directory, action1, scalefusion."""
    external_id: str
    """The vendor's primary key (object id, SID, sAMAccountName, device id...)."""
    display_name: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.platform}:{self.external_id}"


class Manager(BaseModel):
    display_name: str = ""
    email: str = ""
    entra_id: str = ""


class Employee(BaseModel):
    """The single source of truth for a person moving through the lifecycle.

    Everything a workflow needs is here, so playbooks stay declarative and the
    same ``Employee`` can drive Entra, M365, on-prem AD, Action1 and Scalefusion.
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    # --- Who ----------------------------------------------------------- #
    employee_id: str = ""
    """Stable HR identifier. Used as the idempotency key for workflows."""
    first_name: str
    last_name: str
    display_name: str = ""
    preferred_name: str = ""

    # --- Contact -------------------------------------------------------- #
    email: str = ""
    personal_email: str = ""
    mobile_phone: str = ""
    office_phone: str = ""

    # --- Organisation --------------------------------------------------- #
    department: str = ""
    job_title: str = ""
    company: str = ""
    office_location: str = ""
    country: str = ""
    cost_center: str = ""
    manager: Manager | None = None

    employment_type: EmploymentType = EmploymentType.FULL_TIME
    worker_id: str = ""

    # --- Lifecycle ------------------------------------------------------ #
    lifecycle_state: LifecycleState = LifecycleState.PRE_HIRE
    hire_date: date | None = None
    leave_date: date | None = None
    """Last working day. Drives scheduled offboarding."""
    termination_reason: str = ""
    is_voluntary_exit: bool | None = None

    # --- Access provisioning inputs ------------------------------------- #
    username: str = ""
    """Requested sAMAccountName / mailNickname. Auto-derived when empty."""
    upn: str = ""
    password: str | None = Field(default=None, exclude=True, repr=False)
    """Never persisted and never rendered: used only to hand over credentials.

    ``exclude=True`` keeps it out of ``model_dump()``, ``repr=False`` keeps it out
    of logs that stringify the model, and :mod:`iam_agent.core.redact` catches it
    when it travels inside ``Action.params``.
    """
    require_mfa_registration: bool = True
    groups: list[str] = Field(default_factory=list)
    """Group display names or IDs to grant."""
    teams: list[str] = Field(default_factory=list)
    license_skus: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    """Entra directory role names, e.g. ``User Administrator``."""

    # --- Endpoints ------------------------------------------------------ #
    devices: list[DeviceAssignment] = Field(default_factory=list)

    # --- Correlation ---------------------------------------------------- #
    identities: list[IdentityRef] = Field(default_factory=list)
    """Discovered platform handles, filled in by the reconciliation step."""
    attributes: dict[str, Any] = Field(default_factory=dict)
    """Free-form bag for HR-specific fields."""

    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)

    # ---- derived ------------------------------------------------------- #

    @field_validator("email", "personal_email", mode="before")
    @classmethod
    def _lower_email(cls, v: Any) -> Any:
        return v.strip().lower() if isinstance(v, str) else v

    @property
    def full_name(self) -> str:
        if self.display_name:
            return self.display_name
        return f"{self.first_name} {self.last_name}".strip()

    @property
    def correlation_key(self) -> str:
        """Stable key used to find the same human across all five platforms."""
        raw = (self.employee_id or self.email or f"{self.full_name}").strip().lower()
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

    def suggested_username(self, domain: str = "") -> str:
        """Derive a ``jsmith``-style logon name when HR did not supply one.

        Accents are folded away (``Ferrà`` → ``ferra``) on purpose: sAMAccountName
        and NetBIOS-era systems handle non-ASCII badly, and a Catalan or Spanish
        surname would otherwise produce a logon name that breaks print servers,
        legacy LOB apps and SMB paths. The UPN and display name keep the accents.
        """
        if self.username:
            return normalize_logon(self.username)
        if self.email and "@" in self.email:
            return normalize_logon(self.email.split("@", 1)[0])
        first = normalize_logon(self.first_name)
        last = normalize_logon(self.last_name)
        base = f"{first[:1]}{last}"[:20] if first and last else (last or first or "user")
        return base or "user"

    def suggested_upn(self, domain: str) -> str:
        if self.upn:
            return self.upn
        if self.email and domain and self.email.endswith(f"@{domain.lower()}"):
            return self.email
        if not domain:
            return self.email
        return f"{self.suggested_username(domain)}@{domain}"

    def is_leaver(self) -> bool:
        return self.lifecycle_state in (LifecycleState.LEAVER, LifecycleState.OFFBOARDED)

    def days_until_leave(self, today: date | None = None) -> int | None:
        if not self.leave_date:
            return None
        return (self.leave_date - (today or date.today())).days

    def identity_for(self, platform: str) -> IdentityRef | None:
        return next((i for i in self.identities if i.platform == platform), None)


class DeviceAssignment(BaseModel):
    """A device that should be bound to (or released from) an employee."""

    model_config = ConfigDict(str_strip_whitespace=True)

    asset_tag: str = ""
    serial_number: str = ""
    device_name: str = ""
    platform: DevicePlatform = DevicePlatform.UNKNOWN
    ownership: DeviceOwnership = DeviceOwnership.CORPORATE
    model: str = ""
    manufacturer: str = ""

    managed_by: list[str] = Field(default_factory=list)
    """Which consoles manage it: ``action1``, ``scalefusion``, ``intune``..."""

    action1_endpoint_id: str = ""
    scalefusion_device_id: str = ""
    entra_device_id: str = ""

    device_profile_id: str = ""
    device_group_id: str = ""

    state: DeviceState = DeviceState.ENROLLED
    notes: str = ""

    @property
    def is_mobile(self) -> bool:
        return self.platform in (
            DevicePlatform.ANDROID,
            DevicePlatform.IOS,
            DevicePlatform.IPADOS,
        )

    @property
    def is_desktop(self) -> bool:
        return self.platform in (
            DevicePlatform.WINDOWS,
            DevicePlatform.MACOS,
            DevicePlatform.LINUX,
            DevicePlatform.CHROMEOS,
        )

    def identifier(self) -> str:
        """Best available stable identifier."""
        return (
            self.asset_tag
            or self.serial_number
            or self.scalefusion_device_id
            or self.action1_endpoint_id
            or self.device_name
            or "unknown"
        )


Employee.model_rebuild()


# --------------------------------------------------------------------------- #
# Normalised directory objects
# --------------------------------------------------------------------------- #


class DirectoryUser(BaseModel):
    """A user as seen by *any* directory (Entra, on-prem AD)."""

    platform: str
    external_id: str
    username: str = ""
    upn: str = ""
    email: str = ""
    display_name: str = ""
    first_name: str = ""
    last_name: str = ""
    job_title: str = ""
    department: str = ""
    company: str = ""
    manager_id: str = ""
    dn: str = ""
    enabled: bool = True
    mfa_registered: bool | None = None
    license_skus: list[str] = Field(default_factory=list)
    group_ids: list[str] = Field(default_factory=list)
    employee_id: str = ""
    on_premises_sync: bool = False
    last_sign_in: datetime | None = None
    account_expires: datetime | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def access_state(self) -> AccessState:
        return AccessState.ENABLED if self.enabled else AccessState.DISABLED


class DirectoryGroup(BaseModel):
    platform: str
    external_id: str
    display_name: str
    description: str = ""
    mail: str = ""
    dn: str = ""
    """Distinguished name. The primary key for on-premises AD groups."""
    security_enabled: bool = True
    membership_rule: str = ""
    is_dynamic: bool = False
    is_role_assignable: bool = False
    member_count: int | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class Device(BaseModel):
    """A managed endpoint as seen by *any* UEM console (Action1 / Scalefusion)."""

    platform_console: str
    """``action1`` or ``scalefusion``."""
    external_id: str
    device_name: str = ""
    asset_tag: str = ""
    serial_number: str = ""
    imei: str = ""
    os_name: str = ""
    os_version: str = ""
    device_platform: DevicePlatform = DevicePlatform.UNKNOWN
    manufacturer: str = ""
    model: str = ""
    ownership: DeviceOwnership = DeviceOwnership.UNKNOWN

    state: DeviceState = DeviceState.ENROLLED
    online: bool | None = None
    last_seen: datetime | None = None

    assigned_user: str = ""
    assigned_email: str = ""

    compliance: str = ""
    missing_updates: int = 0
    critical_vulnerabilities: int = 0
    battery_level: int | None = None

    device_group_id: str = ""
    device_profile_id: str = ""

    enrolled_at: datetime | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def healthy(self) -> bool:
        return self.state in (DeviceState.ACTIVE, DeviceState.ENROLLED) and self.missing_updates < 5

    def to_assignment(self) -> DeviceAssignment:
        managed = ["action1"] if self.platform_console == "action1" else ["scalefusion"]
        return DeviceAssignment(
            asset_tag=self.asset_tag,
            serial_number=self.serial_number,
            device_name=self.device_name,
            platform=self.device_platform,
            ownership=self.ownership,
            model=self.model,
            manufacturer=self.manufacturer,
            managed_by=managed,
            action1_endpoint_id=self.external_id if self.platform_console == "action1" else "",
            scalefusion_device_id=self.external_id if self.platform_console == "scalefusion" else "",
            device_profile_id=self.device_profile_id,
            device_group_id=self.device_group_id,
            state=self.state,
        )


class MailboxInfo(BaseModel):
    external_id: str = ""
    email: str = ""
    display_name: str = ""
    mailbox_type: str = "user"
    """``user`` | ``shared`` | ``room`` | ``equipment``."""
    primary_smtp: str = ""
    proxy_addresses: list[str] = Field(default_factory=list)
    total_item_size_mb: float = 0.0
    item_count: int = 0
    hidden_from_gal: bool = False
    litigation_hold: bool = False
    forward_to: str = ""
    delegates: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Cross-platform reconciliation
# --------------------------------------------------------------------------- #


class IdentitySnapshot(BaseModel):
    """Everything the agent knows about one person, gathered from all platforms.

    This is what Claude receives as tool output when reasoning about a user, and
    what the drift detector diffs between runs.
    """

    employee: Employee
    directories: dict[str, DirectoryUser] = Field(default_factory=dict)
    """Keyed by platform (``entra``, ``active_directory``)."""
    devices: list[Device] = Field(default_factory=list)
    mailboxes: list[MailboxInfo] = Field(default_factory=list)
    group_memberships: dict[str, list[DirectoryGroup]] = Field(default_factory=dict)
    collected_at: datetime = Field(default_factory=_utcnow)
    warnings: list[str] = Field(default_factory=list)

    # ---- convenience --------------------------------------------------- #

    @property
    def entra(self) -> DirectoryUser | None:
        return self.directories.get("entra")

    @property
    def on_prem(self) -> DirectoryUser | None:
        return self.directories.get("active_directory")

    def mobile_devices(self) -> list[Device]:
        return [
            d
            for d in self.devices
            if d.device_platform
            in (DevicePlatform.ANDROID, DevicePlatform.IOS, DevicePlatform.IPADOS)
        ]

    def desktop_devices(self) -> list[Device]:
        return [
            d
            for d in self.devices
            if d.device_platform
            in (
                DevicePlatform.WINDOWS,
                DevicePlatform.MACOS,
                DevicePlatform.LINUX,
                DevicePlatform.CHROMEOS,
            )
        ]

    def to_markdown(self) -> str:
        """Human-readable estate report for the CLI, MCP and approval reviews."""
        employee = self.employee
        lines = [
            f"# {employee.full_name or self.identity_hint()}",
            "",
        ]
        facts = [
            ("employee id", employee.employee_id),
            ("e-mail", employee.email),
            ("UPN", employee.upn),
            ("username", employee.username),
            ("department", employee.department),
            ("job title", employee.job_title),
            ("lifecycle", employee.lifecycle_state.value),
            ("employment", employee.employment_type.value),
            ("hire date", employee.hire_date.isoformat() if employee.hire_date else ""),
            ("leave date", employee.leave_date.isoformat() if employee.leave_date else ""),
        ]
        lines += [f"- **{label}:** {value}" for label, value in facts if value]
        if employee.manager and employee.manager.email:
            lines.append(f"- **manager:** {employee.manager.email}")

        if self.directories:
            lines += ["", "## Directory accounts", ""]
            lines.append("| platform | upn / username | enabled | last sign-in | MFA |")
            lines.append("|---|---|---|---|---|")
            for platform, user in self.directories.items():
                lines.append(
                    f"| {platform} | {user.upn or user.username or '—'} "
                    f"| {'✅' if user.enabled else '⛔'} "
                    f"| {user.last_sign_in.strftime('%Y-%m-%d') if user.last_sign_in else '—'} "
                    f"| {'yes' if user.mfa_registered else 'no' if user.mfa_registered is False else '—'} |"
                )

        for platform, groups in self.group_memberships.items():
            if groups:
                lines += ["", f"## Groups ({platform})", ""]
                lines += [f"- {g.display_name}" for g in groups]

        if self.mailboxes:
            lines += ["", "## Mailboxes", ""]
            lines.append("| type | address | hidden | hold |")
            lines.append("|---|---|---|---|")
            for box in self.mailboxes:
                lines.append(
                    f"| {box.mailbox_type} | {box.primary_smtp or '—'} "
                    f"| {'yes' if box.hidden_from_gal else 'no'} "
                    f"| {'yes' if box.litigation_hold else 'no'} |"
                )

        if self.devices:
            lines += ["", "## Devices", ""]
            lines.append("| console | device | platform | owner | state | ownership | compliance |")
            lines.append("|---|---|---|---|---|---|---|")
            for device in self.devices:
                lines.append(
                    f"| {device.platform_console} | {device.device_name or device.serial_number} "
                    f"| {device.device_platform.value} | {device.assigned_email or 'unassigned'} "
                    f"| {device.state.value} | {device.ownership.value} | {device.compliance} |"
                )

        if self.warnings:
            lines += ["", "## Warnings", ""]
            lines += [f"- ⚠️ {w}" for w in self.warnings]

        lines += ["", f"_collected {self.collected_at.strftime('%Y-%m-%d %H:%M UTC')}_"]
        return "\n".join(lines)

    def identity_hint(self) -> str:
        """Best available label when the employee record is empty."""
        for value in (
            self.employee.email,
            self.employee.upn,
            self.employee.username,
            self.employee.employee_id,
        ):
            if value:
                return value
        for user in self.directories.values():
            if user.upn or user.username:
                return user.upn or user.username
        return "unknown identity"

    def summary(self) -> dict[str, Any]:
        """Compact view for logs, audit records and Claude tool results."""
        return {
            "employee_id": self.employee.employee_id,
            "name": self.employee.full_name,
            "email": self.employee.email,
            "lifecycle_state": self.employee.lifecycle_state.value,
            "directories": {
                p: {"enabled": u.enabled, "upn": u.upn, "username": u.username}
                for p, u in self.directories.items()
            },
            "devices": [
                {
                    "console": d.platform_console,
                    "name": d.device_name,
                    "platform": d.device_platform.value,
                    "state": d.state.value,
                }
                for d in self.devices
            ],
            "mailboxes": [
                {"email": m.email, "type": m.mailbox_type, "size_mb": m.total_item_size_mb}
                for m in self.mailboxes
            ],
            "group_count": {k: len(v) for k, v in self.group_memberships.items()},
            "warnings": self.warnings,
        }


class DriftFinding(BaseModel):
    """A single inconsistency detected between platforms."""

    severity: str = "medium"
    category: str = ""
    """e.g. ``orphaned_access``, ``sync_gap``, ``stale_device``."""
    subject: str = ""
    """Who/what the finding is about."""
    description: str = ""
    platforms: list[str] = Field(default_factory=list)
    recommended_action: str = ""


class DriftReport(BaseModel):
    generated_at: datetime = Field(default_factory=_utcnow)
    findings: list[DriftFinding] = Field(default_factory=list)

    def by_severity(self) -> dict[str, list[DriftFinding]]:
        out: dict[str, list[DriftFinding]] = {}
        for f in self.findings:
            out.setdefault(f.severity, []).append(f)
        return out

    @property
    def is_clean(self) -> bool:
        return not any(f.severity in ("high", "critical") for f in self.findings)
