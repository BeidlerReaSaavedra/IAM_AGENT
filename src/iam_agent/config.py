"""Central configuration for the IAM Agent.

All settings are read from environment variables (optionally via a `.env` file)
with the ``IAM_`` prefix. Nothing here holds secrets by default: an unconfigured
deployment boots in ``mock`` mode so the whole system can be exercised safely.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from functools import lru_cache
from typing import Annotated, Literal

from pydantic import BeforeValidator, Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# --------------------------------------------------------------------------- #
# Enums / type aliases
# --------------------------------------------------------------------------- #

Backend = Literal["live", "mock"]
"""``live`` talks to the real vendor APIs, ``mock`` uses the in-memory simulator."""

ExecutionMode = Literal["dry_run", "approval_required", "autonomous"]
"""Global safety posture.

* ``dry_run``           - plan only, never write.
* ``approval_required`` - reads are live; every write waits for a human (default).
* ``autonomous``        - writes execute immediately for risk <= AUTONOMOUS_MAX_RISK.
"""

RiskLevel = Literal["low", "medium", "high", "critical"]

RISK_ORDER: dict[str, int] = {"low": 1, "medium": 2, "high": 3, "critical": 4}


# --------------------------------------------------------------------------- #
# Per-platform settings
# --------------------------------------------------------------------------- #


def split_csv(value: object) -> object:
    """Coerce an environment variable into a list of strings.

    Env vars are strings, so a list setting arrives as ``"a,b,c"`` - or, very
    commonly, as ``""`` when the line is present in a copied `.env.example` but
    left unfilled. Without this, an empty value raises a validation error at
    startup, which is a bad failure mode for a config file that ships with empty
    placeholders.
    """
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    return value


#: List setting that tolerates comma-separated and empty environment values.
#:
#: ``NoDecode`` is load-bearing: pydantic-settings treats a nested list field as
#: "complex" and runs ``json.loads`` on the raw environment value *before* any
#: validator sees it, so ``IAM_M365__DEFAULT_LICENSE_SKUS=ENTERPRISEPACK,EMS``
#: raised a SettingsError at import time. Disabling the decode lets ``split_csv``
#: handle it, which is what an operator writing a .env actually expects.
#:
#: Use this for every ``list[str]`` in this module so a new field cannot forget it.
StringList = Annotated[list[str], NoDecode, BeforeValidator(split_csv)]


class EntraSettings(BaseSettings):
    """Azure Entra ID (Microsoft Graph) - identity plane."""

    model_config = SettingsConfigDict(env_prefix="IAM_ENTRA_", extra="ignore")

    enabled: bool = False
    backend: Backend = "mock"

    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    """Client secret OR certificate; prefer the certificate for production."""
    certificate_path: str | None = None
    certificate_thumbprint: str | None = None
    certificate_password: str | None = None

    graph_base_url: str = "https://graph.microsoft.com"
    graph_version: str = "v1.0"
    authority: str = ""

    # Scopes requested via client-credentials flow (application permissions).
    scopes: StringList = Field(default_factory=lambda: ["https://graph.microsoft.com/.default"])

    # Optional: pin the domain used to build userPrincipalNames.
    primary_domain: str = ""

    # Optional: Entra ID Governance Lifecycle Workflows.
    enable_lifecycle_workflows: bool = True

    @field_validator("authority", mode="before")
    @classmethod
    def _blank_to_none(cls, v: str) -> str:
        return v or ""

    def resolved_authority(self) -> str:
        return self.authority or f"https://login.microsoftonline.com/{self.tenant_id}"

    @property
    def graph_url(self) -> str:
        return f"{self.graph_base_url.rstrip('/')}/{self.graph_version.strip('/')}"


class M365Settings(BaseSettings):
    """Microsoft 365 service administration (Exchange Online, Teams, SharePoint, licenses).

    Shares the same app registration as Entra by default but can point at its own.
    """

    model_config = SettingsConfigDict(env_prefix="IAM_M365_", extra="ignore")

    enabled: bool = False
    backend: Backend = "mock"

    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    certificate_path: str | None = None
    certificate_thumbprint: str | None = None
    certificate_password: str | None = None

    graph_base_url: str = "https://graph.microsoft.com"
    graph_version: str = "v1.0"

    # Exchange Online PowerShell / REST bridge (optional, used only when set).
    exchange_powershell_endpoint: str = "https://outlook.office365.com/powershell-liveid/"

    # Default mailbox conversion target on offboarding.
    convert_mailbox_to_shared: bool = True
    shared_mailbox_retention_days: int = 90

    # Default licence SKUs applied on onboarding (SKU part numbers, e.g. "ENTERPRISEPACK").
    default_license_skus: StringList = Field(default_factory=list)

    @property
    def graph_url(self) -> str:
        return f"{self.graph_base_url.rstrip('/')}/{self.graph_version.strip('/')}"


class ActiveDirectorySettings(BaseSettings):
    """On-premises Active Directory Domain Services via LDAP/LDAPS."""

    model_config = SettingsConfigDict(env_prefix="IAM_AD_", extra="ignore")

    enabled: bool = False
    backend: Backend = "mock"

    servers: StringList = Field(default_factory=list)
    """Domain controllers, e.g. ``["dc01.corp.local", "dc02.corp.local"]``."""
    port: int = 636
    use_ssl: bool = True
    get_info: bool = True

    bind_user: str = ""
    """``CORP\\svc-iam`` or ``svc-iam@corp.local`` or a full DN."""
    bind_password: str = ""

    base_dn: str = ""
    """e.g. ``DC=corp,DC=local``."""
    users_ou: str = ""
    """e.g. ``OU=Usuarios,OU=CORP,DC=corp,DC=local``. Falls back to base_dn."""
    groups_ou: str = ""
    disabled_ou: str = ""
    """Optional OU where disabled/leaver accounts are moved."""

    domain_netbios: str = ""
    upn_suffix: str = ""

    # TLS trust
    tls_validate: bool = True
    ca_certs_file: str | None = None

    connect_timeout: int = 10
    receive_timeout: int = 30

    # Safety: never delete an AD object by default, disable + move instead.
    allow_hard_delete: bool = False


class Action1Settings(BaseSettings):
    """Action1 RMM - Windows/macOS/Linux endpoint management and patching."""

    model_config = SettingsConfigDict(env_prefix="IAM_ACTION1_", extra="ignore")

    enabled: bool = False
    backend: Backend = "mock"

    client_id: str = ""
    client_secret: str = ""

    region: Literal["north_america", "europe", "australia"] = "europe"
    base_url: str = ""
    """Overrides ``region`` when set."""

    organization_id: str = ""
    """Optional pin; otherwise the first organization is auto-discovered."""

    token_url_path: str = "oauth2/token"
    token_ttl_seconds: int = 3600

    # Endpoint group used for new joiners / leavers.
    joiner_group_id: str = ""
    leaver_group_id: str = ""

    # Automations that may be launched (must pre-exist in the Action1 console).
    onboarding_automation_id: str = ""
    offboarding_automation_id: str = ""

    # Remote actions considered destructive -> always gated.
    allow_remote_reboot: bool = False
    allow_remote_shutdown: bool = False

    _REGION_HOSTS = {
        "north_america": "https://app.action1.com/api/3.0",
        "europe": "https://app.eu.action1.com/api/3.0",
        "australia": "https://app.au.action1.com/api/3.0",
    }

    @property
    def api_base(self) -> str:
        if self.base_url:
            return self.base_url.rstrip("/")
        return self._REGION_HOSTS.get(self.region, self._REGION_HOSTS["europe"])


class ScalefusionSettings(BaseSettings):
    """Scalefusion UEM/MDM - mobile, rugged, kiosk and desktop device management."""

    model_config = SettingsConfigDict(env_prefix="IAM_SCALEFUSION_", extra="ignore")

    enabled: bool = False
    backend: Backend = "mock"

    api_key: str = ""
    base_url: str = "https://api.scalefusion.com"

    # Scalefusion documents 30 requests/minute and 43200/day.
    rate_limit_per_minute: int = 30
    request_timeout: float = 30.0

    # Which header carries the key. Scalefusion's Developer API accepts the
    # bearer form; override to "api_key" if your account/plan differs.
    auth_header_name: str = "Authorization"
    auth_header_prefix: str = "Bearer "

    # API version segment used for reads (v2 where available, v1 otherwise).
    devices_api_version: str = "v2"

    device_profile_id: str = ""
    """Default profile applied to newly enrolled joiner devices."""
    leaver_device_profile_id: str = ""
    """Restrictive profile applied during offboarding before wipe."""
    device_group_id: str = ""

    # Destructive operations - always gated by policy, never autonomous.
    allow_wipe: bool = True
    allow_retire: bool = True


class AgentSettings(BaseSettings):
    """Claude agent / Anthropic API settings for the autonomous orchestrator."""

    model_config = SettingsConfigDict(env_prefix="IAM_CLAUDE_", extra="ignore")

    enabled: bool = False
    api_key: str = ""
    model: str = "claude-sonnet-4-5"
    max_tokens: int = 8192
    temperature: float = 0.0
    """Keep at 0 for deterministic infrastructure work."""
    system_prompt_path: str = "config/system_prompt.md"
    max_turns: int = 25


class ApprovalSettings(BaseSettings):
    """Human-in-the-loop approval gate configuration."""

    model_config = SettingsConfigDict(env_prefix="IAM_APPROVAL_", extra="ignore")

    default_mode: ExecutionMode = "approval_required"
    autonomous_max_risk: RiskLevel = "low"
    """In ``autonomous`` mode, only actions at or below this risk run unattended."""

    request_timeout_minutes: int = 60
    """A pending approval expires after this many minutes."""

    storage_path: str = "data/approvals.jsonl"
    require_second_approver_for_critical: bool = True

    # Optional notification webhook (Teams/Slack/PagerDuty) for new requests.
    notify_webhook_url: str = ""


class AuditSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IAM_AUDIT_", extra="ignore")

    log_path: str = "data/audit.jsonl"
    run_store_path: str = "data/runs"
    include_request_payloads: bool = True
    redact_fields: StringList = Field(
        default_factory=lambda: [
            "password",
            "client_secret",
            "api_key",
            "certificate_password",
            "bind_password",
            "access_token",
            "refresh_token",
            "temporaryAccessPass",
        ]
    )


class MockSettings(BaseSettings):
    """The simulator backend used when a platform has no live credentials."""

    model_config = SettingsConfigDict(env_prefix="IAM_MOCK_", extra="ignore")

    persist: bool = True
    """Write the simulated estate to disk so separate processes share it.

    Essential for the CLI, where ``iam-agent onboard --execute`` and the later
    ``iam-agent approvals decide`` are different processes: without this the
    second one has never heard of the user the first one created. Turn it off for
    throwaway single-process runs or in tests that want a pristine estate.
    """

    persist_path: str = "data/mock_estate.json"
    """Where the simulated estate lives. Treat as disposable, never as a record."""


class APISettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="IAM_API_", extra="ignore")

    host: str = "0.0.0.0"
    port: int = 8000
    cors_origins: StringList = Field(default_factory=lambda: ["*"])
    api_token: str = ""
    """Shared bearer token protecting the control-plane API. Empty disables auth."""

    # Webhook signing secrets for inbound triggers.
    scalefusion_webhook_secret: str = ""
    hr_webhook_secret: str = ""


# --------------------------------------------------------------------------- #
# Root settings
# --------------------------------------------------------------------------- #


class Settings(BaseSettings):
    """Root configuration object."""

    model_config = SettingsConfigDict(env_prefix="IAM_", env_nested_delimiter="__", extra="ignore")

    environment: Literal["development", "staging", "production"] = "development"
    log_level: str = "INFO"

    # Global kill-switch: when True nothing may write, regardless of other flags.
    global_dry_run: bool = True

    entra: EntraSettings = Field(default_factory=EntraSettings)
    m365: M365Settings = Field(default_factory=M365Settings)
    # Named `ad`, not `active_directory`, and that naming is load-bearing.
    #
    # Nested env vars resolve by ROOT FIELD NAME, not by the sub-model's
    # env_prefix. For every other section the two coincide, so both
    # `IAM_ENTRA__ENABLED` and `IAM_ENTRA_ENABLED` work. With the field called
    # `active_directory` and the prefix `IAM_AD_`, they did not: `IAM_AD__BASE_DN`
    # - the form everybody writes by analogy - silently did nothing, and
    # `validation_alias` does not help, because pydantic-settings matches nested
    # env vars before aliases are consulted.
    #
    # A silently ignored setting is dangerous here in one specific direction:
    # `IAM_ENTRA__ENABLED=true` not applying means the agent talks to the
    # simulator while the operator believes it is talking to their tenant.
    ad: ActiveDirectorySettings = Field(default_factory=ActiveDirectorySettings)
    action1: Action1Settings = Field(default_factory=Action1Settings)
    scalefusion: ScalefusionSettings = Field(default_factory=ScalefusionSettings)

    claude: AgentSettings = Field(default_factory=AgentSettings)
    approval: ApprovalSettings = Field(default_factory=ApprovalSettings)
    audit: AuditSettings = Field(default_factory=AuditSettings)
    api: APISettings = Field(default_factory=APISettings)
    mock: MockSettings = Field(default_factory=MockSettings)

    # ---- helpers --------------------------------------------------------- #

    def platform_backends(self) -> dict[str, Backend]:
        return {
            "entra": self.entra.backend if self.entra.enabled else "mock",
            "m365": self.m365.backend if self.m365.enabled else "mock",
            "active_directory": self.active_directory.backend if self.active_directory.enabled else "mock",
            "action1": self.action1.backend if self.action1.enabled else "mock",
            "scalefusion": self.scalefusion.backend if self.scalefusion.enabled else "mock",
        }

    @property
    def active_directory(self) -> ActiveDirectorySettings:
        """Alias for :attr:`ad`.

        Kept because `settings.active_directory` reads better at call sites and
        was the original name. The *field* is `ad` so that `IAM_AD__<FIELD>`
        resolves - see the comment on the field.
        """
        return self.ad

    def unrecognized_env_vars(self, environ: Mapping[str, str] | None = None) -> list[str]:
        """Environment variables that look like ours but configure nothing.

        A typo in a setting name does not fail loudly - it is simply ignored, and
        the field keeps its default. For most software that is an annoyance; for
        an identity agent it is a safety problem, because the defaults are the
        *safe* ones (dry run, mock backend, no hard deletes). An operator who
        believes they enabled a live connector and actually did not will read
        simulator output as production truth.

        So we enumerate the names we would have accepted and report anything that
        starts with ``IAM_`` and is not among them.
        """
        env = os.environ if environ is None else environ
        recognised: set[str] = set()

        for root_name, root_field in type(self).model_fields.items():
            recognised.add(f"IAM_{root_name.upper()}")
            sub_model = root_field.annotation
            sub_fields = getattr(sub_model, "model_fields", None)
            if not sub_fields:
                continue
            prefix = str(getattr(sub_model, "model_config", {}).get("env_prefix", "")).upper()
            for sub_name in sub_fields:
                # Root-field form: IAM_<ROOT>__<FIELD>
                recognised.add(f"IAM_{root_name.upper()}__{sub_name.upper()}")
                # Sub-model prefix form: IAM_ENTRA_<FIELD>
                if prefix:
                    recognised.add(f"{prefix}{sub_name.upper()}")

        return sorted(
            key for key in env
            if key.upper().startswith("IAM_") and key.upper() not in recognised
        )

    def platform_backends_live(self) -> list[str]:
        """Platforms that will be talked to for real.

        Surfaced to the agent and to operators because the difference between
        "this ran against your tenant" and "this ran against a simulator" is the
        single most important fact about any result this system produces.
        """
        return sorted(p for p, b in self.platform_backends().items() if b == "live")

    def platform_backends_mock(self) -> list[str]:
        """Platforms currently answered by the simulator."""
        return sorted(p for p, b in self.platform_backends().items() if b != "live")

    def effective_mode(self) -> ExecutionMode:
        """The global dry-run flag always wins over a permissive mode."""
        if self.global_dry_run:
            return "dry_run"
        return self.approval.default_mode

    def describe(self) -> dict[str, object]:
        """Non-sensitive summary, safe to log or return from the API."""
        return {
            "environment": self.environment,
            "global_dry_run": self.global_dry_run,
            "effective_mode": self.effective_mode(),
            "approval_mode": self.approval.default_mode,
            "autonomous_max_risk": self.approval.autonomous_max_risk,
            "backends": self.platform_backends(),
            "platforms_enabled": {
                "entra": self.entra.enabled,
                "m365": self.m365.enabled,
                "active_directory": self.active_directory.enabled,
                "action1": self.action1.enabled,
                "scalefusion": self.scalefusion.enabled,
            },
            "claude_model": self.claude.model,
        }


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings singleton. Call ``get_settings.cache_clear()`` in tests."""
    return Settings(_env_file=(".env",))  # type: ignore[call-arg]
