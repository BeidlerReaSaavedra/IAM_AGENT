"""Configuration resolution.

Env-var handling has two failure modes that matter more here than in most
software, because the defaults are the *safe* ones:

* A setting that silently does not apply leaves the agent on the mock backend or
  in dry run while the operator believes they configured production. Reading
  simulator output as production truth is the worst outcome available.
* A list setting given an empty value crashes startup, which is what a freshly
  copied ``.env.example`` used to do.

Both are pinned here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from iam_agent.config import Settings, get_settings, split_csv

REPO_ROOT = Path(__file__).resolve().parents[1]
ENV_EXAMPLE = REPO_ROOT / ".env.example"


@pytest.fixture
def load_env(monkeypatch):
    """Apply a mapping of env vars and rebuild settings from scratch."""

    def _apply(**vars_: str) -> Settings:
        for key in list(vars_):
            if vars_[key] is None:
                monkeypatch.delenv(key, raising=False)
            else:
                monkeypatch.setenv(key, vars_[key])
        get_settings.cache_clear()
        return get_settings()

    yield _apply
    get_settings.cache_clear()


# --------------------------------------------------------------------------- #
# Nested env var spelling
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "var",
    ["IAM_AD__BASE_DN", "IAM_AD_BASE_DN"],
)
def test_active_directory_accepts_both_spellings(load_env, var: str) -> None:
    """`IAM_AD__<FIELD>` is what everybody writes by analogy; it must work.

    Nested env vars resolve by ROOT FIELD NAME, not by the sub-model's
    env_prefix. For every other section the two coincide. The AD field is
    therefore named `ad`, with `settings.active_directory` kept as a property.
    """
    settings = load_env(**{var: "DC=corp,DC=local"})
    assert settings.ad.base_dn == "DC=corp,DC=local"
    assert settings.active_directory.base_dn == "DC=corp,DC=local"


@pytest.mark.parametrize(
    "var, expected",
    [
        ("IAM_ENTRA__ENABLED", True),
        ("IAM_ENTRA_ENABLED", True),
        ("IAM_APPROVAL__DEFAULT_MODE", "autonomous"),
        ("IAM_APPROVAL_DEFAULT_MODE", "autonomous"),
        ("IAM_SCALEFUSION__RATE_LIMIT_PER_MINUTE", 30),
        ("IAM_M365__SHARED_MAILBOX_RETENTION_DAYS", 45),
    ],
)
def test_every_section_accepts_both_spellings(load_env, var: str, expected) -> None:
    settings = load_env(**{var: str(expected).lower() if isinstance(expected, bool) else str(expected)})
    # Walk to the value without hardcoding the attribute path for each case.
    value = settings
    for part in _resolve_path(var):
        value = getattr(value, part)
    assert value == expected, var


def _resolve_path(var: str) -> list[str]:
    """Map an env var name onto the attribute path that should carry it."""
    body = var.removeprefix("IAM_")
    head, sep, tail = body.partition("__")
    if not sep:
        head, _, tail = body.partition("_")
    head = head.lower()
    field = tail.lower()
    root = Settings.model_fields
    if head == "ad":
        head = "ad"
    for name in root:
        if name.upper() == head.upper():
            head = name
            break
    sub = getattr(Settings(), head)
    for name in type(sub).model_fields:
        if name.upper() == field.upper():
            field = name
            break
    return [head, field]


def test_active_directory_property_matches_the_field() -> None:
    settings = Settings()
    assert settings.active_directory is settings.ad


# --------------------------------------------------------------------------- #
# List coercion
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("a,b,c", ["a", "b", "c"]),
        ("a, b , c", ["a", "b", "c"]),
        ("single", ["single"]),
        ("", []),
        ("   ", []),
        (",,,", []),
    ],
)
def test_split_csv(raw: str, expected: list[str]) -> None:
    assert split_csv(raw) == expected


def test_split_csv_passes_non_strings_through() -> None:
    assert split_csv(["already", "a", "list"]) == ["already", "a", "list"]
    assert split_csv(None) is None


def test_empty_list_env_vars_do_not_crash_startup(load_env) -> None:
    """A copied .env.example with blanks must still start."""
    settings = load_env(
        IAM_ENTRA__SCOPES="",
        IAM_M365__DEFAULT_LICENSE_SKUS="",
        IAM_AD__SERVERS="",
        IAM_API__CORS_ORIGINS="",
    )
    assert settings.m365.default_license_skus == []
    assert settings.ad.servers == []


def test_comma_separated_lists_are_parsed(load_env) -> None:
    settings = load_env(
        IAM_AD__SERVERS="dc01.corp.local,dc02.corp.local",
        IAM_M365__DEFAULT_LICENSE_SKUS="ENTERPRISEPACK,EMS",
    )
    assert settings.ad.servers == ["dc01.corp.local", "dc02.corp.local"]
    assert settings.m365.default_license_skus == ["ENTERPRISEPACK", "EMS"]


def test_empty_redact_fields_does_not_wipe_the_shipped_list() -> None:
    """`redact_fields` REPLACES the default, so a blank value is a security regression.

    ``.env.example`` therefore ships the line commented out. This test keeps it
    that way: if someone uncomments it with an empty value, the shipped defaults
    (which include ``temporaryAccessPass`` and ``refresh_token``) vanish.
    """
    default = Settings().audit.redact_fields
    assert "temporaryAccessPass" in default
    assert "refresh_token" in default
    text = ENV_EXAMPLE.read_text(encoding="utf-8")
    active = [
        line for line in text.splitlines()
        if line.strip().startswith("IAM_AUDIT__REDACT_FIELDS")
    ]
    assert not active, "IAM_AUDIT__REDACT_FIELDS must stay commented out in .env.example"


# --------------------------------------------------------------------------- #
# Unrecognised variables must be loud
# --------------------------------------------------------------------------- #


def test_typos_are_reported(load_env) -> None:
    settings = load_env(
        IAM_ENTRA_ENABLEDD="true",
        IAM_APROVAL__DEFAULT_MODE="autonomous",
        IAM_AD__BASE_DNN="DC=x,DC=y",
    )
    found = settings.unrecognized_env_vars()
    assert "IAM_ENTRA_ENABLEDD" in found
    assert "IAM_APROVAL__DEFAULT_MODE" in found
    assert "IAM_AD__BASE_DNN" in found


def test_valid_variables_are_not_flagged(load_env) -> None:
    settings = load_env(
        IAM_ENTRA__ENABLED="true",
        IAM_ENTRA_ENABLED="true",
        IAM_AD__BASE_DN="DC=x",
        IAM_AD_BASE_DN="DC=x",
        IAM_GLOBAL_DRY_RUN="false",
        IAM_APPROVAL__DEFAULT_MODE="autonomous",
        IAM_MOCK__PERSIST="false",
    )
    assert settings.unrecognized_env_vars() == []


def test_unrelated_environment_is_ignored(load_env) -> None:
    settings = load_env(PATH="/usr/bin", HOME="/root", NOT_OURS="x")
    assert settings.unrecognized_env_vars() == []


async def test_preflight_fails_on_a_typo(load_env) -> None:
    """Preflight is the moment to discover a setting that never applied."""
    from iam_agent.core.orchestrator import Orchestrator

    settings = load_env(IAM_ENTRA_ENABLEDD="true")
    orch = Orchestrator(settings)
    report = await orch.preflight()
    assert report["ok"] is False
    assert report["unrecognized_env"] == ["IAM_ENTRA_ENABLEDD"]
    assert any("matches no setting" in p for p in report["problems"])
    await orch.aclose()


# --------------------------------------------------------------------------- #
# .env.example must be loadable and honest
# --------------------------------------------------------------------------- #


def test_env_example_loads_without_error(monkeypatch) -> None:
    """Every key in the shipped example must be a real, accepted setting."""
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, sep, value = line.partition("=")
        assert sep, f"malformed line in .env.example: {line!r}"
        monkeypatch.setenv(key.strip(), value)

    get_settings.cache_clear()
    settings = get_settings()
    assert settings.unrecognized_env_vars() == [], (
        ".env.example ships keys that configure nothing: "
        f"{settings.unrecognized_env_vars()}"
    )
    get_settings.cache_clear()


def test_env_example_documents_the_dry_run_default(monkeypatch) -> None:
    """The shipped example must not silently enable writes."""
    for line in ENV_EXAMPLE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        monkeypatch.setenv(key.strip(), value)
    get_settings.cache_clear()
    settings = get_settings()
    assert settings.global_dry_run is True
    assert settings.approval.default_mode == "approval_required"
    assert settings.ad.allow_hard_delete is False
    assert settings.action1.allow_remote_reboot is False
    get_settings.cache_clear()


# --------------------------------------------------------------------------- #
# Posture helpers
# --------------------------------------------------------------------------- #


def test_backend_classification() -> None:
    settings = Settings()
    assert settings.platform_backends_live() == []
    assert set(settings.platform_backends_mock()) == {
        "entra", "m365", "active_directory", "action1", "scalefusion"
    }

    live = Settings(entra={"enabled": True, "backend": "live", "tenant_id": "t", "client_id": "c"})
    assert live.platform_backends_live() == ["entra"]
    assert "entra" not in live.platform_backends_mock()


def test_global_dry_run_overrides_the_approval_mode() -> None:
    """The master kill switch wins over everything."""
    settings = Settings(
        global_dry_run=True,
        approval={"default_mode": "autonomous", "autonomous_max_risk": "critical"},
    )
    assert settings.effective_mode() == "dry_run"


def test_autonomous_mode_is_reported_when_dry_run_is_off() -> None:
    settings = Settings(
        global_dry_run=False,
        approval={"default_mode": "autonomous", "autonomous_max_risk": "critical"},
    )
    assert settings.effective_mode() == "autonomous"
