"""HTTP surface: webhook authentication and the two inbound integration points.

Webhooks are the only way an external system can start a lifecycle run without a
human typing a command, so signature verification is the whole security model
here. The failure mode that matters is a verifier that silently rejects
legitimate events: it looks exactly like an attacker being turned away, and the
only symptom is that nothing ever happens.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from iam_agent.api.app import _signature_matches, create_app
from iam_agent.config import Settings
from iam_agent.connectors.mock.store import get_mock_store


def _client(**api_settings) -> TestClient:
    get_mock_store(reseed=True)
    settings = Settings(
        api={
            "api_token": "test-token",
            "hr_webhook_secret": "hr-secret",
            "scalefusion_webhook_secret": "sf-secret",
            **api_settings,
        }
    )
    return TestClient(create_app(settings))


def _sign(secret: str, body: bytes, *, prefix: str = "") -> str:
    return prefix + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# --------------------------------------------------------------------------- #
# Signature matching
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("prefix", ["", "sha256="])
def test_signature_accepts_both_wire_formats(prefix: str) -> None:
    """GitHub-style senders prefix with `sha256=`; others send the bare digest.

    Scalefusion's exact format is not documented, so both must be accepted - a
    verifier matching only one spelling rejects every legitimate event.
    """
    body = b'{"event":"device.enrolled"}'
    assert _signature_matches("s", body, _sign("s", body, prefix=prefix)) is True


def test_signature_is_case_and_space_insensitive() -> None:
    body = b"payload"
    good = _sign("s", body)
    assert _signature_matches("s", body, good.upper()) is True
    assert _signature_matches("s", body, f"  {good}  ") is True


def test_signature_rejects_a_tampered_body() -> None:
    body = b'{"event":"device.enrolled"}'
    signature = _sign("s", body)
    assert _signature_matches("s", b'{"event":"device.wiped"}', signature) is False


def test_signature_rejects_the_wrong_secret() -> None:
    body = b"payload"
    assert _signature_matches("s", body, _sign("attacker-secret", body)) is False


def test_signature_rejects_empty_and_garbage() -> None:
    body = b"payload"
    assert _signature_matches("s", body, None) is False
    assert _signature_matches("s", body, "") is False
    assert _signature_matches("s", body, "sha256=") is False
    assert _signature_matches("s", body, "not-a-digest") is False


def test_absent_secret_disables_verification() -> None:
    """With no secret there is nothing to compare against - callers must refuse.

    `_signature_matches` cannot distinguish "no secret configured" from "valid",
    so the endpoints check separately via `_require_webhook_secret`. Tested below.
    """
    assert _signature_matches("", b"body", None) is True


def test_the_prefix_alone_is_not_a_signature() -> None:
    """`sha256=` stripped to empty must not compare equal to an empty digest."""
    assert _signature_matches("s", b"", "sha256=") is False


# --------------------------------------------------------------------------- #
# Webhook endpoints
# --------------------------------------------------------------------------- #


def test_scalefusion_webhook_accepts_a_signed_event() -> None:
    client = _client()
    body = json.dumps(
        {"event": "device.enrolled", "device_id": "dev-9", "user_email": "nserra@contoso-balears.example"}
    ).encode()
    response = client.post(
        "/webhooks/scalefusion",
        content=body,
        headers={"Content-Type": "application/json",
                 "X-Scalefusion-Signature": _sign("sf-secret", body)},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["received"] is True
    assert payload["event"] == "device.enrolled"


def test_scalefusion_webhook_rejects_a_bad_signature() -> None:
    client = _client()
    body = json.dumps({"event": "device.enrolled"}).encode()
    response = client.post(
        "/webhooks/scalefusion",
        content=body,
        headers={"Content-Type": "application/json", "X-Scalefusion-Signature": "deadbeef"},
    )
    assert response.status_code == 401


def test_scalefusion_webhook_rejects_an_unsigned_request() -> None:
    client = _client()
    response = client.post(
        "/webhooks/scalefusion",
        content=b'{"event":"device.lost"}',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 401, "an unsigned webhook must not be honoured"


def test_hr_webhook_accepts_a_signed_joiner_event() -> None:
    client = _client()
    body = json.dumps(
        {
            "event_type": "joiner",
            "employee": {
                "employee_id": "EMP-9001",
                "first_name": "Aina",
                "last_name": "Serra",
                "email": "aserra@contoso-balears.example",
                "department": "Ventas",
            },
            "reason": "new starter",
        }
    ).encode()
    response = client.post(
        "/webhooks/hr",
        content=body,
        headers={"Content-Type": "application/json",
                 "X-Hub-Signature": _sign("hr-secret", body, prefix="sha256=")},
    )
    assert response.status_code == 200, response.text


def test_hr_webhook_checks_the_signature_before_the_schema() -> None:
    """A malformed body from an unauthenticated caller must be 401, not 422.

    FastAPI validates declared body parameters before the handler runs, so a
    typed `body: HRWebhookEvent` put signature checking second: an unsigned
    request could probe the schema and a bad signature was never reported.
    """
    client = _client()
    body = json.dumps({"nonsense": True}).encode()
    response = client.post(
        "/webhooks/hr",
        content=body,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 401, "authentication must precede validation"


def test_hr_webhook_rejects_a_malformed_but_signed_event() -> None:
    """Once authenticated, a bad payload is a 422 with a useful message."""
    client = _client()
    body = json.dumps({"nonsense": True}).encode()
    response = client.post(
        "/webhooks/hr",
        content=body,
        headers={"Content-Type": "application/json",
                 "X-Hub-Signature": _sign("hr-secret", body)},
    )
    assert response.status_code == 422
    assert "malformed HR event" in response.text


def test_hr_webhook_rejects_a_bad_signature() -> None:
    client = _client()
    body = json.dumps({"event_type": "joiner"}).encode()
    response = client.post(
        "/webhooks/hr",
        content=body,
        headers={"Content-Type": "application/json", "X-Hub-Signature": "sha256=wrong"},
    )
    assert response.status_code == 401


# --------------------------------------------------------------------------- #
# Bearer token
# --------------------------------------------------------------------------- #


def test_decisions_require_the_api_token() -> None:
    client = _client()
    response = client.post("/approvals/does-not-exist/decision", json={"approve": True})
    assert response.status_code in (401, 403)


def test_decisions_reject_a_wrong_token() -> None:
    client = _client()
    response = client.post(
        "/approvals/does-not-exist/decision",
        json={"approve": True},
        headers={"Authorization": "Bearer not-the-token"},
    )
    assert response.status_code in (401, 403)


def test_reads_do_not_require_a_token() -> None:
    """Reads are not gated; only decisions and inbound webhooks are."""
    client = _client()
    assert client.get("/health").status_code == 200
    assert client.get("/preflight").status_code == 200
    assert client.get("/approvals").status_code == 200


# --------------------------------------------------------------------------- #
# CLI employee parsing
# --------------------------------------------------------------------------- #
#
# `first_name` and `last_name` are the only fields on Employee without a default,
# so the CLI helper has to supply them even when the operator gave a bare
# identifier. Both natural invocations used to raise a pydantic ValidationError.


def test_cli_parses_a_full_name_identifier() -> None:
    from iam_agent.cli import _employee

    employee = _employee(identifier="Aina Serra", department="Ventas")
    assert employee.first_name == "Aina"
    assert employee.last_name == "Serra"
    assert employee.department == "Ventas"


def test_cli_keeps_composite_surnames_together() -> None:
    """Spanish and Catalan names routinely carry two surnames."""
    from iam_agent.cli import _employee

    employee = _employee(identifier="Miquel Àngel Camps")
    assert employee.first_name == "Miquel"
    assert employee.last_name == "Àngel Camps"


def test_cli_preserves_diacritics_in_names() -> None:
    from iam_agent.cli import _employee

    employee = _employee(identifier="Bea Solà")
    assert employee.last_name == "Solà"


def test_cli_treats_an_email_as_an_email() -> None:
    from iam_agent.cli import _employee

    employee = _employee(identifier="bsola@contoso-balears.example")
    assert employee.email == "bsola@contoso-balears.example"
    assert employee.username == "", "an email must not also be read as a logon name"


def test_cli_treats_a_bare_token_as_a_logon_name() -> None:
    """Offboarding someone you only know by username must not require their name."""
    from iam_agent.cli import _employee

    employee = _employee(identifier="nserra")
    assert employee.username == "nserra"
    assert employee.first_name == ""
    assert employee.last_name == ""


def test_cli_explicit_name_flags_win_over_the_identifier() -> None:
    from iam_agent.cli import _employee

    employee = _employee(
        identifier="Aina Serra", first_name="Aina-Maria", last_name="Serra Ferrer"
    )
    assert employee.first_name == "Aina-Maria"
    assert employee.last_name == "Serra Ferrer"


def test_cli_manager_becomes_a_manager_object() -> None:
    from iam_agent.cli import _employee

    employee = _employee(identifier="Aina Serra", manager_email="lferra@contoso-balears.example")
    assert employee.manager is not None
    assert employee.manager.email == "lferra@contoso-balears.example"


# --------------------------------------------------------------------------- #
# Fail closed by default
# --------------------------------------------------------------------------- #
#
# api_token, hr_webhook_secret and scalefusion_webhook_secret all default to
# empty, so "not configured" is the out-of-the-box state rather than an edge
# case. An earlier version treated it as "nothing to check" and let requests
# through, which meant a default deployment had an unauthenticated endpoint that
# could approve device wipes, and two that could start offboardings.


def _open_client() -> TestClient:
    """An API with every secret and token left at its default (empty)."""
    get_mock_store(reseed=True)
    return TestClient(create_app(Settings()))


def test_webhooks_refuse_when_no_secret_is_configured() -> None:
    client = _open_client()
    for path in ("/webhooks/hr", "/webhooks/scalefusion"):
        response = client.post(
            path, content=b'{"event_type":"leaver"}', headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 503, f"{path} must fail closed, got {response.status_code}"
        assert "is not set" in response.text


def test_the_webhook_error_names_the_setting_to_fix() -> None:
    """A refusal that does not say what to configure just becomes a support ticket."""
    client = _open_client()
    response = client.post("/webhooks/hr", content=b"{}", headers={"Content-Type": "application/json"})
    assert "IAM_API__HR_WEBHOOK_SECRET" in response.text

    response = client.post(
        "/webhooks/scalefusion", content=b"{}", headers={"Content-Type": "application/json"}
    )
    assert "IAM_API__SCALEFUSION_WEBHOOK_SECRET" in response.text


def test_decisions_refuse_when_no_token_is_configured() -> None:
    client = _open_client()
    response = client.post(
        "/approvals/does-not-exist/decision",
        json={"approve": True, "decided_by": "someone@corp.example"},
    )
    assert response.status_code == 403, response.text
    assert "IAM_API__API_TOKEN" in response.text


def test_reads_still_work_on_an_unconfigured_api() -> None:
    """Failing closed applies to routes that authorise writes, not to reads."""
    client = _open_client()
    assert client.get("/health").status_code == 200
    assert client.get("/preflight").status_code == 200
    assert client.get("/approvals").status_code == 200
    assert client.get("/devices").status_code == 200


def test_wildcard_cors_does_not_allow_credentials() -> None:
    """`cors_origins` defaults to ["*"]; credentials must not be allowed with it."""
    client = _open_client()
    response = client.get("/health", headers={"Origin": "https://evil.example"})
    assert response.headers.get("access-control-allow-credentials") != "true"


def test_narrow_cors_may_allow_credentials() -> None:
    get_mock_store(reseed=True)
    settings = Settings(api={"cors_origins": ["https://intranet.corp.local"]})
    client = TestClient(create_app(settings))
    response = client.get("/health", headers={"Origin": "https://intranet.corp.local"})
    assert response.headers.get("access-control-allow-origin") == "https://intranet.corp.local"
