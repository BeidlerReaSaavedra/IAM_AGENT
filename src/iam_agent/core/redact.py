"""Secret redaction and safe serialisation of action parameters.

This exists because an :class:`~iam_agent.core.result.Action` carries its
arguments in ``params``, and some of those arguments are credentials: the
initial password for a new hire, a Temporary Access Pass, an API key. Those
params end up in three durable places - the audit log, the persisted run record
and the approval queue. If any one of them writes the raw value, a plaintext
password lands on disk in ``data/``.

So every path to storage goes through :func:`safe_params`, and the redaction list
lives here, in one place, rather than being duplicated (and eventually missed)
per writer.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

_SECRET_HINTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "apikey",
    "api_key",
    "credential",
    "certificate_password",
    "passphrase",
    "temporaryaccesspass",
    "temporary_access_pass",
    "access_pass",
    "private_key",
    "authorization",
    "unicodepwd",
    "pin",
    "otp",
)

REDACTED = "***REDACTED***"


def is_secret_field(field: str) -> bool:
    """True when a key name suggests it holds a credential."""
    lowered = field.lower().replace("_", "")
    return any(hint.replace("_", "") in lowered for hint in _SECRET_HINTS)


def redact(obj: Any) -> Any:
    """Recursively mask secret-looking keys inside dicts and lists."""
    if isinstance(obj, dict):
        return {
            k: (REDACTED if isinstance(k, str) and is_secret_field(k) else redact(v))
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    if isinstance(obj, BaseModel):
        return redact(obj.model_dump(mode="json"))
    return obj


def _compact_model(obj: BaseModel) -> Any:
    """Render a pydantic model as a small, human-readable dict.

    Approval reviewers should see *who* is being created, not a 900-character
    ``repr()`` of every field. Secret-marked fields are excluded by the model
    itself (``exclude=True``) and then redacted again here as a second line of
    defence.
    """
    keep = {
        "employee_id", "first_name", "last_name", "display_name", "email", "upn",
        "username", "department", "job_title", "company", "office_location",
        "country", "employment_type", "lifecycle_state", "hire_date", "leave_date",
        "termination_reason", "manager", "groups", "teams", "license_skus", "roles",
    }
    try:
        data = obj.model_dump(mode="json", exclude_none=True)
    except Exception:
        return str(obj)[:200]
    compact = {k: v for k, v in data.items() if k in keep and v not in (None, "", [])}
    # Anything not whitelisted is summarised rather than dumped in full.
    omitted = sorted(k for k in data if k not in keep and data[k] not in (None, "", [], {}))
    if omitted:
        compact["_also_set"] = omitted
    return compact


def safe_params(params: dict[str, Any], *, max_depth: int = 4) -> dict[str, Any]:
    """Produce a storage-safe, review-friendly copy of action parameters."""
    out: dict[str, Any] = {}
    for key, value in params.items():
        if is_secret_field(key):
            out[key] = REDACTED
        elif isinstance(value, BaseModel):
            out[key] = redact(_compact_model(value))
        else:
            out[key] = redact(value)
    return out


def safe_json(value: Any, *, limit: int = 4000) -> str:
    """JSON-encode for a review document, redacted and length-capped."""
    import json

    text = json.dumps(redact(value), default=str, ensure_ascii=False)
    if len(text) > limit:
        return text[:limit] + f"… (+{len(text) - limit} chars truncated)"
    return text


__all__ = ["REDACTED", "is_secret_field", "redact", "safe_json", "safe_params"]
