"""Every operation a connector can emit MUST be explicitly classified.

The policy engine fails safe - an unknown operation is treated as ``critical``.
That is the right default for production, but if it triggers silently then a
routine action (adding someone to a Team) starts demanding two-person approval
and the operators learn to ignore the gate. This test makes the risk table a
maintained contract instead of an accident.
"""

from __future__ import annotations

import fnmatch

import pytest

from iam_agent.config import Settings
from iam_agent.connectors import action1, ad_local, entra, m365, scalefusion
from iam_agent.core.policy import _OPERATION_RISK, _READ_PREFIXES, PolicyEngine

ALL_OPS: dict[str, dict[str, str]] = {
    "entra": entra.OPS,
    "m365": m365.OPS,
    "active_directory": ad_local.OPS,
    "action1": action1.OPS,
    "scalefusion": scalefusion.OPS,
}


def every_operation() -> list[tuple[str, str]]:
    return [(platform, op) for platform, ops in ALL_OPS.items() for op in ops.values()]


def is_classified(operation: str) -> bool:
    verb = operation.split(".", 1)[-1]
    if any(verb.startswith(p) for p in _READ_PREFIXES):
        return True
    return any(fnmatch.fnmatch(operation, pattern) for pattern, _ in _OPERATION_RISK)


@pytest.mark.parametrize("platform,operation", every_operation())
def test_operation_is_explicitly_classified(platform: str, operation: str) -> None:
    assert is_classified(operation), (
        f"{operation} is not covered by the risk table; it would silently fall "
        f"back to CRITICAL. Add an explicit rule in core/policy.py."
    )


def test_operation_names_are_namespaced() -> None:
    for platform, ops in ALL_OPS.items():
        for name, operation in ops.items():
            assert operation.startswith(f"{platform}."), (
                f"{platform}.{name} -> '{operation}' must be namespaced by platform"
            )


def test_no_duplicate_operation_ids() -> None:
    seen: dict[str, str] = {}
    for platform, ops in ALL_OPS.items():
        for name, operation in ops.items():
            assert operation not in seen, f"{operation} declared twice ({seen[operation]} and {platform}.{name})"
            seen[operation] = f"{platform}.{name}"


def test_reads_are_never_gated() -> None:
    policy = PolicyEngine(Settings(global_dry_run=False))
    from iam_agent.core.result import Action

    for _platform, operation in every_operation():
        if not policy.is_read(operation):
            continue
        decision = policy.evaluate(Action(operation=operation, platform=operation.split(".")[0]))
        assert decision.allowed and not decision.requires_approval, operation


def test_destructive_operations_are_always_critical() -> None:
    policy = PolicyEngine(Settings(global_dry_run=False))
    for operation in (
        "entra.delete_user",
        "active_directory.delete_user",
        "scalefusion.wipe_device",
        "scalefusion.retire_device",
    ):
        assert policy.classify(operation).value == "critical", operation
