"""Policy engine: the safety layer between Claude's intent and production systems.

Design rules
------------
1. **Reads are free.** Anything that only observes state never needs approval.
2. **Writes are classified.** Each operation maps to a risk level via an explicit
   rule table, never via inference by the model.
3. **The gate is deterministic.** Given the same action and the same settings,
   ``evaluate()`` always returns the same decision. Claude cannot talk its way
   past it - it can only *request* an action.
4. **Deny by default.** Unknown operations are treated as ``critical``.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any, Iterable

from pydantic import BaseModel, Field

from iam_agent.config import Settings
from iam_agent.core.result import Action, RiskLevel


class Decision(BaseModel):
    """Outcome of a policy evaluation."""

    allowed: bool
    requires_approval: bool
    risk: RiskLevel
    reason: str = ""
    applied_rules: list[str] = Field(default_factory=list)
    blocked_reason: str = ""

    @property
    def outcome(self) -> str:
        if not self.allowed:
            return "blocked"
        if self.requires_approval:
            return "approval_required"
        return "auto"


# --------------------------------------------------------------------------- #
# Operation risk table
# --------------------------------------------------------------------------- #

# Explicit classification. Ordering matters: the first matching pattern wins,
# so the most specific rules are listed first.
_OPERATION_RISK: list[tuple[str, RiskLevel]] = [
    # ---- Irreversible / destructive: always critical ---------------------
    ("*.delete_user", RiskLevel.CRITICAL),
    ("*.hard_delete*", RiskLevel.CRITICAL),
    ("scalefusion.wipe_device", RiskLevel.CRITICAL),
    ("scalefusion.retire_device", RiskLevel.CRITICAL),
    ("m365.delete_mailbox", RiskLevel.CRITICAL),

    # ---- High impact ------------------------------------------------------
    ("*.disable_user", RiskLevel.HIGH),
    ("*.enable_user", RiskLevel.MEDIUM),
    ("*.set_password", RiskLevel.HIGH),
    ("*.reset_password", RiskLevel.HIGH),
    ("*.grant_role", RiskLevel.HIGH),
    ("*.revoke_role", RiskLevel.HIGH),
    ("*.run_automation", RiskLevel.HIGH),
    ("*.execute_script", RiskLevel.HIGH),
    ("*.quarantine_endpoint", RiskLevel.HIGH),
    ("*.reboot_endpoint", RiskLevel.MEDIUM),
    ("*.shutdown_endpoint", RiskLevel.HIGH),
    ("*.lock_device", RiskLevel.HIGH),
    ("*.convert_mailbox_to_shared", RiskLevel.MEDIUM),
    ("*.set_mailbox_forwarding", RiskLevel.MEDIUM),
    ("*.grant_mailbox_permission", RiskLevel.MEDIUM),
    ("*.revoke_mailbox_permission", RiskLevel.MEDIUM),
    ("*.set_litigation_hold", RiskLevel.HIGH),
    ("*.remove_all_licenses", RiskLevel.HIGH),
    ("*.remove_all_group_memberships", RiskLevel.HIGH),
    ("*.remove_all_teams_memberships", RiskLevel.HIGH),
    ("*.revoke_all_sessions", RiskLevel.MEDIUM),
    ("*.run_lifecycle_workflow", RiskLevel.HIGH),
    ("*.expire_password", RiskLevel.MEDIUM),
    ("*.set_account_expiry", RiskLevel.MEDIUM),
    ("*.move_user", RiskLevel.MEDIUM),
    ("*.unlock_user", RiskLevel.MEDIUM),

    # ---- Medium impact ----------------------------------------------------
    ("*.create_user", RiskLevel.MEDIUM),
    ("*.update_user", RiskLevel.LOW),
    ("*.add_group_member", RiskLevel.MEDIUM),
    ("*.remove_group_member", RiskLevel.MEDIUM),
    ("*.add_team_member", RiskLevel.MEDIUM),
    ("*.remove_team_member", RiskLevel.MEDIUM),
    ("*.assign_license", RiskLevel.MEDIUM),
    ("*.create_mailbox", RiskLevel.MEDIUM),
    ("*.hide_from_gal", RiskLevel.LOW),
    ("*.apply_device_profile", RiskLevel.MEDIUM),
    ("*.remove_device_profile", RiskLevel.MEDIUM),
    ("*.add_device_to_group", RiskLevel.LOW),
    ("*.remove_device_from_group", RiskLevel.MEDIUM),
    ("*.add_endpoints_to_group", RiskLevel.LOW),
    ("*.remove_endpoints_from_group", RiskLevel.MEDIUM),
    ("*.move_endpoint_group", RiskLevel.LOW),
    ("*.assign_device_user", RiskLevel.LOW),
    ("*.unassign_device_user", RiskLevel.MEDIUM),
    ("*.unlock_device", RiskLevel.MEDIUM),
    ("*.share_drive_with", RiskLevel.MEDIUM),
    ("*.create_temporary_access_pass", RiskLevel.MEDIUM),
    ("*.send_email", RiskLevel.LOW),
    ("*.create_group", RiskLevel.MEDIUM),
    ("*.update_group", RiskLevel.LOW),

    # ---- Low impact -------------------------------------------------------
    ("*.send_alarm", RiskLevel.LOW),
    ("*.tag_device", RiskLevel.LOW),
    ("*.set_description", RiskLevel.LOW),
    ("*.set_manager", RiskLevel.LOW),
]

_READ_PREFIXES = (
    "get_", "list_", "search_", "describe_", "check_", "fetch_",
    "count_", "preview_", "find_",
)


@dataclass(frozen=True)
class PolicyRule:
    """An operator-authored override."""

    name: str
    match: str
    """Glob against ``operation`` (e.g. ``scalefusion.wipe_*``)."""
    effect: str = "require_approval"
    """``allow`` | ``require_approval`` | ``deny``."""
    reason: str = ""
    platforms: tuple[str, ...] = ()


class PolicyEngine:
    """Classifies actions and decides whether they may run."""

    def __init__(
        self,
        settings: Settings,
        extra_rules: Iterable[PolicyRule] = (),
    ) -> None:
        self.settings = settings
        self.rules: list[PolicyRule] = list(extra_rules)
        self._cache: dict[str, RiskLevel] = {}

    # ---- risk classification -------------------------------------------- #

    def classify(self, operation: str) -> RiskLevel:
        """Map an operation verb to a risk level. Unknown == critical."""
        if operation in self._cache:
            return self._cache[operation]

        verb = operation.split(".", 1)[-1]

        # Pure reads are always low and never gated.
        if any(verb.startswith(p) for p in _READ_PREFIXES):
            self._cache[operation] = RiskLevel.LOW
            return RiskLevel.LOW

        for pattern, risk in _OPERATION_RISK:
            if fnmatch.fnmatch(operation, pattern):
                self._cache[operation] = risk
                return risk

        # Fail safe: an operation nobody classified is treated as dangerous.
        self._cache[operation] = RiskLevel.CRITICAL
        return RiskLevel.CRITICAL

    def is_read(self, operation: str) -> bool:
        verb = operation.split(".", 1)[-1]
        return any(verb.startswith(p) for p in _READ_PREFIXES)

    # ---- decision -------------------------------------------------------- #

    def evaluate(self, action: Action) -> Decision:
        """Decide what should happen to ``action``.

        Never raises, never performs I/O.
        """
        applied: list[str] = []
        risk = action.risk if action.risk != RiskLevel.LOW else self.classify(action.operation)

        # Adopt the stricter of the declared and the classified risk.
        classified = self.classify(action.operation)
        if classified.rank > risk.rank:
            risk = classified
            applied.append(f"risk_table:{action.operation}={classified.value}")
        action.risk = risk

        # 1. Reads bypass everything.
        if self.is_read(action.operation):
            return Decision(
                allowed=True,
                requires_approval=False,
                risk=RiskLevel.LOW,
                reason="read-only operation",
                applied_rules=["bypass:read_only"],
            )

        # 2. Global kill switch.
        if self.settings.global_dry_run:
            return Decision(
                allowed=True,
                requires_approval=False,
                risk=risk,
                reason="global dry-run enabled; action will be planned and logged, not applied",
                applied_rules=applied + ["global_dry_run"],
            )

        # 3. Operator rules take precedence over mode.
        for rule in self.rules:
            if not fnmatch.fnmatch(action.operation, rule.match):
                continue
            if rule.platforms and action.platform not in rule.platforms:
                continue
            applied.append(f"rule:{rule.name}")
            if rule.effect == "deny":
                return Decision(
                    allowed=False,
                    requires_approval=False,
                    risk=risk,
                    reason=rule.reason or f"denied by policy rule {rule.name}",
                    applied_rules=applied,
                    blocked_reason=rule.reason or rule.name,
                )
            if rule.effect == "allow":
                return Decision(
                    allowed=True,
                    requires_approval=False,
                    risk=risk,
                    reason=rule.reason or f"explicitly allowed by rule {rule.name}",
                    applied_rules=applied,
                )
            # require_approval
            return Decision(
                allowed=True,
                requires_approval=True,
                risk=risk,
                reason=rule.reason or f"rule {rule.name} requires human approval",
                applied_rules=applied,
            )

        # 4. Platform-specific capability guards.
        guard = self._capability_guard(action)
        if guard:
            applied.append(guard[0])
            return Decision(
                allowed=False,
                requires_approval=False,
                risk=risk,
                reason=guard[1],
                applied_rules=applied,
                blocked_reason=guard[1],
            )

        # 5. Mode-based decision.
        mode = self.settings.effective_mode()
        ceiling = RiskLevel(self.settings.approval.autonomous_max_risk)

        if mode == "dry_run":
            return Decision(
                allowed=True,
                requires_approval=False,
                risk=risk,
                reason="execution mode is dry_run",
                applied_rules=applied + ["mode:dry_run"],
            )

        if mode == "autonomous" and risk.rank <= ceiling.rank:
            return Decision(
                allowed=True,
                requires_approval=False,
                risk=risk,
                reason=f"autonomous mode, risk {risk.value} <= ceiling {ceiling.value}",
                applied_rules=applied + ["mode:autonomous"],
            )

        # approval_required (default), or autonomous above the ceiling
        return Decision(
            allowed=True,
            requires_approval=True,
            risk=risk,
            reason=(
                f"execution mode '{mode}' requires approval for risk '{risk.value}' "
                f"(autonomous ceiling: '{ceiling.value}')"
            ),
            applied_rules=applied + [f"mode:{mode}"],
        )

    # ---- capability guards ----------------------------------------------- #

    def _capability_guard(self, action: Action) -> tuple[str, str] | None:
        """Block operations the operator explicitly switched off in config."""
        ad = self.settings.active_directory
        a1 = self.settings.action1
        sf = self.settings.scalefusion

        if action.operation == "active_directory.delete_user" and not ad.allow_hard_delete:
            return (
                "guard:ad.allow_hard_delete=false",
                "On-prem AD hard delete is disabled (IAM_AD_ALLOW_HARD_DELETE). "
                "Use disable_user + move to the disabled OU instead.",
            )

        if action.operation == "action1.reboot_endpoint" and not a1.allow_remote_reboot:
            return (
                "guard:action1.allow_remote_reboot=false",
                "Remote reboot via Action1 is disabled (IAM_ACTION1_ALLOW_REMOTE_REBOOT).",
            )

        if action.operation == "action1.shutdown_endpoint" and not a1.allow_remote_shutdown:
            return (
                "guard:action1.allow_remote_shutdown=false",
                "Remote shutdown via Action1 is disabled (IAM_ACTION1_ALLOW_REMOTE_SHUTDOWN).",
            )

        if action.operation == "scalefusion.wipe_device" and not sf.allow_wipe:
            return (
                "guard:scalefusion.allow_wipe=false",
                "Device wipe via Scalefusion is disabled (IAM_SCALEFUSION_ALLOW_WIPE).",
            )

        if action.operation == "scalefusion.retire_device" and not sf.allow_retire:
            return (
                "guard:scalefusion.allow_retire=false",
                "Device retirement via Scalefusion is disabled (IAM_SCALEFUSION_ALLOW_RETIRE).",
            )

        # BYOD devices must never be wiped - only unenrolled/retired.
        if action.operation == "scalefusion.wipe_device":
            ownership = str(action.params.get("ownership", "")).lower()
            if ownership == "byod":
                return (
                    "guard:byod_wipe",
                    "Refusing to wipe a BYOD device. Retire/unenrol instead so only the "
                    "work profile is removed.",
                )

        return None

    # ---- bulk helpers ----------------------------------------------------- #

    def evaluate_all(self, actions: Iterable[Action]) -> list[tuple[Action, Decision]]:
        return [(a, self.evaluate(a)) for a in actions]

    def summarize(self, actions: Iterable[Action]) -> dict[str, Any]:
        pairs = self.evaluate_all(actions)
        buckets = {"auto": 0, "approval_required": 0, "blocked": 0}
        by_risk: dict[str, int] = {}
        for _action, decision in pairs:
            buckets[decision.outcome] = buckets.get(decision.outcome, 0) + 1
            by_risk[decision.risk.value] = by_risk.get(decision.risk.value, 0) + 1
        return {
            "total": len(pairs),
            **buckets,
            "by_risk": by_risk,
        }


# --------------------------------------------------------------------------- #
# Default operator rules
# --------------------------------------------------------------------------- #


DEFAULT_RULES: tuple[PolicyRule, ...] = (
    PolicyRule(
        name="protect_global_admins",
        match="entra.revoke_role",
        effect="require_approval",
        reason="Revoking Entra directory roles always needs a human sign-off.",
    ),
    PolicyRule(
        name="protect_domain_admins",
        match="active_directory.remove_group_member",
        effect="require_approval",
        reason="Removing on-prem group membership may drop Domain/Enterprise Admin rights.",
    ),
    PolicyRule(
        name="no_autonomous_wipe",
        match="scalefusion.wipe_device",
        effect="require_approval",
        reason="Device wipe is irreversible; always confirm with a human.",
    ),
    PolicyRule(
        name="no_autonomous_deletion",
        match="*.delete_user",
        effect="require_approval",
        reason="Account deletion is irreversible within the retention window.",
    ),
)
