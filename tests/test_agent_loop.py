"""The autonomous agent loop.

These tests use a scripted fake Anthropic client, so they exercise the loop's own
logic - tool wiring, result plumbing, turn budgeting, and above all the approval
boundary - without an API key or network access.

The central property under test is that **the model cannot approve its own work**.
That is the difference between "human in the loop" as a control and as a comment in
a README, so it gets several tests from several angles.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from pydantic import BaseModel

from conftest import approve_everything
from iam_agent.agent.loop import FORBIDDEN_DECIDERS, WITHHELD_TOOLS, AgentLoop
from iam_agent.config import Settings
from iam_agent.connectors.mock.store import get_mock_store

# --------------------------------------------------------------------------- #
# A scripted stand-in for the Anthropic client
# --------------------------------------------------------------------------- #


class FakeText(BaseModel):
    type: str = "text"
    text: str = ""


class FakeToolUse(BaseModel):
    type: str = "tool_use"
    id: str = ""
    name: str = ""
    input: dict[str, Any] = {}


class FakeResponse(BaseModel):
    content: list[Any]
    stop_reason: str = "end_turn"


class FakeMessages:
    def __init__(self, script: list[FakeResponse]) -> None:
        self.script = list(script)
        self.calls: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> FakeResponse:
        # Deep copy: the loop keeps mutating the same `messages` list it hands us,
        # so storing the reference would let a later turn rewrite history and make
        # assertions about "what the model saw on turn N" meaningless.
        self.calls.append(json.loads(json.dumps(kwargs, default=str)))
        if not self.script:
            return FakeResponse(content=[FakeText(text="(no more scripted turns)")])
        return self.script.pop(0)


class FakeClient:
    def __init__(self, script: list[FakeResponse]) -> None:
        self.messages = FakeMessages(script)


def _loop(script: list[FakeResponse], settings: Settings | None = None, **kwargs: Any) -> AgentLoop:
    cfg = settings or Settings(global_dry_run=True, claude={"api_key": "sk-test"})
    return AgentLoop(settings=cfg, client=FakeClient(script), interactive=False, quiet=True, **kwargs)


# --------------------------------------------------------------------------- #
# Tool surface
# --------------------------------------------------------------------------- #


async def test_decision_tool_is_not_exposed_to_the_model():
    loop = _loop([])
    names = {t["name"] for t in await loop.tool_schemas()}
    assert names, "the agent should have a tool surface at all"
    assert not (names & WITHHELD_TOOLS), f"withheld tools leaked to the model: {names & WITHHELD_TOOLS}"
    # Read tools must be present, or the agent cannot do anything useful.
    for expected in ("iam_status", "find_people", "get_identity", "audit_estate"):
        assert expected in names, expected


async def test_withheld_tool_refuses_even_when_called_directly():
    """Belt and braces: the guard is in call_tool, not only in the schema list."""
    loop = _loop([])
    text, is_error = await loop.call_tool(
        "decide_approval", {"approval_id": "apv_whatever", "approve": True, "decided_by": "claude"}
    )
    assert is_error is True
    assert "withheld" in json.loads(text)["error"]


async def test_every_exposed_tool_has_a_usable_schema():
    loop = _loop([])
    for tool in await loop.tool_schemas():
        assert tool["name"]
        assert tool["description"].strip(), f"{tool['name']} has no description"
        assert tool["input_schema"].get("type") == "object", tool["name"]
        assert isinstance(tool["input_schema"].get("properties"), dict), tool["name"]


@pytest.mark.parametrize("identity", sorted(FORBIDDEN_DECIDERS))
def test_reserved_approver_identities_are_rejected(identity: str):
    with pytest.raises(ValueError):
        AgentLoop(
            settings=Settings(global_dry_run=True),
            approver=identity,
            interactive=False,
            quiet=True,
        )


def test_plan_only_forces_a_dry_run_even_if_settings_say_otherwise():
    """A --plan-only flag that still writes would be the worst kind of lie."""
    writable = Settings(
        global_dry_run=False,
        approval={"default_mode": "autonomous", "autonomous_max_risk": "critical"},
    )
    loop = AgentLoop(settings=writable, plan_only=True, interactive=False, quiet=True)
    assert loop.settings.global_dry_run is True
    assert loop.plan_only is True


def test_system_prompt_carries_the_posture_and_the_rules():
    loop = _loop([])
    prompt = loop.system_prompt()
    assert "You cannot approve anything" in prompt
    assert "Never route around a gate" in prompt
    assert "Simulated platforms" in prompt


def test_system_prompt_shouts_when_everything_is_simulated():
    loop = _loop([], settings=Settings(global_dry_run=True))
    assert "none" in loop.system_prompt() or "entra" in loop.system_prompt()


# --------------------------------------------------------------------------- #
# Loop mechanics
# --------------------------------------------------------------------------- #


async def test_loop_executes_tools_and_feeds_results_back():
    script = [
        FakeResponse(
            content=[FakeToolUse(id="t1", name="iam_status", input={})],
            stop_reason="tool_use",
        ),
        FakeResponse(content=[FakeText(text="Everything is simulated.")], stop_reason="end_turn"),
    ]
    loop = _loop(script)
    outcome = await loop.run("what is the posture?")

    assert outcome.ok
    assert outcome.turns == 2
    assert outcome.stop_reason == "end_turn"
    assert outcome.final_text == "Everything is simulated."
    assert [c["tool"] for c in outcome.tool_calls] == ["iam_status"]

    # The tool result must reach the model as a paired tool_result block.
    messages = loop.client.messages.calls[1]["messages"]
    results = [b for b in messages[-1]["content"] if b.get("type") == "tool_result"]
    assert results and results[0]["tool_use_id"] == "t1"
    assert results[0]["is_error"] is False
    assert "settings" in results[0]["content"]


async def test_tool_errors_are_returned_not_raised():
    """A crash here would end the run; the model needs to see the failure instead."""
    script = [
        FakeResponse(
            content=[FakeToolUse(id="t1", name="no_such_tool", input={})], stop_reason="tool_use"
        ),
        FakeResponse(content=[FakeText(text="That tool does not exist.")], stop_reason="end_turn"),
    ]
    loop = _loop(script)
    outcome = await loop.run("try a bad tool")

    assert outcome.ok, "an unknown tool must not abort the loop"
    assert outcome.tool_calls[0]["error"] is True
    messages = loop.client.messages.calls[1]["messages"]
    results = [b for b in messages[-1]["content"] if b.get("type") == "tool_result"]
    assert results[0]["is_error"] is True


async def test_turn_budget_is_respected():
    """A model that never stops calling tools must not loop forever."""
    endless = [
        FakeResponse(
            content=[FakeToolUse(id=f"t{i}", name="iam_status", input={})], stop_reason="tool_use"
        )
        for i in range(50)
    ]
    loop = _loop(endless, max_turns=3)
    outcome = await loop.run("keep going")

    assert outcome.turns == 3
    assert outcome.stop_reason == "max_turns"
    assert not outcome.ok
    assert len(loop.client.messages.calls) == 3


async def test_empty_prompt_is_reported_not_sent():
    loop = _loop([])
    outcome = await loop.run("   ")
    assert outcome.error == "empty prompt"
    assert loop.client.messages.calls == [], "nothing should have been sent to the model"


# --------------------------------------------------------------------------- #
# The approval boundary - the property that matters most
# --------------------------------------------------------------------------- #


async def test_agent_cannot_self_approve_a_run_it_started(settings):
    """End to end: the agent starts an onboarding and the run stays parked."""
    get_mock_store(reseed=True)
    script = [
        FakeResponse(
            content=[
                FakeToolUse(
                    id="t1",
                    name="onboard_employee",
                    input={
                        "employee": {
                            "first_name": "Aina",
                            "last_name": "Serra",
                            "department": "Ventas",
                            "job_title": "Account Executive",
                            "manager_email": "lferra@contoso-balears.example",
                        },
                        "reason": "agent test",
                    },
                )
            ],
            stop_reason="tool_use",
        ),
        FakeResponse(content=[FakeText(text="Parked for approval.")], stop_reason="end_turn"),
    ]
    writable = Settings(
        global_dry_run=False,
        approval={
            "default_mode": "approval_required",
            "autonomous_max_risk": "low",
            "storage_path": settings.approval.storage_path,
        },
        audit={
            "log_path": settings.audit.log_path,
            "run_store_path": settings.audit.run_store_path,
        },
    )
    loop = AgentLoop(
        settings=writable,
        client=FakeClient(script),
        interactive=False,
        quiet=True,
        approver="operator@corp",
    )
    outcome = await loop.run("onboard Aina Serra")

    assert outcome.parked_approvals, "the agent should have noticed the gate"
    # The run must still be waiting - the agent had no way to clear it.
    from iam_agent.core.orchestrator import Orchestrator

    orch = Orchestrator(writable)
    pending = orch.list_approvals(status="pending")
    assert pending, "the gate must still be standing after the agent finished"
    runs = orch.list_runs(workflow="onboarding")
    assert runs and runs[0].status.value == "awaiting_approval", runs[0].status.value

    # ...and a human can still clear it normally.
    rounds = await approve_everything(orch)
    assert rounds > 0
    assert orch.get_run(runs[0].id).status.value == "completed"
    await orch.aclose()
    await loop.aclose()


async def test_withheld_tool_is_refused_mid_conversation(settings):
    """Even if the model guesses the name, calling it returns a refusal."""
    get_mock_store(reseed=True)
    script = [
        FakeResponse(
            content=[
                FakeToolUse(
                    id="t1", name="decide_approval",
                    input={"approval_id": "apv_guessed", "approve": True, "decided_by": "claude"},
                )
            ],
            stop_reason="tool_use",
        ),
        FakeResponse(content=[FakeText(text="Understood, I cannot do that.")], stop_reason="end_turn"),
    ]
    loop = _loop(script, settings=settings)
    outcome = await loop.run("approve everything")

    assert outcome.tool_calls[0]["error"] is True
    messages = loop.client.messages.calls[1]["messages"]
    refusal = next(b for b in messages[-1]["content"] if b.get("type") == "tool_result")
    assert "not available to the agent" in refusal["content"]

    # Nothing was decided anywhere.
    from iam_agent.core.approval import ApprovalStore

    assert ApprovalStore(settings.approval).list(status=None) == []


# --------------------------------------------------------------------------- #
# System prompt discovery
# --------------------------------------------------------------------------- #


def test_system_prompt_is_found_regardless_of_cwd(tmp_path, monkeypatch):
    """A relative default must not depend on where the process was started.

    The agent gets launched from a shell, a systemd unit, a container and pytest.
    Resolving ``config/system_prompt.md`` against cwd alone made it fall back to
    built-in text silently - the agent still ran, it just stopped following the
    house rules, which is the kind of failure nobody notices.
    """
    from iam_agent.agent.loop import resolve_prompt_path

    found = resolve_prompt_path("config/system_prompt.md")
    assert found is not None and found.exists(), (
        "the shipped config/system_prompt.md should be discoverable from the repo"
    )

    monkeypatch.chdir(tmp_path)
    still_found = resolve_prompt_path("config/system_prompt.md")
    assert still_found is not None and still_found.exists()
    assert still_found.resolve() == found.resolve()

    loop = _loop([])
    assert "You cannot approve anything" in loop.system_prompt(), (
        "the operator-maintained prompt must be in use, not the built-in fallback"
    )


def test_missing_prompt_falls_back_cleanly(tmp_path):
    from iam_agent.agent.loop import resolve_prompt_path

    assert resolve_prompt_path(str(tmp_path / "nope.md")) is None
    assert resolve_prompt_path("") is None

    loop = _loop([])
    loop.settings.claude.system_prompt_path = str(tmp_path / "nope.md")
    prompt = loop.system_prompt()
    # Still a usable prompt, and still carrying the non-negotiables.
    assert "You cannot approve anything" in prompt
    assert "awaiting_approval" in prompt
