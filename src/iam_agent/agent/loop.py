"""The autonomous orchestrator: Claude driving the same tools as the MCP server.

This is the second half of the runtime. The MCP server lets *your* Claude
(Claude Code, Claude Desktop) drive the estate; this loop lets the agent run on
its own - from a cron job, a webhook or ``iam-agent agent`` - without a human
sitting in a chat client.

Safety design
-------------
The tool surface is **not redefined here**. It is taken from
:func:`~iam_agent.mcp_server.server.build_server`, so the autonomous agent and an
interactive Claude session see exactly the same 33 tools with the same schemas.
One tool is deliberately withheld:

* ``decide_approval`` is removed from what the model can call.

That is the whole point of the hybrid model. If the agent could approve its own
plan, "human in the loop" would be a label rather than a control. Instead, when a
tool result reports ``awaiting_approval``, *this code* renders the review
document and asks the operator - and records the decision under the operator's
identity, never the model's. In non-interactive mode the loop simply stops and
reports the parked gate, leaving it for the CLI or API to clear.

Everything else the agent can do is still bounded by the policy engine: reads are
free, writes gate, critical writes need two distinct humans, and capability guards
block BYOD wipes and on-prem hard deletes outright.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel

from iam_agent.config import Settings, get_settings
from iam_agent.core.errors import IAMAgentError
from iam_agent.mcp_server.server import INSTRUCTIONS, build_server, get_orchestrator

console = Console()

#: Tools the model is never allowed to call, whatever it asks for.
WITHHELD_TOOLS = frozenset({"decide_approval"})

#: Identity the loop refuses to record a decision under, even if asked.
FORBIDDEN_DECIDERS = frozenset({"claude", "agent", "ai", "system", "api", "anonymous", ""})


@dataclass
class AgentOutcome:
    """What a single agent run produced."""

    prompt: str
    final_text: str = ""
    turns: int = 0
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    parked_approvals: list[dict[str, Any]] = field(default_factory=list)
    stop_reason: str = ""
    error: str = ""
    elapsed_s: float = 0.0

    @property
    def ok(self) -> bool:
        return not self.error and self.stop_reason not in ("max_turns", "error")

    def to_dict(self) -> dict[str, Any]:
        return {
            "prompt": self.prompt,
            "final_text": self.final_text,
            "turns": self.turns,
            "stop_reason": self.stop_reason,
            "error": self.error,
            "elapsed_s": round(self.elapsed_s, 2),
            "tool_calls": self.tool_calls,
            "parked_approvals": self.parked_approvals,
        }


class AgentLoop:
    """Drives Claude over the IAM tool surface until the work is done or parked."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        max_turns: int | None = None,
        plan_only: bool = False,
        approver: str = "operator",
        interactive: bool = True,
        client: Any = None,
        quiet: bool = False,
    ) -> None:
        cfg = settings or get_settings()
        if plan_only and not cfg.global_dry_run:
            # Force read-only rather than trusting the model to behave: a
            # --plan-only flag that still writes would be the worst kind of lie.
            cfg = cfg.model_copy(update={"global_dry_run": True})
        self.settings = cfg
        self.plan_only = plan_only or cfg.global_dry_run
        self.max_turns = max_turns or cfg.claude.max_turns
        self.interactive = interactive
        self.quiet = quiet
        self.approver = self._validate_approver(approver)

        self.server = build_server(cfg)
        self._client = client
        self._tools: list[dict[str, Any]] | None = None

    # ------------------------------------------------------------------ #
    # Setup
    # ------------------------------------------------------------------ #

    @staticmethod
    def _validate_approver(name: str) -> str:
        clean = (name or "").strip()
        if clean.lower() in FORBIDDEN_DECIDERS:
            raise ValueError(
                f"approver identity {name!r} is reserved: approval decisions must be "
                "attributable to a real human and are written to the immutable audit log."
            )
        return clean or "operator"

    @property
    def client(self) -> Any:
        if self._client is None:
            from anthropic import AsyncAnthropic

            self._client = AsyncAnthropic(api_key=self.settings.claude.api_key or None)
        return self._client

    async def tool_schemas(self) -> list[dict[str, Any]]:
        """Anthropic-shaped tool definitions, straight from the MCP server."""
        if self._tools is not None:
            return self._tools

        tools: list[dict[str, Any]] = []
        for tool in await self.server.list_tools():
            if tool.name in WITHHELD_TOOLS:
                continue
            schema = getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", None) or {}
            if not isinstance(schema, dict) or not schema:
                dumped = tool.model_dump(by_alias=True)
                schema = dumped.get("inputSchema") or dumped.get("input_schema") or {}
            tools.append(
                {
                    "name": tool.name,
                    "description": (tool.description or "").strip() or f"IAM tool {tool.name}",
                    "input_schema": schema or {"type": "object", "properties": {}},
                }
            )
        self._tools = tools
        return tools

    def system_prompt(self) -> str:
        """Load the operator-maintained system prompt, falling back to built-ins."""
        path = resolve_prompt_path(self.settings.claude.system_prompt_path)
        extra = ""
        if path is not None:
            try:
                extra = path.read_text(encoding="utf-8").strip()
            except OSError:
                extra = ""

        posture = (
            "PLAN-ONLY: global dry run is active. Every tool will simulate and nothing "
            "will be written to any platform. Use this to explain what would happen."
            if self.plan_only
            else f"Execution mode: {self.settings.effective_mode()}. Writes are real and "
            "will gate on human approval."
        )
        parts = [
            extra or INSTRUCTIONS,
            "",
            "## Current posture",
            f"- {posture}",
            f"- Live platforms: {', '.join(self.settings.platform_backends_live()) or 'none'}",
            f"- Simulated platforms: {', '.join(self.settings.platform_backends_mock()) or 'none'}",
            "",
            "## Approval rules you must follow",
            "- You cannot approve anything. `decide_approval` is not available to you, "
            "and asking for it will not work.",
            "- When a tool returns `awaiting_approval`, stop calling write tools and tell "
            "the operator exactly which approval ids are pending and what each one does.",
            "- Never try to route around a gate by splitting a blocked action into smaller "
            "ones, by using an ad-hoc action instead of the workflow, or by retrying.",
            "- If a tool returns `refused`, `blocked_by_policy` or `manual_step_required`, "
            "report it verbatim. Do not improvise an equivalent action.",
        ]
        return "\n".join(parts)

    # ------------------------------------------------------------------ #
    # Tool execution
    # ------------------------------------------------------------------ #

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> tuple[str, bool]:
        """Invoke one MCP tool, returning (text, is_error). Never raises."""
        if name in WITHHELD_TOOLS:
            return (
                json.dumps(
                    {
                        "error": "tool withheld",
                        "detail": (
                            f"'{name}' is not available to the agent. Approval decisions must "
                            "be made by a human through the CLI, the API or the MCP client."
                        ),
                    }
                ),
                True,
            )
        try:
            result = await self.server.call_tool(name, arguments or {})
        except IAMAgentError as exc:
            return json.dumps(exc.to_dict(), ensure_ascii=False), True
        except Exception as exc:  # noqa: BLE001 - the model must see the failure, not a crash
            return (
                json.dumps(
                    {"error": type(exc).__name__, "detail": str(exc)[:2000]}, ensure_ascii=False
                ),
                True,
            )

        text = _flatten_content(result)
        is_error = bool(getattr(result, "isError", False))
        return text, is_error

    # ------------------------------------------------------------------ #
    # The loop
    # ------------------------------------------------------------------ #

    async def run(self, prompt: str) -> AgentOutcome:
        """Send one instruction to Claude and drive tools until it settles."""
        outcome = AgentOutcome(prompt=prompt)
        started = time.monotonic()

        if not prompt.strip():
            prompt = await self._interactive_prompt()
            outcome.prompt = prompt
        if not prompt.strip():
            outcome.error = "empty prompt"
            return outcome

        tools = await self.tool_schemas()
        messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]

        try:
            for turn in range(1, self.max_turns + 1):
                outcome.turns = turn
                response = await self.client.messages.create(
                    model=self.settings.claude.model,
                    max_tokens=self.settings.claude.max_tokens,
                    temperature=self.settings.claude.temperature,
                    system=self.system_prompt(),
                    tools=tools,
                    messages=messages,
                )

                blocks = list(response.content)
                text_parts = [b.text for b in blocks if getattr(b, "type", "") == "text"]
                tool_uses = [b for b in blocks if getattr(b, "type", "") == "tool_use"]

                if text_parts:
                    chunk = "\n".join(text_parts).strip()
                    outcome.final_text = chunk
                    if not self.quiet and chunk:
                        console.print(Markdown(chunk))

                # Record the assistant turn verbatim so tool_result blocks pair up.
                messages.append({"role": "assistant", "content": [b.model_dump() for b in blocks]})

                if not tool_uses:
                    outcome.stop_reason = str(response.stop_reason or "end_turn")
                    break

                results: list[dict[str, Any]] = []
                for use in tool_uses:
                    name = use.name
                    arguments = dict(use.input or {})
                    if not self.quiet:
                        console.print(f"[dim]→ {name}({_brief(arguments)})[/dim]")
                    text, is_error = await self.call_tool(name, arguments)
                    outcome.tool_calls.append(
                        {"turn": turn, "tool": name, "arguments": arguments, "error": is_error}
                    )
                    if not self.quiet:
                        console.print(f"[dim]← {'error' if is_error else 'ok'} {text[:220]}[/dim]")
                    results.append(
                        {
                            "type": "tool_result",
                            "tool_use_id": use.id,
                            "content": text,
                            "is_error": is_error,
                        }
                    )

                    parked = _extract_parked(text)
                    if parked:
                        outcome.parked_approvals.extend(parked)
                        await self._handle_parked(parked)

                messages.append({"role": "user", "content": results})
            else:
                outcome.stop_reason = "max_turns"
                if not self.quiet:
                    console.print(
                        f"[yellow]stopped after {self.max_turns} turns without settling[/yellow]"
                    )
        except Exception as exc:  # noqa: BLE001
            outcome.error = f"{type(exc).__name__}: {exc}"
            outcome.stop_reason = "error"
            if not self.quiet:
                console.print(f"[red]agent error:[/red] {outcome.error}")

        outcome.elapsed_s = time.monotonic() - started
        return outcome

    # ------------------------------------------------------------------ #
    # Human-in-the-loop
    # ------------------------------------------------------------------ #

    async def _handle_parked(self, parked: list[dict[str, Any]]) -> None:
        """Present a gate to the operator and, if interactive, take the decision.

        The decision is recorded under the *operator's* identity. The model is not
        told the outcome until its next tool call, and cannot make it itself.
        """
        orch = get_orchestrator()
        for item in parked:
            approval_id = item.get("approval_id")
            if not approval_id:
                continue
            try:
                request = orch.get_approval(approval_id)
            except Exception:  # noqa: BLE001
                continue

            if not self.quiet:
                console.print(Panel(Markdown(request.to_review_markdown()), border_style="yellow"))

            if not self.interactive:
                console.print(
                    f"[yellow]parked on approval {approval_id}.[/yellow] Clear it with "
                    f"`iam-agent approvals decide {approval_id} --approve --approver you@corp`"
                )
                continue

            decision = _ask_operator(request)
            if decision is None:
                continue
            approve, comment = decision
            try:
                result = await orch.decide_approval(
                    approval_id,
                    approve=approve,
                    decided_by=self.approver,
                    comment=comment or ("approved at the console" if approve else "refused at the console"),
                )
                console.print(
                    f"[bold]{'approved' if approve else 'rejected'}[/bold] {approval_id} "
                    f"→ run {result.get('run_status')}"
                )
            except (ValueError, IAMAgentError) as exc:
                console.print(f"[red]could not record the decision:[/red] {exc}")

    async def _interactive_prompt(self) -> str:
        if not self.interactive:
            return ""
        console.print(
            Panel(
                "Describe the identity or endpoint change you want. Examples:\n\n"
                "- *Onboard Miquel Àngel Camps into IT, starting 3 November, manager Laura Ferrà*\n"
                "- *Offboard Bea Solà; she left last month and is still enabled*\n"
                "- *Who still has access to the Finance SharePoint?*\n"
                "- *Audit the estate for drift and tell me what to fix first*",
                title="IAM Agent",
                border_style="cyan",
            )
        )
        try:
            return input("> ").strip()
        except EOFError:
            return ""

    async def aclose(self) -> None:
        orch = get_orchestrator()
        await orch.aclose()


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def resolve_prompt_path(raw: str) -> Path | None:
    """Find the operator's system prompt regardless of the current directory.

    ``config/system_prompt.md`` is a *relative* default, and this process gets
    started from all over: a shell in the repo root, a systemd unit with ``/`` as
    cwd, a container, or pytest in a tmpdir. Resolving against cwd alone meant the
    prompt silently fell back to the built-in text - a subtle failure, because the
    agent still works, it just stops following the house rules nobody noticed were
    missing. Candidates are tried in order and the first hit wins.
    """
    if not raw:
        return None
    path = Path(raw).expanduser()
    if path.is_absolute():
        return path if path.exists() else None

    # src/iam_agent/agent/loop.py -> parents[3] is the repository root.
    repo_root = Path(__file__).resolve().parents[3]
    for candidate in (path, Path.cwd() / path, repo_root / path):
        if candidate.exists():
            return candidate
    return None


def _flatten_content(result: Any) -> str:
    """Join the text blocks of a CallToolResult into one string."""
    parts: list[str] = []
    for block in getattr(result, "content", None) or []:
        text = getattr(block, "text", None)
        if text is None and isinstance(block, dict):
            text = block.get("text")
        if text:
            parts.append(str(text))
    if parts:
        return "\n".join(parts)
    # Structured content (mcp >= 1.10) or an unexpected shape: dump it.
    structured = getattr(result, "structuredContent", None)
    if structured:
        return json.dumps(structured, ensure_ascii=False, default=str)
    return json.dumps({"result": str(result)[:2000]}, ensure_ascii=False)


def _extract_parked(text: str) -> list[dict[str, Any]]:
    """Pull the pending approval list out of a tool result, if there is one."""
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(payload, dict):
        return []
    pending = payload.get("awaiting_approval")
    return pending if isinstance(pending, list) else []


def _brief(arguments: dict[str, Any], limit: int = 140) -> str:
    try:
        text = json.dumps(arguments, ensure_ascii=False, default=str)
    except TypeError:
        text = str(arguments)
    return text if len(text) <= limit else text[:limit] + "…"


def _ask_operator(request: Any) -> tuple[bool, str] | None:
    """Blocking console prompt. Returns (approve, comment) or None to skip."""
    try:
        answer = input(
            f"\nApprove {request.id} ({request.title}, risk={request.risk.value}, "
            f"{len(request.approvals)}/{request.required_approvals} signatures)? "
            "[y]es / [n]o / [s]kip > "
        ).strip().lower()
    except EOFError:
        return None
    if answer in ("y", "yes"):
        comment = input("comment for the audit log (optional): ").strip()
        return True, comment
    if answer in ("n", "no"):
        comment = input("reason for refusing (optional): ").strip()
        return False, comment
    return None


__all__ = [
    "AgentLoop",
    "AgentOutcome",
    "WITHHELD_TOOLS",
    "FORBIDDEN_DECIDERS",
    "resolve_prompt_path",
]
