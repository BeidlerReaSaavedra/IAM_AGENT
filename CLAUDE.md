# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

An identity and endpoint lifecycle agent. It automates **onboarding**, **offboarding**
and **internal transfers** across five platforms:

| Platform | Covers |
|---|---|
| Microsoft Entra ID | Cloud identity - the anchor object for every person |
| Microsoft 365 | Mailboxes, Teams, licences, drives |
| Active Directory (on-prem) | The on-premises forest, often the source of authority |
| Action1 | Windows PCs and servers (RMM) |
| Scalefusion | Mobile devices (MDM) |

One shared connector core is exposed three ways: an **MCP server** (33 tools) for
Claude Code and Claude Desktop, a **REST control plane** (32 routes plus HR and
Scalefusion webhooks), and a **CLI** (`iam-agent`). All three drive the same
orchestrator, the same policy engine and the same approval queue.

## The safety model - read this before changing anything

The system runs in a **hybrid** posture: reads are live and ungated; every write
requires human approval.

- `core/policy.py` classifies each operation into `low | medium | high | critical` via
  59 explicit rules. **Unknown operations fail safe to `critical`.** If you add a
  connector method, add its risk rule too, and keep `tests/test_policy_coverage.py`
  green - it asserts every operation of all five connectors is classified, namespaced
  correctly, never gated if it is a read, and always critical if destructive.
- Critical actions require **two distinct approvers**.
- Capability guards block on-premises hard deletes, endpoint reboots/shutdowns and full
  BYOD wipes outright, regardless of mode.
- **Nothing may approve its own work.** `decide_approval` rejects `decided_by` values of
  `claude`, `agent`, `ai` and `system`; the MCP server rejects them again; the agent
  loop withholds the tool from the model entirely; `.claude/settings.json` denies it.
  This layering is deliberate. Do not remove a layer because another one "already
  covers it".

If you are asked to make something run without approval, the answer is to change the
execution mode in configuration (`IAM_APPROVAL__DEFAULT_MODE`), never to weaken the
policy engine or bypass a gate in code.

## Conventions that will bite you if you ignore them

**Operation naming.** An operation is `"{platform}.{method_name}"` and the suffix must
be the *real connector method name*, because dispatch is symbolic
(`core/dispatch.py` resolves the string to a bound coroutine at execution time). Read
verbs (`get_`, `list_`, `search_`, `describe_`, `check_`, `fetch_`, `count_`,
`preview_`, `find_`, `resolve_`) are automatically LOW and never gated. Exceptions live
in `OPERATION_ALIASES`.

**Actions carry no closures.** `Action.executor` stays `None`. Plans must survive JSON
round-trips so a run can be approved in a different process from the one that planned
it. Binding a `partial()` onto an action looks convenient and breaks resume - it forces
re-planning, which mints new approval ids, which loops forever. This has been done and
reverted; do not reintroduce it.

**Approvals are not cleared after use.** `resume()` sets `ActionStatus.APPROVED` and
*keeps* `approval_id`, because policy re-evaluates on every pass and would re-gate
forever otherwise. `Executor._is_cleared()` is what consults the decision.

**Params must match connector kwargs exactly.** `Executor._apply` dispatches
`operation` with `params` unpacked. A typo is a `TypeError` at execution time, not at
plan time.

**Planners must be pure.** A `Workflow.plan()` reads and decides; it never writes. Reads
are performed by the executor's preflight step and passed in through the context.

**Pydantic silently drops unknown constructor kwargs.** `DirectoryGroup(dn=...)` built
fine while the field did not exist, and failed much later as an `AttributeError`. When a
connector passes a kwarg, confirm the model declares it.

**Secrets.** `core/redact.py` is the single source of truth. An onboarding action
legitimately carries the new hire's initial password, and a TAP action carries the pass
itself, so all three durable sinks - the audit log, the run store and the approval queue
- go through it. `tests/test_secret_redaction.py` asserts a canary password never
reaches any file under `data/`. Route new persistence through `safe_params`/`redact`,
never past it.

**Mock and live must agree.** Every mock response is mapped through the same shape the
live API returns (`_store_to_graph` and friends). Snake_case store keys fed to
camelCase Graph mappers produce silently empty fields rather than errors.

**Accented names.** `normalize_logon()` folds diacritics for usernames only. Catalan and
Spanish names are the norm here - do not "fix" a test by hardcoding an unaccented
username.

## Environment

```bash
python3 -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q          # 163 tests
```

Runtime is **Python 3.11** (`requires-python >=3.11`). No PEP 695 generics and no
`type` statement - use `from __future__ import annotations`. There is no `uv`; use
`.venv/bin/pip`.

`mcp` 2.x renamed `FastMCP` to `MCPServer`, which now lives at
`mcp.server.mcpserver`. `mcp.server.fastmcp` is gone. Do not write v1-style FastMCP
code; if it is ever needed, pin `mcp<2`.

No credentials are required to run anything: each connector falls back to a
deterministic in-memory simulator. `data/` holds runtime state (audit log, approval
queue, persisted runs, simulated estate) and is gitignored. `rm -rf data` resets it.

Settings come from the environment with prefix `IAM_` and nested delimiter `__`, e.g.
`IAM_APPROVAL__DEFAULT_MODE`, `IAM_ENTRA_TENANT_ID`. `get_settings()` is `lru_cache`d -
call `cache_clear()` in tests.

## Layout

```
src/iam_agent/
  core/          policy, executor, dispatch, approvals, audit, redaction, reconcile
  connectors/    base + entra, m365, ad_local, action1, scalefusion, mock/store
  workflows/     base, onboarding, offboarding, transfer, registry
  mcp_server/    33 tools for Claude
  api/           FastAPI control plane + webhooks
  agent/         the autonomous loop (Claude driving the same tools)
  cli.py         typer CLI, the `iam-agent` console script
config/          system_prompt.md - operator-maintained agent instructions
.claude/         settings.json (permissions) + agents/ (four subagents)
docs/            architecture, setup, permissions, runbooks
```

## Subagents

`.claude/agents/` defines four, each with a deliberately scoped tool list:

- **iam-auditor** - read-only. No write tools at all; that is the point.
- **iam-onboarding** - joiners.
- **iam-offboarding** - leavers. Highest-stakes; revoke-first ordering.
- **iam-endpoints** - Action1 and Scalefusion fleet work.

None of them can call `decide_approval`. When you add a tool, decide which agents should
see it and update their frontmatter - an agent with a write tool it does not understand
is worse than one without it.

## When changing behaviour

- Add or extend a test in the same commit. The suites that matter most are
  `test_policy_coverage.py` (every operation classified), `test_secret_redaction.py`
  (no credential reaches disk), `test_persistence.py` (state survives a process
  restart) and `test_run_status.py` (status roll-up semantics).
- `is_complete` means *succeeded*; `is_terminal` means *settled*. The executor needs the
  first to stop dependents of a failed step from running; the run roll-up needs the
  second so a failed run is not reported as still running. Both have been gotten
  backwards.
- Never swallow an exception into a default that looks like success. A bare
  `except: continue` in the approval loader once turned a missing `import json` into a
  silently empty queue, which is indistinguishable from "nothing needs approving".
