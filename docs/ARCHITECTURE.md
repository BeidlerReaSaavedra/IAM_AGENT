# Architecture

How the pieces fit together, and why they fit that way.

---

## One core, four surfaces

The same connector core is exposed four ways. This is not convenience — it is the
point. An MCP tool, a REST route, a CLI command and an autonomous agent turn all
resolve to the same `Orchestrator` method, so the safety model cannot differ
between them. There is no "admin API" that skips approvals.

```
Claude Code ──► MCP server (33 tools) ─┐
Claude API  ──► Agent loop (32 tools) ─┤
HR system   ──► REST API (32 routes) ──┼──► Orchestrator ──► Workflows ──► Connectors
you         ──► CLI (typer) ───────────┘         │
                                                 ├── policy & risk
                                                 ├── approval store
                                                 ├── executor
                                                 ├── audit log
                                                 └── drift reconciler
```

The agent loop exposes **32** tools, not 33: `decide_approval` is withheld. So is
the MCP tool of the same name from every subagent, via the `deny` list in
`.claude/settings.json`. An agent that could sign its own write approvals would
defeat the entire model, so this is enforced structurally in two places rather
than by instruction.

---

## The layers

### Connectors (`connectors/`)

Five platforms, each an abstract base plus two implementations:

| Platform | Module | Live transport | Simulator |
|---|---|---|---|
| Entra ID | `entra.py` | Microsoft Graph via `msal` client credentials | `MockEntraConnector` |
| M365 | `m365.py` | Microsoft Graph (service plane) | `MockM365Connector` |
| On-prem AD | `ad_local.py` | `ldap3` over LDAPS | `MockADConnector` |
| Action1 | `action1.py` | OAuth2 client credentials | `MockAction1Connector` |
| Scalefusion | `scalefusion.py` | API key, v2 REST | `MockScalefusionConnector` |

Every connector publishes an `OPS` mapping of its operations. The naming rule is
`"{platform}.{method_name}"`, and the suffix **must be the real connector method
name** — the dispatcher resolves operations by looking the method up, so a plan
that names a method which does not exist fails loudly at dispatch time rather
than silently doing nothing.

Both implementations must agree. Where they cannot — because Graph genuinely
lacks the capability — the connector returns `exchange_step_required` with the
exact PowerShell cmdlet rather than reporting success. A plan that claims to have
converted a mailbox to shared when Graph cannot do that is worse than a plan that
admits it needs a human.

### The simulator (`connectors/mock/store.py`)

A deterministic estate: 7 employees, 13 groups, directory roles, licence SKUs,
6 Teams, 8 Action1 endpoints, 5 Scalefusion devices, in the domain
`contoso-balears.example`. It is seeded with problems on purpose — an orphan
(`bsola@…`, enabled everywhere, left 40 days ago), a disabled-in-Entra-but-live-in-AD
leaver with a BYOD handset, a stale unowned device — so the drift detector has
something to find.

Ids are minted with `uuid5` over a counter reset in `__init__`, so every fresh
store produces the same estate. This matters more than it sounds: with `uuid4` a
persisted plan referenced ids that no longer existed after a restart, and
resuming it failed.

Writes go through `_PersistingDict` to `data/mock_estate.json` atomically, so
state survives across processes. You can onboard someone in one shell and find
them in the next.

### Policy (`core/policy.py`)

Classifies every operation by risk. Read verbs — `get_`, `list_`, `search_`,
`describe_`, `check_`, `fetch_`, `count_`, `preview_`, `find_`, `resolve_` — are
`low` and never gated. Everything else is matched against duty-specific rules.

**An operation the policy does not recognise is classified `critical`.** Failing
safe costs an extra approval; failing open costs an incident. This is the single
most important default in the codebase, and it is why adding a connector method
without a policy rule produces a noisy plan rather than a quiet hole.

`annotate_plan` walks a plan and marks which steps need approval under the
effective mode, recording its reasoning in `assumptions`.

### Approvals (`core/approval.py`)

Gates are persisted to `data/approvals.jsonl`. Critical actions require **two
distinct approvers** — the store rejects a second signature from the same
identity. Requests expire. Deciding a gate resumes the parked run automatically.

An approval is **never cleared after use.** An earlier design cleared
`action.approval_id` once consumed, which made the policy engine re-gate the same
action forever and looped the executor. The approval id stays; the *status* is
what changes.

The approver identity is checked against `FORBIDDEN_DECIDERS = {claude, agent, ai,
system, api, anonymous, ""}`. An agent may not approve as itself.

### Executor (`core/executor.py`)

Walks a plan honouring `depends_on`, parks on gates, and recomputes run status
from step status.

Two distinctions are load-bearing:

- `PlanStep.is_complete` **excludes** `FAILED`. The executor's dependency gate
  uses it, and treating a failed dependency as satisfied would run downstream
  steps against a broken state.
- `PlanStep.is_terminal` **includes** `FAILED`. The status roll-up uses it.

An earlier roll-up used `all(s.is_complete)`, so a run with a failed step reported
`running` forever. Both accessors must stay as they are.

### Dispatch (`core/dispatch.py`)

Resolves `"platform.method"` onto live connector code and coerces parameters to
the target signature. This exists because plans are **persisted and resumed**,
possibly in a different process days later.

An earlier design bound executor closures onto actions (`action.executor =
partial(...)`). That is not serialisable, and replanning on resume minted new
approval ids and looped forever. Everything is symbolic now: a plan on disk is
just data.

### Workflows (`workflows/`)

Declarative playbooks. They read state, compute a delta, and emit an
`ExecutionPlan` — they never call connectors directly at execution time.

| Workflow | Steps | Gates (approval_required) | Notes |
|---|---|---|---|
| `onboarding` | 7 | 5 | Idempotent: skips what exists, fills gaps |
| `offboarding` | ~11 | 8 | Revoke-first; ~12 approval rounds in practice |
| `transfer` | 7 | 5 | Delta-only; nothing destructive |
| `deferred_deletion` / `purge` | — | — | Retention-gated; refuses without `allow_hard_delete` |

Onboarding order: preflight → Entra identity → M365 licensing → groups and Teams
→ on-prem AD → authentication → verification. The AD account is created
**disabled**, the password is set over LDAPS, and only then is it enabled — that
ordering is not optional, because `unicodePwd` must be written UTF-16LE over an
encrypted channel and an enabled account with no password is a hole.

Offboarding is revoke-first: sessions and access go before memberships, and
licences are released **last**, after the mailbox has been preserved. Releasing a
licence first would destroy the data the shared-mailbox step depends on. There is
a test pinning that ordering.

Transfer is delta-only. A department change is not a security incident: the person
stays enabled in both directories, sessions are not revoked, devices and mailboxes
are untouched, and baseline groups like `All-Employees` are protected from
removal. Licences are exchanged in a single `assignLicense` call carrying both
`addLicenses` and `removeLicenses`, so a mover is never left holding two SKUs and
never left without one.

### Redaction (`core/redact.py`)

One module, used by the audit log, the run store and the approval queue. This
centralisation is deliberate: three copies of a redaction list will drift, and
drift means one of them writes a temporary access pass or an LDAPS bind password
in plaintext. That happened — `RunStore.save()` and `ApprovalStore` both wrote
initial passwords unredacted until everything was routed through here.

`safe_params()` scrubs action parameters on the way to disk. `model_dump()` alone
is not enough, because `Action.params` holds raw credentials and pydantic has no
reason to know that.

---

## Data flow: one onboarding

```
CLI/MCP/REST/agent
   │
   ▼
Orchestrator.run_workflow("onboarding", employee, requested_by=…)
   │
   ├─ workflow.build_plan()          reads real state from all five platforms
   │                                 computes the delta, emits ExecutionPlan
   ├─ policy.annotate_plan()         classifies risk, marks gates
   ├─ RunStore.save()                persisted (redacted) before anything runs
   │
   ▼
executor.execute(run)
   │
   ├─ step 1 preflight               reads, no gate
   ├─ step 2 entra_identity          GATE → parks → ApprovalStore + notifier
   │      ⋯ human runs `iam-agent approvals decide <id> --approve --approver …`
   │      ⋯ Orchestrator.decide_approval() → executor.resume()
   ├─ dispatch("entra.create_user")  resolves the live method, coerces params
   ├─ connector writes               audited, result recorded on the Action
   ⋮
   └─ step 10 verification           re-reads every platform, confirms end state
   │
   ▼
RunRecord.status → completed · 7/7
```

Nothing is executed that was not in the plan the human approved. Resuming a
parked run **does not rebuild the plan** — that was the bug that minted new
approval ids and looped forever.

---

## Configuration (`config.py`)

Pydantic settings, `lru_cached` via `get_settings()`. Thirteen root fields across
ten sections.

Two behaviours here are non-obvious and both were found by accident:

**Nested env vars resolve by root field name, not by the sub-model's
`env_prefix`.** For every section those coincide, so `IAM_ENTRA__ENABLED` and
`IAM_ENTRA_ENABLED` both work. They did not for AD: the field was named
`active_directory` while its prefix was `IAM_AD_`, so `IAM_AD__BASE_DN` — the form
everybody writes by analogy — silently did nothing. `validation_alias` does not
help; pydantic-settings matches nested vars before aliases are consulted. The
field is now `ad`, with `settings.active_directory` kept as a property.

**pydantic-settings JSON-decodes nested list fields before any validator runs.**
So `IAM_M365__DEFAULT_LICENSE_SKUS=ENTERPRISEPACK,EMS` raised at import, and a
blank value raised a `list_type` error — which is exactly what a freshly copied
`.env.example` produced. All five list fields now use:

```python
StringList = Annotated[list[str], NoDecode, BeforeValidator(split_csv)]
```

`NoDecode` is the part that matters; a `BeforeValidator` alone is not enough.

`unrecognized_env_vars()` enumerates every accepted name and reports `IAM_*`
variables that configure nothing. `preflight` treats that as a failure. The
asymmetry is why: the defaults are the safe ones, so a silently ignored setting
leaves the agent on the simulator while the operator believes it is live.

---

## Invariants worth knowing before you change something

These are all in `CLAUDE.md` too, which Claude Code reads automatically.

1. **Operations are named `platform.method_name` and the method must exist.**
2. **Never bind a closure onto an action.** Plans are serialised; dispatch is symbolic.
3. **Never clear an approval id after use.** The status changes; the reference stays.
4. **`is_complete` excludes FAILED; `is_terminal` includes it.** Different callers.
5. **Pydantic silently drops unknown constructor kwargs.** A misspelled field name
   does not error, it just does nothing.
6. **Unknown operations are `critical`.** Do not add a permissive fallback.
7. **Redaction goes through `core/redact.py`.** No second list.
8. **Mock and live must agree.** Where they cannot, return `*_step_required`.
9. **Accented names break logons.** `normalize_logon()` folds diacritics:
   `Miquel Àngel Camps` → `mangelcamps`.
10. **A blank env list value replaces the default.** Comment optional lists out
    rather than shipping them empty.

---

## What is deliberately not here

- **No database.** JSONL and per-run JSON files under `data/`. `RunStore` is four
  methods; swap it for Postgres when the volume justifies it.
- **No hard deletes by default.** `IAM_AD_ALLOW_HARD_DELETE=false`. Deletion is a
  separate retention-gated workflow.
- **No BYOD wipes.** Refused outright, not gated. A retention-only action is
  offered instead.
- **No script execution on endpoints.** Action1's remote-execution surface is not
  exposed. The precedent for this is
  [`borgels/mcp-server-action1`](https://github.com/borgels/mcp-server-action1),
  which omits it for the same reason: handing an LLM arbitrary code execution
  across a fleet is not a gating problem.
- **No self-approval.** Enforced in `.claude/settings.json` and in the agent loop.
