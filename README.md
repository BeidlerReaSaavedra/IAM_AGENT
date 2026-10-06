# IAM Agent

An identity and endpoint lifecycle agent for **Microsoft Entra ID**, **Microsoft 365**,
**on-premises Active Directory**, **Action1** (RMM / PCs) and **Scalefusion** (MDM / mobile).

It automates **onboarding**, **offboarding** and **transfer** across all five platforms —
identity *and* devices — and it can be driven three ways from one shared core:

| Surface | Command | Who drives it |
|---|---|---|
| **MCP server** | `iam-agent mcp` | Claude Code / Claude Desktop, with four scoped subagents |
| **Autonomous agent** | `iam-agent agent` | Claude over the Anthropic API, with its own tool loop |
| **REST control plane** | `iam-agent serve` | Your HR system, webhooks, or a dashboard |
| **CLI** | `iam-agent …` | You, directly |

```
┌─────────────────────────────────────────────────────────────────────┐
│  MCP server (33 tools)   REST API (32 routes)   CLI   Agent loop    │
├─────────────────────────────────────────────────────────────────────┤
│  Orchestrator · policy & risk · approvals · executor · audit · drift │
├─────────────────────────────────────────────────────────────────────┤
│  Workflows: onboarding · offboarding · transfer · purge              │
├─────────────────────────────────────────────────────────────────────┤
│  Connectors: Entra · M365 · AD (ldap3) · Action1 · Scalefusion       │
│              each with a live implementation and a simulator         │
└─────────────────────────────────────────────────────────────────────┘
```

---

## The safety model

This agent can delete accounts, wipe phones and revoke licences. Everything about
the design follows from that.

**1. Reads are live. Writes are gated.** Every mutation is classified by risk
(`low` → `critical`) and, in the default `approval_required` mode, parks the run
until a named human approves it. Critical actions — hard deletes, device wipes —
need **two distinct approvers**.

```bash
iam-agent approvals list
iam-agent approvals show <id>       # the review document a human reads
iam-agent approvals decide <id> --approve --approver you@corp.example
```

**2. Dry run is the default.** `IAM_GLOBAL_DRY_RUN=true` ships as the default and
overrides everything else, including `IAM_APPROVAL__DEFAULT_MODE=autonomous`.
Nothing writes until you deliberately turn it off.

**3. Nothing is hard-deleted by default.** `IAM_AD_ALLOW_HARD_DELETE=false`.
Leavers are disabled, their mailboxes become shared with litigation hold where
requested, and deletion is a separate `purge` workflow gated on a retention window.

**4. BYOD is never wiped.** A full wipe of a personally-owned device is refused
outright, not merely gated.

**5. Unknown means critical.** An operation the policy engine does not recognise
is classified `critical`, not `low`. Failing safe costs an extra approval;
failing open costs an incident.

**6. Secrets never reach the log.** One redaction module (`core/redact.py`) is the
single source of truth for the audit log, the run store and the approval queue, so
they cannot drift apart and leave one of them writing a TAP or a bind password in
plaintext.

**7. Misconfiguration is loud.** `preflight` fails on any `IAM_*` variable that
matches no setting, because the defaults here are the *safe* ones — a mistyped
`IAM_ENTRA__ENABLED=true` would otherwise leave the agent talking to the simulator
while you believed it was talking to your tenant, and you would read simulator
output as production truth.

---

## Quick start

```bash
# Python 3.11+
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

cp .env.example .env          # 92 documented keys; safe defaults, works as-is
iam-agent preflight           # what is live, what is simulated, what is unset
iam-agent status
```

With no credentials at all, every platform falls back to a deterministic simulator
populated with a realistic estate (7 employees, 13 groups, 6 Teams, 8 Action1
endpoints, 5 Scalefusion devices) in the domain `contoso-balears.example`. It
persists to `data/mock_estate.json`, so state survives across processes — you can
onboard someone in one shell and find them in the next.

```bash
# Plan a joiner (nothing executes; this is the default)
iam-agent onboard "Aina Serra" --department Ventas --manager lferra@contoso-balears.example

# Execute for real, with approval gates
IAM_GLOBAL_DRY_RUN=false IAM_APPROVAL__DEFAULT_MODE=approval_required \
  iam-agent onboard "Aina Serra" --department Ventas --execute

iam-agent approvals list
iam-agent approvals decide <id> --approve --approver you@corp.example
iam-agent runs show <run-id>
```

CLI exit codes are scriptable: `3` = parked awaiting approval, `2` = bad input or
approver, `1` = preflight or drift failure.

---

## Connecting it to Claude Code

`.mcp.json`, `.claude/settings.json` and `.claude/agents/` are committed, so
Claude Code picks the server up on launch:

```bash
claude          # then: "onboard Aina Serra into Ventas, starting Monday"
```

Four subagents scope the tool surface by job:

| Subagent | Role |
|---|---|
| `iam-auditor` | Read-only. 18 tools, no writes of any kind. |
| `iam-onboarding` | Joiners. Plans before executing, folds diacritics, binds serials. |
| `iam-offboarding` | Leavers. Revoke-first ordering, mailbox preservation, BYOD rules. |
| `iam-endpoints` | Action1 + Scalefusion fleet: containment vs provisioning, ownership. |

**None of them can approve.** `mcp__iam-agent__decide_approval` is in the `deny`
list in `.claude/settings.json`, and the autonomous agent loop withholds it too —
an agent that could sign its own write approvals would defeat the entire model.
A human runs `iam-agent approvals decide`.

---

## The three ways to run it

### Autonomous agent

```bash
export ANTHROPIC_API_KEY=sk-ant-…
iam-agent agent "Find anyone still enabled who left more than 30 days ago and offboard them"
```

Its own tool loop over the same 33 tools minus `decide_approval`, with the
operator-maintained prompt in `config/system_prompt.md`. It parks on approval
gates and reports what is waiting rather than routing around it.

### REST control plane

```bash
iam-agent serve --host 0.0.0.0 --port 8000
curl -s localhost:8000/preflight | jq
```

32 routes: identity lookups, drift, devices, runs, approvals, audit, and two
inbound webhooks (`/webhooks/hr` for joiner/mover/leaver events,
`/webhooks/scalefusion` for device lifecycle). Both verify an HMAC-SHA256
signature over the raw body **before** parsing it. Approval decisions require a
bearer token; reads do not.

### MCP server

```bash
iam-agent mcp        # stdio, for Claude Code / Claude Desktop
```

---

## Workflows

**Onboarding** — 7 steps, 5 approval gates. Preflight → Entra identity → M365
licensing → groups and Teams → on-prem AD → authentication (TAP) → verification.
Creates the account disabled, sets the password over LDAPS, then enables it, in
that order. Idempotent: re-running for someone already provisioned skips what
exists and fills the gaps.

**Offboarding** — revoke-first, ~8 gates, typically ~12 approval rounds because
critical steps need two approvers each. Sessions revoked, licences released,
groups and Teams stripped, AD account disabled, mailbox converted to shared and
hidden from the GAL, corporate devices wiped and retired, BYOD untouched.

**Transfer** — delta-only, 4 gates. Nothing destructive: the person stays enabled
in both directories, sessions are not revoked, devices and mailboxes are
untouched. Department groups and Teams are swapped, licences are exchanged in a
single atomic `assignLicense` call so a mover is never left holding two SKUs, and
baseline groups like `All-Employees` are protected from removal.

**Purge** — deletes Entra objects for leavers whose retention window has expired.
Refuses when `allow_hard_delete` is false.

Some things Graph cannot do. Where that is the case the plan says so explicitly —
a mailbox type flip, FullAccess grant or litigation hold comes back as
`exchange_step_required` with the exact PowerShell cmdlet to run, rather than
silently claiming success.

---

## Configuration

Copy `.env.example` and fill in what you have. Every key is documented inline with
the reason it exists.

Env vars accept two spellings, `IAM_<SECTION>__<FIELD>` and `IAM_<SECTION>_<FIELD>`.
Prefixes: `IAM_ENTRA_`, `IAM_M365_`, `IAM_AD_`, `IAM_ACTION1_`, `IAM_SCALEFUSION_`,
`IAM_CLAUDE_`, `IAM_APPROVAL_`, `IAM_AUDIT_`, `IAM_API_`, `IAM_MOCK_`.

Two things worth knowing, both learned the hard way:

- **List values are comma-separated**, and a *blank* value means an empty list —
  it replaces the default rather than keeping it. `.env.example` therefore ships
  `IAM_AUDIT__REDACT_FIELDS` commented out: an empty value there would silently
  remove `temporaryAccessPass` and `refresh_token` from redaction.
- **A typo is reported, not ignored.** `iam-agent preflight` lists every `IAM_*`
  variable that configures nothing.

Platform credentials: Entra ID and M365 use client-credentials against Microsoft
Graph (`msal`); Action1 uses OAuth2 client credentials; Scalefusion uses an API key
and is rate-limited to 30 requests/minute and 43,200/day; on-prem AD binds over
LDAPS with `ldap3` — password writes are refused without TLS, because
`unicodePwd` must be sent UTF-16LE over an encrypted channel.

### Documentation

| | |
|---|---|
| [`docs/SETUP.md`](docs/SETUP.md) | Per-platform app registration, exact Graph permissions, LDAPS, credential handling |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | How the layers fit together, and the invariants that are easy to break |
| [`docs/RUNBOOKS.md`](docs/RUNBOOKS.md) | Onboard, offboard, transfer, lost device, compromised account, orphan sweep, rollback |
| [`CLAUDE.md`](CLAUDE.md) | Project memory for Claude Code |
| [`.env.example`](.env.example) | All 92 settings, each with the reason it exists |

---

## Development

```bash
make test       # rm -rf data && pytest
make lint       # ruff + mypy
make demo       # a full onboarding → approval → completion cycle
```

237 tests. `ruff` clean, `mypy` clean over all 36 modules.

Tests run against the simulator with `global_dry_run=False` and
`approval_required`, so the approval machinery is exercised rather than bypassed.
Each test starts from a freshly reseeded estate in a temporary cwd.

`CLAUDE.md` holds the project memory for Claude Code: the invariants that are easy
to break, why operations are named `platform.method_name`, and why nothing is ever
bound as a closure onto an action.

---

## Layout

```
src/iam_agent/
├── config.py             # settings; env resolution; posture helpers
├── cli.py                # typer app
├── agent/loop.py         # autonomous Claude tool loop
├── api/app.py            # FastAPI control plane (32 routes)
├── mcp_server/server.py  # MCP server (33 tools)
├── core/
│   ├── models.py         # Employee, IdentitySnapshot, Device, DriftFinding…
│   ├── policy.py         # risk classification & duty gating
│   ├── approval.py       # two-person integrity, expiry, notifications
│   ├── executor.py       # runs plans, honours dependencies, parks on gates
│   ├── dispatch.py       # resolves "platform.method" onto live connector code
│   ├── orchestrator.py   # the API every surface shares
│   ├── reconcile.py      # drift detection across all five platforms
│   ├── result.py         # Action, PlanStep, ExecutionPlan, RunRecord, RunStore
│   ├── redact.py         # the only place secrets are masked
│   └── audit.py          # append-only JSONL
├── connectors/           # base + entra, m365, ad_local, action1, scalefusion
│   └── mock/store.py     # deterministic, persisted simulator
└── workflows/            # onboarding, offboarding, transfer, registry
```

## Licence

MIT.
