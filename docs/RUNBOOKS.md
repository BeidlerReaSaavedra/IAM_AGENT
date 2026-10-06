# Runbooks

Procedures for the things you will actually do. Every command here works against
the simulator with no configuration, so you can rehearse before touching a tenant.

Convention: `<…>` is a value you supply. Commands assume you are in the repository
root with `.venv` activated, or that `iam-agent` is on your `PATH`.

---

## Contents

1. [Start of shift: what is the state of things?](#1-start-of-shift)
2. [Onboard a joiner](#2-onboard-a-joiner)
3. [Offboard a leaver](#3-offboard-a-leaver)
4. [Move someone between departments](#4-move-someone-between-departments)
5. [Lost or stolen device](#5-lost-or-stolen-device)
6. [Compromised account](#6-compromised-account)
7. [Sweep for orphans](#7-sweep-for-orphans)
8. [Handle approval gates](#8-handle-approval-gates)
9. [Resume, cancel and roll back](#9-resume-cancel-and-roll-back)
10. [Exchange steps Graph cannot do](#10-exchange-steps-graph-cannot-do)
11. [Audit and evidence](#11-audit-and-evidence)
12. [Driving it from Claude Code](#12-driving-it-from-claude-code)

---

## 1. Start of shift

```bash
iam-agent preflight      # live vs simulated per platform; fails on config typos
iam-agent status         # connector health, latency, safety posture, pending gates
iam-agent approvals list # what is waiting on a human
iam-agent runs list      # anything parked or failed overnight
```

`preflight` exits non-zero if any `IAM_*` variable matches no setting. **Read that
before you trust anything else** — the defaults are the safe ones, so a mistyped
`IAM_ENTRA__ENABLED=true` leaves you talking to the simulator while believing
otherwise, and simulator output looks exactly like production output.

Exit codes across the CLI: `3` = parked awaiting approval, `2` = bad input or
approver, `1` = preflight or drift failure. Safe to script against.

---

## 2. Onboard a joiner

### Rehearse first

```bash
iam-agent onboard "Aina Serra Ferrer" \
  --department Ventas \
  --job-title "Account Executive" \
  --manager lferra@contoso-balears.example \
  --hire-date 2026-11-15 \
  --employee-id EMP-9001
```

Without `--execute` this plans only. Read the output: the steps, the gates, and
the **assumptions**. If an assumption says something you did not expect — a
department group you disagree with, a licence tier you did not ask for — fix the
input, not the plan.

### Then execute

```bash
IAM_GLOBAL_DRY_RUN=false iam-agent onboard "Aina Serra Ferrer" \
  --department Ventas --manager lferra@contoso-balears.example --execute
```

The run parks at the first gate and the CLI exits `3`. Work the gates
([§8](#8-handle-approval-gates)). Expect **5 approval rounds** and 7 steps:

```
1. preflight          reads only, no gate
2. entra_identity     GATE  create the account
3. m365_licensing     GATE  assign the licence
4. groups_and_teams   GATE  department groups + Teams
5. onprem_ad          GATE  on-premises account
6. authentication     GATE  temporary access pass
10. verification      re-reads every platform, confirms the end state
```

### Options

```bash
-o licenses=ENTERPRISEPACK          # override the department baseline
-o groups=Proyecto-X,Comité-SSH     # extra Entra groups
-o teams=Finance                    # Teams to join
-o device_serials=C02X1234ABCD      # bind a specific machine
-o password='…'                     # never logged; a TAP is generated otherwise
```

### Names with diacritics

Catalan and Spanish names are folded for the logon name, and this is deliberate:
`Miquel Àngel Camps` → `mangelcamps`. Display names keep their accents; only the
`sAMAccountName`/UPN prefix is ASCII. If a joiner's logon looks wrong, check
`normalize_logon()` rather than "fixing" the name.

Both of these work and mean different things:

```bash
iam-agent onboard "Aina Serra"                    # a name → split into given/family
iam-agent offboard aserra@contoso-balears.example # an email → looked up
iam-agent offboard aserra                         # a logon name → looked up
```

### Verify

```bash
iam-agent identity aserra@contoso-balears.example
iam-agent runs show <run-id>
```

The verification step already re-read every platform, but look at the identity
yourself the first few times. Confirm: enabled in Entra and AD, correct licence,
expected groups, manager set, and a TAP issued (hand it to the joiner through a
separate channel — it appears in the run record only redacted).

---

## 3. Offboard a leaver

```bash
iam-agent offboard bsola@contoso-balears.example --reason "resignation"
```

Plan it first, then `--execute`. Expect **~12 approval rounds**, because critical
steps need two distinct approvers each. The order is revoke-first:

```
immediate_lockdown    CRITICAL — sessions revoked, account disabled, devices contained
…
remove_memberships    groups, Teams, directory roles
mailbox_continuity    convert to shared, hide from GAL, delegate access
license_removal       released LAST, after the mailbox is preserved
ad_cleanup            disabled and moved to the disabled OU
verification
```

`license_removal` coming after `mailbox_continuity` is not incidental — releasing
a licence first would destroy the data the shared-mailbox step depends on. There
is a test pinning that ordering.

### Options

```bash
-o emergency=true               # hostile/same-day: quarantines endpoints immediately
-o retain_mailbox=true          # default; shared mailbox instead of removal
-o mailbox_delegate=lferra@…    # who gets access (defaults to the manager)
-o litigation_hold=true         # legal preservation — see below
-o wipe_mobile=true             # default; corporate handsets only, never BYOD
-o forward_mail_to=team@…       # optional
```

**Litigation hold is off by default.** It is a legal measure that blocks purge
indefinitely and consumes storage. Apply it for investigations or VIP departures,
not routinely. It also has no Graph API — see [§10](#10-exchange-steps-graph-cannot-do).

### What should remain afterwards

```bash
iam-agent identity bsola@contoso-balears.example
```

- Enabled: **False** in Entra and in AD
- Groups: **none**
- Mailbox: **shared**, hidden from the GAL, delegate has FullAccess
- Corporate devices: wiped and retired, unassigned
- BYOD devices: **untouched**, but unassigned
- Licences: released
- The account itself: **present**. Nothing is hard-deleted.

### BYOD

A full wipe of a personally-owned device is **refused outright** — not gated,
refused. You will see `{"refused": true}` in the plan. The retention-only action
(remove corporate data, unassign the user) is offered and goes through the normal
approval flow. Do not try to route around the refusal; if a BYOD device genuinely
needs wiping, that is a legal conversation, not a tooling one.

### Deletion

Separate, retention-gated, and off by default:

```bash
iam-agent purge --reason "retention window elapsed"        # plans
iam-agent purge --execute                                  # requires ALLOW_HARD_DELETE=true
```

With `IAM_AD__ALLOW_HARD_DELETE=false` this refuses with an `AuthorizationError`.
That is correct behaviour. Changing it is a policy decision that should not be
made in the middle of an offboarding.

---

## 4. Move someone between departments

```bash
iam-agent transfer nserra@contoso-balears.example \
  --department Finanzas \
  --job-title "Responsable de Control" \
  --manager jpuig@contoso-balears.example \
  --reason "internal promotion" --execute
```

**5 gates**, 7 steps. This is delta-only and nothing destructive happens:

- The person stays **enabled** in both directories
- Sessions are **not** revoked
- Devices and mailboxes are **untouched**
- Baseline groups (`All-Employees`, `MFA-Required`, `MDM-Enrolled`) are protected
- Department groups are swapped: `Ventas-All` → `Finanzas-All`
- Teams are swapped: `Comercial` → `Finance`
- Licences are exchanged **atomically** — one `assignLicense` call carrying both
  halves, so the old SKU is released and there is no service gap

### What it will not do

A transfer does not remove groups it did not derive from the department. Someone
in `Ventas-Campo` who moves to Finanzas **keeps** `Ventas-Campo`. That is
deliberate: the workflow will not strip access it has no evidence was
department-derived. Review the group delta in the plan and remove stragglers
explicitly if they should go.

```bash
iam-agent identity nserra@contoso-balears.example    # check the result
```

---

## 5. Lost or stolen device

Find it, then contain it. Containment is separate from provisioning and should not
wait on an offboarding.

```bash
iam-agent devices                                    # everything, both consoles
iam-agent identity <owner@corp.example>              # that person's devices
```

### Corporate device

```bash
iam-agent offboard <owner@corp.example> -o emergency=true      # if they also left
```

Or contain the device on its own through the API/MCP `lock_device` / `wipe_device`
tools. A wipe is a gated write and needs approval; on a critical-risk device, two
approvers.

### BYOD

You can **lock** it and **unassign** the user. You cannot full-wipe it, and the
refusal is not configurable. Retention-only removal of corporate data is the
offered path.

### Sequencing

Lock **before** wipe. A wipe on a device that is still reachable by a thief races
the wipe itself, and locking first stops that. Lost-mode sequencing is:
lock → locate → revoke the owner's sessions → wipe (corporate only) → retire →
unassign.

---

## 6. Compromised account

Speed matters more than ceremony here, but the gates still apply — that is what
makes the action auditable after the fact.

```bash
# 1. Revoke everything, immediately
iam-agent offboard <user@corp.example> -o emergency=true --reason "compromise" --execute

# 2. Work the gates as fast as two humans can
iam-agent approvals list
iam-agent approvals decide <id> --approve --approver you@corp.example --comment "active compromise"
```

The `immediate_lockdown` step is `critical` and needs **two distinct approvers**.
Have the second person ready before you start. If you genuinely cannot get one,
that is a reason to do it manually in the Entra portal in parallel — not a reason
to weaken `AUTONOMOUS_MAX_RISK`.

Then verify:

```bash
iam-agent identity <user@corp.example>
iam-agent drift --identifier <user@corp.example>
```

Look specifically for: sessions revoked, account disabled, devices contained,
group memberships stripped, and no lingering directory roles.

If the account should **not** be offboarded (compromised but employed), use the
MCP/API `revoke_sessions` and `disable_user` tools directly rather than the
offboarding workflow, and re-enable afterwards.

---

## 7. Sweep for orphans

Accounts still enabled after their leave date. This is the highest-value recurring
job here, and it is what the simulator is seeded to demonstrate.

```bash
iam-agent drift                 # whole estate
iam-agent drift --identifier <email>   # one person
```

Findings carry a severity. The ones that matter most:

```
[critical] Leave date … is 40 day(s) in the past but the Entra account is still ENABLED.
[critical] On-prem AD account still enabled 40 day(s) after the leave date.
[high]     … is still enrolled and assigned, state=active.
[high]     Account is enabled but has no strong authentication method registered.
```

Then act on them:

```bash
iam-agent offboard <orphan@corp.example> --reason "orphaned account, left <date>" --execute
```

Or let the agent do the sweep:

```bash
iam-agent agent "Find everyone still enabled who left more than 30 days ago and offboard them"
```

It will plan each one, park on the gates, and report what is waiting. It cannot
approve them itself.

Schedule it. `purge` and the drift sweep are the two jobs worth putting in cron;
the drift sweep weekly is a reasonable starting point.

---

## 8. Handle approval gates

```bash
iam-agent approvals list                      # what is pending
iam-agent approvals show <apv_…>              # the review document
iam-agent approvals decide <apv_…> --approve --approver you@corp.example --comment "checked with manager"
iam-agent approvals decide <apv_…> --reject  --approver you@corp.example --comment "not after all"
```

`--approver` is **required** and must be a real identity. `claude`, `agent`, `ai`,
`system`, `api` and `anonymous` are rejected outright — an agent may not approve
as itself, and neither may a script pretending to be nobody.

`--wait` is the default: the run resumes in-process and you see it finish. Use
`--no-wait` to decide and return immediately (useful from a ticketing system).

### Read the review document before deciding

`approvals show` renders what a human actually needs: the subject, the risk,
whether it is reversible, every action with its **redacted** parameters, and what
depends on it. If you find yourself approving without reading it, the gate is not
doing its job.

### Two-person integrity

`critical` actions need two **distinct** approvers. The store rejects a second
signature from the same identity, so you cannot satisfy it alone:

```
[critical] immediate_lockdown — user@corp.example  (1/2 approvers)
[critical] immediate_lockdown — user@corp.example  (2/2 approvers)
```

### Rejecting

A rejection **cancels the run**. Nothing further executes and nothing already
executed is undone automatically — see [§9](#9-resume-cancel-and-roll-back) if you
need to reverse work that was already applied.

### Expiry

Gates expire. `approvals list` shows the deadline; expired requests are reported
separately and the run will not resume against a stale approval.

---

## 9. Resume, cancel and roll back

```bash
iam-agent runs list
iam-agent runs show <run-id>
iam-agent runs resume <run-id>
iam-agent runs cancel <run-id> --reason "superseded"
iam-agent runs rollback <run-id>
```

### Resume

Runs survive process restarts — they are persisted to `data/runs/*.json`. Resuming
**does not rebuild the plan.** That was a real bug: rebuilding minted new approval
ids and the run looped forever. The plan on disk is the plan that was approved.

### Rollback

Executes the compensating actions for everything already applied. Two caveats:

- It compensates what **this run** did. It does not undo a state that was already
  wrong.
- Not everything is compensable. A wiped device is not unwiped. `reversible` on
  each action tells you before you rely on it.

Read `runs show <run-id>` and check which actions are marked reversible before
promising anyone a rollback.

---

## 10. Exchange steps Graph cannot do

Some offboarding steps have no Microsoft Graph API. The plan says so explicitly
rather than pretending:

```
exchange_step_required: Set-Mailbox -Shared -Identity user@corp.example
```

Run these in an Exchange Online PowerShell session:

```powershell
Connect-ExchangeOnline

# Convert to shared (preserves the data, releases the licence)
Set-Mailbox -Shared -Identity <user@corp.example>

# Hide from the global address list
Set-Mailbox -Identity <user@corp.example> -HiddenFromAddressListsEnabled $true

# Delegate access to the manager
Add-MailboxPermission -Identity <user@corp.example> -User <manager@corp.example> -AccessRights FullAccess

# Litigation hold, when it was requested
Set-Mailbox -Identity <user@corp.example> -LitigationHoldEnabled $true
```

Then resume the run:

```bash
iam-agent runs resume <run-id>
```

Seeing `exchange_step_required` is **not a failure**. A plan that claimed to have
converted a mailbox when Graph cannot do that would be far worse.

---

## 11. Audit and evidence

Everything is appended to `data/audit.jsonl`. It is append-only and secrets are
redacted on the way in.

```bash
iam-agent audit                       # tail
iam-agent audit -n 500 --event approval_approved
iam-agent audit --run-id <run-id>     # one run, end to end
```

Via the API:

```bash
curl -s 'localhost:8000/audit?n=200&event=action_executed' | jq
curl -s localhost:8000/runs/<run-id> | jq
curl -s localhost:8000/runs/<run-id>/markdown
```

The markdown form is the one to attach to a ticket or hand to an auditor: the
plan, every action, who approved what and when, and the final state.

### What is never in the log

Passwords, temporary access passes, client secrets, bind passwords, API keys,
refresh tokens. Redaction is centralised in `core/redact.py` and applied to the
audit log, the run store **and** the approval queue, so the three cannot drift
apart. If you add a secret-bearing field, add it there — nowhere else.

---

## 12. Driving it from Claude Code

```bash
claude
```

`.mcp.json` registers the server automatically. Four subagents are available and
scope the tools by job:

| Ask for | Subagent | Can write? |
|---|---|---|
| "audit our estate for drift" | `iam-auditor` | no — 18 read-only tools |
| "onboard Aina Serra into Ventas" | `iam-onboarding` | yes, gated |
| "offboard Bea Solà, she left in August" | `iam-offboarding` | yes, gated |
| "which devices are unpatched?" | `iam-endpoints` | yes, gated |

They will plan, show you the plan, and then tell you a gate is waiting. **You**
run the decide command:

```bash
iam-agent approvals decide <apv_…> --approve --approver you@corp.example
```

`decide_approval` is in the `deny` list in `.claude/settings.json` and withheld
from the agent loop. That is structural, not a prompt instruction — no amount of
asking will get Claude to approve its own write.

### Useful prompts

```
"Who is still enabled but left more than 30 days ago?"
"Show me every device with critical vulnerabilities, grouped by owner."
"Plan an offboarding for <email> with emergency=true and tell me what needs approving."
"What would change if I moved <email> from Ventas to Finanzas? Plan only."
"Compare Entra and on-prem AD group membership for <email>."
```

Add "plan only" when you want to read before anything is staged. The `--plan-only`
flag on `iam-agent agent` enforces it: no write may even be planned.
