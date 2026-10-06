# Setup

Getting from a fresh clone to a working deployment, platform by platform.

**You do not need any of this to start.** With no credentials configured, every
platform falls back to a deterministic simulator and the whole system works —
plans, approvals, execution, drift detection, the lot. Do that first:

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
iam-agent preflight
python scripts/demo.py          # full onboarding → approvals → offboarding cycle
```

Then enable platforms one at a time. Each one is independently switchable via
`IAM_<PLATFORM>_BACKEND=live|mock`, so you can run Entra for real while Action1
is still simulated.

---

## The order to do this in

1. **Reads first.** Enable a platform with `IAM_GLOBAL_DRY_RUN=true` and run
   `iam-agent identity <someone>` and `iam-agent drift`. Confirm what comes back
   matches reality before anything can write.
2. **One platform at a time.** Mixed live/simulated is supported and useful, but
   debugging five at once is not.
3. **Approvals on, always.** `IAM_APPROVAL__DEFAULT_MODE=approval_required` is the
   default. `autonomous` exists for break-glass and scheduled housekeeping; if you
   turn it on, set `IAM_APPROVAL__AUTONOMOUS_MAX_RISK=medium` or lower so critical
   actions still gate.
4. **`preflight` before every session.** It reports live vs simulated per platform,
   and fails on any `IAM_*` variable that matches no setting.

```bash
iam-agent preflight
iam-agent status
```

---

## Microsoft Entra ID

**App registration** — Entra admin centre → App registrations → New registration.

Authentication: **no redirect URI**. This is a daemon using client credentials.

Create a client secret (Certificates & secrets → New client secret) and copy the
**value**, not the secret id — the value is shown once.

```dotenv
IAM_ENTRA__ENABLED=true
IAM_ENTRA__BACKEND=live
IAM_ENTRA__TENANT_ID=00000000-0000-0000-0000-000000000000
IAM_ENTRA__CLIENT_ID=11111111-1111-1111-1111-111111111111
IAM_ENTRA__CLIENT_SECRET=…
IAM_ENTRA__PRIMARY_DOMAIN=contoso-balears.example
```

### Application permissions

All are **Application** type, granted under API permissions → Add a permission →
Microsoft Graph, then **Grant admin consent**.

| Permission | Why |
|---|---|
| `User.ReadWrite.All` | Create/update users, set manager, assign licences, revoke sessions |
| `Group.ReadWrite.All` | Read and write group membership |
| `RoleManagement.ReadWrite.Directory` | Grant and revoke Entra directory roles |
| `UserAuthenticationMethod.ReadWrite.All` | Issue and read temporary access passes |
| `TeamMember.ReadWrite.All` | Add and remove Teams members |
| `Organization.Read.All` | Read `subscribedSkus` for licence capacity, and `organization` |
| `Domain.Read.All` | Resolve the tenant's verified domains for UPN derivation |
| `Files.ReadWrite.All` | OneDrive sharing invitations during offboarding handover |
| `Mail.ReadWrite` | Inbox rules (forwarding) during offboarding |
| `MailboxSettings.ReadWrite` | Mailbox settings and delegation |
| `LifecycleWorkflows.ReadWrite.All` | Only if you use Entra ID Governance lifecycle workflows |

Grant the **minimum you need for the workflows you will actually run**. A
read-only audit deployment needs `User.Read.All`, `Group.Read.All`,
`Organization.Read.All` and `Domain.Read.All` — nothing else. The `iam-auditor`
subagent never calls a write tool, so it works with read-only grants.

### Lifecycle workflows (optional)

If you want the agent to drive Entra ID Governance lifecycle workflows rather than
making Graph calls directly, it needs `LifecycleWorkflows.ReadWrite.All` **and**
the calling identity must hold the **Lifecycle Administrator** role **and** the
tenant must be licensed for **Entra ID Governance**. Without all three, the
`list_lifecycle_workflows` and `run_lifecycle_workflow` operations fail.

One caveat worth knowing before you rely on them: the built-in
`disableOnPremisesAccount` task does **not** support users with Entra role
assignments or membership of a role-assignable group. Those users need the
on-premises path instead, which is why this agent talks to AD directly rather
than only through lifecycle workflows.

---

## Microsoft 365

Same app registration and same Graph token as Entra — the split is logical, not
authenticational. Entra is the identity plane; M365 is the service plane
(licences, mailboxes, Teams, OneDrive).

```dotenv
IAM_M365__ENABLED=true
IAM_M365__BACKEND=live
IAM_M365__TENANT_ID=…
IAM_M365__CLIENT_ID=…
IAM_M365__CLIENT_SECRET=…
IAM_M365__DEFAULT_LICENSE_SKUS=ENTERPRISEPACK
IAM_M365__CONVERT_MAILBOX_TO_SHARED=true
IAM_M365__SHARED_MAILBOX_RETENTION_DAYS=90
```

`DEFAULT_LICENSE_SKUS` is comma-separated and is what a joiner receives when the
request does not specify one. Leave the `.env.example` line **blank or commented**
if you want the department baseline to decide.

### What Graph cannot do

Three offboarding operations have no Graph equivalent and come back as
`exchange_step_required` with the exact PowerShell cmdlet:

| Operation | Cmdlet |
|---|---|
| Convert mailbox to shared | `Set-Mailbox -Shared` |
| Grant FullAccess to a delegate | `Add-MailboxPermission -User … -AccessRights FullAccess` |
| Place mailbox on litigation hold | `Set-Mailbox -LitigationHoldEnabled $true` |

The plan tells you this rather than pretending. Run the cmdlets in an Exchange
Online PowerShell session, then resume the run. This is a Microsoft limitation,
not a gap in the connector — if you know a supported Graph path, it belongs in
`connectors/m365.py`.

Litigation hold is **not** applied by default. It is an explicit option
(`--option litigation_hold=true`) or implied for VIP employment types, because it
blocks purge indefinitely and consumes storage.

---

## On-premises Active Directory

Needs a service account and **LDAPS**. Password writes are refused without TLS,
because `unicodePwd` must be sent UTF-16LE over an encrypted channel — that is an
Active Directory constraint, not a policy choice here.

```dotenv
IAM_AD__ENABLED=true
IAM_AD__BACKEND=live
IAM_AD__SERVERS=dc01.corp.local,dc02.corp.local
IAM_AD__PORT=636
IAM_AD__USE_SSL=true
IAM_AD__TLS_VALIDATE=true
IAM_AD__CA_CERTS_FILE=/etc/ssl/certs/corp-ca.pem
IAM_AD__BIND_USER=CN=svc-iam-agent,OU=Service Accounts,DC=corp,DC=local
IAM_AD__BIND_PASSWORD=…
IAM_AD__BASE_DN=DC=corp,DC=local
IAM_AD__USERS_CONTAINER=OU=Usuarios,DC=corp,DC=local
IAM_AD__DISABLED_OU=OU=Disabled,DC=corp,DC=local
IAM_AD__ALLOW_HARD_DELETE=false
```

### Naming, and a trap

This section accepts both `IAM_AD__<FIELD>` and `IAM_AD_<FIELD>`. That was not
always true and the history is worth knowing, because it is the one place a
typo-shaped mistake actually bit:

Nested env vars in pydantic-settings resolve by **root field name**, not by the
sub-model's `env_prefix`. Every other section's prefix stem happens to equal its
field name, so both spellings work by coincidence. AD's field was named
`active_directory` while its prefix was `IAM_AD_`, so `IAM_AD__BASE_DN` silently
did nothing. The field is now `ad` and both forms work.

If you get this wrong elsewhere, `iam-agent preflight` will tell you — it reports
every `IAM_*` variable that matches no setting.

### Service account rights

The bind account needs, scoped as narrowly as your OU structure allows:

- Create/delete user objects in `USERS_CONTAINER`
- Write `userAccountControl`, `unicodePwd`, `pwdLastSet`, and the profile
  attributes (`title`, `department`, `company`, `manager`, `memberOf`)
- Move objects into `DISABLED_OU`
- Read across `BASE_DN` for lookups and drift detection

**Do not grant Domain Admins.** `ALLOW_HARD_DELETE=false` means the agent will
refuse deletions even if the account could perform them, and that refusal is the
point — but a least-privilege bind account means a compromised credential cannot
do what the policy already forbids.

Delegation via an OU-scoped role is the right shape: *Create, delete and manage
user accounts* on the users OU, plus *Reset passwords* if the agent should own
that.

---

## Action1 (RMM — PCs and servers)

Console → **Configuration → Users & API Credentials → + New API Credentials**.
The secret is shown **once**.

```dotenv
IAM_ACTION1__ENABLED=true
IAM_ACTION1__BACKEND=live
IAM_ACTION1__CLIENT_ID=…
IAM_ACTION1__CLIENT_SECRET=…
IAM_ACTION1__REGION=europe
IAM_ACTION1__ORGANIZATION_ID=…
```

`REGION=europe` gives `https://app.eu.action1.com/api/3.0`; `north_america` gives
the US host. Action1 isolates by organization, so `ORGANIZATION_ID` matters if the
credential can see more than one.

Authentication is OAuth2 client credentials: the connector POSTs form-encoded
`client_id`/`client_secret` to `{base}/oauth2/token` and uses the returned JWT as
a bearer token for about an hour.

### What is deliberately not exposed

Action1's remote script execution, package deployment and reboot surfaces are
**not** wired up. `IAM_ACTION1__ALLOW_REMOTE_REBOOT=false` by default, and there
is no `execute_script` operation at all.

This mirrors
[`borgels/mcp-server-action1`](https://github.com/borgels/mcp-server-action1),
which omits the same capabilities for the same reason. Arbitrary code execution
across a fleet is not a gating problem — no approval workflow makes it safe to
hand an LLM a shell on every endpoint. What *is* exposed: endpoint inventory,
patch and vulnerability status, group membership, and containment actions.

Rate limits are per organization; the connector does not retry aggressively.

---

## Scalefusion (MDM — mobile)

Dashboard → **Integrations → Developer API → Generate API Key**. Regenerating
**disables the previous key**, so rotate deliberately.

```dotenv
IAM_SCALEFUSION__ENABLED=true
IAM_SCALEFUSION__BACKEND=live
IAM_SCALEFUSION__API_KEY=…
IAM_SCALEFUSION__API_VERSION=v2
IAM_SCALEFUSION__RATE_LIMIT_PER_MINUTE=30
```

Base URL is `https://api.scalefusion.com`. Constraints from the vendor:

- **30 requests/minute and 43,200/day.** The connector throttles to
  `RATE_LIMIT_PER_MINUTE`; lowering it is safe, raising it will get you 429s.
- **CORS-blocked from browsers.** It must be called from a backend, which is what
  this is. Do not proxy it through a browser-side app.
- Testing needs at least one managed device, one Device Profile and one Device
  Group to exist.

Both `v1` and `v2` endpoints exist. This connector uses `v2`
(`/api/v2/devices.json` and friends).

### BYOD

A full wipe of a personally-owned device is **refused outright** — not gated, not
approval-required, refused. `ownership` is read from the device record. A
retention-only action (remove corporate data, unassign the user) is offered
instead and does go through the normal approval flow.

### Webhooks (optional)

Scalefusion can POST device lifecycle events to `/webhooks/scalefusion`. This
needs the **Enterprise 2023 plan** and Integrations write permission.

```dotenv
IAM_SCALEFUSION__WEBHOOK_SECRET=…
IAM_API__SCALEFUSION_WEBHOOK_SECRET=…   # same value; this is what the API verifies
```

Events include Device Enrolled/Activated/Unenrolled/Deleted/Locked/Unlocked/
Lost/Found, User Signed In/Out, Shutdown, Reboot, Custom Properties Updated and
SIM Swap.

The endpoint verifies an HMAC-SHA256 signature over the **raw body** before
parsing it, and refuses with `503` if no secret is configured. The vendor's exact
wire format is not documented, so both a bare hex digest and a `sha256=`-prefixed
one are accepted — a verifier matching only one spelling would reject every
legitimate event, and that failure is indistinguishable from turning away an
attacker.

---

## The control plane

```dotenv
IAM_API__HOST=0.0.0.0
IAM_API__PORT=8000
IAM_API__API_TOKEN=…                      # required for approval decisions
IAM_API__HR_WEBHOOK_SECRET=…
IAM_API__CORS_ORIGINS=https://intranet.corp.local
```

**`API_TOKEN` is required, and the endpoint fails closed without it.** It guards
`POST /approvals/{id}/decision` — the only route that can authorise a write. If it
is unset that route returns `403` naming this setting, rather than accepting the
request as `anonymous`. Reads are unguarded by design (they cannot authorise
anything), and inbound webhooks use their own HMAC secrets.

The same applies to both webhook secrets: unset means `503`, not "verification
skipped". All three default to empty, so a freshly started API refuses writes
until you configure it — that is deliberate. Use `iam-agent approvals decide`
locally while developing; it runs as the invoking user and enforces the approver
identity itself.

`CORS_ORIGINS` defaults to `["*"]`. **Set it explicitly in production.** The
default is convenient for development and wrong everywhere else. With a wildcard
the app also sets `allow_credentials=False` — credentials plus a wildcard origin
is a combination that becomes exploitable the moment anything else is narrowed, so
it is not offered even by accident. Note that a
*blank* value means an empty list, not the default — list settings replace rather
than extend, which is also why `.env.example` ships `IAM_AUDIT__REDACT_FIELDS`
commented out.

```bash
iam-agent serve --host 0.0.0.0 --port 8000
curl -s localhost:8000/preflight | jq
```

### HR webhook

`POST /webhooks/hr` accepts joiner/mover/leaver events and starts the matching
workflow:

```json
{
  "event_type": "leaver",
  "employee": { "email": "bsola@contoso-balears.example", "first_name": "Bea", "last_name": "Solà" },
  "reason": "resignation",
  "requested_by": "workday",
  "execute": true
}
```

Signed with `X-Hub-Signature: sha256=<hmac>` over the raw body when
`HR_WEBHOOK_SECRET` is set. **An unsigned leaver event is a denial-of-service
vector against your own staff**, so configure the secret whenever the endpoint is
reachable.

The signature is checked **before** the payload is parsed. A malformed body from
an unauthenticated caller gets `401`, not `422` — otherwise the schema is
probeable without a secret and a bad signature is never reported.

---

## The autonomous agent

Only needed for `iam-agent agent`. The MCP server and the REST API do not require
an Anthropic key — Claude Code and Claude Desktop bring their own.

```dotenv
IAM_CLAUDE__API_KEY=sk-ant-…
IAM_CLAUDE__MODEL=claude-sonnet-4-5
IAM_CLAUDE__MAX_TURNS=25
IAM_CLAUDE__SYSTEM_PROMPT_PATH=config/system_prompt.md
```

```bash
iam-agent agent "Find anyone still enabled who left more than 30 days ago and offboard them"
iam-agent agent --plan-only "…"      # forced read-only: no write may be planned
```

The agent gets **32** tools — everything except `decide_approval`. When it hits a
gate it parks the run and reports what is waiting. It cannot route around a
refusal, and `FORBIDDEN_DECIDERS` blocks it from approving as `claude`, `agent`,
`ai`, `system`, `api` or `anonymous`.

`SYSTEM_PROMPT_PATH` is resolved relative to the repository root, not the cwd, so
the operator-maintained prompt in `config/system_prompt.md` is found no matter
where you launch from. An earlier version resolved it against cwd and silently
fell back to a built-in prompt.

---

## Claude Code integration

Nothing to configure — `.mcp.json`, `.claude/settings.json` and `.claude/agents/`
are committed. Launch `claude` in the repository root and the server is available.

`.claude/settings.json` encodes the safety model as **permissions rather than
instructions**: 19 read tools allowed, 13 write tools set to ask, and
`mcp__iam-agent__decide_approval` denied outright. Instructions can be argued
with; a deny rule cannot.

Four subagents scope the surface by job — `iam-auditor` (read-only, 18 tools),
`iam-onboarding`, `iam-offboarding`, `iam-endpoints`. Each documents the gate
command a human must run and forbids routing around a refusal.

---

## Verifying a live connection

```bash
iam-agent preflight                 # live vs simulated per platform, plus problems
iam-agent status                    # connector health with latency
iam-agent find "bea solà"           # does directory search work?
iam-agent identity bsola@corp.example   # full estate for one person
iam-agent devices                   # Action1 + Scalefusion inventory
iam-agent drift                     # cross-platform consistency
```

`preflight` reports each connector as `{name, healthy, backend, detail,
latency_ms}`. Note the key is `detail`, not `message` — worth knowing if you are
parsing it.

Then, and only then:

```bash
IAM_GLOBAL_DRY_RUN=false iam-agent onboard "Aina Serra" --department Ventas --execute
```

The run parks. Read the gate with `iam-agent approvals show <id>`, decide it with
`iam-agent approvals decide <id> --approve --approver you@corp.example`, and watch
it complete with `iam-agent runs show <run-id>`.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `preflight` reports a variable that "matches no setting" | Typo, or the `IAM_AD__` vs `IAM_AD_` trap. Fix the spelling. |
| Platform shows `simulated` when you set it live | `BACKEND` unset, or a required credential missing — `preflight` says which |
| ValidationError on startup from a list setting | Blank value means empty list. Comment the line out. |
| AD password write refused | `USE_SSL=false`. LDAPS is mandatory for `unicodePwd`. |
| Scalefusion 429 | Over 30 req/min. Lower `RATE_LIMIT_PER_MINUTE`. |
| Action1 401 | Client credentials expired or wrong region host. |
| `exchange_step_required` in a plan | Not a failure. Graph cannot do it; run the PowerShell cmdlet given. |
| Run stuck at `running` forever | Fixed — a failed step used to be counted as incomplete. Update if you see it. |
| Approvals queue empty but a run is parked | Was a `NameError` swallowed by a bare `except`. Update if you see it. |
| CLI `ValidationError: first_name / last_name` | Fixed. `onboard "Full Name"` and `offboard username` both work now. |
| `403 IAM_API__API_TOKEN is not set` | Correct behaviour. Set the token, or decide approvals via the CLI. |
| `503 …_WEBHOOK_SECRET is not set` | Correct behaviour. Configure the secret before exposing the endpoint. |

State lives in `data/`: `audit.jsonl`, `approvals.jsonl`, `runs/*.json`,
`mock_estate.json`. Delete the directory to start clean — `make reset` does it and
reseeds.
