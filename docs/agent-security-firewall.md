> Historical milestone/reference document. Results and limitations below describe the recorded milestone, not fresh verification or the current setup. Use [the current README](../README.md), [offline runbook](demo-runbook.md) and [current readiness results](demo-readiness.md). Machine-specific paths are redacted placeholders; do not execute historical commands as current setup instructions.

# AI Agent Security Firewall — isolated implementation

Implementation lives in `<project-root>`, a source snapshot of the
current uncommitted M1–M4 work, not a Git branch or activation of the protected checkout.
No PostgreSQL connection, migration, `.env` copy, backup copy or Git mutation is needed.

## Enforcement flow

Provisioned bearer credential → server-owned agent/human identity → strict action
schema → role + case + owner + transaction policy → immutable action binding →
optional human approval → policy/identity/expiry recheck → bounded read adapter →
atomic request consumption and authenticated audit commit → release result.

The dedicated FastAPI app exposes only `/api/v1/security` endpoints. It deliberately
does not mount the unauthenticated demo APIs. Agents receive no SQL, filesystem,
network, callback, code-execution or permission-management tools. Existing Case,
Transaction, RiskAssessment and Evidence models provide real investigation records.

Roles: `reader` can read case/assessment summaries and bounded case transactions,
accounts, evidence and relationships; `investigator` additionally may
request a case report. Every report needs an independently provisioned human
`approver` with matching owner and case scope. Human credentials cannot submit agent
actions. Client role/identity overrides and extra parameters are rejected.
Legacy owner-null transactions are accessible only through an owned case; an explicit
conflicting owner is rejected. Reports return record references and risk categories,
not amounts, personal identifiers, arbitrary free text or agent-generated findings.

Requests persist in a separate SQLite ledger. Their exact action, parameters,
identity, owner, scope and five-minute expiry are HMAC-bound. Approval is bound to
that digest and human identity. Serialized ledger transactions prevent concurrent
consumption; durable execution audit prevents replay even if request status changes.
A result is never released before the consumption/audit transaction commits. These
are read-only tools; no external mutation/recovery or automatic retry occurs.

Audit rows contain identity, decision, reason code, case/operation/request reference,
human approval attribution, timestamp and execution outcome. Triggers prohibit
update/delete; an HMAC chain detects alteration. Tokens, raw request headers, tool
results, exception details and financial amounts are not logged. Audit failure
prevents execution/result delivery. The human dashboard is owner/case scoped.

## Local execution

Use the existing Python environment with `PYTHONPATH` pointing to this snapshot's
`backend`. Provision secrets through process environment, never `.env` or Git:

- `FRAUDSENTINEL_FIREWALL_AUDIT_KEY`: a stable randomly generated 32-byte key in hex.
- `FRAUDSENTINEL_FIREWALL_CREDENTIALS`: JSON array with `token`, `id`, `kind`, `role`,
  `owner_id`, `cases`. Tokens must be independently generated high-entropy secrets
  of at least 32 characters. Use distinct agent and human tokens; deliver the human
  token only to the approving person. Preserve the audit key across restarts.

The synthetic seed's owner is `user_demo_analyst`; get its case ID from
`backend/scripts/seed_demo_data.py`. Configure only that case for the initial demo.
Run `python -m scripts.run_agent_firewall`. This binds loopback port 8002 with access
logs disabled and creates only snapshot-local `tmp/agent-security` SQLite
files. It does not load the original checkout’s `.env` or connect to PostgreSQL. The existing virtualenv is
reused; no additional dependency was installed.

Run the snapshot frontend with `npm run dev -- --port 5176`; open `/#security`.
The specific security proxy goes to 8002. Supply the human credential in the password
field; it is retained only in component memory and cleared with Clear session.
The original overview/investigation views remain available; to use them, configure
`API_PROXY_TARGET` to an authorized isolated synthetic backend, never an agent's tool
endpoint. The security view itself does not request foundation data.

API sequence:
1. Agent POST `/api/v1/security/requests` with operation/case_id and, only for an
   assessment summary, transaction_id. Response gives decision and request_id.
2. Human reviews GET `/api/v1/security/dashboard` and POSTs
   `/api/v1/security/requests/{id}/approval` with exactly `{"approved":true}` or false.
3. Original agent POSTs `/api/v1/security/requests/{id}/execute`. Parameters cannot
   be replaced at execution. Reuse, expiry, revoked scope and forged approvals fail.

## Verification and boundaries

The integrated snapshot passes 177 backend tests: 130 existing tests, 32 firewall
security tests and 15 workflow integration checks. Six opt-in PostgreSQL/live-service
tests remain skipped. There are 21 passing browser checks: 18 existing UI regressions,
two mocked dashboard checks and one real browser-to-API approval/investigation flow.
TypeScript/Vite build and configured Ruff lint/format checks pass. All database tests
use synthetic SQLite fixtures; PostgreSQL migration 0003 remains unapplied.
See `firewall-integration.md` for the final integration architecture and reproduction.

No Alembic migration was created or applied. Local SQLite ledger initialization is
sandbox-only; production persistence would need a separately reviewed migration.
M2–M4 activation, including migration 0003, remains deferred.

This is an integrated development security boundary, not production identity or OS
isolation. Human identity is verified by a separately provisioned secret, not OIDC,
MFA or a corporate identity provider. Agents must run outside the service process
with access only to this API; do not grant host Python, DB credentials, other demo
endpoints or unrestricted networking. An OS/container network sandbox and production
identity provider are deployment requirements, not implemented guarantees here.
The host, provisioning process and audit key are trusted. A privileged attacker who
can restore the entire ledger to an older copy cannot be detected without an external
immutable anchor. No external SIEM, distributed policy service, rate limiting or
large-dataset pagination is implemented; this release targets small synthetic cases.
No LLM/provider is connected and no autonomous agent or sensitive write tool runs.
