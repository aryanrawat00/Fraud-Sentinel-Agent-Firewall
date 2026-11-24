> Historical milestone/reference document. Results and limitations below describe the recorded milestone, not fresh verification or the current setup. Use [the current README](../README.md), [offline runbook](demo-runbook.md) and [current readiness results](demo-readiness.md). Machine-specific paths are redacted placeholders; do not execute historical commands as current setup instructions.

# Firewall integration plan

All work stays in the existing isolated source snapshot. The original protected
checkout is not a deployment target. Its current files and pending activation
manifest remain unchanged. Pre-integration source copies are in tmp/before-integration.

Compatibility findings: the initial firewall launcher creates only foundation tables;
M2–M4 services need WorkflowBase tables. The original demo identity is not human
authentication and must not be exposed on the secured agent listener. The original
firewall report tool only returned live counts/references, not stored M4 reports.
RelationshipService normally scopes by owner, not investigation, so an agent adapter
must further restrict transactions and supporting sources to exactly one case.

Plan: preserve the firewall identity/approval/ledger mechanisms; add an investigation
adapter using existing scoped repositories, workflow models and relationship service.
Expose the adapter through the same request/policy/approval/execution entry point.
Add authenticated human case context in the same application. Wire an explicit
secured mode into create_app; refuse legacy/demo endpoints in that mode rather than
expose a bypass. Leave the existing demo/sandbox mode unchanged for its existing tests.
Use only temporary SQLite synthetic schemas for integration tests; no Alembic upgrade.
Deep-link from case details to the security workspace, with case-specific approvals,
provenance, stored report references and denial reasons. Test the deterministic
analysis → evidence → stored report → agent request → human approval → scoped read
→ human review workflow. Agent requests are scripted, not an operational LLM.

## Completed integration

The existing `create_app` factory accepts an explicit `firewall` together with the
same isolated engine and test/sandbox settings. This secured mode exposes the
credential-verified security API and refuses legacy demo routes for anonymous,
agent and human callers. The default M1–M4 app mode remains unchanged. This is not
a replacement authentication implementation for the legacy developer UI.

`agent_investigations.py` reuses `IntelligenceRepository`, `InvestigationService`,
`RelationshipService`, and the actual stored workflow models. All reads recheck
case ownership, case grants and transaction/account associations. Every supporting
assessment/evidence source must belong to that exact case. The adapter uses one
read snapshot and explicit limits: 100 transactions, 100 accounts, 500 assessments,
100 evidence records and 25 stored reports. Invalid scope or excess limits fail
closed instead of returning a misleading partial report.

Stored report content is checked against its fingerprint and case/source references.
Agents receive report identifiers, fingerprints and source references, not full
financial narratives or raw personal information. Case-report access requires human
approval. All other exposed tools are bounded reads; no agent write, arbitrary SQL,
file, network, permission-management or executable-code tool is registered.

The human approval desk now accepts a case context and displays actual assessments,
evidence provenance, account relationships and report fingerprints. Existing case
details link to `/#security?case=<id>`. Approval requests can be filtered by that case.
Scoped denial attempts, approvals, execution and human review appear in audit history.
The human context API rejects agents and unscoped humans. The host/runtime boundary
and credential-provisioning limitations from `agent-security-firewall.md` still apply.

## Reproduce the synthetic integrated workflow

Use the snapshot backend on PYTHONPATH and the existing Python environment.
Provision distinct agent/human secrets and a stable audit key as documented in
`agent-security-firewall.md`; do not place real credentials in source or `.env`.
For a fresh full investigation fixture, set these process-only options:

- `FRAUDSENTINEL_FIREWALL_DATASET`: a new alphanumeric/underscore/hyphen dataset name.
- `FRAUDSENTINEL_FIREWALL_SEED_WORKFLOW=1`.
- Grant the agent and human `case_agent_workflow`, owned by `user_demo_analyst`.
- Run `python -m scripts.run_agent_firewall` (loopback port 8002 by default).
- Run the snapshot frontend on 5176 and open `/#security?case=case_agent_workflow`.
  The security proxy defaults to 8002; `SECURITY_PROXY_TARGET` can select another
  isolated listener. `FRAUDSENTINEL_FIREWALL_PORT` sets its loopback port.

A new dataset uses the real deterministic M2 scoring, M3 evidence collection and
M4 investigation/report services to create synthetic records. Existing datasets are
not migrated or reseeded; an older dataset missing workflow tables is refused.
Initialization creates local SQLite fixture tables directly, never runs Alembic,
and cannot target the protected main checkout or its PostgreSQL database.

The tested sequence is: deterministic suspicious-activity assessment → evidence
collection and case/report creation → scripted agent request → policy decision →
human review and approval → execution revalidation → scoped retrieval → audit and
human review. The browser integration uses real HTTP endpoints and SQLite records.
It does not simulate an operational LLM or claim autonomous investigation.

The legacy developer investigation workspace and secured gateway must be supplied
consistent, authorized isolated data when used together. The gateway deliberately
does not expose the legacy unauthenticated editing APIs. Human SSO for those legacy
APIs, production persistence, OS/network isolation, agent write tools and LLM
orchestration remain outside this integration. No deployment into the main checkout
is implied by this completed isolated implementation.

## Verification results

- Backend: **177 passed, 6 intentionally skipped** (PostgreSQL/live-service opt-ins).
- Existing browser regressions: **18 passed**, using isolated in-memory SQLite APIs.
- Security browser checks: **3 passed**, including one real full approval workflow.
- TypeScript/production build, Ruff lint and formatting: passed (64 Python files).
- A pre-existing Starlette/httpx deprecation warning remains.

Commands run from the snapshot:

```powershell
$env:PYTHONPATH='<project-root>\backend'
$env:RUN_POSTGRES_TESTS='0'
$env:RUN_PHASE2_POSTGRES_TESTS='0'
$env:RUN_POSTGRES_READONLY_TESTS='0'
$env:RUN_SANDBOX_HTTP_TESTS='0'
<historical-checkout-root>\.venv\Scripts\python.exe -B -m pytest -c backend/pyproject.toml tests -q
<historical-checkout-root>\.venv\Scripts\ruff.exe check --config backend/pyproject.toml backend tests
<historical-checkout-root>\.venv\Scripts\ruff.exe format --config backend/pyproject.toml --check backend tests
Set-Location frontend
$env:PLAYWRIGHT_BROWSERS_PATH='<historical-checkout-root>\tmp\playwright'
npm run build
npm run test:e2e -- --config playwright.security.config.ts
npm run test:e2e -- --config playwright.regression.config.ts
```

The regression fixture initially used file-backed SQLite, which the existing sandbox
guard correctly rejected. It now uses the supported in-memory fixture, explicitly
allows its actual frontend test origin, and serializes requests on its single SQLite
connection. The final 18-test run contains no server errors. The security test startup
now permits a bounded 45-second startup and retains credential-redacted diagnostics;
its final real API workflow passed. No application guard was weakened for tests.

No migration was created or applied. No active database writes, `.env` changes,
Git mutations or GitHub actions were performed by this integration work. Original source/protected-file hashes and
all saved pre-integration snapshot copies were verified. The machine-readable
changed-file list and preservation results are in `firewall-integration-results.json`.


## Final checkpoint observation

The final read-only Git check found main clean at
`8c4d7a6f999f7c3e9d5d7c379b3f6d7fa3cd1f27` ("Phase 2 M2-M4 implementation checkpoint"),
rather than the recorded starting checkpoint `decf38e6a3ce1a636b799b660dea545e01d469b3`.
This integration performed no Git mutations. All 131 original source files and all
143 protected-file hashes still match their saved baselines. The checkpoint change
was observed, not reverted or overwritten. The old activation readiness checks bind
the earlier checkout state: reconcile/review that package before any later approval.
No activation or migration was attempted to resolve the difference.
