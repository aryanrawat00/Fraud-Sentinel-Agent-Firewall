# FraudSentinel

A local synthetic fraud-investigation prototype with bounded AI access,
human approval and evidence-bound reports.

Public repository: https://github.com/aryanrawat00/Fraud-Sentinel-Agent-Firewall

## Implemented functionality

- Seven deterministic risk rules with score contributions.
- Recorded account relationships, evidence collection, cases and reports.
- Python Agent Security Firewall: server-owned identities, role/owner/case scope,
  allowlisted reads, human approval, replay protection and authenticated audit.
- Bounded orchestration, human review, SQLite persistence and explicit recovery.
- OpenAI/Gemini adapters and structured claims v2 validation against the authorized
  snapshot; constrained inferences, unknowns and recommendation codes.
- React investigation, approval, report and saved-history interfaces.

Risk scores are review indicators, not probabilities or proof of fraud.
OPA is **not implemented**. No trained fraud model, production identity system,
OS sandbox or proven real-world accuracy is claimed. Live Gemini failed before
grounding; its exact cause remains unknown. Mocked HTTP is not live verification.

## Start here

Follow [the offline demo runbook](docs/demo-runbook.md).
The normal secured server starts with `python -m scripts.run_agent_firewall`.
For the offline Gemini v2 demonstration, the test harness
`python tests/support/run_llm_browser.py --gemini` starts that server with a mocked provider.
The investigation workspace and secured workflow have **separate synthetic
datasets**. Cases do not automatically transfer between them.

[Current readiness results](docs/demo-readiness.md) distinguish fresh checks from
historical milestones. Older milestone documents describe their original scope,
not current startup instructions. See [architecture](docs/architecture.md) and
[structured claims](docs/structured-claims.md).

## Requirements

Python >=3.12 (3.12 verified), Node.js >=22.12.0, npm, and locked dependencies.
Browser checks need an existing Playwright Chromium installation.
PostgreSQL 16 is only needed for the separate legacy foundation deployment.

A clone does not include a virtual environment, node_modules, browsers,
credentials or runtime data. Choose a compatible Python executable; set
PYTHONPATH to this checkout's backend. Never modify a shared environment for a demo.

After explicit installation approval, a fresh independent environment can use:

```powershell
py -3.12 -m venv .venv
./.venv/Scripts/python.exe -m pip install -r backend/requirements-dev.lock
npm.cmd --prefix frontend ci
```

An editable backend install is unnecessary with PYTHONPATH configured.
Do not install into a node_modules junction/shared environment. Browser downloads
require separate approval.

## Structure

| Path | Purpose |
| --- | --- |
| backend/app/ | APIs, models, services, security and provider adapters |
| backend/scripts/ | Synthetic generators and isolated launchers |
| backend/migrations/ | PostgreSQL migration history |
| frontend/src/ | React/TypeScript workspaces |
| tests/, frontend/tests/ | Backend and browser checks |
| tests/support/run_llm_browser.py | Offline provider fixture using MockTransport |
| docs/ | Current runbook and historical milestone evidence |
| deploy/ | Legacy Docker/Nginx deployment |
| policy/, ml/ | Reserved OPA/ML scaffolding |
| tmp/ | Ignored local datasets, receipts and temporary harnesses |

## Configuration and safety

The offline demo needs no real AI API key or .env file. The secured launcher
uses process-only FRAUDSENTINEL_FIREWALL_CREDENTIALS,
FRAUDSENTINEL_FIREWALL_AUDIT_KEY, FRAUDSENTINEL_FIREWALL_DATASET,
FRAUDSENTINEL_FIREWALL_PORT and FRAUDSENTINEL_FIREWALL_SEED_WORKFLOW.
The runbook explains identity provisioning and restart requirements.

Legacy settings include APP_ENV, DEMO_MODE, INVESTIGATION_SANDBOX,
SCORING_RULES_PATH, POSTGRES_HOST, POSTGRES_PORT, POSTGRES_DB, POSTGRES_USER,
POSTGRES_PASSWORD and CORS_ORIGINS. Vite's API_PROXY_TARGET and
SECURITY_PROXY_TARGET select the backends. Never place secrets in VITE_ variables.

.env.example contains non-secret local defaults and an empty password, not usable
credentials. Keep actual credentials, environment files, databases, reports,
backups, logs and temporary harnesses out of Git.

## Legacy Docker/PostgreSQL path

docker-compose.yml automatically runs alembic upgrade head and starts the earlier
foundation service. It does not deploy the secured SQLite workflow or its proxy.
It is **not the offline demo startup path**. Migrations, seed/reset helpers and
PostgreSQL sandbox creation require separate target review and approval.

## Verification and publication

Use narrowly selected synthetic tests, not PostgreSQL or live-provider opt-ins.
A non-emitting frontend check is:

```powershell
node frontend/node_modules/typescript/bin/tsc -p frontend/tsconfig.json --noEmit --incremental false --pretty false
```

A typecheck is not a production build or browser rehearsal.
Follow [CONTRIBUTING.md](CONTRIBUTING.md): approve the exact upload list before
staging, review staged content, then separately approve commits and pushes.
