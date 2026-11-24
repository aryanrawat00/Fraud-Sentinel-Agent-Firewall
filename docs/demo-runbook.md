# Offline synthetic demo runbook

Run only from this checkout in PowerShell. Do not use the older milestone
migration/activation commands. No live AI key, PostgreSQL connection, migration
or production data is required.

## Runtime preflight

Select an existing compatible interpreter in each backend terminal:
`$python = (Resolve-Path './.venv/Scripts/python.exe').Path` if this checkout has
an independent environment. Otherwise use the explicit compatible interpreter
approved by the owner. Check `& $python -B --version` and installed dependencies
before use; do not install or alter a shared environment.

Requirements: Python >=3.12, backend/requirements-dev.lock dependencies,
Node >=22.12, frontend dependencies. Existing browser tests additionally need the
matching Playwright Chromium cache. Historical Playwright configurations resolve
a sibling development interpreter/cache; review these before running on a clone.
No dependency installation is part of routine startup.

## Terminal 1: investigation workspace

```powershell
# At the repository root, with $python selected above.
$env:PYTHONPATH = "$PWD/backend"
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:FRAUDSENTINEL_LLM_PROVIDER = 'disabled'
& $python -B -m scripts.run_integration_ui_fixture --investigations
```

This creates a fresh in-memory synthetic SQLite fixture and listens on
127.0.0.1:8006. Changes disappear when the process stops. The launcher also creates
its ignored tmp/ui-regression directory; it does not load financial records.

## Terminal 2: normal secured workflow backend

Credentials must be explicitly provisioned before starting the launcher.
Never reuse an unknown dataset or substitute the illustrative placeholders below.

| Process variable | Required meaning |
| --- | --- |
| FRAUDSENTINEL_FIREWALL_DATASET | Fresh alphanumeric/underscore/hyphen name, 1-64 characters; explicit known name for a reviewed restart |
| FRAUDSENTINEL_FIREWALL_AUDIT_KEY | Stable random key of at least 32 bytes, represented as hexadecimal |
| FRAUDSENTINEL_FIREWALL_CREDENTIALS | JSON identity array described below |
| FRAUDSENTINEL_FIREWALL_SEED_WORKFLOW | 1 for a new synthetic workflow dataset |
| FRAUDSENTINEL_FIREWALL_PORT | 8002 for this runbook |

Illustrative schema only, **not runnable credentials**:

```json
[
  {"token":"<distinct-random-agent-secret>","id":"demo_agent","kind":"agent","role":"investigator","owner_id":"user_demo_analyst","cases":["case_agent_workflow"]},
  {"token":"<distinct-random-human-secret>","id":"demo_human","kind":"human","role":"approver","owner_id":"user_demo_analyst","cases":["case_agent_workflow"]}
]
```

Tokens must be independently generated high-entropy secrets of at least 32
characters. Supply them through a trusted interactive launcher or secret manager,
not source, .env, command arguments, terminal output or chat. The human credential
belongs only in the local password field. Preserve identity/token/audit-key pairing
securely for any dataset intended to survive a restart. For a temporary rehearsal,
discard credentials only after verification and service shutdown; its saved ledger
will then be intentionally unavailable. Do not reset a ledger to regain access.

Once these variables are provisioned in this terminal:

```powershell
$env:PYTHONPATH = "$PWD/backend"
$env:PYTHONDONTWRITEBYTECODE = '1'
$env:FRAUDSENTINEL_LLM_PROVIDER = 'disabled'
$env:FRAUDSENTINEL_FIREWALL_PORT = '8002'
$env:FRAUDSENTINEL_FIREWALL_SEED_WORKFLOW = '1'
& $python -B -m scripts.run_agent_firewall
```

### Terminal 2 alternative for offline Gemini v2 verification

For the rehearsed v2 demonstration, use the same provisioning and replace only
the last command above with the following. Both launchers bind the secured port.

```powershell
& $python -B tests/support/run_llm_browser.py --gemini
```

The existing fixture injects GeminiProvider with httpx.MockTransport and synthetic
responses, replacing the configured live provider factory. The fixed dummy test
key is not a usable credential. This is an **offline test adapter**, not Gemini
inference or a free-tier API call. Do not replace it with check_llm_provider --live.

Select deterministic mode with the normal launcher and disabled provider.
Select provider mode for the offline v2 rehearsal only after the UI shows mocked HTTP.

The secured launcher creates files only in tmp/agent-security/<dataset>.
Existing datasets are not migrated or reseeded; missing workflow tables cause
refusal. Do not delete, rename or replace existing SQLite files or lock files.

## Terminal 3: frontend

```powershell
$env:API_PROXY_TARGET = 'http://127.0.0.1:8006'
$env:SECURITY_PROXY_TARGET = 'http://127.0.0.1:8002'
npm.cmd --prefix frontend run dev -- --port 5178
```

Open http://127.0.0.1:5178 and then
http://127.0.0.1:5178/#security?case=case_agent_workflow.

## Rehearsal sequence

1. Show synthetic transactions; analyze scenario_high in the investigation
   workspace and explain the rule contributions.
2. Collect evidence and inspect the directed recorded account relationships.
3. State that the secured workspace uses a **separate seeded case**, not a case
   automatically transferred from the first service.
4. Enter the human credential in the security workspace. Choose AI provider mode
   only when the status explicitly identifies the mocked HTTP fixture.
5. Start the investigation. Advance each bounded step; observe awaiting_approval
   and absence of a final report before approval.
6. Load security activity, inspect the exact request, approve it, then advance.
7. Explain verified snapshot facts, constrained/unverified inferences, explicit
   unknowns and controlled recommendations. Evidence equality is not external truth.
8. Record human review, refresh, re-enter the credential and reopen saved history.
   Restart verification must retain the same dataset, identities and audit key.

Deterministic mode deliberately produces no AI hypotheses; use the offline fixture
to demonstrate all four v2 categories. Rejection tests, not an API retry, demonstrate
that fabricated values fail validation.

## Stop and troubleshoot

Clear the browser session and press Ctrl+C in each server terminal. Do not remove
database files or bypass ownership locks. Do not use docker compose down -v,
seed/reset commands, or migrations as troubleshooting.

- Occupied port: stop only your known service or choose a reviewed alternative
  consistently across backend/proxy; never kill an unrelated process.
- Refused credential/scope: check provisioning and the exact case; do not weaken policy.
- Lost audit key: keep the old dataset intact; use a new explicitly authorized
  synthetic dataset instead of resetting history.
- Unavailable provider: verify the offline launcher, not live credentials.
- Windows test stall in asyncio socketpair: permit local loopback in the runner;
  do not change application behavior to bypass the restriction.
- Shared runtime missing: request approval for a standalone environment. Do not
  reinstall into the older project's Python or node_modules junction.

Capture only synthetic screenshots with credential inputs masked/cleared.
Keep recordings and generated reports local and ignored. A screenshot is a fallback
demonstration artifact, not proof of live AI or production performance.
