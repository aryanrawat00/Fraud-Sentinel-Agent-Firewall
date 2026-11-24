# Current demo readiness — 24 November 2026

## Fresh verification

| Check | Observed result |
| --- | --- |
| Existing interpreter/dependencies | Python 3.12.14; required FastAPI/Pydantic/SQLAlchemy/httpx/pytest/uvicorn/psycopg packages available |
| Targeted backend tests | **56 passed, 0 failed**, 8.15 seconds; one existing Starlette/httpx deprecation warning |
| Targeted browser tests | **4 passed, 0 failed**, 23.2 seconds |
| Frontend non-emitting TypeScript check | **PASS**, exit 0 |
| Separate offline UI rehearsal on 8006/8002/5178 | **PASS**, seven workflow checkpoints and masked screenshots |
| Live Gemini/OpenAI | **NOT RUN**; previous live Gemini failure remains unresolved |
| Production build / broad suite / PostgreSQL | **NOT RUN**, unnecessary for this documentation/demo task |

The first restricted backend run was interrupted after 24 test dots with no final
result. A one-test diagnostic stalled in Python's asyncio socketpair initialization,
before TestClient setup completed. It was also stopped. Allowing local loopback
resolved the runner restriction; the complete selected run then passed. No source
or security check was weakened. Browser startup emitted existing tooling warnings.

## Exact selected tests

From the repository root, using a compatible existing interpreter, PYTHONPATH
pointing to backend, PYTHONDONTWRITEBYTECODE=1, PYTEST_DISABLE_PLUGIN_AUTOLOAD=1,
FRAUDSENTINEL_LLM_PROVIDER=disabled, and PostgreSQL/sandbox opt-ins disabled:

```powershell
# Use a unique new ignored directory; never an existing dataset.
$testRoot = Join-Path "$PWD/tmp" ('readiness-pytest-' + [guid]::NewGuid().ToString('N'))
& $python -B -m pytest -c backend/pyproject.toml -p no:cacheprovider --basetemp $testRoot tests/unit/test_detection_rules.py tests/integration/test_investigation_claims.py tests/integration/test_firewall_workflow.py::test_real_workflow_analysis_evidence_report_approval_and_review tests/integration/test_investigation_persistence.py::test_completed_report_review_and_events_survive_restart -q
```

The claims tests exercise valid facts/inferences/unknowns/recommendations,
unsupported fields/values/sources, atomic rejection, approved projection and both
provider adapters with mocked HTTP. No external provider request is made.

Browser command, from frontend, with an existing Playwright browser cache,
temporary/cache/output directories under this checkout's ignored tmp, and live
providers disabled:

```powershell
node node_modules/@playwright/test/cli.js test tests/security-integration.spec.ts --config playwright.security.config.ts --grep 'real investigation flows|bounded investigation engine|history, review and lifecycle|gemini adapter with mocked HTTP' --output "$testRoot/results" --reporter list
```

The four tests verify: human approval and scoped execution; deterministic bounded
report/review; history and lifecycle across actual backend restart; mocked Gemini
v2 provenance and claims. The restart test depends on the earlier completed run,
so retain this selected sequence.

From the repository root:

```powershell
node frontend/node_modules/typescript/bin/tsc -p frontend/tsconfig.json --noEmit --incremental false --pretty false
```

## Separate UI rehearsal

A temporary ignored helper started the actual investigation fixture on 8006,
the offline Gemini test harness on 8002, and Vite on 5178. The harness
injects a mock transport and delegates to the normal secured launcher,
`scripts.run_agent_firewall`. The rehearsal generated random
agent/human/audit credentials in memory for a fresh synthetic dataset.
Browser navigation exercised:

1. Synthetic overview.
2. scenario_high analysis and displayed AMOUNT_SPIKE contribution.
3. Evidence collection.
4. Directed recorded account relationships.
5. A separate secured case, bounded steps, awaiting_approval and no final report.
6. Human-approved mocked Gemini report with verified facts, unverified inferences,
   explicit unknowns and controlled recommendations.
7. Human review and reload of persisted history after a browser refresh.

This was an automated UI rehearsal with Playwright, not an interactive human
walkthrough. Native computer-use runtime initialization was unavailable.
Screenshots masked credential fields. No trace, credentials or headers were saved.
All rehearsal services stopped afterward; temporary credentials were discarded.
Existing datasets were not reused or reset. Keep this temporary dataset as a test
artifact; it is not the credential-provisioned hackathon session.

## What remains

- The operator should practice the clicks and rehearse the short explanation.
- Provision a new explicitly selected event dataset and securely retain its
  identity/audit-key pairing for restart demonstration.
- The checked runtime and frontend dependencies are currently shared with a
  sibling checkout. No packages or older-project files were changed. A portable
  standalone setup needs installation approval; historical browser configs still
  contain sibling interpreter assumptions.
- Reports render detailed JSON; browser Find helps present individual categories.
  This task did not redesign the UI.
- Two launcher safety guards retain a development-checkout path. They were not
  changed merely to remove a path string; review portability before another host.
- Public staging, commit and push require their respective approvals.

## Historical versus current claims

Historical milestone counts in other documents remain historical. M11's previously
reported total is not asserted as freshly reproduced here. OPA, production identity,
OS/network isolation, trained fraud accuracy and live Gemini success are not claimed.
The current demo uses synthetic records and mock_http only.
