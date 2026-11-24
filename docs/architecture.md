# Current architecture

React uses relative APIs through Vite. The offline demo routes /api to the
synthetic investigation backend (8006) and /api/v1/security to the secured
backend (8002). Their datasets are separate; cases do not transfer automatically.

## Investigation workspace

The test-only launcher creates synthetic in-memory SQLite records. Services
calculate deterministic risk contributions, recorded connections, evidence and
reports. This legacy demo uses a fixed identity and must remain local. Its data
disappears at shutdown.

## Secured workflow

Server-provisioned bearer identities bind allowlisted reads to role, owner and
case. The Python firewall requires human approval for case_report and rechecks
scope, expiry and replay protection at execution. Agents have no arbitrary SQL,
filesystem, shell, network or financial-action tool.

The engine checkpoints bounded progress in an authenticated SQLite store, with
fingerprint-bound human review. Uncertain interrupted execution never replays
automatically. Reopening history needs stable identities and audit key.
SQLite records are not encrypted at rest.

## Grounding

OpenAI/Gemini adapters bound time and output and validate structured schemas.
apply_analysis then calls validate_claims against the server's evidence catalog
before modifying the report. Exact field agreement means consistency with the
supplied snapshot, not independent truth. Inferences and unknowns use restricted
codes; recommendations are rendered from controlled templates.

The offline browser fixture uses httpx.MockTransport and fabricated responses.
Live Gemini success is unverified. An unavailable live provider is not silently
replaced by a successful mock.

## Limits

OPA remains scaffolding. Python application policy is not OS/network isolation
or production identity. Risk scores are uncalibrated review signals, not trained
fraud probabilities. PostgreSQL/Alembic and Docker retain the earlier foundation
deployment; Compose automatically migrates and does not deploy the secured
workflow. Follow the current demo runbook, not historical activation commands.
