> Historical milestone/reference document. Results and limitations below describe the recorded milestone, not fresh verification or the current setup. Use [the current README](../README.md), [offline runbook](demo-runbook.md) and [current readiness results](demo-readiness.md). Machine-specific paths are redacted placeholders; do not execute historical commands as current setup instructions.

# Investigation engine — isolated development milestone

Implemented in `<project-root>`. This extends the existing authenticated
firewall application and its case workspace. It does not activate the main checkout. Persistence and recovery are now implemented;
see [investigation-persistence.md](investigation-persistence.md) for the current storage/lifecycle contract.

## Execution and security boundary

1. A provisioned human approver opens the existing Agent security workspace for an
   authorized case. The existing case adapter rechecks identity, grant and ownership.
2. Start a run in explicitly labelled deterministic development mode, or select the
   unconfigured provider to see an explicit unavailable result. The API defaults to
   provider mode; it never silently substitutes a mock.
3. The server selects the first provisioned investigator agent, ordered by identity,
   with the same owner and case grant. A client/model cannot select privileges or
   substitute an identity. Only the creating human can view/control that run.
4. Advance once to plan, then once per bounded tool step. The UI shows plan, progress,
   tool decisions, request IDs, failure details and cancellation controls. Every agent
   read calls `Firewall.submit` and `Firewall.execute`; the latter rechecks policy,
   registration, current case ownership, expiry, approval and replay protection.
5. The final `case_report` read requires the existing human approval flow. Load security
   activity, inspect case evidence, approve the exact request, then advance the run.
   Pending requests stay pending; rejection/expiry stops the run. The engine never
   calls the approval API itself.
6. Assemble the report from the final, consistent case projection. Earlier reads are
   separately fingerprinted and may reflect different points in time. They are not
   combined into an allegedly atomic historical snapshot.
7. Display the report for human review. `completed` means report assembly completed,
   with review still pending. Review records either `reviewed_no_determination` or
   `needs_more_evidence`, bound to the report fingerprint and run version. It does not
   certify current records or authorize any adverse conclusion/action.

The lifecycle is `created → planning → ready → investigating ↔ awaiting_approval → completed`,
with explicit pause/resume and interruption recovery.
Active states can fail or be cancelled; terminal states cannot resume. Run versions
and a locked busy claim reject concurrent/stale advances. Locks are released for
provider awaits; cancellation or access revocation is rechecked before publishing
output. Interrupted/failed runs never retry consumed tools automatically. Cancellation
stops this orchestrator; it does not revoke independently issued firewall credentials
or existing firewall approvals. Any still-pending request can be rejected in the
approval desk and otherwise expires under the existing policy.

## Provider and grounding contracts

`Provider` is an async protocol with `plan(context)` and `analyze(authorized_projection)`.
The original milestone used no operational LLM. A real OpenAI Responses adapter is now
available through explicit configuration; see [real-llm-integration.md](real-llm-integration.md).
`DeterministicProvider` produces six fixed reads and no model hypotheses. An injected
test/provider adapter receives copied bounded projections, never a database, filesystem,
shell, network tool, credential, permission object or approval capability.

Plans reject extra fields, arbitrary tools, cross-case arguments, repeated operations,
missing context/report steps and more than six steps. Plans start with `case_summary`
and end with `case_report`. Default intermediate steps read case transactions,
accounts, evidence and relationships. Existing assessment history and case/report
references come from the final read; unrestricted historical/organization-wide search
is outside this milestone.

Local/custom test providers retain a five-second deadline. The configured real adapter
has a bounded total deadline (45 seconds by default). Structured output is capped at 32 KiB. Unavailability, rate limits, malformed/oversized output and exceptions fail
closed without raw exception disclosure. Adapters are trusted server code and must
cooperate with async cancellation and enforce transport deadlines; this is not an OS
sandbox or a hard kill boundary for malicious provider code.

Model results use a closed hypothesis schema: a review category, an existing typed
assessment/evidence reference, and low/medium confidence. Confidence is an uncalibrated
provider label, not a fraud probability. Unknown sources, verified-fact fields, guilt/verdict fields and unsupported conclusions
are rejected. Bounded explanatory prose is allowed only in unverified model sections. Hypotheses are labelled
unverified, kept separate from recorded facts and risk indicators, and deduplicated.

Reports contain objective, case status/version, steps and security decisions, source
registry, transaction facts, deduplicated evidence, provenance, account relationships,
stored risk assessments, existing report references, hypotheses, assumptions,
limitations, next steps and human review. Transaction/account references are resolved
within the final projection; conflicting or missing references fail closed. Existing
M2/M3 risk scores/patterns are reused, not recalculated as invented AI findings.
The report SHA-256 covers immutable report content, excluding the fingerprint itself
and mutable human review annotations. Human review references that immutable digest.

## API and UI

All routes are on the existing authenticated `/api/v1/security` surface. Legacy demo
routes remain absent from this secured application. Responses use `Cache-Control: no-store`.

| Method and path | Body / purpose |
| --- | --- |
| POST `/runs` | `case_id`, optional `mode` (`provider` or `deterministic`) |
| GET `/runs/{id}` | Current authorized run state |
| POST `/runs/{id}/advance` | Current integer `version`; at most one tool step |
| POST `/runs/{id}/cancel` | Current `version` |
| POST `/runs/{id}/review` | `version`, `fingerprint`, allowed review `decision` |

Use the existing isolated launcher and process-scoped credential configuration in
[firewall-integration.md](firewall-integration.md). No new environment variable or
`.env` edit is needed. The seeded workflow case is `case_agent_workflow`. Open
`/#security?case=case_agent_workflow`; credentials remain in page memory. Changing
the credential/case or clearing the session removes the engine view. No report or
credential is written to browser storage. Preserve a run ID to retrieve its state
through authenticated case history after page refresh or service restart.

## Development limits and activation

Run/report/review state now persists in a separate authenticated SQLite investigation
ledger, bounded to 128 retained runs. See the persistence milestone document for
transactional checkpoints, lifecycle events, explicit safe recovery and single-owner
locking. The firewall ledger remains authoritative for tool execution. Production
identity, distributed claims, audit anchoring and provider transport remain future work.

There are no agent mutations, autonomous financial decisions, customer contacts,
account freezes, regulatory submissions or consequential conclusions. Human review
does not add such capabilities. No application schema migration was created or
applied. Migration 0003 and main-checkout activation remain deferred; the prior
checkpoint mismatch still needs separate activation-package reconciliation.

## Verification

Use the commands in [firewall-integration.md](firewall-integration.md), keeping all
PostgreSQL/activation opt-ins disabled. New tests exercise real synthetic M2–M4 data
and the real firewall, with deterministic providers and fault injection. Browser tests
cover start, bounded steps, exact human approval, grounded report/review, explicit
provider unavailability and malformed-response recovery.

The original orchestration file inventory and verification are recorded in
`orchestration-results.json`; current persistence results are in `persistence-results.json`. Pre-existing snapshot source was saved byte-for-byte
under `tmp/before-orchestration`, indexed by `orchestration-baseline.json`. Existing
integration receipts/backups were retained. No main-checkout source, active database,
`.env`, existing backup, Git state or GitHub content was changed by this milestone.
