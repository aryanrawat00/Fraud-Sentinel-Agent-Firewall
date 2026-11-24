> Historical milestone/reference document. Results and limitations below describe the recorded milestone, not fresh verification or the current setup. Use [the current README](../README.md), [offline runbook](demo-runbook.md) and [current readiness results](demo-readiness.md). Machine-specific paths are redacted placeholders; do not execute historical commands as current setup instructions.

# Investigation persistence, lifecycle and recovery

Implemented only in `<project-root>`. This milestone extends the
existing investigation engine, provider/report contracts, authenticated security API
and workspace. It does not activate the main checkout or connect to its database.

## Storage and initialization

The trusted server stores investigations in a separate SQLite file alongside the
isolated firewall ledger: `<firewall-ledger-filename>.investigations.sqlite3`.
For the existing launcher this is `security.sqlite3.investigations.sqlite3` under
the selected snapshot `tmp/agent-security` dataset. The financial database and the
firewall's existing tables are not changed. No credentials are copied into the file.

The additive, version-1 initializer in `investigation_store.py` creates three tables
only in a new investigation file: `store_version`, `runs`, and `lifecycle_events`.
An existing incomplete/unsupported ledger is refused, never reset or repaired
automatically. There is no Alembic/application migration and no change to migration
0003. Initialization, reopen, schema-version rejection and transaction rollback are
tested using disposable databases.

SQLite uses WAL, `synchronous=FULL`, foreign keys, a five-second busy timeout and
`BEGIN IMMEDIATE` transactions. A checkpoint and its lifecycle event commit together.
Revision comparisons reject stale writes. An exclusive OS file lock permits one
service owner for each investigation ledger; it is released on shutdown/process exit.
A second live owner is refused instead of attempting recovery over active execution.

State and per-run event chains are HMAC authenticated with a domain-separated use of
the existing server-held firewall audit key. Reuse the same provisioned key and
identities when restarting a dataset. Wrong keys, malformed records, invalid lifecycle
histories, report-fingerprint mismatch and checkpoint/event disagreement fail closed.
Triggers prevent ordinary event update/deletion and investigation deletion. Reads
revalidate integrity; writes preserve identity/scope and append lifecycle history.
No unsafe deserialization, executable objects or model callbacks are stored.

## Persisted data

Runs retain identity/case bindings, objective, plan, states, progress, step decisions,
firewall request IDs, result fingerprints and source references. They also retain
created/updated/started/completed times, sanitized failure categories, cancellation
identity/time, recovery classification, API version and storage revision.

The final bounded case projection supplies a report snapshot, including findings,
hypotheses, provenance and limitations. This projection already excludes raw personal
financial fields and free narratives. Intermediate steps retain source identifiers
and fingerprints rather than duplicate transaction payloads. A final analysis draft
is saved only when necessary to resume analysis without rereading the approved tool.
It is not exposed as a completed report and is removed when the report completes.

Reports are immutable, version 1 per run. New analysis requires a new run; case history
therefore retains previous reports rather than replacing them or inheriting review.
Human review is recorded once, with reviewer, time, decision, notes, report version and
the exact report fingerprint. Mutable review annotations are excluded from the report
content fingerprint. Neither agents nor models can review, rewrite or approve reports.

## Lifecycle and recovery

`created → planning → ready → investigating ↔ awaiting_approval → completed`.
Eligible active states can pause, fail or cancel. Paused runs resume only to their saved
safe state, after explicit human action and fresh authorization. Terminal states cannot
restart. An API version protects every advance/pause/resume/cancel/review request;
duplicate requests fail with a conflict rather than repeat an operation.

The engine saves intent before firewall submission and before execution. A committed
result checkpoint records its source references and execution status. On restart:

| Durable checkpoint | Recovery |
| --- | --- |
| Created, ready, awaiting approval, paused, completed, failed or cancelled, idle | Restore as saved; execute nothing |
| Interrupted planning | Pause; explicit resume may create a new plan, with no tool replay |
| Interrupted safe step boundary | Pause; explicit resume proceeds from completed steps |
| Approved report read checkpointed, analysis unfinished | Pause; resume analysis using the saved projection, without executing the tool again |
| Submission/execution intent with no committed result checkpoint | Pause as uncertain, block resume, require reconciliation |
| Terminal state committed before busy flag was cleared | Clear the stale claim; preserve terminal state and report |

There is deliberately no automatic reconciliation/retry button for uncertain execution.
Inspect the recorded request ID (if available), intent events and firewall audit using
an authorized human identity. Keep the uncertain run as evidence; cancel it only when
appropriate. Any replacement run is separate work and must follow the same approval
policy. A crash after firewall commit but before the investigation checkpoint is tested
explicitly: the old read remains consumed and the run cannot replay it.

Every view/list/resume rechecks the current human identity and case ownership through
the existing firewall case adapter. Resume also rechecks the agent grant/policy.
Tool execution still uses `Firewall.submit`/`Firewall.execute` and the existing approval,
expiry, integrity and replay checks. A persisted approval is never treated as permanent.
Cancelling a run does not revoke independently provisioned credentials or approvals;
pending requests can be rejected in the existing approval desk and otherwise expire.

## UI and API

The existing security workspace includes case-scoped history, details, recorded progress,
interruption warnings, pause/resume/cancel, reports and human review notes. Refresh or
navigate back, re-enter the credential and load history to reopen a saved run. Credentials
are intentionally not stored in the browser. Loading, empty, malformed and refused
responses are explicit. Uncertain runs expose no resume/advance control. No mutation
is automatically retried by the frontend.

In addition to the existing run routes:

- `GET /api/v1/security/runs?case_id=...` lists only the initiating human's case runs.
- `GET /api/v1/security/runs/{id}` includes authenticated lifecycle events.
- `POST /api/v1/security/runs/{id}/pause` and `/resume` require the current `version`.
- `/review` accepts optional `notes` (maximum 1,000 characters); do not enter secrets.

A real LLM adapter is now available through explicit process configuration; see
[real-llm-integration.md](real-llm-integration.md). Disabled/unavailable and deterministic
modes remain explicit. No `.env` change is required. Provider bindings are persisted
as additive metadata; the SQLite schema is unchanged.

## Limitations and production path

This is a single-service local development implementation, not production readiness.
SQLite locking assumes a local filesystem. No multi-worker/network-filesystem support
is claimed. Reports are not encrypted at rest; protect the directory and audit key with
host access controls. Host/key compromise or rollback of an entire ledger to a prior
valid snapshot is not detectable without external audit anchoring. Never delete lock
files to bypass ownership checks. Loss of the key prevents verified access; there is
no key-reset or destructive recovery path.

The existing 128-run capacity remains, now across restarts. No automatic purge or
retention policy was added. Event retention/pagination, archival and key rotation need
review before broader deployment. Production PostgreSQL migration should preserve run
IDs, source/report fingerprints, review bindings, revisions and event history; replace
the local owner lock with transactional claims and fencing, and reconcile uncertain
operations explicitly. Migrate and verify a copy before any cutover. No production
migration is created or applied here.

Verification totals and changed-file hashes are in `persistence-results.json`. All
prior snapshot source is preserved in `tmp/before-persistence`, indexed by
`persistence-baseline.json`. Existing receipts remain historical records. Main activation,
migration 0003, checkpoint reconciliation and all Git/GitHub actions remain out of scope.
