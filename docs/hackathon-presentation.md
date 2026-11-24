# Hackathon presentation notes

## Approximately two minutes

Financial investigators need traceable reasons to review unusual transactions,
not an AI accusation. FraudSentinel demonstrates that workflow using synthetic
records. Seven deterministic rules produce review scores and individual
contributions. Recorded transaction connections show related accounts; evidence
and reports keep references to the underlying records.

The secured workflow gives an investigator agent only bounded, allowlisted reads.
Python policy checks bind each action to identity, role, owner and case. A human
must approve the protected report read, and execution rechecks the request.
The agent cannot grant itself permission, run arbitrary SQL or take financial action.

Structured claims v2 separates exact snapshot facts, constrained inferences,
explicit unknowns and controlled recommendations. The backend checks values and
references before publishing a report. SQLite checkpoints retain progress and
human review; uncertain interrupted execution is not automatically replayed.

Today's demo uses an offline mocked Gemini adapter. That verifies integration
and grounding, not live model quality. Live Gemini success is unverified. OPA,
production identity, OS isolation and calibrated real-world accuracy remain future
work. The goal is a reviewable, bounded investigation prototype.

## Slide checklist

1. Problem and synthetic-data boundary.
2. Architecture: UI -> scoped services/firewall -> bounded provider -> validation.
3. Risk contribution and related-account evidence screenshots.
4. Human approval before protected report access.
5. Facts / inferences / unknowns / recommendations with source references.
6. Persistence, recovery and honest limitations.

The ordinary investigation backend and secured case have separate datasets.
Explain the transition explicitly. Keep the raw report readable by using browser
Find for verified_claims, model_hypotheses and model_missing_evidence; do not read
the entire JSON aloud.

## Likely questions

| Question | Short answer |
| --- | --- |
| Why trust AI with sensitive information? | Do not grant general trust: bound access, minimize fields, require authorization and human approval. This demo uses synthetic data only. |
| How are unauthorized actions restricted? | Server-owned identity/scope, allowlisted operations, approval binding, expiry and execution rechecks; no arbitrary tool execution. |
| How do you prevent invented evidence? | Reject unsupported sources, unavailable fields, wrong values/types and unauthorized prose before report publication. This verifies supplied records, not real-world truth. |
| Why human approval? | A person reviews the exact protected read and its scope. Model output cannot authorize itself or adverse financial action. |
| What happens after a crash? | Durable checkpoints preserve history. Safe boundaries can resume explicitly; uncertain consumed operations remain blocked from automatic replay. |
| What does the score mean? | A deterministic review signal with rule contributions, not a calibrated probability or fraud verdict. |
| Facts versus inferences? | Facts equal fields in the authorized snapshot. Inferences are limited review suggestions, explicitly unverified. Unknowns stay unknown. |
| What remains before production? | Production identity/secret management, least-privilege deployment, isolation, encryption/retention, external audit anchoring, scalability and real-world validation. OPA is not implemented. |

Use local masked screenshots as fallback. Never describe an offline mock as a
successful live Gemini call or quote unmeasured accuracy/latency metrics.
