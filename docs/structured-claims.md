# Milestone 10 — evidence-bound claims

Both providers now use `investigation-v2`. The analysis contract accepts structured
claims and recommendation codes, never model-written explanations or narrative
recommendations. Plans and the existing tool/approval workflow are unchanged.

## Contract and validation

Each claim has four fields: `claim_type` (`fact`, `inference`, `unknown`), `source`,
`field` and `value`. Its subject is the referenced source; there is no independent
subject/text that can contradict the binding. For example:

```json
{
  "claims": [
    {"claim_type":"fact","source":"transaction:scenario_high","field":"amount","value":"20000.00"},
    {"claim_type":"unknown","source":"account:scenario_sender","field":"ownership","value":null}
  ],
  "recommendations": [{"action":"review_source_records","sources":["transaction:scenario_high"]}],
  "evidence_sufficiency":"insufficient"
}
```

This fabricated example is accepted only if that exact transaction/value and account
are present in the investigation's authorized snapshot.

The provider sees a bounded `data_sources` catalog with allowlisted fields and
transaction provenance. The backend independently rebuilds that catalog from the
server's final report snapshot before validating claims. A source reference alone
does not establish support. Fact checks require an available field, matching scalar
type and exact value. Decimal amounts use canonical strings; timestamps use the
projected UTC ISO string. Equivalent differently formatted values are conservatively
rejected rather than guessed or coerced.

Connections and counts are computed from scoped transaction endpoints/statuses;
their stable relationship references include underlying transaction provenance.
No observed edge proves common ownership, intent, settled funds or criminality.
An unrelated account citation cannot support a transaction amount. Nonexistent or
cross-case references, unavailable fields, conflicting claims and extra narrative
fields fail validation. Fraud labels, real-world ownership and intent have no
supported factual source fields.

Inference codes are deliberately small:

- `risk_review`: requires an assessment with a positive score and positive factors.
- `evidence_review`: requires a scoped evidence record.
- `relationship_review`: requires a connection derived from scoped transactions.

Inferences have `value=null`, fixed low/uncalibrated confidence, verified supporting
fields and backend-written explanations. They remain `unverified_inference`; they
cannot introduce factual premises through prose. This permits useful review-oriented
inferences without claiming unrestricted natural-language reasoning is validated.

Unknowns also have `value=null`. Allowlisted unknowns include account ownership,
identity and intent, external connections, case historical context, and unavailable
transaction amount/time. A field already supplied cannot be labeled missing. The
scope is “unknown in supplied evidence,” not a claim that evidence does not exist
elsewhere. Any unknown or empty analysis forces `evidence_sufficiency=insufficient`.

Recommendations select only `review_source_records`, `seek_independent_evidence`,
or `review_alternative_explanations`, with scoped sources. All recommendation text
comes from backend templates and makes no new factual assertions.

## Projection, reporting and failures

Amounts/timestamps were intentionally omitted by the privacy-minimized agent
projection. Only the existing **human-approved `case_report` operation** now adds
`amount`, `currency` and UTC `occurred_at`, in the same scoped database read.
Ordinary transaction tools and human context retain their narrower projections.
Customer identity, device details, arbitrary stored prose and unrestricted records
remain withheld. The approval UI explains the fields sent for provider analysis.
Keep development data synthetic; authorization to read fields is not a provider
confidentiality or retention guarantee.

Validation completes before any report mutation. A rejected response produces no
successful report; the engine records a terminal sanitized error. It does not retry
the consumed tool or downgrade the invalid response into an empty successful result.
Examples: `claim_value_mismatch` means compare the proposed value with its cited
field; `claim_field_unavailable` means omit the factual claim or use an allowed
unknown; `claim_source_outside_snapshot` means use only the authorized catalog;
`claim_inference_unsupported` means its evidence/predicate does not qualify.
Never change access controls to resolve one of these errors.

New reports carry `claim_contract=evidence-claims-v1`, `verified_claims`, separate
`model_hypotheses` and `model_missing_evidence`, plus controlled recommendations.
“Verified” means equal to supplied snapshot data, not independent real-world truth.
Existing recorded facts, source references, fingerprint-bound human review and
signed persistence remain in place. Historical reports are not rewritten or
retroactively certified; the UI labels them as historical narrative reports.
Saved v1 provider identities remain readable, but cannot advance under a v2
provider. Start a new investigation instead of silently changing a run's contract.

## Verification and limits

Only directly affected tests were run: claims, projections, report generation,
Gemini/OpenAI mocked contracts, engine, persistence and firewall regressions, plus
the security/report browser suite. No live API call or database migration occurred.
The original M8 fabricated-prose reproducer now expects rejection.

This is a constrained claim language, not a general semantic truth detector. New
claim/inference types require explicit evidence rules and templates. External
identity, intent, legal conclusions, historical completeness and source-data accuracy
are not verified. Previously stored narrative reports retain their old limitations.

Next step: start a new **synthetic** investigation after restarting the isolated
server so it loads the v2 contract. Reuse the existing configured provider only
when a live request budget is separately authorized; all verification here used
mocked providers and incurred no API usage.

## Verification receipt and changed files

Final distinct results: **218 backend tests passed, 13 browser tests passed,
0 remaining failures, 0 skipped**. This was targeted testing, not the full suite.
The initial backend run had 216 passes and one outdated mocked Gemini response
failure; removing its obsolete `confidence` input fixed both parametrized recovery
cases. One additional authoritative-catalog test passed separately. TypeScript,
production build, and lint/format checks for changed Python files passed. One
existing Starlette TestClient deprecation warning remains. No live API calls.

Firewall authorization/execution and persistence-store source hashes are unchanged.
The engine change only exposes the validator's sanitized error code. The new
projection and provider contract changes are covered by the tests above.

Files changed (relative to the isolated snapshot):

- `backend/app/services/agent_investigations.py`
- `backend/app/services/gemini_provider.py`
- `backend/app/services/investigation_claims.py`
- `backend/app/services/investigation_engine.py`
- `backend/app/services/investigation_provider.py`
- `backend/app/services/investigation_report.py`
- `backend/app/services/openai_provider.py`
- `docs/gemini-integration.md`
- `docs/real-llm-integration.md`
- `docs/structured-claims.md`
- `frontend/src/app/InvestigationEngine.tsx`
- `frontend/tests/security-integration.spec.ts`
- `frontend/tests/security.spec.ts`
- `tests/integration/test_firewall_workflow.py`
- `tests/integration/test_gemini_provider.py`
- `tests/integration/test_gemini_quality.py`
- `tests/integration/test_investigation_claims.py`
- `tests/integration/test_investigation_engine.py`
- `tests/integration/test_real_llm.py`
- `tests/support/run_llm_browser.py`
