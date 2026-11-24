"""Provider-independent evidence binding and controlled report text; no model prose."""

import hashlib
import json
from collections import defaultdict
from decimal import Decimal

from app.services.investigation_provider import Analysis

CLAIM_CONTRACT = "evidence-claims-v1"
FIELDS = {
    "transaction": (
        "transaction_id",
        "source_account_id",
        "destination_account_id",
        "amount",
        "currency",
        "occurred_at",
        "status",
    ),
    "account": ("account_id", "status"),
    "assessment": ("assessment_id", "transaction_id", "risk_category", "score"),
    "evidence": ("evidence_id", "transaction_id", "assessment_id", "verification_status"),
    "case": ("case_id", "status", "version", "transaction_count"),
}
INFERENCES = {
    "risk_review": (
        "assessment",
        "Inference: the recorded risk indicators warrant human review; "
        "legitimate explanations remain possible. This is not a fraud finding.",
    ),
    "evidence_review": (
        "evidence",
        "Inference: the cited evidence merits independent validation before a conclusion.",
    ),
    "relationship_review": (
        "relationship",
        "Inference: the recorded transfer connection merits review; "
        "shared ownership, intent and settled fund flow are not established.",
    ),
}
UNKNOWN_FIELDS = {
    "account": {"ownership", "identity", "intent", "external_relationships"},
    "transaction": {"amount", "occurred_at", "intent"},
    "case": {"intent", "historical_context", "external_relationships"},
}
RECOMMENDATIONS = {
    "review_source_records": (
        "Review the cited source records with an authorized human investigator."
    ),
    "seek_independent_evidence": "Seek independent evidence before drawing a conclusion.",
    "review_alternative_explanations": "Review alternative explanations with a human investigator.",
}


class ClaimValidationError(ValueError):
    """Only static codes leave the validator; never echo an untrusted value or reference."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def evidence_catalog(report):
    """Rebuild from the server's final snapshot, never from provider-supplied evidence."""
    catalog = {}

    def add(kind, row, identifier):
        ref = kind + ":" + row[identifier]
        if ref not in report["data_sources"]:
            raise ClaimValidationError("claim_source_outside_snapshot")
        catalog[ref] = {
            "kind": kind,
            "fields": {key: row[key] for key in FIELDS[kind] if row.get(key) is not None},
        }
        return catalog[ref]

    for fact in report["facts"]:
        add("transaction", fact["record"], "transaction_id")
    for row in report["related_accounts"]:
        add("account", row, "account_id")
    for item in report["risk_indicators"]:
        entry = add("assessment", item["record"], "assessment_id")
        entry["factor_codes"] = sorted(
            {f["code"] for f in item["record"]["factors"] if Decimal(str(f["contribution"])) > 0}
        )
        entry["source_transactions"] = sorted(
            {
                "transaction:" + tx
                for f in item["record"]["factors"]
                for tx in f["source_transaction_ids"]
            }
        )
    for row in report["supporting_evidence"]:
        entry = add("evidence", row, "evidence_id")
        entry["source_transactions"] = sorted(
            {"transaction:" + tx for tx in [row["transaction_id"], *row["source_transaction_ids"]]}
        )
    add("case", {**report["case_context"], "transaction_count": len(report["facts"])}, "case_id")

    # Connections and counts are derived from scoped records, not asserted by the model.
    pairs = defaultdict(list)
    for fact in report["facts"]:
        row = fact["record"]
        if row["source_account_id"] and row["destination_account_id"]:
            pairs[(row["source_account_id"], row["destination_account_id"])].append(row)
    for (source, destination), rows in sorted(pairs.items()):
        refs = sorted("transaction:" + row["transaction_id"] for row in rows)
        key = hashlib.sha256(json.dumps([source, destination, refs]).encode()).hexdigest()
        catalog["relationship:" + key] = {
            "kind": "relationship",
            "fields": {
                "source": source,
                "destination": destination,
                "transaction_count": len(rows),
                "completed_count": sum(row["status"] == "completed" for row in rows),
            },
            "source_transactions": refs,
        }
    return catalog


def validate_claims(report, raw):
    analysis = Analysis.model_validate(raw)
    catalog = evidence_catalog(report)
    facts, inferences, unknowns, recommendations = [], [], [], []
    seen = {}
    for claim in analysis.claims:
        evidence = catalog.get(claim.source)
        if evidence is None:
            raise ClaimValidationError("claim_source_outside_snapshot")
        key = (claim.source, claim.field)
        value = claim.model_dump()
        if key in seen:
            if seen[key] != value:
                raise ClaimValidationError("claim_conflict")
            continue
        seen[key] = value
        fields = evidence["fields"]
        bound = {"source": claim.source, "field": claim.field}
        if claim.claim_type == "fact":
            if claim.field not in fields:
                raise ClaimValidationError("claim_field_unavailable")
            actual = fields[claim.field]
            if type(claim.value) is not type(actual) or claim.value != actual:
                raise ClaimValidationError("claim_value_mismatch")
            facts.append(
                {
                    **value,
                    "status": "verified_against_snapshot",
                    "provenance": bound,
                    "text": f"Recorded {claim.field} for {claim.source}: {json.dumps(actual)}.",
                }
            )
        elif claim.claim_type == "inference":
            rule = INFERENCES.get(claim.field)
            if claim.value is not None or not rule or evidence["kind"] != rule[0]:
                raise ClaimValidationError("claim_inference_unsupported")
            if claim.field == "risk_review" and (
                not evidence.get("factor_codes") or Decimal(fields["score"]) <= 0
            ):
                raise ClaimValidationError("claim_inference_unsupported")
            inferences.append(
                {
                    **value,
                    "status": "unverified_inference",
                    "confidence": "low",
                    "text": rule[1],
                    "support": {"source": claim.source, **evidence},
                }
            )
        else:
            if (
                claim.value is not None
                or claim.field not in UNKNOWN_FIELDS.get(evidence["kind"], set())
                or claim.field in fields
            ):
                raise ClaimValidationError("claim_unknown_unsupported")
            unknowns.append(
                {
                    **value,
                    "status": "unknown_in_supplied_evidence",
                    "provenance": bound,
                    "text": f"Unknown {claim.field} for {claim.source} in the supplied evidence.",
                }
            )
    for item in analysis.recommendations:
        if any(source not in catalog for source in item.sources):
            raise ClaimValidationError("claim_source_outside_snapshot")
        recommendations.append(
            {
                **item.model_dump(),
                "text": RECOMMENDATIONS[item.action],
                "status": "human_review_suggestion",
            }
        )
    # No report mutation happens until the entire response has passed validation.
    return {
        "claim_contract": CLAIM_CONTRACT,
        "verified_claims": facts,
        "model_hypotheses": inferences,
        "model_missing_evidence": unknowns,
        "model_recommendations": recommendations,
        "model_evidence_sufficiency": "insufficient"
        if unknowns or not analysis.claims
        else analysis.evidence_sufficiency,
        "unverified_assumptions": ["Inferences require independent human validation."]
        if inferences
        else [],
    }
