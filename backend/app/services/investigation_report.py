"""Build factual projections from a firewall-authorized, consistent case read."""

import hashlib
import json

from app.services.investigation_claims import evidence_catalog, validate_claims


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def report_digest(report):
    """Bind the immutable report content; review annotations have a separate lifecycle."""
    return digest(
        {
            k: v
            for k, v in report.items()
            if k not in {"fingerprint", "human_review_status", "human_conclusions"}
        }
    )


def ground_report(view, case_id, steps, mode):
    if view.get("case_id") != case_id:
        raise ValueError("Case mismatch")
    sources = {"case:" + case_id: {"kind": "case", "record": case_id}}
    facts, risks = [], []

    def register(kind, rows, field):
        unique = {}
        for row in rows:
            key = kind + ":" + row[field]
            if key in unique and unique[key] != row:
                raise ValueError("Conflicting source record")
            unique[key] = row
            sources[key] = {"kind": kind, "record": row[field]}
        return unique

    txs = register("transaction", view["transactions"], "transaction_id")
    accounts = register("account", view["accounts"], "account_id")
    assessments = register("assessment", view["assessments"], "assessment_id")
    evidence = register("evidence", view["evidence"], "evidence_id")
    reports = register("report", view["reports"], "report_id")

    def tx_sources(ids):
        refs = sorted({"transaction:" + item for item in ids})
        if any(ref not in txs for ref in refs):
            raise ValueError("Unresolved transaction provenance")
        return refs

    for ref, row in txs.items():
        related = [
            "account:" + row[k] for k in ("source_account_id", "destination_account_id") if row[k]
        ]
        if any(a not in accounts for a in related):
            raise ValueError("Unresolved account")
        facts.append({"kind": "recorded_transaction", "sources": [ref, *related], "record": row})
    for ref, row in assessments.items():
        refs = tx_sources([row["transaction_id"]])
        for factor in row["factors"]:
            refs += tx_sources(factor["source_transaction_ids"])
        risks.append(
            {
                "kind": "stored_risk_assessment",
                "sources": sorted({ref, *refs}),
                "record": row,
                "interpretation": "Recorded risk indicator; not proof of fraud.",
            }
        )
    for ref, row in evidence.items():
        refs = tx_sources([row["transaction_id"], *row["source_transaction_ids"]])
        if row["assessment_id"] and "assessment:" + row["assessment_id"] not in assessments:
            raise ValueError("Unresolved evidence assessment")
        sources[ref]["source_transactions"] = refs
    for ref, row in reports.items():
        sources[ref]["source_transactions"] = tx_sources(row["source_transaction_ids"])
    patterns = view["relationships"]
    for node in patterns["nodes"]:
        if "account:" + node["account_id"] not in accounts:
            raise ValueError("Unresolved relationship account")
    for edge in patterns["edges"]:
        tx_sources(edge["transaction_ids"])
        if any("account:" + edge[k] not in accounts for k in ("source", "destination")):
            raise ValueError("Unresolved relationship edge")
    for finding in patterns["findings"]:
        tx_sources(finding["source_transaction_ids"])
        if any("account:" + a not in accounts for a in finding["account_ids"]):
            raise ValueError("Unresolved pattern account")
    report = {
        "objective": "Review case records and organize evidence for human investigation",
        "case_context": {k: view[k] for k in ("case_id", "status", "version")},
        "provider_mode": mode,
        "steps_performed": steps,
        "data_sources": sources,
        "facts": facts,
        "supporting_evidence": list(evidence.values()),
        "suspicious_patterns": patterns,
        "related_accounts": list(accounts.values()),
        "risk_indicators": risks,
        "existing_report_references": list(reports.values()),
        "model_hypotheses": [],
        "unverified_assumptions": [],
        "limitations": [
            *view["limitations"],
            "Deterministic mode does not generate AI hypotheses."
            if mode == "deterministic"
            else "Provider hypotheses are unverified and constrained to source references.",
            "Earlier steps are separate reads. Report facts use the final case_report snapshot.",
            "Case-only historical patterns; no external data or unrestricted historical search.",
            "Persisted case snapshot; review source records again when current facts are needed.",
            "Findings may become stale; human review does not certify current database state.",
        ],
        "recommendations": [
            "Validate evidence and alternative explanations before drawing conclusions.",
            "Review source records with an authorized human investigator.",
        ],
        "human_review_status": "pending",
        "human_conclusions": [],
    }

    for ref, entry in evidence_catalog(report).items():
        report["data_sources"].setdefault(ref, {"kind": entry["kind"], "record": ref})
        report["data_sources"][ref].update(entry)
    return report


def apply_analysis(report, raw):
    validated = validate_claims(report, raw)
    report.update(validated)
    report["limitations"].append(
        "Facts are verified only against the authorized snapshot, not external truth. "
        "Inferences remain unverified; ownership, intent and external context are not inferred."
    )
    return report
