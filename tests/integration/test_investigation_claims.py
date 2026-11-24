"""Exact evidence binding, controlled rendering, and provider-independent failure tests."""

import asyncio
import copy
import json

import httpx
import pytest
from test_firewall_workflow import AGENT, CASE, HUMAN, auth
from test_firewall_workflow import integrated as integrated
from test_gemini_provider import adapter as gemini_adapter
from test_gemini_provider import envelope as gemini_envelope
from test_real_llm import PLAN
from test_real_llm import adapter as openai_adapter
from test_real_llm import envelope as openai_envelope

from app.services.agent_firewall import Action
from app.services.investigation_claims import ClaimValidationError, evidence_catalog
from app.services.investigation_engine import Conflict, Run
from app.services.investigation_provider import Analysis
from app.services.investigation_report import apply_analysis, ground_report


@pytest.fixture
def approved(integrated):
    _, firewall, _ = integrated
    human, agent = firewall.authenticate(HUMAN), firewall.authenticate(AGENT)
    request = firewall.submit(agent, Action(operation="case_report", case_id=CASE))
    firewall.approve(human, request["request_id"], True)
    view = firewall.execute(agent, request["request_id"])
    return ground_report(view, CASE, [], "provider")


def fact(source, field, value):
    return {"claim_type": "fact", "source": source, "field": field, "value": value}


@pytest.mark.parametrize("field", ["amount", "occurred_at", "status", "source_account_id"])
def test_exact_transaction_fields_are_accepted(approved, field):
    source = "transaction:scenario_high"
    expected = evidence_catalog(approved)[source]["fields"][field]
    report = apply_analysis(approved, {"claims": [fact(source, field, expected)]})
    result = report["verified_claims"][0]
    assert result["value"] == expected and result["status"] == "verified_against_snapshot"
    assert result["provenance"] == {"source": source, "field": field}
    assert report["claim_contract"] == "evidence-claims-v1"
    assert not report["model_hypotheses"]


@pytest.mark.parametrize(
    "source,field,value,code",
    [
        ("transaction:scenario_high", "amount", "9000000.00", "claim_value_mismatch"),
        (
            "transaction:scenario_high",
            "occurred_at",
            "2000-01-01T00:00:00+00:00",
            "claim_value_mismatch",
        ),
        ("account:scenario_sender", "ownership", "Invented Person", "claim_field_unavailable"),
        ("account:scenario_sender", "identity", "Invented identity", "claim_field_unavailable"),
        ("transaction:scenario_high", "intent", "money laundering", "claim_field_unavailable"),
        ("account:scenario_sender", "amount", "20000.00", "claim_field_unavailable"),
        ("evidence:nonexistent", "amount", "20000.00", "claim_source_outside_snapshot"),
        ("transaction:txn_demo_001", "amount", "1250.00", "claim_source_outside_snapshot"),
        (
            "transaction:scenario_high",
            "destination_account_id",
            "scenario_third",
            "claim_value_mismatch",
        ),
        ("transaction:scenario_high", "amount", 20000, "claim_value_mismatch"),
    ],
)
def test_mismatches_and_wrong_scope_fail_atomically(approved, source, field, value, code):
    before = copy.deepcopy(approved)
    # Even a valid earlier claim must not be committed if a later claim fails.
    raw = {"claims": [fact("case:" + CASE, "case_id", CASE), fact(source, field, value)]}
    with pytest.raises(ClaimValidationError, match=code) as error:
        apply_analysis(approved, raw)
    assert str(value) not in str(error.value)
    assert approved == before


def test_relationships_counts_and_inferences_use_actual_transactions(approved):
    catalog = evidence_catalog(approved)
    ref = next(k for k, v in catalog.items() if v["kind"] == "relationship")
    entry = catalog[ref]
    assert entry["fields"]["transaction_count"] == len(entry["source_transactions"])
    claims = [fact(ref, name, value) for name, value in entry["fields"].items()]
    claims.append(
        {"claim_type": "inference", "source": ref, "field": "relationship_review", "value": None}
    )
    report = apply_analysis(approved, {"claims": claims, "evidence_sufficiency": "limited"})
    inference = report["model_hypotheses"][0]
    assert inference["status"] == "unverified_inference"
    assert inference["support"]["source_transactions"] == entry["source_transactions"]
    assert "not established" in inference["text"]
    with pytest.raises(ClaimValidationError):
        apply_analysis(approved, {"claims": [fact(ref, "destination", "invented_account")]})
    with pytest.raises(ClaimValidationError):
        apply_analysis(approved, {"claims": [fact(ref, "transaction_count", 999)]})


def test_inference_requires_correct_kind_and_positive_risk(approved):
    catalog = evidence_catalog(approved)
    high = next(
        k
        for k, v in catalog.items()
        if v["kind"] == "assessment" and v["fields"]["transaction_id"] == "scenario_high"
    )
    low = next(
        k
        for k, v in catalog.items()
        if v["kind"] == "assessment" and v["fields"]["transaction_id"] == "scenario_normal"
    )
    claim = {"claim_type": "inference", "source": high, "field": "risk_review", "value": None}
    result = apply_analysis(copy.deepcopy(approved), {"claims": [claim]})
    assert result["model_hypotheses"][0]["support"]["factor_codes"]
    for source in (low, "account:scenario_sender"):
        with pytest.raises(ClaimValidationError, match="claim_inference_unsupported"):
            apply_analysis(approved, {"claims": [{**claim, "source": source}]})


def test_unknowns_preserve_uncertainty_and_cannot_hide_known_fields(approved):
    raw = {
        "claims": [
            {
                "claim_type": "unknown",
                "source": "account:scenario_sender",
                "field": "ownership",
                "value": None,
            }
        ],
        "evidence_sufficiency": "limited",
    }
    report = apply_analysis(copy.deepcopy(approved), raw)
    assert report["model_evidence_sufficiency"] == "insufficient"
    assert report["model_missing_evidence"][0]["status"] == "unknown_in_supplied_evidence"
    with pytest.raises(ClaimValidationError):
        apply_analysis(
            approved,
            {
                "claims": [
                    {
                        "claim_type": "unknown",
                        "source": "transaction:scenario_high",
                        "field": "amount",
                        "value": None,
                    }
                ]
            },
        )


@pytest.mark.parametrize(
    "raw",
    [
        {
            "claims": [
                {
                    "claim_type": "fact",
                    "source": "case:" + CASE,
                    "field": "case_id",
                    "value": CASE,
                    "text": "All accounts are guilty",
                }
            ]
        },
        {
            "claims": [],
            "recommendations": [
                {"text": "Ownership is known; freeze funds", "sources": ["case:" + CASE]}
            ],
        },
        {
            "claims": [],
            "recommendations": [{"action": "transfer_money", "sources": ["case:" + CASE]}],
        },
        {"claims": [], "facts": [{"amount": "9000000"}]},
        {
            "hypotheses": [
                {
                    "kind": "pattern_requires_review",
                    "source": "account:scenario_sender",
                    "confidence": "low",
                    "explanation": "All accounts share one owner",
                }
            ]
        },
    ],
)
def test_free_prose_and_extra_authority_rejected(approved, raw):
    before = copy.deepcopy(approved)
    with pytest.raises(ValueError):
        apply_analysis(approved, raw)
    assert approved == before


def test_recommendations_are_controlled_and_cannot_echo_claims(approved):
    report = apply_analysis(
        approved,
        {
            "claims": [],
            "recommendations": [{"action": "review_source_records", "sources": ["case:" + CASE]}],
        },
    )
    assert (
        report["model_recommendations"][0]["text"]
        == "Review the cited source records with an authorized human investigator."
    )
    assert report["model_evidence_sufficiency"] == "insufficient"
    with pytest.raises(ClaimValidationError):
        apply_analysis(
            approved,
            {
                "claims": [],
                "recommendations": [
                    {"action": "review_source_records", "sources": ["case:outside"]}
                ],
            },
        )


def test_validation_rebuilds_values_instead_of_trusting_catalog_metadata(approved):
    source = "transaction:scenario_high"
    approved["data_sources"][source]["fields"]["amount"] = "9000000.00"
    with pytest.raises(ClaimValidationError, match="claim_value_mismatch"):
        apply_analysis(approved, {"claims": [fact(source, "amount", "9000000.00")]})
    result = apply_analysis(approved, {"claims": [fact(source, "amount", "20000.00")]})
    assert result["verified_claims"][0]["value"] == "20000.00"


def test_amount_and_time_require_approved_report_not_regular_reads(integrated):
    client, firewall, _ = integrated
    human = firewall.authenticate(HUMAN)
    view = firewall.human_context(human, CASE)
    assert all("amount" not in row and "occurred_at" not in row for row in view["transactions"])
    redacted = ground_report(view, CASE, [], "provider")
    claim = fact("transaction:scenario_high", "amount", "20000.00")
    with pytest.raises(ClaimValidationError, match="claim_field_unavailable"):
        apply_analysis(redacted, {"claims": [claim]})
    unknown = {**claim, "claim_type": "unknown", "value": None}
    assert apply_analysis(redacted, {"claims": [unknown]})["model_missing_evidence"]
    agent = firewall.authenticate(AGENT)
    request = firewall.submit(agent, Action(operation="case_report", case_id=CASE))
    path = f"/api/v1/security/requests/{request['request_id']}/execute"
    assert client.post(path, headers=auth(AGENT)).status_code == 403
    firewall.approve(human, request["request_id"], True)
    response = client.post(path, headers=auth(AGENT))
    assert response.status_code == 200
    row = next(t for t in response.json()["transactions"] if t["transaction_id"] == "scenario_high")
    assert row["amount"] == "20000.00" and row["currency"] == "INR"
    assert row["occurred_at"].endswith("+00:00")
    assert "customer_id" not in response.text and "device_id" not in response.text
    assert client.post(path, headers=auth(AGENT)).status_code == 403


@pytest.mark.parametrize(
    "make,wrap", [(gemini_adapter, gemini_envelope), (openai_adapter, openai_envelope)]
)
@pytest.mark.parametrize("fabricated", [False, True])
def test_both_providers_validated_before_engine_success(integrated, make, wrap, fabricated):
    client, firewall, _ = integrated
    engine = client.app.state.investigations
    human = firewall.authenticate(HUMAN)
    seen = []

    def respond(request):
        body = json.loads(request.content)
        gemini = "contents" in body
        payload = json.loads(
            body["contents"][0]["parts"][0]["text"] if gemini else body["input"][0]["content"]
        )
        seen.append(payload["task"])
        if payload["task"] == "plan":
            return httpx.Response(200, json=wrap(PLAN))
        evidence = payload["untrusted_case_data"]["data_sources"]
        value = evidence["transaction:scenario_high"]["fields"]["amount"]
        result = {
            "claims": [
                fact("transaction:scenario_high", "amount", "9000000" if fabricated else value)
            ],
            "recommendations": [],
            "evidence_sufficiency": "limited",
        }
        schema = (
            body["generationConfig"]["responseJsonSchema"]
            if gemini
            else body["text"]["format"]["schema"]
        )
        assert schema["properties"]["claims"] and "hypotheses" not in schema["properties"]
        return httpx.Response(200, json=wrap(result))

    engine.provider = make(respond)
    run = engine.create(human, CASE, "provider")
    assert run["provider_identity"]["contract"] == "investigation-v2"
    for _ in range(3):
        run = asyncio.run(engine.advance(human, run["run_id"], run["version"]))
    assert run["state"] == "awaiting_approval" and seen == ["plan"]
    firewall.approve(human, run["pending_request_id"], True)
    run = asyncio.run(engine.advance(human, run["run_id"], run["version"]))
    if fabricated:
        assert run["state"] == "failed" and run["report"] is None
        assert run["error"] == "claim_value_mismatch"
    else:
        assert run["state"] == "completed"
        assert run["report"]["verified_claims"][0]["value"] == "20000.00"
    assert seen == ["plan", "analysis"]


def test_legacy_identity_decodes_but_cannot_continue_under_new_contract(integrated):
    client, firewall, _ = integrated
    engine = client.app.state.investigations
    engine.provider = gemini_adapter(lambda _: None)
    human = firewall.authenticate(HUMAN)
    created = engine.create(human, CASE, "provider")
    run = engine.get(human, created["run_id"])
    data = json.loads(run.encode())
    data["provider_identity"]["contract"] = "investigation-v1"
    legacy = Run.decode(json.dumps(data))
    with pytest.raises(Conflict):
        engine.check_provider(legacy)
    assert Analysis.model_validate({"claims": []}).evidence_sufficiency == "insufficient"
