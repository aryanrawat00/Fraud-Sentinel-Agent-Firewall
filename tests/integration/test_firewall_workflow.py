"""Real deterministic investigation services + HTTP firewall; no LLM or PostgreSQL."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.main import create_app
from app.models import Evidence, Transaction
from app.models.workflow import InvestigationReport, WorkflowBase
from app.repositories.intelligence import IntelligenceRepository
from app.schemas.workflow import InvestigationCreate
from app.services.agent_firewall import Firewall, Principal
from app.services.detection import DetectionService
from app.services.evidence import EvidenceService
from app.services.investigations import InvestigationService
from scripts.seed_demo_data import seed_demo
from scripts.synthetic_scenarios import create_scenarios

AGENT = "integration-agent-" + "a" * 40
HUMAN = "integration-human-" + "h" * 40
CASE = "case_firewall_integration"
OWNER = "user_demo_analyst"


@pytest.fixture
def integrated(engine, tmp_path):
    WorkflowBase.metadata.create_all(engine)
    with Session(engine) as session, session.begin():
        seed_demo(session)
        repo = IntelligenceRepository(session, OWNER)
        create_scenarios(repo)
        analysis = DetectionService(repo).analyze("scenario_high")
        evidence = EvidenceService(repo).collect(analysis["assessment"]["assessment_id"])
        ids = list(
            session.scalars(
                select(Transaction.transaction_id).where(
                    Transaction.transaction_id.like("scenario_%")
                )
            )
        )
        InvestigationService(repo).create(
            InvestigationCreate(
                case_id=CASE,
                title="Synthetic investigation",
                transaction_ids=ids,
                evidence_ids=[e.evidence_id for e in evidence],
                assessment_ids=[analysis["assessment"]["assessment_id"]],
            )
        )
        report = InvestigationService(repo).report(CASE)
    f = Firewall(
        engine,
        tmp_path / "ledger.sqlite3",
        {
            AGENT: Principal("agent_workflow", "agent", "investigator", OWNER, frozenset({CASE})),
            HUMAN: Principal("human_workflow", "human", "approver", OWNER, frozenset({CASE})),
        },
        b"z" * 32,
    )
    settings = Settings(_env_file=None, app_env="test", demo_mode=True, investigation_sandbox=True)
    with TestClient(
        create_app(settings, engine, firewall=f), raise_server_exceptions=False
    ) as client:
        yield client, f, report
    f.db.close()


def auth(token):
    return {"Authorization": "Bearer " + token}


def request(client, operation, case_id=CASE, **params):
    return client.post(
        "/api/v1/security/requests",
        headers=auth(AGENT),
        json=dict(operation=operation, case_id=case_id, **params),
    )


def test_real_workflow_analysis_evidence_report_approval_and_review(integrated):
    client, f, report = integrated
    denied = request(client, "case_report", case_id="case_outside_scope").json()
    assert denied["decision"] == "DENY"
    proposal = request(client, "case_report").json()
    rid = proposal["request_id"]
    assert proposal["decision"] == "REQUIRE_APPROVAL"
    path = f"/api/v1/security/requests/{rid}"
    assert client.post(path + "/execute", headers=auth(AGENT)).status_code == 403
    assert (
        client.post(path + "/approval", headers=auth(AGENT), json={"approved": True}).status_code
        == 403
    )
    assert (
        client.post(path + "/approval", headers=auth(HUMAN), json={"approved": True}).json()[
            "status"
        ]
        == "approved"
    )
    response = client.post(path + "/execute", headers=auth(AGENT))
    assert response.status_code == 200, response.text
    view = response.json()
    assert view["evidence"] and view["accounts"] and view["relationships"]["edges"]
    assert any(a["risk_category"] == "critical" for a in view["assessments"])
    assert view["reports"][0]["report_id"] == report["report_id"]
    assert view["reports"][0]["fingerprint"] == report["fingerprint"]
    txids = set(view["transaction_ids"])
    assert all(set(e["source_transaction_ids"]) <= txids for e in view["evidence"])
    assert all(
        set(factor["source_transaction_ids"]) <= txids
        for a in view["assessments"]
        for factor in a["factors"]
    )
    assert "amount" in response.text and "occurred_at" in response.text
    assert "customer_id" not in response.text
    assert client.post(path + "/execute", headers=auth(AGENT)).status_code == 403
    human = client.get(f"/api/v1/security/investigations/{CASE}", headers=auth(HUMAN))
    assert (
        human.status_code == 200 and human.json()["reports"][0]["report_id"] == report["report_id"]
    )
    log = client.get("/api/v1/security/dashboard", headers=auth(HUMAN)).json()["events"]
    assert {"REQUIRE_APPROVAL", "APPROVED", "EXECUTED", "REVIEWED"} <= {e["decision"] for e in log}


@pytest.mark.parametrize(
    "operation,key",
    [
        ("case_transactions", "transactions"),
        ("case_accounts", "accounts"),
        ("case_evidence", "evidence"),
        ("case_relationships", "relationships"),
        ("assessment_summary", "assessments"),
    ],
)
def test_supported_tools_use_real_scoped_records(integrated, operation, key):
    client, _, _ = integrated
    params = {"transaction_id": "scenario_high"} if operation == "assessment_summary" else {}
    proposal = request(client, operation, **params).json()
    assert proposal["decision"] == "ALLOW"
    response = client.post(
        f"/api/v1/security/requests/{proposal['request_id']}/execute", headers=auth(AGENT)
    )
    assert response.status_code == 200, response.text
    assert response.json()[key]


@pytest.mark.parametrize("token", [None, AGENT])
def test_agent_and_anonymous_cannot_use_human_context(integrated, token):
    client, _, _ = integrated
    assert (
        client.get(
            f"/api/v1/security/investigations/{CASE}", headers=auth(token) if token else {}
        ).status_code
        == 403
    )


@pytest.mark.parametrize("token", [None, AGENT, HUMAN])
def test_secured_mode_has_no_legacy_bypass(integrated, token):
    client, _, _ = integrated
    for path in [
        "/api/v1/demo/overview",
        "/api/v1/intelligence/dashboard",
        "/api/v1/intelligence/cases",
        "/docs",
    ]:
        assert client.get(path, headers=auth(token) if token else {}).status_code == 404


def test_shared_owner_does_not_allow_other_case(integrated):
    client, _, _ = integrated
    proposal = request(client, "assessment_summary", transaction_id="txn_demo_001").json()
    assert proposal["decision"] == "DENY"
    assert (
        client.get("/api/v1/security/investigations/case_demo_001", headers=auth(HUMAN)).status_code
        == 403
    )


def test_foreign_provenance_fails_closed(integrated):
    client, f, _ = integrated
    with Session(f.engine) as session, session.begin():
        row = session.scalar(select(Evidence).where(Evidence.case_id == CASE))
        row.provenance = {**row.provenance, "source_transaction_ids": ["txn_demo_001"]}
    rid = request(client, "case_evidence").json()["request_id"]
    assert client.post(
        f"/api/v1/security/requests/{rid}/execute", headers=auth(AGENT)
    ).status_code in {403, 503}


def test_report_content_tamper_is_not_released(integrated):
    client, f, report = integrated
    with Session(f.engine) as session, session.begin():
        row = session.get(InvestigationReport, report["report_id"])
        row.content = {**row.content, "recommendations": ["injected"]}
    rid = request(client, "case_report").json()["request_id"]
    client.post(
        f"/api/v1/security/requests/{rid}/approval", headers=auth(HUMAN), json={"approved": True}
    )
    assert client.post(
        f"/api/v1/security/requests/{rid}/execute", headers=auth(AGENT)
    ).status_code in {403, 503}


def test_missing_workflow_schema_is_not_auto_migrated(engine, tmp_path):
    f = Firewall(
        engine,
        tmp_path / "ledger.sqlite3",
        {AGENT: Principal("a", "agent", "reader", OWNER, frozenset({CASE}))},
        b"z" * 32,
    )
    settings = Settings(_env_file=None, app_env="test", investigation_sandbox=True, demo_mode=True)
    with patch("alembic.command.upgrade") as upgrade:
        app = create_app(settings, engine, firewall=f)
        assert app is not None
        upgrade.assert_not_called()
    f.db.close()
