import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api.agent_security import create_firewall_app
from app.models.workflow import WorkflowBase
from app.services.agent_firewall import Action, Firewall, Principal, Refused
from scripts.seed_demo_data import DEMO_CASE_ID, seed_demo

AGENT = "a" * 48
HUMAN = "h" * 48


@pytest.fixture
def firewall(engine, tmp_path):
    WorkflowBase.metadata.create_all(engine)
    with Session(engine) as session, session.begin():
        seed_demo(session)
    cases = frozenset({DEMO_CASE_ID})
    f = Firewall(
        engine,
        tmp_path / "ledger.sqlite3",
        {
            AGENT: Principal("agent1", "agent", "investigator", "user_demo_analyst", cases),
            HUMAN: Principal("human1", "human", "approver", "user_demo_analyst", cases),
            "r" * 48: Principal("reader", "agent", "reader", "user_demo_analyst", cases),
            "x" * 48: Principal("other", "agent", "investigator", "other_owner", cases),
            "s" * 48: Principal(
                "unscoped", "agent", "investigator", "user_demo_analyst", frozenset({"other_case"})
            ),
        },
        b"k" * 32,
    )
    yield f
    f.db.close()


@pytest.fixture
def api(firewall):
    with TestClient(create_firewall_app(firewall), raise_server_exceptions=False) as client:
        yield client


def headers(token=AGENT):
    return {"Authorization": "Bearer " + token}


def submit(api, op="case_summary", token=AGENT, **params):
    return api.post(
        "/api/v1/security/requests",
        headers=headers(token),
        json=dict(operation=op, case_id=DEMO_CASE_ID, **params),
    )


def execute(api, rid, token=AGENT):
    return api.post(f"/api/v1/security/requests/{rid}/execute", headers=headers(token))


def approve(api, rid, approved=True, token=HUMAN):
    return api.post(
        f"/api/v1/security/requests/{rid}/approval",
        headers=headers(token),
        json={"approved": approved},
    )


def test_allowed_scoped_read_and_replay(api):
    r = submit(api).json()
    assert r["decision"] == "ALLOW"
    result = execute(api, r["request_id"])
    assert result.status_code == 200
    assert result.json()["transaction_count"] == 6
    assert "amount" not in result.text and "customer_id" not in result.text
    assert execute(api, r["request_id"]).status_code == 403


@pytest.mark.parametrize("token", [None, "wrong", "a" * 47])
def test_unauthorized_credentials(api, token):
    assert api.get("/api/v1/security/dashboard", headers=headers(token or "")).status_code == 403


@pytest.mark.parametrize("token", ["x" * 48, "s" * 48])
def test_owner_and_case_scope_denied(api, token):
    r = submit(api, token=token).json()
    assert r["decision"] == "DENY"
    assert execute(api, r["request_id"], token).status_code == 403


@pytest.mark.parametrize(
    "payload",
    [
        {"operation": "sql", "case_id": DEMO_CASE_ID},
        {"operation": "case_summary", "case_id": DEMO_CASE_ID, "role": "approver"},
        {"operation": "case_summary", "case_id": "../../secrets"},
        {"operation": "case_summary", "case_id": DEMO_CASE_ID, "url": "http://localhost"},
    ],
)
def test_input_and_escalation_denied(api, payload):
    assert api.post("/api/v1/security/requests", headers=headers(), json=payload).status_code == 422


def test_sensitive_approval_and_agent_cannot_approve(api):
    r = submit(api, "case_report").json()
    rid = r["request_id"]
    assert r["status"] == "pending" and execute(api, rid).status_code == 403
    assert approve(api, rid, token=AGENT).status_code == 403
    assert approve(api, rid).json()["status"] == "approved"
    assert execute(api, rid).status_code == 200
    assert execute(api, rid).status_code == 403
    assert approve(api, rid).status_code == 403


def test_reader_cannot_request_sensitive_tool(api):
    assert submit(api, "case_report", token="r" * 48).json()["decision"] == "DENY"


def test_human_cannot_impersonate_agent(api):
    assert submit(api, token=HUMAN).json()["decision"] == "DENY"


def test_rejection_and_expiry(api, firewall):
    rid = submit(api, "case_report").json()["request_id"]
    assert approve(api, rid, False).json()["status"] == "rejected"
    assert execute(api, rid).status_code == 403
    rid = submit(api, "case_report").json()["request_id"]
    now = firewall.clock()
    firewall.clock = lambda: now + 301
    assert approve(api, rid).json()["status"] == "expired"
    assert execute(api, rid).status_code == 403


def test_action_tamper_fails(api, firewall):
    rid = submit(api, "case_report").json()["request_id"]
    approve(api, rid)
    firewall.db.execute(
        "UPDATE requests SET action=? WHERE id=?",
        (json.dumps({"operation": "case_summary", "case_id": DEMO_CASE_ID}), rid),
    )
    assert execute(api, rid).status_code == 403


def test_forged_approval_fails(api, firewall):
    rid = submit(api, "case_report").json()["request_id"]
    firewall.db.execute(
        "UPDATE requests SET status='approved',approver='human1',approval_mac='fake' WHERE id=?",
        (rid,),
    )
    assert execute(api, rid).status_code == 403


def test_consumed_status_tamper_cannot_replay(api, firewall):
    rid = submit(api).json()["request_id"]
    assert execute(api, rid).status_code == 200
    firewall.db.execute("UPDATE requests SET status='ready' WHERE id=?", (rid,))
    assert execute(api, rid).status_code == 403


def test_cross_agent_execution_denied(api):
    rid = submit(api).json()["request_id"]
    assert execute(api, rid, "r" * 48).status_code == 403


def test_approval_identity_revocation(api, firewall):
    rid = submit(api, "case_report").json()["request_id"]
    approve(api, rid)
    firewall.identities = {k: v for k, v in firewall.identities.items() if v.kind != "human"}
    assert execute(api, rid).status_code == 403


def test_audit_immutable_redacted_and_dashboard_human_only(api, firewall):
    rid = submit(api).json()["request_id"]
    execute(api, rid)
    assert api.get("/api/v1/security/dashboard", headers=headers()).status_code == 403
    dashboard = api.get("/api/v1/security/dashboard", headers=headers(HUMAN))
    assert dashboard.status_code == 200 and dashboard.json()["events"]
    assert AGENT not in dashboard.text and HUMAN not in dashboard.text
    assert "amount" not in dashboard.text
    with pytest.raises(sqlite3.IntegrityError):
        firewall.db.execute("DELETE FROM events")


def test_policy_failure_fails_closed(api, firewall):
    with patch.object(firewall, "policy", side_effect=RuntimeError("private details")):
        r = submit(api)
        assert r.status_code == 503 and "private details" not in r.text


def test_audit_failure_does_not_release_data(api, firewall):
    rid = submit(api).json()["request_id"]
    with patch.object(firewall, "event", side_effect=RuntimeError("disk failure")):
        assert execute(api, rid).status_code == 503
    assert firewall.request(rid)["status"] == "ready"


def test_parallel_consumption_only_once(firewall):
    p = firewall.authenticate(AGENT)
    rid = firewall.submit(p, Action(operation="case_summary", case_id=DEMO_CASE_ID))["request_id"]

    def run(_):
        try:
            firewall.execute(p, rid)
            return True
        except Refused:
            return False

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(pool.map(run, range(4))) == 1


def test_no_legacy_bypass_routes(api):
    for path in [
        "/api/v1/demo/overview",
        "/api/v1/intelligence/dashboard",
        "/docs",
        "/openapi.json",
    ]:
        assert api.get(path).status_code == 404


def test_oversized_request(api):
    assert (
        api.post("/api/v1/security/requests", headers=headers(), content="x" * 5000).status_code
        == 413
    )


def test_transaction_resource_must_belong_to_case(api):
    r = submit(api, "assessment_summary", transaction_id="missing_or_foreign").json()
    assert r["decision"] == "DENY"


def test_approved_request_can_expire(api, firewall):
    rid = submit(api, "case_report").json()["request_id"]
    approve(api, rid)
    now = firewall.clock()
    firewall.clock = lambda: now + 301
    assert execute(api, rid).status_code == 403


def test_audit_tamper_refuses_execution(api, firewall):
    rid = submit(api).json()["request_id"]
    firewall.db.execute("DROP TRIGGER immutable_events_update")
    firewall.db.execute("UPDATE events SET payload='{}'")
    assert execute(api, rid).status_code in {403, 503}


def test_consumption_survives_restart(api, firewall, tmp_path):
    rid = submit(api).json()["request_id"]
    assert execute(api, rid).status_code == 200
    second = Firewall(
        firewall.engine,
        tmp_path / "ledger.sqlite3",
        {AGENT: firewall.authenticate(AGENT), HUMAN: firewall.authenticate(HUMAN)},
        b"k" * 32,
    )
    try:
        with pytest.raises(Refused):
            second.execute(second.authenticate(AGENT), rid)
    finally:
        second.db.close()


def test_unregistered_principal_refused(firewall):
    with pytest.raises(Refused):
        firewall.submit(
            Principal(
                "spoof", "agent", "investigator", "user_demo_analyst", frozenset({DEMO_CASE_ID})
            ),
            Action(operation="case_summary", case_id=DEMO_CASE_ID),
        )


def test_tool_failure_logged_without_releasing_private_details(api, firewall):
    rid = submit(api).json()["request_id"]
    with patch.object(firewall, "_read_tool", side_effect=RuntimeError("private financial data")):
        response = execute(api, rid)
        assert response.status_code == 503
        assert "private financial" not in response.text
    events = [json.loads(r["payload"]) for r in firewall.db.execute("SELECT payload FROM events")]
    assert any(e["reason"] == "execution_or_policy_failure" for e in events)


def test_launcher_seeds_only_its_isolated_sqlite_files(tmp_path, monkeypatch):
    import scripts.run_agent_firewall as launcher

    monkeypatch.setattr(
        launcher, "__file__", str(tmp_path / "backend/scripts/run_agent_firewall.py")
    )
    monkeypatch.setenv("FRAUDSENTINEL_FIREWALL_AUDIT_KEY", (b"k" * 32).hex())
    monkeypatch.setenv(
        "FRAUDSENTINEL_FIREWALL_CREDENTIALS",
        json.dumps(
            [
                dict(
                    token=AGENT,
                    id="agent1",
                    kind="agent",
                    role="investigator",
                    owner_id="user_demo_analyst",
                    cases=[DEMO_CASE_ID],
                ),
                dict(
                    token=HUMAN,
                    id="human1",
                    kind="human",
                    role="approver",
                    owner_id="user_demo_analyst",
                    cases=[DEMO_CASE_ID],
                ),
            ]
        ),
    )
    instances = []

    def factory(*args):
        f = Firewall(*args)
        instances.append(f)
        return f

    monkeypatch.setattr(launcher, "Firewall", factory)

    def serve(app, **options):
        assert options["host"] == "127.0.0.1" and options["access_log"] is False
        with TestClient(app) as client:
            rid = submit(client).json()["request_id"]
            assert execute(client, rid).json()["transaction_count"] == 6

    monkeypatch.setattr(launcher.uvicorn, "run", serve)
    try:
        launcher.main()
        assert (tmp_path / "tmp/agent-security/synthetic.sqlite3").is_file()
        assert (tmp_path / "tmp/agent-security/security.sqlite3").is_file()
    finally:
        for f in instances:
            f.db.close()
            f.engine.dispose()
