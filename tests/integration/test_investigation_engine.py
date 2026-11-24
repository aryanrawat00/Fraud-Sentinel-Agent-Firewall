"""Orchestration uses real synthetic M2-M4 services and the real security boundary."""

import asyncio
import copy
from unittest.mock import patch

import pytest
from pydantic import ValidationError
from sqlalchemy import select
from test_firewall_workflow import AGENT, CASE, HUMAN, auth
from test_firewall_workflow import integrated as integrated

from app.db.base import Base
from app.models.workflow import WorkflowBase
from app.services.agent_firewall import Principal, Refused
from app.services.investigation_engine import Conflict, InvestigationEngine, Run
from app.services.investigation_provider import (
    DeterministicProvider,
    Plan,
    ProviderRateLimited,
)
from app.services.investigation_report import apply_analysis, ground_report, report_digest
from app.services.investigation_store import StoreConflict

BASE = "/api/v1/security/runs"


def start(client, **kwargs):
    r = client.post(
        BASE, headers=auth(HUMAN), json={"case_id": CASE, "mode": "deterministic", **kwargs}
    )
    assert r.status_code == 200, r.text
    return r.json()


def advance(client, run):
    r = client.post(
        BASE + "/" + run["run_id"] + "/advance",
        headers=auth(HUMAN),
        json={"version": run["version"]},
    )
    assert r.status_code == 200, r.text
    return r.json()


def awaiting(client):
    run = start(client)
    for _ in range(7):
        run = advance(client, run)
        if run["state"] == "awaiting_approval":
            return run
        assert run["state"] in {"ready", "investigating"}, run
    pytest.fail("Bounded run did not await approval")


def completed(client):
    run = awaiting(client)
    r = client.post(
        f"/api/v1/security/requests/{run['pending_request_id']}/approval",
        headers=auth(HUMAN),
        json={"approved": True},
    )
    assert r.status_code == 200
    run = advance(client, run)
    assert run["state"] == "completed", run
    return run


def test_complete_grounded_report_and_fingerprint_bound_review(integrated):
    client, f, original = integrated

    def records():
        with f.engine.connect() as connection:
            return {
                t.name: [
                    tuple(row) for row in connection.execute(select(t).order_by(*t.primary_key))
                ]
                for metadata in (Base.metadata, WorkflowBase.metadata)
                for t in metadata.sorted_tables
            }

    before = records()
    run = completed(client)
    report = run["report"]
    assert report["provider_mode"] == "deterministic"
    assert report["model_hypotheses"] == []
    assert report["human_review_status"] == "pending"
    assert report["facts"] and report["supporting_evidence"] and report["risk_indicators"]
    assert original["report_id"] in {r["report_id"] for r in report["existing_report_references"]}
    for finding in report["facts"] + report["risk_indicators"]:
        assert set(finding["sources"]) <= report["data_sources"].keys()
    assert report_digest(report) == report["fingerprint"]
    assert len(run["steps"]) == 6 and all(s["status"] == "executed" for s in run["steps"])
    events = f.dashboard(f.authenticate(HUMAN))["events"]
    assert sum(e["decision"] == "EXECUTED" for e in events) == 6
    path = BASE + "/" + run["run_id"] + "/review"
    body = {
        "version": run["version"],
        "fingerprint": "0" * 64,
        "decision": "reviewed_no_determination",
    }
    assert client.post(path, headers=auth(HUMAN), json=body).status_code == 409
    body["fingerprint"] = report["fingerprint"]
    assert client.post(path, headers=auth(AGENT), json=body).status_code == 403
    reviewed = client.post(path, headers=auth(HUMAN), json=body).json()
    assert reviewed["report"]["human_review_status"] == "reviewed_no_determination"
    assert report_digest(reviewed["report"]) == report["fingerprint"]
    assert records() == before  # Orchestration/review never mutates investigation records.
    assert (
        client.post(
            path, headers=auth(HUMAN), json={**body, "version": reviewed["version"]}
        ).status_code
        == 409
    )
    assert (
        client.post(
            BASE + "/" + run["run_id"] + "/advance",
            headers=auth(HUMAN),
            json={"version": reviewed["version"]},
        ).status_code
        == 409
    )


@pytest.mark.parametrize(
    "steps",
    [
        [],
        [{"operation": "shell"}],
        [{"operation": "case_summary", "case_id": "foreign"}, {"operation": "case_report"}],
        [{"operation": "case_report"}, {"operation": "case_summary"}],
        [
            {"operation": "case_summary"},
            {"operation": "case_summary"},
            {"operation": "case_report"},
        ],
        [{"operation": "assessment_summary"}, {"operation": "case_report"}],
        [{"operation": "case_summary"}] * 7,
    ],
)
def test_reject_unsafe_plans(steps):
    with pytest.raises(ValidationError):
        Plan.model_validate({"steps": steps})


@pytest.mark.parametrize(
    "mutation,expected",
    [
        ("unavailable", "provider_unavailable"),
        ("rate", "provider_rate_limited"),
        ("timeout", "provider_timeout"),
        ("malformed", "invalid_structured"),
        ("oversize", "invalid_structured"),
        ("crash", "execution_failed"),
    ],
)
def test_provider_failures_are_terminal_without_fallback(integrated, mutation, expected):
    client, f, _ = integrated
    engine = client.app.state.investigations

    class Broken(DeterministicProvider):
        async def plan(self, context):
            if mutation == "rate":
                raise ProviderRateLimited
            if mutation == "timeout":
                await asyncio.sleep(1)
            if mutation == "malformed":
                return {"steps": [], "sql": "DROP TABLE cases"}
            if mutation == "oversize":
                return {"extra": "x" * 33000}
            raise RuntimeError("sensitive diagnostics withheld")

    if mutation != "unavailable":
        engine.provider = Broken()
    engine.timeout = 0.01
    run = advance(client, start(client, mode="provider"))
    assert run["state"] == "failed" and run["error"].startswith(expected)
    assert run["report"] is None and run["steps"] == []
    assert not any(
        e["decision"] == "EXECUTED" for e in f.dashboard(f.authenticate(HUMAN))["events"]
    )


def test_agent_cannot_start_run_or_choose_authority(integrated):
    client, _, _ = integrated
    assert client.post(BASE, headers=auth(AGENT), json={"case_id": CASE}).status_code == 403
    assert client.post(BASE, headers=auth(HUMAN), json={"case_id": "foreign"}).status_code == 403
    assert (
        client.post(
            BASE, headers=auth(HUMAN), json={"case_id": CASE, "agent_id": "admin"}
        ).status_code
        == 422
    )


def test_pending_cannot_execute_without_human_and_stale_version_rejected(integrated):
    client, _, _ = integrated
    run = awaiting(client)
    newer = advance(client, run)
    assert newer["state"] == "awaiting_approval" and newer["report"] is None and not newer["busy"]
    assert (
        client.post(
            BASE + "/" + run["run_id"] + "/advance",
            headers=auth(HUMAN),
            json={"version": run["version"]},
        ).status_code
        == 409
    )
    assert (
        client.post(
            f"/api/v1/security/requests/{run['pending_request_id']}/approval",
            headers=auth(AGENT),
            json={"approved": True},
        ).status_code
        == 403
    )


@pytest.mark.parametrize("failure", ["reject", "expired", "agent_revoked", "tool_error", "denied"])
def test_firewall_failures_stop_orchestration(integrated, failure):
    client, f, _ = integrated
    if failure in {"reject", "expired"}:
        run = awaiting(client)
        if failure == "reject":
            client.post(
                f"/api/v1/security/requests/{run['pending_request_id']}/approval",
                headers=auth(HUMAN),
                json={"approved": False},
            )
        else:
            f.clock = lambda: 10**12
        run = advance(client, run)
    else:
        run = advance(client, start(client))
        if failure == "agent_revoked":
            f.identities = {k: v for k, v in f.identities.items() if v.kind != "agent"}
            run = advance(client, run)
        elif failure == "tool_error":
            with patch.object(f, "_read_tool", side_effect=RuntimeError("private db error")):
                run = advance(client, run)
        else:
            with patch.object(f, "policy", return_value=("DENY", "revoked")):
                run = advance(client, run)
            assert run["steps"][-1]["decision"] == "DENY"
    assert run["state"] == "failed" and run["report"] is None


def test_cancel_and_review_cannot_skip_lifecycle(integrated):
    client, _, _ = integrated
    run = start(client)
    path = BASE + "/" + run["run_id"]
    assert (
        client.post(
            path + "/review",
            headers=auth(HUMAN),
            json={"version": 0, "fingerprint": "0" * 64, "decision": "needs_more_evidence"},
        ).status_code
        == 409
    )
    assert (
        client.post(
            path + "/review",
            headers=auth(HUMAN),
            json={"version": 0, "fingerprint": "0" * 64, "decision": "guilty"},
        ).status_code
        == 422
    )
    cancelled = client.post(path + "/cancel", headers=auth(HUMAN), json={"version": 0}).json()
    assert cancelled["state"] == "cancelled"
    assert (
        client.post(path + "/advance", headers=auth(HUMAN), json={"version": 1}).status_code == 409
    )


def test_identity_scope_revocation_and_restart(integrated):
    client, f, _ = integrated
    run = start(client)
    original = f.authenticate(HUMAN)
    other = Principal("other", "human", "approver", original.owner_id, original.cases)
    f.identities[b"test-other"] = other
    with pytest.raises(Refused):
        client.app.state.investigations.get(other, run["run_id"])
    f.identities = {k: v for k, v in f.identities.items() if v != original}
    assert client.get(BASE + "/" + run["run_id"], headers=auth(HUMAN)).status_code == 403
    with pytest.raises(StoreConflict):
        InvestigationEngine(f)  # A second live service cannot recover or steal a run.


def test_provider_cancellation_and_duplicate_execution_claim(integrated):
    client, f, _ = integrated
    human = f.authenticate(HUMAN)
    engine = client.app.state.investigations

    async def scenario():
        entered, release = asyncio.Event(), asyncio.Event()

        class Slow(DeterministicProvider):
            async def plan(self, context):
                entered.set()
                await release.wait()
                return await super().plan(context)

        engine.provider = Slow()
        run = engine.create(human, CASE, "provider")
        task = asyncio.create_task(engine.advance(human, run["run_id"], 0))
        await entered.wait()
        with pytest.raises(Conflict):
            await engine.advance(human, run["run_id"], 1)
        cancelled = engine.cancel(human, run["run_id"], 1)
        assert cancelled["state"] == "cancelled"
        release.set()
        result = await task
        assert result["state"] == "cancelled" and not result["plan"] and not result["busy"]

    asyncio.run(scenario())


def test_evidence_deduplication_and_unresolved_provenance(integrated):
    _, f, _ = integrated
    view = f.human_context(f.authenticate(HUMAN), CASE)
    view["evidence"].append(copy.deepcopy(view["evidence"][0]))
    report = ground_report(view, CASE, [], "deterministic")
    ids = [r["evidence_id"] for r in report["supporting_evidence"]]
    assert len(ids) == len(set(ids))
    view["evidence"][0]["source_transaction_ids"].append("foreign")
    with pytest.raises(ValueError):
        ground_report(view, CASE, [], "deterministic")


def test_hypotheses_must_be_supported_deduplicated_and_never_verdicts(integrated):
    _, f, _ = integrated
    report = ground_report(f.human_context(f.authenticate(HUMAN), CASE), CASE, [], "provider")
    source = next(k for k, v in report["data_sources"].items() if v["kind"] == "assessment")
    item = {"claim_type": "inference", "field": "risk_review", "source": source, "value": None}
    assert len(apply_analysis(report, {"claims": [item, item]})["model_hypotheses"]) == 1
    with pytest.raises(ValueError):
        apply_analysis(report, {"claims": [{**item, "source": "assessment:invented"}]})
    with pytest.raises(ValidationError):
        apply_analysis(report, {"claims": [{**item, "conclusion": "guilty"}]})
    with pytest.raises(ValidationError):
        apply_analysis(report, {"claims": [{**item, "kind": "guilty"}]})


@pytest.mark.parametrize("result", ["invented", "guilty", "timeout"])
def test_final_analysis_failure_never_releases_report_or_replays_tool(integrated, result):
    client, f, _ = integrated
    engine = client.app.state.investigations

    class BadAnalysis(DeterministicProvider):
        async def analyze(self, sources):
            assert sources["facts"] and sources["risk_indicators"]
            if result == "timeout":
                await asyncio.sleep(1)
            return {
                "hypotheses": [
                    {
                        "kind": "guilty" if result == "guilty" else "risk_requires_review",
                        "source": "assessment:invented",
                        "confidence": "medium",
                    }
                ]
            }

    engine.provider = BadAnalysis()
    engine.timeout = 0.01
    run = start(client, mode="provider")
    for _ in range(7):
        run = advance(client, run)
    assert run["state"] == "awaiting_approval"
    request_id = run["pending_request_id"]
    client.post(
        f"/api/v1/security/requests/{request_id}/approval",
        headers=auth(HUMAN),
        json={"approved": True},
    )
    run = advance(client, run)
    assert run["state"] == "failed" and run["report"] is None
    assert run["steps"][-1]["status"] == "executed"
    assert (
        client.post(
            f"/api/v1/security/requests/{request_id}/execute", headers=auth(AGENT)
        ).status_code
        == 403
    )


def test_run_limit_and_case_grant_rechecked(integrated):
    client, f, _ = integrated
    engine = client.app.state.investigations
    engine.max_runs = 1
    run = start(client)
    assert client.post(BASE, headers=auth(HUMAN), json={"case_id": CASE}).status_code == 409
    import hashlib

    human = f.authenticate(HUMAN)
    f.identities[hashlib.sha256(HUMAN.encode()).digest()] = Principal(
        human.identity, human.kind, human.role, human.owner_id, frozenset({"different_case"})
    )
    assert client.get(BASE + "/" + run["run_id"], headers=auth(HUMAN)).status_code == 403


@pytest.mark.parametrize(
    "source,target",
    [
        ("created", "completed"),
        ("completed", "investigating"),
        ("failed", "planning"),
        ("cancelled", "planning"),
    ],
)
def test_invalid_state_transitions(source, target):
    p = Principal("human", "human", "approver", "owner", frozenset({CASE}))
    run = Run("run", CASE, p, p, "deterministic", state=source)
    with pytest.raises(Conflict):
        run.transition(target)
