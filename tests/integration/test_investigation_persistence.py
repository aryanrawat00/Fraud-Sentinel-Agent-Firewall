"""Disposable investigation-ledger restart, crash-window and integrity tests."""

import asyncio
import hashlib
import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

import pytest
from test_firewall_workflow import AGENT, CASE, HUMAN
from test_firewall_workflow import integrated as integrated
from test_investigation_engine import awaiting, completed, start

from app.services.agent_firewall import Principal, Refused
from app.services.investigation_engine import Conflict, InvestigationEngine, Run
from app.services.investigation_provider import DeterministicProvider
from app.services.investigation_store import StoreConflict, StoreCorrupt


def restart(client, f):
    client.app.state.investigations.close()
    engine = InvestigationEngine(f)
    client.app.state.investigations = engine
    return engine


def test_completed_report_review_and_events_survive_restart(integrated):
    client, f, _ = integrated
    run = completed(client)
    human = f.authenticate(HUMAN)
    engine = client.app.state.investigations
    reviewed = engine.review(
        human,
        run["run_id"],
        run["version"],
        run["report"]["fingerprint"],
        "needs_more_evidence",
        "Check alternative explanations",
    )
    engine = restart(client, f)
    try:
        restored = engine.get(human, run["run_id"]).public()
        assert restored == reviewed
        assert (
            restored["report"]["human_conclusions"][0]["notes"] == "Check alternative explanations"
        )
        assert restored["report"]["human_conclusions"][0]["reviewed_at"] > 0
        assert engine.list_runs(human, CASE)[0]["run_id"] == run["run_id"]
        assert any(
            e["event"] == "human_review_recorded" for e in engine.store.events(run["run_id"])
        )
        with pytest.raises(Conflict):
            asyncio.run(engine.advance(human, run["run_id"], restored["version"]))
        payload = engine.store.db.execute("SELECT payload FROM runs").fetchone()[0]
        assert AGENT not in payload and HUMAN not in payload
    finally:
        engine.close()


@pytest.mark.parametrize(
    "phase,safe",
    [("planning", True), ("checkpoint", True), ("submitting", False), ("executing", False)],
)
def test_crash_windows_never_blindly_repeat_work(integrated, phase, safe):
    client, f, _ = integrated
    human = f.authenticate(HUMAN)
    engine = client.app.state.investigations
    run = start(client)
    if phase != "planning":
        asyncio.run(engine.advance(human, run["run_id"], 0))
    record = engine.get(human, run["run_id"])
    if phase == "planning":
        record.transition("planning")
    record.busy = True
    record.phase = phase
    engine.save(record, "simulated_process_crash")
    with patch.object(f, "execute", side_effect=AssertionError("No execution during recovery")):
        engine = restart(client, f)
        try:
            recovered = engine.get(human, run["run_id"])
            assert (
                recovered.state == "paused"
                and recovered.interrupted
                and recovered.resumable == safe
            )
            assert not recovered.busy
            if safe:
                result = engine.resume(human, recovered.run_id, recovered.version)
                assert result["state"] in {"created", "ready"}
            else:
                with pytest.raises(Conflict):
                    engine.resume(human, recovered.run_id, recovered.version)
        finally:
            engine.close()


def test_final_analysis_checkpoint_resumes_without_tool_replay(integrated):
    client, f, _ = integrated
    engine = client.app.state.investigations
    human = f.authenticate(HUMAN)

    class Crash(BaseException):
        pass

    class CrashAnalysis(DeterministicProvider):
        async def analyze(self, sources):
            raise Crash()

    engine.provider = CrashAnalysis()
    # Plan with real provider protocol; the final projection is durable before analysis.
    run = engine.create(human, CASE, "provider")
    for _ in range(7):
        run = asyncio.run(engine.advance(human, run["run_id"], run["version"]))
    f.approve(human, run["pending_request_id"], True)
    with pytest.raises(Crash):
        asyncio.run(engine.advance(human, run["run_id"], run["version"]))
    record = engine.get(human, run["run_id"])
    assert record.draft and record.steps[-1]["status"] == "executed"
    # Simulate a hard exit before finally released the claim.
    record.busy = True
    engine.save(record, "simulated_hard_exit")
    engine = restart(client, f)
    try:
        engine.provider = DeterministicProvider()
        record = engine.get(human, run["run_id"])
        resumed = engine.resume(human, record.run_id, record.version)
        with patch.object(f, "execute", side_effect=AssertionError("Tool must not replay")):
            done = asyncio.run(engine.advance(human, record.run_id, resumed["version"]))
        assert done["state"] == "completed" and done["report"]["facts"]
    finally:
        engine.close()


def test_approval_expiry_after_restart_is_enforced(integrated):
    client, f, _ = integrated
    run = awaiting(client)
    human = f.authenticate(HUMAN)
    f.approve(human, run["pending_request_id"], True)
    engine = restart(client, f)
    try:
        f.clock = lambda: 10**12
        result = asyncio.run(engine.advance(human, run["run_id"], run["version"]))
        assert result["state"] == "failed" and result["report"] is None
    finally:
        engine.close()


def test_approval_tampering_after_restart_fails_closed(integrated):
    client, f, _ = integrated
    run = awaiting(client)
    human = f.authenticate(HUMAN)
    f.approve(human, run["pending_request_id"], True)
    f.db.execute(
        "UPDATE requests SET approval_mac='forged' WHERE id=?", (run["pending_request_id"],)
    )
    engine = restart(client, f)
    try:
        result = asyncio.run(engine.advance(human, run["run_id"], run["version"]))
        assert result["state"] == "failed" and result["report"] is None
    finally:
        engine.close()


def test_pause_resume_cancellation_and_failed_runs_survive(integrated):
    client, f, _ = integrated
    human = f.authenticate(HUMAN)
    engine = client.app.state.investigations
    created = engine.create(human, CASE, "deterministic")
    paused = engine.pause(human, created["run_id"], 0)
    engine = restart(client, f)
    try:
        resumed = engine.resume(human, created["run_id"], paused["version"])
        cancelled = engine.cancel(human, created["run_id"], resumed["version"])
        assert cancelled["cancellation"]["actor"] == human.identity
        failed = engine.create(human, CASE, "provider")
        failed = asyncio.run(engine.advance(human, failed["run_id"], 0))
        assert failed["state"] == "failed"
        engine.close()
        engine = InvestigationEngine(f)
        assert engine.get(human, created["run_id"]).state == "cancelled"
        assert engine.get(human, failed["run_id"]).state == "failed"
        with pytest.raises(Conflict):
            engine.resume(human, failed["run_id"], failed["version"])
    finally:
        engine.close()


@pytest.mark.parametrize(
    "tamper", ["payload", "events", "signed_invalid", "fingerprint", "review_binding"]
)
def test_loaded_record_integrity_fails_closed(integrated, tamper):
    client, f, _ = integrated
    run = completed(client)
    engine = client.app.state.investigations
    db = engine.store.db
    if tamper == "payload":
        db.execute("UPDATE runs SET payload='{}'")
    elif tamper == "events":
        db.execute("DROP TRIGGER immutable_lifecycle_delete")
        db.execute("DELETE FROM lifecycle_events WHERE seq=(SELECT MAX(seq) FROM lifecycle_events)")
    else:
        record = engine.get(f.authenticate(HUMAN), run["run_id"])
        if tamper == "signed_invalid":
            record.state = "invented"
        elif tamper == "fingerprint":
            record.report["facts"] = []
        else:
            record.report["human_review_status"] = "reviewed_no_determination"
        # Even a server caller cannot save an internally inconsistent signed record.
        with pytest.raises((ValueError, StoreCorrupt)):
            engine.save(record, "invalid_write")
        return
    with pytest.raises(StoreCorrupt):
        engine.get(f.authenticate(HUMAN), run["run_id"])
    engine.close()
    with pytest.raises(StoreCorrupt):
        InvestigationEngine(f)


def test_transaction_rollback_leaves_previous_checkpoint(integrated):
    client, f, _ = integrated
    run = start(client)
    engine = client.app.state.investigations
    human = f.authenticate(HUMAN)
    before = engine.get(human, run["run_id"]).public()
    engine.store.db.execute(
        "CREATE TRIGGER fail_event BEFORE INSERT ON lifecycle_events "
        "BEGIN SELECT RAISE(ABORT,'test failure'); END"
    )
    with pytest.raises(sqlite3.IntegrityError):
        engine.pause(human, run["run_id"], 0)
    assert engine.get(human, run["run_id"]).public() == before


def test_concurrent_updates_and_stale_snapshots_are_rejected(integrated):
    client, f, _ = integrated
    run = start(client)
    engine = client.app.state.investigations
    human = f.authenticate(HUMAN)
    stale = engine.get(human, run["run_id"])

    def attempt():
        try:
            return engine.pause(human, run["run_id"], 0)["state"]
        except StoreConflict:
            return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: attempt(), range(2))) == ["conflict", "paused"]
    with pytest.raises(StoreConflict):
        engine.save(stale, "stale_write")
    with pytest.raises(StoreConflict):
        InvestigationEngine(f)


def test_scope_and_identity_revalidated_after_restart(integrated):
    client, f, _ = integrated
    run = start(client)
    human = f.authenticate(HUMAN)
    engine = restart(client, f)
    try:
        with pytest.raises(Refused):
            engine.list_runs(f.authenticate(AGENT), CASE)
        with pytest.raises(Refused):
            engine.list_runs(human, "different_case")
        changed = Principal(
            human.identity, human.kind, human.role, human.owner_id, frozenset({"different_case"})
        )
        f.identities[hashlib.sha256(HUMAN.encode()).digest()] = changed
        with pytest.raises(Refused):
            engine.get(changed, run["run_id"])
    finally:
        engine.close()


def test_schema_initialization_is_additive_and_version_checked(integrated):
    client, f, _ = integrated
    engine = client.app.state.investigations
    assert engine.store.db.execute("PRAGMA synchronous").fetchone()[0] == 2
    assert engine.store.db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert engine.store.db.execute("SELECT version FROM store_version").fetchone()[0] == 1
    assert {r[0] for r in f.db.execute("SELECT name FROM sqlite_master WHERE type='table'")} == {
        "requests",
        "events",
    }
    path = engine.store.path
    engine.close()
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM store_version")
    with pytest.raises(StoreCorrupt):
        InvestigationEngine(f)


def test_crash_after_firewall_commit_before_checkpoint_never_replays(integrated):
    client, f, _ = integrated
    human = f.authenticate(HUMAN)
    engine = client.app.state.investigations
    run = engine.create(human, CASE, "deterministic")
    run = asyncio.run(engine.advance(human, run["run_id"], 0))

    class ProcessCrash(BaseException):
        pass

    real_save = engine.save

    def crash_on_result(record, event, *args, **kwargs):
        if event == "tool_result_checkpoint":
            raise ProcessCrash
        return real_save(record, event, *args, **kwargs)

    with patch.object(engine, "save", side_effect=crash_on_result):
        with pytest.raises(ProcessCrash):
            asyncio.run(engine.advance(human, run["run_id"], run["version"]))
    events = f.dashboard(human)["events"]
    assert sum(e["decision"] == "EXECUTED" for e in events) == 1
    engine = restart(client, f)
    try:
        record = engine.get(human, run["run_id"])
        assert record.state == "paused" and not record.resumable
        assert record.steps[-1]["status"] == "uncertain"
        with patch.object(f, "execute", side_effect=AssertionError("Unsafe replay")):
            with pytest.raises(Conflict):
                engine.resume(human, record.run_id, record.version)
    finally:
        engine.close()


def test_revoked_agent_cannot_resume_and_wrong_key_cannot_load(integrated):
    client, f, _ = integrated
    human = f.authenticate(HUMAN)
    engine = client.app.state.investigations
    run = engine.create(human, CASE, "deterministic")
    paused = engine.pause(human, run["run_id"], 0)
    engine = restart(client, f)
    try:
        f.identities = {k: v for k, v in f.identities.items() if v.kind != "agent"}
        with pytest.raises(Refused):
            engine.resume(human, run["run_id"], paused["version"])
    finally:
        engine.close()
    original = f.key
    f.key = b"other-development-key" * 2
    try:
        with pytest.raises(StoreCorrupt):
            InvestigationEngine(f)
    finally:
        f.key = original


@pytest.mark.parametrize("change", ["scope", "history", "version"])
def test_saved_identity_history_and_versions_cannot_be_rewritten(integrated, change):
    client, f, _ = integrated
    engine = client.app.state.investigations
    human = f.authenticate(HUMAN)
    run = engine.create(human, CASE, "deterministic")
    asyncio.run(engine.advance(human, run["run_id"], 0))
    record = engine.get(human, run["run_id"])
    before = record.public()
    if change == "scope":
        record.case_id = "different_case"
    elif change == "history":
        record.history = ["created"]
    else:
        record.version += 10
    with pytest.raises(StoreConflict):
        engine.save(record, "invalid_rewrite")
    assert engine.get(human, run["run_id"]).public() == before


def test_incomplete_checkpoint_does_not_invent_default_metadata(integrated):
    client, f, _ = integrated
    run = start(client)
    engine = client.app.state.investigations
    record = json.loads(engine.get(f.authenticate(HUMAN), run["run_id"]).encode())
    del record["created_at"]
    with pytest.raises(ValueError, match="Incomplete investigation checkpoint"):
        Run.decode(json.dumps(record))
