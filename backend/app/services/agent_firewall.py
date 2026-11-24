"""Bounded agent tools for the isolated development API; no arbitrary execution."""

import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.models import Case, Transaction
from app.services.agent_investigations import investigation_view

Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,64}$")]


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    operation: Literal[
        "case_summary",
        "assessment_summary",
        "case_report",
        "case_transactions",
        "case_accounts",
        "case_evidence",
        "case_relationships",
    ]
    case_id: Identifier
    transaction_id: Identifier | None = None


@dataclass(frozen=True)
class Principal:
    identity: str
    kind: Literal["agent", "human"]
    role: str
    owner_id: str
    cases: frozenset[str]


class Refused(Exception):
    pass


class Firewall:
    """Server-held identities and policy; callers never supply execution callbacks."""

    def __init__(
        self, engine, ledger: Path, credentials: dict[str, Principal], key: bytes, clock=time.time
    ):
        if engine.dialect.name != "sqlite" or len(key) < 32 or not credentials:
            raise ValueError("Requires isolated SQLite data, credentials and a 32-byte audit key")
        if any(len(token) < 32 for token in credentials):
            raise ValueError("Credentials require at least 32 characters")
        if len({p.identity for p in credentials.values()}) != len(credentials):
            raise ValueError("Principal identities must be unique")
        for p in credentials.values():
            if p.kind not in {"agent", "human"} or not p.cases:
                raise ValueError("Invalid principal")
        self.engine, self.clock, self.key = engine, clock, key
        self.identities = {hashlib.sha256(t.encode()).digest(): p for t, p in credentials.items()}
        self.lock = threading.RLock()
        self.db = sqlite3.connect(ledger, check_same_thread=False, isolation_level=None, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS requests(
          id TEXT PRIMARY KEY, actor TEXT NOT NULL, owner TEXT NOT NULL, scope TEXT NOT NULL,
          action TEXT NOT NULL, digest TEXT NOT NULL, status TEXT NOT NULL, expires REAL NOT NULL,
          approver TEXT, approval_mac TEXT);
        CREATE TABLE IF NOT EXISTS events(
          seq INTEGER PRIMARY KEY, payload TEXT NOT NULL, mac TEXT NOT NULL);
        CREATE TRIGGER IF NOT EXISTS immutable_events_update BEFORE UPDATE ON events
          BEGIN SELECT RAISE(ABORT, 'immutable audit'); END;
        CREATE TRIGGER IF NOT EXISTS immutable_events_delete BEFORE DELETE ON events
          BEGIN SELECT RAISE(ABORT, 'immutable audit'); END;
        """)
        with self.lock:
            self.verify_audit()

    def mac(self, value):
        return hmac.new(self.key, value.encode(), hashlib.sha256).hexdigest()

    def verify_audit(self):
        previous = ""
        for row in self.db.execute("SELECT * FROM events ORDER BY seq"):
            expected = self.mac(previous + row["payload"])
            if not hmac.compare_digest(expected, row["mac"]):
                raise Refused("Audit integrity failure")
            previous = row["mac"]
        return previous

    def event(
        self, actor, decision, reason, request_id=None, scope=None, operation=None, approver=None
    ):
        previous = self.verify_audit()
        payload = json.dumps(
            dict(
                actor=actor,
                decision=decision,
                reason=reason,
                request_id=request_id,
                case_id=scope,
                operation=operation,
                approver=approver,
                timestamp=self.clock(),
            ),
            sort_keys=True,
        )
        self.db.execute(
            "INSERT INTO events(payload,mac) VALUES (?,?)", (payload, self.mac(previous + payload))
        )

    def rejection(self, reason, principal=None, request_id=None):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                scope = operation = safe_request = None
                if principal and request_id:
                    row = self.db.execute(
                        "SELECT * FROM requests WHERE id=?", (request_id,)
                    ).fetchone()
                    if (
                        row
                        and row["owner"] == principal.owner_id
                        and row["scope"] in principal.cases
                        and (principal.kind == "human" or row["actor"] == principal.identity)
                    ):
                        try:
                            self.request(request_id)
                        except Refused:
                            pass  # Never attribute a rejection to tampered scope fields.
                        else:
                            safe_request, scope = request_id, row["scope"]
                            operation = json.loads(row["action"])["operation"]
                self.event(
                    principal.identity if principal else "unauthenticated",
                    "DENY",
                    reason,
                    safe_request,
                    scope,
                    operation,
                )
                self.db.commit()
            except BaseException:
                self.db.rollback()
                raise

    def authenticate(self, token):
        principal = self.identities.get(hashlib.sha256(token.encode()).digest())
        if principal is None:
            self.rejection("invalid_credential")
            raise Refused("Invalid credentials")
        return principal

    def registered(self, principal):
        if principal not in self.identities.values():
            raise Refused("Unregistered identity")

    def policy(self, p, action):
        self.registered(p)
        if p.kind != "agent" or p.role not in {"reader", "investigator"}:
            return "DENY", "agent_role_required"
        if action.case_id not in p.cases:
            return "DENY", "scope_denied"
        if (action.operation == "assessment_summary") != (action.transaction_id is not None):
            return "DENY", "invalid_parameters"
        with Session(self.engine) as session:
            case = session.get(Case, action.case_id)
            if case is None or case.owner_id != p.owner_id:
                return "DENY", "resource_denied"
            if action.transaction_id:
                tx = session.get(Transaction, action.transaction_id)
                if (
                    tx is None
                    or tx.owner_id not in {None, p.owner_id}
                    or tx.case_id != action.case_id
                ):
                    return "DENY", "resource_denied"
        if action.operation == "case_report":
            return (
                ("REQUIRE_APPROVAL", "human_review_required")
                if p.role == "investigator"
                else ("DENY", "role_denied")
            )
        return "ALLOW", "scoped_read"

    def binding(self, actor, owner, scope, action, expires):
        return self.mac(json.dumps([actor, owner, scope, action, expires], separators=(",", ":")))

    def submit(self, p, action):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                decision, reason = self.policy(p, action)
                rid = secrets.token_hex(16)
                payload = action.model_dump_json()
                expires = self.clock() + 300
                digest = self.binding(p.identity, p.owner_id, action.case_id, payload, expires)
                status = {"ALLOW": "ready", "DENY": "denied", "REQUIRE_APPROVAL": "pending"}[
                    decision
                ]
                self.db.execute(
                    "INSERT INTO requests VALUES (?,?,?,?,?,?,?,?,NULL,NULL)",
                    (rid, p.identity, p.owner_id, action.case_id, payload, digest, status, expires),
                )
                self.event(p.identity, decision, reason, rid, action.case_id, action.operation)
                self.db.commit()
                return dict(request_id=rid, decision=decision, status=status, expires_at=expires)
            except BaseException:
                self.db.rollback()
                raise

    def request(self, rid):
        row = self.db.execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone()
        if row is None:
            raise Refused("Request unavailable")
        expected = self.binding(
            row["actor"], row["owner"], row["scope"], row["action"], row["expires"]
        )
        if not hmac.compare_digest(expected, row["digest"]):
            raise Refused("Request integrity failure")
        return row

    def approve(self, p, rid, approved):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.registered(p)
                row = self.request(rid)
                if (
                    p.kind != "human"
                    or p.role != "approver"
                    or row["owner"] != p.owner_id
                    or row["scope"] not in p.cases
                    or p.identity == row["actor"]
                ):
                    raise Refused("Human approval not authorized")
                if row["status"] != "pending":
                    raise Refused("Request is not pending")
                status = (
                    ("approved" if approved else "rejected")
                    if self.clock() < row["expires"]
                    else "expired"
                )
                signature = self.mac(row["digest"] + p.identity + status)
                self.db.execute(
                    "UPDATE requests SET status=?,approver=?,approval_mac=? WHERE id=?",
                    (status, p.identity, signature, rid),
                )
                self.event(
                    row["actor"],
                    status.upper(),
                    "human_decision",
                    rid,
                    row["scope"],
                    approver=p.identity,
                )
                self.db.commit()
                return dict(request_id=rid, status=status)
            except BaseException:
                self.db.rollback()
                raise

    def execute(self, p, rid):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                self.registered(p)
                row = self.request(rid)
                if row["actor"] != p.identity or row["owner"] != p.owner_id or p.kind != "agent":
                    raise Refused("Execution identity mismatch")
                if any(
                    json.loads(e["payload"]).get("request_id") == rid
                    and json.loads(e["payload"]).get("decision") == "EXECUTED"
                    for e in self.db.execute("SELECT payload FROM events")
                ):
                    raise Refused("Request already consumed")
                self.verify_audit()
                action = Action.model_validate_json(row["action"])
                decision, _ = self.policy(p, action)
                if self.clock() >= row["expires"]:
                    self.db.execute("UPDATE requests SET status='expired' WHERE id=?", (rid,))
                    self.event(p.identity, "DENY", "expired", rid, row["scope"], action.operation)
                    self.db.commit()
                    raise Refused("Request expired")
                if decision == "DENY" or row["status"] not in {"ready", "approved"}:
                    raise Refused("Execution not authorized")
                if decision == "REQUIRE_APPROVAL":
                    humans = [
                        h
                        for h in self.identities.values()
                        if h.identity == row["approver"]
                        and h.kind == "human"
                        and h.role == "approver"
                        and h.owner_id == p.owner_id
                        and row["scope"] in h.cases
                    ]
                    if (
                        row["status"] != "approved"
                        or not humans
                        or not hmac.compare_digest(
                            self.mac(row["digest"] + row["approver"] + "approved"),
                            row["approval_mac"] or "",
                        )
                    ):
                        raise Refused("Approval invalid")
                # Only bounded reads: no caller SQL, files, URLs, callbacks or code.
                result = self._read_tool(p, action)
                self.db.execute("UPDATE requests SET status='executed' WHERE id=?", (rid,))
                self.event(
                    p.identity,
                    "EXECUTED",
                    "bounded_read_completed",
                    rid,
                    row["scope"],
                    action.operation,
                    row["approver"],
                )
                self.db.commit()  # Do not release data if durable audit/consumption fails.
                return result
            except BaseException:
                self.db.rollback()
                raise

    def _read_tool(self, p, action):
        return investigation_view(self.engine, p, action)

    def human_context(self, p, case_id):
        from types import SimpleNamespace

        self.registered(p)
        if p.kind != "human" or p.role != "approver" or case_id not in p.cases:
            raise Refused("Human case access denied")
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                result = investigation_view(
                    self.engine,
                    p,
                    SimpleNamespace(
                        case_id=case_id, operation="human_context", transaction_id=None
                    ),
                )
                self.event(
                    p.identity,
                    "REVIEWED",
                    "human_case_context",
                    scope=case_id,
                    operation="human_context",
                )
                self.db.commit()
                return result
            except BaseException:
                self.db.rollback()
                raise

    def dashboard(self, p):
        self.registered(p)
        if p.kind != "human" or p.role != "approver":
            raise Refused("Human approver required")
        with self.lock:
            self.verify_audit()
            rows = self.db.execute(
                "SELECT * FROM requests WHERE owner=? ORDER BY expires DESC LIMIT 500",
                (p.owner_id,),
            ).fetchall()
            requests = []
            visible = set()
            for row in rows:
                if row["scope"] in p.cases:
                    self.request(row["id"])
                    visible.add(row["id"])
                    status = (
                        "expired"
                        if self.clock() >= row["expires"]
                        and row["status"] in {"pending", "ready", "approved"}
                        else row["status"]
                    )
                    requests.append(
                        dict(
                            request_id=row["id"],
                            agent_id=row["actor"],
                            action=json.loads(row["action"]),
                            status=status,
                            approver=row["approver"],
                        )
                    )
            events = [
                json.loads(r["payload"])
                for r in self.db.execute("SELECT payload FROM events ORDER BY seq DESC LIMIT 1000")
            ]
            return dict(
                requests=requests,
                events=[
                    e
                    for e in events
                    if e["request_id"] in visible
                    or (e["actor"] == p.identity and e["case_id"] in p.cases)
                ],
                permissions=[
                    dict(
                        agent_id=a.identity,
                        role=a.role,
                        cases=sorted(a.cases & p.cases),
                        tools=[
                            "case_summary",
                            "assessment_summary",
                            "case_transactions",
                            "case_accounts",
                            "case_evidence",
                            "case_relationships",
                        ]
                        + (["case_report: human approval"] if a.role == "investigator" else []),
                    )
                    for a in self.identities.values()
                    if a.kind == "agent" and a.owner_id == p.owner_id and a.cases & p.cases
                ],
            )
