"""Trusted server-side SQLite ledger; never exposed as an agent tool."""

import hashlib
import hmac
import json
import os
import sqlite3
import threading
from pathlib import Path

from app.services.agent_firewall import Refused


class StoreConflict(Exception):
    pass


class StoreCorrupt(Refused):
    pass


class InvestigationStore:
    """One service owner per ledger, transactional CAS and authenticated event chains.

    The process lock is released by the OS on crash. It is not a distributed lease.
    Host/key compromise and whole-ledger rollback require external audit anchoring.
    """

    def __init__(self, firewall, validate):
        with firewall.lock:
            ledger = firewall.db.execute("PRAGMA database_list").fetchone()[2]
        if not ledger:
            raise ValueError("A file-backed isolated firewall ledger is required")
        self.path = Path(ledger).with_name(Path(ledger).name + ".investigations.sqlite3")
        self.key = firewall.key
        self.validate = validate
        self.lock = threading.RLock()
        self.closed = False
        self.guard = open(str(self.path) + ".lock", "a+b")
        try:
            if os.name == "nt":
                import msvcrt

                self.guard.seek(0)
                msvcrt.locking(self.guard.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.guard.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.guard.close()
            raise StoreConflict("Investigation ledger already has a service owner") from None
        fresh = not self.path.exists()
        try:
            self.db = sqlite3.connect(
                self.path, isolation_level=None, timeout=5, check_same_thread=False
            )
            self.db.row_factory = sqlite3.Row
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            if fresh:
                self.db.executescript("""
                BEGIN IMMEDIATE;
                CREATE TABLE store_version(version INTEGER PRIMARY KEY CHECK(version=1));
                INSERT INTO store_version VALUES(1);
                CREATE TABLE runs(
                  id TEXT PRIMARY KEY, revision INTEGER NOT NULL CHECK(revision>=0),
                  payload TEXT NOT NULL, mac TEXT NOT NULL);
                CREATE TABLE lifecycle_events(
                  run_id TEXT NOT NULL REFERENCES runs(id) ON DELETE RESTRICT,
                  seq INTEGER NOT NULL CHECK(seq>=0), payload TEXT NOT NULL,
                  previous TEXT NOT NULL, mac TEXT NOT NULL,
                  PRIMARY KEY(run_id,seq));
                CREATE TRIGGER immutable_lifecycle_update BEFORE UPDATE ON lifecycle_events
                  BEGIN SELECT RAISE(ABORT,'immutable lifecycle'); END;
                CREATE TRIGGER immutable_lifecycle_delete BEFORE DELETE ON lifecycle_events
                  BEGIN SELECT RAISE(ABORT,'immutable lifecycle'); END;
                CREATE TRIGGER preserve_investigations BEFORE DELETE ON runs
                  BEGIN SELECT RAISE(ABORT,'investigation retention required'); END;
                COMMIT;
                """)
            if [r[0] for r in self.db.execute("SELECT version FROM store_version")] != [1]:
                raise StoreCorrupt("Unsupported investigation ledger version")
            if self.db.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise StoreCorrupt("Investigation ledger integrity failure")
            for run_id in self.ids():
                self.load(run_id)
        except BaseException:
            if hasattr(self, "db"):
                self.db.close()
            self.guard.close()
            raise

    def mac(self, value):
        return hmac.new(
            self.key, ("investigation-v1:" + value).encode(), hashlib.sha256
        ).hexdigest()

    def close(self):
        with self.lock:
            if not self.closed:
                self.db.close()
                self.guard.close()
                self.closed = True

    def ids(self):
        with self.lock:
            return [r[0] for r in self.db.execute("SELECT id FROM runs ORDER BY rowid DESC")]

    def _load(self, run_id):
        row = self.db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            return None
        bound = f"{run_id}:{row['revision']}:{row['payload']}"
        if not hmac.compare_digest(self.mac(bound), row["mac"]):
            raise StoreCorrupt("Investigation state integrity failure")
        previous = ""
        events = []
        for seq, e in enumerate(
            self.db.execute("SELECT * FROM lifecycle_events WHERE run_id=? ORDER BY seq", (run_id,))
        ):
            signed = f"{run_id}:{seq}:{previous}:{e['payload']}"
            if (
                e["seq"] != seq
                or e["previous"] != previous
                or not hmac.compare_digest(self.mac(signed), e["mac"])
            ):
                raise StoreCorrupt("Investigation lifecycle integrity failure")
            previous = e["mac"]
            events.append(json.loads(e["payload"]))
        if len(events) != row["revision"] + 1 or events[-1]["state_mac"] != row["mac"]:
            raise StoreCorrupt("Investigation checkpoint mismatch")
        try:
            run = self.validate(row["payload"])
        except Exception:
            raise StoreCorrupt("Invalid persisted investigation") from None
        if run.run_id != run_id:
            raise StoreCorrupt("Investigation identity mismatch")
        run.revision = row["revision"]
        return run

    def load(self, run_id):
        with self.lock:
            return self._load(run_id)

    def events(self, run_id):
        with self.lock:
            self._load(run_id)
            return [
                json.loads(r[0])
                for r in self.db.execute(
                    "SELECT payload FROM lifecycle_events WHERE run_id=? ORDER BY seq", (run_id,)
                )
            ]

    def save(self, run, event, actor, *, create=False):
        with self.lock:
            self.db.execute("BEGIN IMMEDIATE")
            try:
                current = self._load(run.run_id)
                if create:
                    if current is not None:
                        raise StoreConflict("Investigation already exists")
                elif current is None or current.revision != run.revision:
                    raise StoreConflict("Investigation checkpoint changed")
                if current:
                    immutable = (
                        "case_id",
                        "human",
                        "agent",
                        "mode",
                        "objective",
                        "created_at",
                        "provider_identity",
                    )
                    if any(getattr(current, name) != getattr(run, name) for name in immutable):
                        raise StoreConflict("Investigation identity and scope are immutable")
                    if run.history[: len(current.history)] != current.history:
                        raise StoreConflict("Lifecycle history cannot be rewritten")
                    if run.version not in {current.version, current.version + 1}:
                        raise StoreConflict("Invalid lifecycle version")
                if current and current.report:
                    if not run.report or current.report["fingerprint"] != run.report["fingerprint"]:
                        raise StoreConflict("Reports are immutable; create a new investigation")
                    if (
                        current.report["human_review_status"] != "pending"
                        and current.report != run.report
                    ):
                        raise StoreConflict("Human review is immutable")
                payload = run.encode()
                self.validate(payload)
                revision = 0 if create else run.revision + 1
                mac = self.mac(f"{run.run_id}:{revision}:{payload}")
                if create:
                    self.db.execute(
                        "INSERT INTO runs VALUES(?,?,?,?)", (run.run_id, revision, payload, mac)
                    )
                else:
                    self.db.execute(
                        "UPDATE runs SET revision=?,payload=?,mac=? WHERE id=? AND revision=?",
                        (revision, payload, mac, run.run_id, run.revision),
                    )
                prior = self.db.execute(
                    "SELECT mac FROM lifecycle_events WHERE run_id=? ORDER BY seq DESC LIMIT 1",
                    (run.run_id,),
                ).fetchone()
                previous = prior[0] if prior else ""
                entry = json.dumps(
                    {
                        "event": event,
                        "actor": actor,
                        "timestamp": run.updated_at,
                        "state": run.state,
                        "version": run.version,
                        "state_mac": mac,
                    },
                    sort_keys=True,
                )
                event_mac = self.mac(f"{run.run_id}:{revision}:{previous}:{entry}")
                self.db.execute(
                    "INSERT INTO lifecycle_events VALUES(?,?,?,?,?)",
                    (run.run_id, revision, entry, previous, event_mac),
                )
                self.db.commit()
                run.revision = revision
            except BaseException:
                self.db.rollback()
                raise
