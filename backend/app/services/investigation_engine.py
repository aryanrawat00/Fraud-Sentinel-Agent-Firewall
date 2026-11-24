"""Bounded single-process development orchestration. Financial reads use Firewall only."""

import asyncio
import copy
import json
import secrets
import threading
import time
from dataclasses import asdict, field, fields
from typing import Literal

from pydantic import ConfigDict, TypeAdapter, ValidationError
from pydantic.dataclasses import dataclass

from app.services.agent_firewall import Action, Principal, Refused
from app.services.investigation_claims import ClaimValidationError
from app.services.investigation_provider import (
    DeterministicProvider,
    Plan,
    Provider,
    ProviderRateLimited,
    ProviderUnavailable,
    UnavailableProvider,
)
from app.services.investigation_report import apply_analysis, digest, ground_report, report_digest
from app.services.investigation_store import InvestigationStore, StoreConflict, StoreCorrupt
from app.services.openai_provider import ProviderBinding, ProviderFailure

TRANSITIONS = {
    "created": {"planning", "paused", "cancelled"},
    "planning": {"ready", "paused", "failed", "cancelled"},
    "ready": {"investigating", "paused", "failed", "cancelled"},
    "paused": {"created", "ready", "investigating", "awaiting_approval", "failed", "cancelled"},
    "investigating": {"awaiting_approval", "paused", "completed", "failed", "cancelled"},
    "awaiting_approval": {"investigating", "paused", "failed", "cancelled"},
    "completed": set(),
    "failed": set(),
    "cancelled": set(),
}


class Conflict(StoreConflict):
    pass


@dataclass(config=ConfigDict(extra="forbid", strict=True, allow_inf_nan=False))
class Run:
    run_id: str
    case_id: str
    human: Principal
    agent: Principal
    mode: str
    state: Literal[
        "created",
        "planning",
        "ready",
        "investigating",
        "awaiting_approval",
        "paused",
        "completed",
        "failed",
        "cancelled",
    ] = "created"
    version: int = 0
    busy: bool = False
    plan: list = field(default_factory=list)
    steps: list = field(default_factory=list)
    history: list = field(default_factory=lambda: ["created"])
    pending: str | None = None
    report: dict | None = None
    error: str | None = None
    revision: int = -1
    objective: str = "Organize authorized case evidence for human review"
    created_at: float = field(default_factory=time.time)
    updated_at: float = field(default_factory=time.time)
    started_at: float | None = None
    completed_at: float | None = None
    cancellation: dict | None = None
    draft: dict | None = None
    phase: Literal["idle", "checkpoint", "planning", "submitting", "executing", "analyzing"] = (
        "idle"
    )
    resume_state: str | None = None
    interrupted: bool = False
    resumable: bool = True
    provider_identity: dict | None = None

    def encode(self):
        data = asdict(self)
        data.pop("revision")
        return json.dumps(data, default=lambda v: sorted(v), sort_keys=True, allow_nan=False)

    @classmethod
    def decode(cls, payload):
        expected = {f.name for f in fields(cls)} - {"revision"}
        # Additive metadata only: prior signed checkpoints retain their original bytes.
        if set(json.loads(payload)) not in (expected, expected - {"provider_identity"}):
            raise ValueError("Incomplete investigation checkpoint")
        run = TypeAdapter(cls).validate_json(payload, strict=True)
        if run.provider_identity is not None:
            ProviderBinding.model_validate(run.provider_identity)
        Action(operation="case_summary", case_id=run.case_id)
        if run.history[0:1] != ["created"] or any(
            b not in TRANSITIONS.get(a, set()) for a, b in zip(run.history, run.history[1:])
        ):
            raise ValueError("Invalid transition history")
        if (
            run.updated_at < run.created_at
            or run.version < 0
            or not run.history
            or run.history[-1] != run.state
        ):
            raise ValueError("Invalid lifecycle")
        if (
            run.mode not in {"provider", "deterministic"}
            or run.human.kind != "human"
            or run.agent.kind != "agent"
        ):
            raise ValueError("Invalid run identity")
        if (
            run.human.owner_id != run.agent.owner_id
            or run.case_id not in run.human.cases
            or run.case_id not in run.agent.cases
        ):
            raise ValueError("Invalid stored scope")
        if run.plan:
            Plan.model_validate({"steps": run.plan})
        elif run.steps or run.state in {"ready", "investigating", "awaiting_approval", "completed"}:
            raise ValueError("Missing plan")
        if len(run.steps) > len(run.plan):
            raise ValueError("Unexpected steps")
        for i, step in enumerate(run.steps):
            if step["operation"] != run.plan[i]["operation"] or step["status"] not in {
                "ready",
                "pending",
                "denied",
                "executed",
                "failed",
                "uncertain",
            }:
                raise ValueError("Invalid persisted step")
            if i < len(run.steps) - 1 and step["status"] != "executed":
                raise ValueError("Incomplete preceding step")
        if run.pending and (not run.steps or run.steps[-1]["request_id"] != run.pending):
            raise ValueError("Invalid approval reference")
        if run.state == "awaiting_approval" and not run.pending:
            raise ValueError("Missing approval reference")
        if run.state == "completed" and (
            not run.report
            or len(run.steps) != len(run.plan)
            or any(s["status"] != "executed" for s in run.steps)
        ):
            raise ValueError("Incomplete completed run")
        for report in (run.report, run.draft):
            if report and report["case_context"]["case_id"] != run.case_id:
                raise ValueError("Report scope mismatch")
        if run.report:
            if report_digest(run.report) != run.report["fingerprint"]:
                raise ValueError("Report content changed")
            status = run.report["human_review_status"]
            reviews = run.report["human_conclusions"]
            if status == "pending":
                if reviews:
                    raise ValueError("Invalid pending review")
            elif status in {"reviewed_no_determination", "needs_more_evidence"}:
                if (
                    len(reviews) != 1
                    or reviews[0]["reviewed_fingerprint"] != run.report["fingerprint"]
                    or reviews[0]["reviewer"] != run.human.identity
                    or reviews[0]["decision"] != status
                ):
                    raise ValueError("Review binding mismatch")
                if (
                    not isinstance(reviews[0]["notes"], str)
                    or len(reviews[0]["notes"]) > 1000
                    or not isinstance(reviews[0]["reviewed_at"], (int, float))
                ):
                    raise ValueError("Invalid review annotation")
            else:
                raise ValueError("Invalid review status")
        return run

    def transition(self, target):
        if target not in TRANSITIONS[self.state]:
            raise Conflict("Invalid investigation state transition")
        self.state = target
        self.updated_at = time.time()
        if target == "planning" and self.started_at is None:
            self.started_at = self.updated_at
        if target in {"completed", "failed", "cancelled"}:
            self.completed_at = self.updated_at
        self.history.append(target)

    def public(self):
        return copy.deepcopy(
            {
                "run_id": self.run_id,
                "case_id": self.case_id,
                "agent_id": self.agent.identity,
                "provider_mode": self.mode,
                "state": self.state,
                "version": self.version,
                "busy": self.busy,
                "plan": self.plan,
                "steps": self.steps,
                "history": self.history,
                "pending_request_id": self.pending,
                "report": self.report,
                "error": self.error,
                "objective": self.objective,
                "provider_identity": self.provider_identity,
                "created_at": self.created_at,
                "updated_at": self.updated_at,
                "started_at": self.started_at,
                "completed_at": self.completed_at,
                "cancellation": self.cancellation,
                "interrupted": self.interrupted,
                "resumable": self.resumable,
                "report_version": 1 if self.report else None,
            }
        )


class InvestigationEngine:
    def __init__(self, firewall, *, provider: Provider | None = None, timeout=5.0, max_runs=128):
        self.firewall = firewall
        self.provider = provider or UnavailableProvider()
        self.timeout = timeout
        self.max_runs = max_runs
        self.lock = threading.RLock()
        self.active_tasks = {}
        self.store = InvestigationStore(firewall, Run.decode)
        try:
            self.recover()
        except BaseException:
            self.store.close()
            raise

    def save(self, run, event, actor=None, *, create=False):
        run.updated_at = time.time()
        self.store.save(run, event, actor or run.human.identity, create=create)

    def recover(self):
        # Exclusive OS ownership proves the previous service cannot still be executing.
        for run_id in self.store.ids():
            run = self.store.load(run_id)
            if run.busy:
                run.busy = False
                if run.state not in {"completed", "failed", "cancelled", "paused"}:
                    previous = run.state
                    run.interrupted = True
                    run.resumable = run.phase not in {"submitting", "executing"}
                    run.resume_state = (
                        ("created" if previous == "planning" else previous)
                        if run.resumable
                        else None
                    )
                    run.error = (
                        "interrupted_at_safe_checkpoint"
                        if run.resumable
                        else "uncertain_execution; reconciliation_required"
                    )
                    if not run.resumable and run.steps and run.steps[-1]["status"] != "executed":
                        run.steps[-1]["status"] = "uncertain"
                    run.transition("paused")
                run.version += 1
                self.save(run, "recovered_without_execution", "system_recovery")

    def close(self):
        self.store.close()

    def list_runs(self, human, case_id):
        self.authorize(human, case_id)
        with self.lock:
            runs = [self.store.load(i) for i in self.store.ids()]
            return [
                {
                    k: v
                    for k, v in r.public().items()
                    if k not in {"report", "plan", "steps", "history"}
                }
                for r in runs
                if r.human == human and r.case_id == case_id
            ]

    def provider_binding(self):
        identity = getattr(self.provider, "identity", None)
        return identity() if identity else None

    def check_provider(self, run):
        if run.mode == "provider" and run.provider_identity != self.provider_binding():
            raise Conflict("Provider configuration changed; create a new investigation")

    def authorize(self, human, case_id):
        # The existing human case adapter checks current registration, role, grant and ownership.
        return self.firewall.human_context(human, case_id)

    def create(self, human, case_id, mode):
        if mode not in {"deterministic", "provider"}:
            raise Refused("Unknown provider mode")
        self.authorize(human, case_id)
        candidates = sorted(
            (
                p
                for p in self.firewall.identities.values()
                if p.kind == "agent"
                and p.role == "investigator"
                and p.owner_id == human.owner_id
                and case_id in p.cases
            ),
            key=lambda p: p.identity,
        )
        if not candidates:
            raise Refused("No provisioned investigation agent for this case")
        with self.lock:
            if len(self.store.ids()) >= self.max_runs:
                raise Conflict("Development run capacity reached")
            run = Run(secrets.token_hex(16), case_id, human, candidates[0], mode)
            if mode == "provider":
                run.provider_identity = self.provider_binding()
            self.save(run, "created", create=True)
            return run.public()

    def get(self, human, run_id):
        run = self.store.load(run_id)
        if not run or run.human != human:
            raise Refused("Investigation unavailable to this identity")
        self.authorize(human, run.case_id)
        return run

    @staticmethod
    def version(run, expected):
        if run.version != expected:
            raise Conflict("Stale investigation version; reload before proceeding")

    async def output(self, provider, method, payload):
        result = await asyncio.wait_for(
            getattr(provider, method)(copy.deepcopy(payload)), self.timeout
        )
        # Only structured, bounded JSON objects cross the provider boundary.
        encoded = json.dumps(result, allow_nan=False)
        if len(encoded.encode()) > 32768:
            raise ValueError("Provider response bound exceeded")
        return json.loads(encoded)

    def tool_step(self, run, human):
        """Called under the run lock; never awaits or grants approval."""
        self.firewall.registered(run.agent)
        if run.state == "ready":
            run.transition("investigating")
        if run.draft is not None:
            decision, _ = self.firewall.policy(
                run.agent, Action(operation="case_report", case_id=run.case_id)
            )
            if decision == "DENY":
                raise Refused("Report analysis permission revoked")
            return copy.deepcopy(run.draft)
        index = len([s for s in run.steps if s["status"] == "executed"])
        op = run.plan[index]["operation"]
        if run.state == "awaiting_approval":
            rows = self.firewall.dashboard(human)["requests"]
            pending = next((r for r in rows if r["request_id"] == run.pending), None)
            if not pending or pending["status"] not in {"pending", "approved"}:
                raise Refused("Approval rejected, expired or unavailable")
            if pending["status"] == "pending":
                return None
            run.transition("investigating")
            step = run.steps[-1]
        else:
            run.phase = "submitting"
            self.save(run, "tool_submission_intent")
            proposal = self.firewall.submit(run.agent, Action(operation=op, case_id=run.case_id))
            step = {"operation": op, **proposal}
            run.steps.append(step)
            run.phase = "executing"
            self.save(run, "tool_request_recorded")
            if proposal["decision"] == "DENY":
                raise Refused("Tool denied")
            if proposal["decision"] == "REQUIRE_APPROVAL":
                run.pending = proposal["request_id"]
                run.transition("awaiting_approval")
                run.phase = "idle"
                self.save(run, "approval_requested")
                return None
        run.phase = "executing"
        self.save(run, "tool_execution_intent")
        view = self.firewall.execute(run.agent, step["request_id"])
        step["status"] = "executed"
        step["result_fingerprint"] = digest(view)
        run.pending = None
        step["source_references"] = {
            "case_id": run.case_id,
            "case_version": view["version"],
            "transactions": [v["transaction_id"] for v in view.get("transactions", [])],
            "accounts": [v["account_id"] for v in view.get("accounts", [])],
            "evidence": [v["evidence_id"] for v in view.get("evidence", [])],
            "assessments": [v["assessment_id"] for v in view.get("assessments", [])],
        }
        if op == "case_report":
            run.draft = ground_report(view, run.case_id, copy.deepcopy(run.steps), run.mode)
            run.phase = "analyzing"
        else:
            run.phase = "idle"
        self.save(run, "tool_result_checkpoint")
        return copy.deepcopy(run.draft)

    async def advance(self, human, run_id, expected):
        with self.lock:
            run = self.get(human, run_id)
            self.version(run, expected)
            if run.busy or run.state in {"failed", "cancelled", "completed", "paused"}:
                raise Conflict("Investigation cannot advance")
            self.check_provider(run)
            run.busy = True
            run.version += 1
            planning = run.state == "created"
            run.phase = "planning" if planning else "checkpoint"
            if planning:
                run.transition("planning")
            self.save(run, "execution_claimed")
            self.active_tasks[run_id] = asyncio.current_task()
        provider = DeterministicProvider() if run.mode == "deterministic" else self.provider
        try:
            if planning:
                raw = await self.output(
                    provider,
                    "plan",
                    {
                        "case_id": run.case_id,
                        "objective": "Organize authorized case evidence for human review",
                    },
                )
                with self.lock:
                    run = self.get(human, run_id)
                    if run.state != "cancelled":
                        plan = Plan.model_validate(raw)
                        run.plan = [step.model_dump() for step in plan.steps]
                        run.transition("ready")
                        run.phase = "idle"
                        self.save(run, "plan_ready")
            else:
                with self.lock:
                    run = self.get(human, run_id)
                    report = None if run.state == "cancelled" else self.tool_step(run, human)
                if report is not None:
                    raw = await self.output(
                        provider,
                        "analyze",
                        {
                            k: report[k]
                            for k in (
                                "objective",
                                "case_context",
                                "existing_report_references",
                                "data_sources",
                                "facts",
                                "risk_indicators",
                                "supporting_evidence",
                                "suspicious_patterns",
                            )
                        },
                    )
                    with self.lock:
                        run = self.get(human, run_id)
                        if run.state != "cancelled":
                            report = apply_analysis(report, raw)
                            report["analysis_origin"] = run.provider_identity or {
                                "provider": "deterministic"
                                if run.mode == "deterministic"
                                else "custom_test",
                                "transport": "local",
                                "model": None,
                            }
                            report["fingerprint"] = report_digest(report)
                            run.report = report
                            run.draft = None
                            run.phase = "idle"
                            run.transition("completed")
                            self.save(run, "report_completed")
        except asyncio.CancelledError:
            with self.lock:
                run = self.store.load(run_id)
                if run.state not in {"cancelled", "completed", "failed"}:
                    run.error = "execution_interrupted; no automatic retry"
                    run.transition("failed")
                    run.phase = "idle"
                    self.save(run, "execution_interrupted")
                    raise
        except (StoreCorrupt, StoreConflict):
            raise
        except Exception as error:
            with self.lock:
                run = self.store.load(run_id)
                if run.state not in {"cancelled", "completed", "failed"}:
                    run.error = (
                        error.code
                        if isinstance(error, (ProviderFailure, ClaimValidationError))
                        else "provider_timeout"
                        if isinstance(error, TimeoutError)
                        else "provider_unavailable; no operational AI configured"
                        if isinstance(error, ProviderUnavailable)
                        else "provider_rate_limited"
                        if isinstance(error, ProviderRateLimited)
                        else "invalid_structured_response_or_provenance"
                        if isinstance(error, (ValidationError, ValueError, TypeError))
                        else "authorization_refused"
                        if isinstance(error, Refused)
                        else "execution_failed"
                    )
                    run.transition("failed")
                    if run.steps and run.steps[-1]["status"] not in {"executed", "denied"}:
                        run.steps[-1]["status"] = "failed"
                        run.steps[-1]["error"] = run.error
                    run.phase = "idle"
                    self.save(run, "execution_failed")
                    self.firewall.rejection("investigation_failed", run.agent, run.pending)
        finally:
            with self.lock:
                self.active_tasks.pop(run_id, None)
                current = self.store.load(run_id)
                if current.busy and (
                    current.state in {"completed", "failed", "cancelled"}
                    or current.phase not in {"submitting", "executing"}
                ):
                    current.busy = False
                    self.save(current, "execution_released")
        # Recheck access before releasing results, including failures and cancellation.
        with self.lock:
            return self.get(human, run_id).public()

    def cancel(self, human, run_id, expected):
        with self.lock:
            run = self.get(human, run_id)
            self.version(run, expected)
            run.transition("cancelled")
            run.cancellation = {
                "actor": human.identity,
                "timestamp": time.time(),
                "reason": "human_cancelled",
            }
            run.version += 1
            self.save(run, "cancelled")
            task = self.active_tasks.get(run_id)
            if task is not None and not task.done():
                task.get_loop().call_soon_threadsafe(task.cancel)
            return run.public()

    def pause(self, human, run_id, expected):
        with self.lock:
            run = self.get(human, run_id)
            self.version(run, expected)
            if run.busy:
                raise Conflict("Wait for the bounded step before pausing")
            run.resume_state = run.state
            run.transition("paused")
            run.resumable = True
            run.version += 1
            self.save(run, "paused")
            return run.public()

    def resume(self, human, run_id, expected):
        with self.lock:
            run = self.get(human, run_id)
            self.version(run, expected)
            if run.state != "paused" or run.busy or not run.resumable or not run.resume_state:
                raise Conflict("Investigation requires reconciliation; automatic retry refused")
            self.check_provider(run)
            self.firewall.registered(run.agent)
            decision, _ = self.firewall.policy(
                run.agent, Action(operation="case_summary", case_id=run.case_id)
            )
            if decision == "DENY":
                raise Refused("Resume permission revoked")
            if run.resume_state == "awaiting_approval":
                pending = next(
                    (
                        r
                        for r in self.firewall.dashboard(human)["requests"]
                        if r["request_id"] == run.pending
                    ),
                    None,
                )
                if not pending or pending["status"] not in {"pending", "approved"}:
                    raise Refused("Approval expired, rejected or unavailable")
            run.transition(run.resume_state)
            run.resume_state = None
            run.phase = "idle"
            run.error = None
            run.version += 1
            self.save(run, "resumed_after_authorization")
            return run.public()

    def review(self, human, run_id, expected, fingerprint, decision, notes=""):
        if not isinstance(notes, str) or len(notes) > 1000:
            raise Refused("Review notes exceed bounds")
        with self.lock:
            run = self.get(human, run_id)
            self.version(run, expected)
            if run.state != "completed" or not run.report or run.busy:
                raise Conflict("A completed report is required")
            if (
                run.report["human_review_status"] != "pending"
                or run.report["fingerprint"] != fingerprint
            ):
                raise Conflict("Report already reviewed or fingerprint changed")
            if decision not in {"reviewed_no_determination", "needs_more_evidence"}:
                raise Refused("Consequential conclusions are outside this engine's authority")
            run.report["human_review_status"] = decision
            run.report["human_conclusions"] = [
                {
                    "reviewer": human.identity,
                    "decision": decision,
                    "reviewed_fingerprint": fingerprint,
                    "reviewed_at": time.time(),
                    "notes": notes.strip(),
                    "report_version": 1,
                }
            ]
            run.version += 1
            self.save(run, "human_review_recorded")
            return run.public()
