"""Dedicated authenticated agent surface: intentionally mounts no demo/tool bypass routes."""

from contextlib import asynccontextmanager
from typing import Literal

from fastapi import Depends, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from app.repositories.intelligence import AccessDenied
from app.services.agent_firewall import Action, Firewall, Identifier, Refused
from app.services.investigation_engine import InvestigationEngine
from app.services.investigation_store import StoreConflict


class Approval(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    approved: bool


class StartInvestigation(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    case_id: Identifier
    mode: Literal["provider", "deterministic"] = "provider"


class RunVersion(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    version: int = Field(ge=0)


class ReportReview(RunVersion):
    fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    decision: Literal["reviewed_no_determination", "needs_more_evidence"]
    notes: str = Field(default="", max_length=1000)


def create_firewall_app(firewall: Firewall, *, provider=None) -> FastAPI:
    orchestrator = InvestigationEngine(
        firewall, provider=provider, timeout=getattr(provider, "deadline", 4) + 1
    )

    @asynccontextmanager
    async def lifespan(app):
        try:
            yield
        finally:
            orchestrator.close()

    app = FastAPI(
        title="FraudSentinel Agent Firewall",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.investigations = orchestrator

    @app.exception_handler(StoreConflict)
    async def conflict(request, error):
        return JSONResponse(status_code=409, content={"detail": str(error)})

    @app.middleware("http")
    async def limits(request: Request, call_next):
        if request.url.hostname not in {"127.0.0.1", "localhost", "testserver"}:
            return JSONResponse(status_code=403, content={"detail": "Invalid host"})
        if request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse(status_code=403, content={"detail": "Cross-site request denied"})
        chunks = []
        size = 0
        async for chunk in request.stream():
            size += len(chunk)
            if size > 4096:
                return JSONResponse(status_code=413, content={"detail": "Request too large"})
            chunks.append(chunk)
        request._body = b"".join(chunks)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response

    def principal(request: Request):
        header = request.headers.get("authorization", "")
        token = header[7:] if header.startswith("Bearer ") else ""
        p = firewall.authenticate(token)
        request.state.principal = p
        return p

    @app.exception_handler(Refused)
    async def refused(request, error):
        firewall.rejection(
            "authorization_refused",
            getattr(request.state, "principal", None),
            request.path_params.get("rid"),
        )
        return JSONResponse(status_code=403, content={"detail": str(error)})

    app.add_exception_handler(AccessDenied, refused)

    @app.exception_handler(RequestValidationError)
    async def invalid(request, error):
        firewall.rejection("invalid_request")
        return JSONResponse(status_code=422, content={"detail": "Invalid security request"})

    @app.exception_handler(Exception)
    async def unavailable(request, error):
        try:
            firewall.rejection(
                "execution_or_policy_failure", getattr(request.state, "principal", None)
            )
        except Exception:
            pass  # An unavailable audit store must never release tool results.
        return JSONResponse(
            status_code=503, content={"detail": "Security service unavailable; execution refused"}
        )

    @app.post("/api/v1/security/requests")
    def submit(action: Action, p=Depends(principal)):
        return firewall.submit(p, action)

    @app.post("/api/v1/security/requests/{rid}/execute")
    def execute(rid: str, p=Depends(principal)):
        return firewall.execute(p, rid)

    @app.post("/api/v1/security/requests/{rid}/approval")
    def approve(rid: str, body: Approval, p=Depends(principal)):
        return firewall.approve(p, rid, body.approved)

    @app.get("/api/v1/security/dashboard")
    def dashboard(p=Depends(principal)):
        return firewall.dashboard(p)

    @app.get("/api/v1/security/investigations/{case_id}")
    def context(case_id: str, p=Depends(principal)):
        return firewall.human_context(p, case_id)

    @app.get("/api/v1/security/provider")
    def provider_status(case_id: Identifier, p=Depends(principal)):
        orchestrator.authorize(p, case_id)
        status = getattr(orchestrator.provider, "status", None)
        return (
            status()
            if status
            else {
                "provider": "none",
                "configured": False,
                "model": None,
                "transport": "none",
                "last_outcome": "unavailable",
                "availability": "unavailable",
            }
        )

    @app.post("/api/v1/security/runs")
    def start_run(body: StartInvestigation, p=Depends(principal)):
        return orchestrator.create(p, body.case_id, body.mode)

    @app.get("/api/v1/security/runs")
    def list_runs(case_id: Identifier, p=Depends(principal)):
        return {"runs": orchestrator.list_runs(p, case_id)}

    @app.get("/api/v1/security/runs/{run_id}")
    def get_run(run_id: str, p=Depends(principal)):
        with orchestrator.lock:
            run = orchestrator.get(p, run_id)
            return {**run.public(), "events": orchestrator.store.events(run_id)}

    @app.post("/api/v1/security/runs/{run_id}/advance")
    async def advance_run(run_id: str, body: RunVersion, p=Depends(principal)):
        return await orchestrator.advance(p, run_id, body.version)

    @app.post("/api/v1/security/runs/{run_id}/cancel")
    def cancel_run(run_id: str, body: RunVersion, p=Depends(principal)):
        return orchestrator.cancel(p, run_id, body.version)

    @app.post("/api/v1/security/runs/{run_id}/pause")
    def pause_run(run_id: str, body: RunVersion, p=Depends(principal)):
        return orchestrator.pause(p, run_id, body.version)

    @app.post("/api/v1/security/runs/{run_id}/resume")
    def resume_run(run_id: str, body: RunVersion, p=Depends(principal)):
        return orchestrator.resume(p, run_id, body.version)

    @app.post("/api/v1/security/runs/{run_id}/review")
    def review_run(run_id: str, body: ReportReview, p=Depends(principal)):
        return orchestrator.review(
            p, run_id, body.version, body.fingerprint, body.decision, body.notes
        )

    return app
