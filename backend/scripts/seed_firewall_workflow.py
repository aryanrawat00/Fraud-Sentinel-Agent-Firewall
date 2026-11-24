"""Create a synthetic M2–M4 investigation in a new isolated dataset, never migrate."""

from sqlalchemy import select

from app.models import Transaction
from app.repositories.intelligence import IntelligenceRepository
from app.schemas.workflow import InvestigationCreate
from app.services.detection import DetectionService
from app.services.evidence import EvidenceService
from app.services.investigations import InvestigationService
from scripts.synthetic_scenarios import create_scenarios

CASE_ID = "case_agent_workflow"


def seed_firewall_workflow(session):
    repo = IntelligenceRepository(session, "user_demo_analyst")
    create_scenarios(repo)
    result = DetectionService(repo).analyze("scenario_high")
    evidence = EvidenceService(repo).collect(result["assessment"]["assessment_id"])
    ids = list(
        session.scalars(
            select(Transaction.transaction_id).where(Transaction.transaction_id.like("scenario_%"))
        )
    )
    service = InvestigationService(repo)
    service.create(
        InvestigationCreate(
            case_id=CASE_ID,
            title="Synthetic agent investigation",
            transaction_ids=ids,
            evidence_ids=[e.evidence_id for e in evidence],
            assessment_ids=[result["assessment"]["assessment_id"]],
        )
    )
    return service.report(CASE_ID)
