"""Case-bounded projections of real M1–M4 records for the agent firewall."""

from datetime import UTC

from sqlalchemy import and_, select
from sqlalchemy.orm import Session

from app.models import Account, CaseAccount, Evidence, RiskAssessment, Transaction
from app.models.workflow import InvestigationReport
from app.repositories.intelligence import AccessDenied, IntelligenceRepository
from app.services.detection import fingerprint
from app.services.investigations import InvestigationService
from app.services.relationships import RelationshipService


class CaseReadRepository(IntelligenceRepository):
    def __init__(self, session, owner_id, case_id):
        self.case_id = case_id
        super().__init__(session, owner_id)
        super()._case(case_id)

    def _write(self):
        raise AccessDenied("Agent investigation adapters are read-only")

    def _case(self, case_id):
        if case_id != self.case_id:
            raise AccessDenied("Case scope mismatch")
        return super()._case(case_id)

    def _scope(self):
        return and_(super()._scope(), Transaction.case_id == self.case_id)


def bounded(session, statement, limit):
    rows = list(session.scalars(statement.limit(limit + 1)))
    if len(rows) > limit:
        raise AccessDenied("Investigation exceeds bounded tool limits")
    return rows


def investigation_view(engine, principal, action):
    """Every query is re-scoped; no arbitrary financial free text leaves this adapter."""
    if action.case_id not in principal.cases:
        raise AccessDenied("Case permission revoked")
    with Session(engine) as session:
        # SQLite otherwise defers a real transaction for SELECT: pin one read snapshot.
        session.connection().exec_driver_sql("BEGIN")
        repo = CaseReadRepository(session, principal.owner_id, action.case_id)
        case = InvestigationService(repo).get(action.case_id)
        txs = bounded(session, repo._transactions().order_by(Transaction.transaction_id), 100)
        txids = {row.transaction_id for row in txs}
        if action.transaction_id and action.transaction_id not in txids:
            raise AccessDenied("Transaction outside investigation")
        assessments = bounded(
            session,
            select(RiskAssessment)
            .where(RiskAssessment.transaction_id.in_(txids))
            .order_by(RiskAssessment.assessment_id),
            500,
        )
        evidence = bounded(
            session,
            select(Evidence)
            .where(Evidence.case_id == action.case_id)
            .order_by(Evidence.evidence_id),
            100,
        )
        account_ids = {v for t in txs for v in (t.source_account_id, t.destination_account_id) if v}
        account_ids.update(
            session.scalars(
                select(CaseAccount.account_id)
                .where(
                    CaseAccount.case_id == action.case_id,
                    CaseAccount.owner_id == principal.owner_id,
                )
                .limit(101)
            )
        )
        if len(account_ids) > 100:
            raise AccessDenied("Account bound exceeded")
        accounts = bounded(
            session,
            select(Account)
            .where(Account.account_id.in_(account_ids), Account.owner_id == principal.owner_id)
            .order_by(Account.account_id),
            100,
        )
        if {a.account_id for a in accounts} != account_ids:
            raise AccessDenied("Account ownership mismatch")

        def sources(ids):
            if (
                not isinstance(ids, list)
                or any(not isinstance(i, str) for i in ids)
                or not set(ids) <= txids
            ):
                raise AccessDenied("Supporting provenance crosses investigation scope")
            return sorted(set(ids))

        assessment_view = []
        for a in assessments:
            factors = [
                dict(
                    code=f["code"],
                    contribution=f["contribution"],
                    source_transaction_ids=sources(f["source_transaction_ids"]),
                )
                for f in a.factors
            ]
            if not action.transaction_id or a.transaction_id == action.transaction_id:
                assessment_view.append(
                    dict(
                        assessment_id=a.assessment_id,
                        transaction_id=a.transaction_id,
                        risk_category=a.risk_category,
                        score=str(a.risk_score),
                        method=a.method,
                        model_version=a.model_version,
                        factors=factors,
                    )
                )
        evidence_view = []
        for e in evidence:
            if e.transaction_id not in txids or (e.account_id and e.account_id not in account_ids):
                raise AccessDenied("Evidence association outside investigation")
            if e.assessment_id and not any(
                a.assessment_id == e.assessment_id and a.transaction_id == e.transaction_id
                for a in assessments
            ):
                raise AccessDenied("Evidence assessment mismatch")
            evidence_view.append(
                dict(
                    evidence_id=e.evidence_id,
                    transaction_id=e.transaction_id,
                    assessment_id=e.assessment_id,
                    kind=e.kind,
                    verification_status=e.verification_status,
                    method=e.method,
                    source_transaction_ids=sources(
                        (e.provenance or {}).get("source_transaction_ids", [e.transaction_id])
                    ),
                )
            )
        reports = []
        for r in bounded(
            session,
            select(InvestigationReport)
            .where(InvestigationReport.case_id == action.case_id)
            .order_by(InvestigationReport.created_at.desc()),
            25,
        ):
            stored = InvestigationService(repo).get_report(action.case_id, r.report_id)
            content = stored["content"]
            if (
                fingerprint(content) != stored["fingerprint"]
                or content.get("case", {}).get("case_id") != action.case_id
            ):
                raise AccessDenied("Stored investigation report integrity mismatch")
            ids = [
                t["transaction_id"]
                for t in content.get("recorded_facts", {}).get("transactions", [])
            ]
            ids += [t["transaction_id"] for t in content.get("supporting_source_transactions", [])]
            sources(ids)
            reports.append(
                dict(
                    report_id=r.report_id,
                    case_id=r.case_id,
                    fingerprint=r.fingerprint,
                    created_at=stored["created_at"],
                    source_transaction_ids=sorted(set(ids)),
                    projection="reference_only; full narrative not released to agents",
                )
            )
        result = dict(
            case_id=action.case_id,
            status=case["status"],
            version=case["version"],
            transaction_count=len(txs),
            assessment_count=len(assessments),
            limitations=[
                "Bounded case-only projection; not a fraud conclusion.",
                "Stored free text and personal identity fields are withheld. "
                "Amounts and UTC timestamps require the approved case_report read.",
            ],
        )
        if action.operation in {"assessment_summary", "case_report", "human_context"}:
            result["assessments"] = assessment_view
        if action.operation in {"case_transactions", "case_report", "human_context"}:
            result["transactions"] = [
                dict(
                    transaction_id=t.transaction_id,
                    source_account_id=t.source_account_id,
                    destination_account_id=t.destination_account_id,
                    status=t.status,
                    **(
                        {
                            "amount": str(t.amount),
                            "currency": t.currency,
                            "occurred_at": t.occurred_at.replace(tzinfo=t.occurred_at.tzinfo or UTC)
                            .astimezone(UTC)
                            .isoformat(),
                        }
                        if action.operation == "case_report"
                        else {}
                    ),
                )
                for t in txs
            ]
        if action.operation in {"case_accounts", "case_report", "human_context"}:
            result["accounts"] = [
                dict(account_id=a.account_id, status=a.status, is_synthetic=a.is_synthetic)
                for a in accounts
            ]
        if action.operation in {"case_evidence", "case_report", "human_context"}:
            result["evidence"] = evidence_view
        if action.operation in {"case_relationships", "case_report", "human_context"}:
            result["relationships"] = RelationshipService.from_records(None, txs)
        if action.operation in {"case_report", "human_context"}:
            result.update(
                reports=reports,
                evidence_ids=[e["evidence_id"] for e in evidence_view],
                transaction_ids=sorted(txids),
            )
        return result
