"""Structured provider boundary. No credentials, tools, database or network are supplied."""

from typing import Annotated, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

Operation = Literal[
    "case_summary",
    "case_transactions",
    "case_accounts",
    "case_evidence",
    "case_relationships",
    "case_report",
]
OPERATIONS = (
    "case_summary",
    "case_transactions",
    "case_accounts",
    "case_evidence",
    "case_relationships",
    "case_report",
)


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class Step(StrictModel):
    operation: Operation


class Plan(StrictModel):
    steps: Annotated[list[Step], Field(min_length=2, max_length=6)]

    @model_validator(mode="after")
    def bounded_plan(self):
        ops = [s.operation for s in self.steps]
        if ops[0] != "case_summary" or ops[-1] != "case_report" or len(set(ops)) != len(ops):
            raise ValueError("Unique case reads must begin with context and end with report")
        return self


class Claim(StrictModel):
    claim_type: Literal["fact", "inference", "unknown"]
    source: Annotated[str, Field(min_length=1, max_length=160)]
    field: Literal[
        "transaction_id",
        "source_account_id",
        "destination_account_id",
        "amount",
        "currency",
        "occurred_at",
        "status",
        "account_id",
        "assessment_id",
        "risk_category",
        "score",
        "evidence_id",
        "verification_status",
        "case_id",
        "version",
        "transaction_count",
        "source",
        "destination",
        "completed_count",
        "risk_review",
        "evidence_review",
        "relationship_review",
        "ownership",
        "identity",
        "intent",
        "historical_context",
        "external_relationships",
    ]
    value: Annotated[str, Field(max_length=160)] | int | None


class Recommendation(StrictModel):
    action: Literal[
        "review_source_records", "seek_independent_evidence", "review_alternative_explanations"
    ]
    sources: Annotated[list[str], Field(min_length=1, max_length=8)]


class Analysis(StrictModel):
    claims: Annotated[list[Claim], Field(max_length=40)]
    recommendations: Annotated[list[Recommendation], Field(max_length=8)] = []
    evidence_sufficiency: Literal["limited", "insufficient"] = "insufficient"


class ProviderUnavailable(Exception):
    pass


class ProviderRateLimited(Exception):
    pass


class Provider(Protocol):
    """Adapters must be async, cancellation-safe and have their own transport deadlines.

    Outputs are JSON-compatible objects, never executable actions or narrative facts.
    """

    async def plan(self, context: dict) -> object: ...

    async def analyze(self, sources: dict) -> object: ...


class UnavailableProvider:
    async def plan(self, context):
        raise ProviderUnavailable

    async def analyze(self, sources):
        raise ProviderUnavailable


class DeterministicProvider:
    """Explicit deterministic development mode, NOT an operational LLM."""

    async def plan(self, context):
        return {"steps": [{"operation": op} for op in OPERATIONS]}

    async def analyze(self, sources):
        return {"claims": [], "evidence_sufficiency": "insufficient"}
