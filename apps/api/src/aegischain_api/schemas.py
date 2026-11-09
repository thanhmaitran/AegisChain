"""Pydantic request/response schemas (validation at the API boundary)."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

UUID_PATTERN = r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"


class ProjectCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")


class ProjectOut(BaseModel):
    id: str
    name: str


class PolicyEvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str = Field(pattern=UUID_PATTERN)
    policy: str = Field(min_length=1, max_length=64)


class AnalysisSummary(BaseModel):
    id: str
    decision: str
    evidence_digest: str
    components: int
    vulnerabilities: int
    reasons: list[str]
