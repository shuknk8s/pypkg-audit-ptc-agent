import operator
from typing import Annotated, Literal, TypedDict

from pydantic import BaseModel, ConfigDict, Field, ValidationError


class CVEEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve_id: str
    severity: Literal["critical", "high", "medium", "low", "unknown"]
    summary: str
    status: Literal["affecting_pinned", "not_relevant", "needs_interpretation"]
    determination_method: Literal["cpe_range", "agent_interpretation", "heuristic"]


class Phase2Result(BaseModel):
    model_config = ConfigDict(extra="forbid")
    package: str
    pinned_version: str
    latest_version: str | None
    versions_behind: int
    cves_affecting_pinned: list[CVEEntry]
    cves_not_relevant: list[CVEEntry]
    needs_interpretation: list[CVEEntry]
    total_cves_found: int
    changelog_analysis: str
    changelog_excerpts: list[str]
    upgrade_recommendation: str
    risk_rating: Literal["low", "medium", "high", "critical"]
    changelog: dict


class Phase3Result(Phase2Result):
    breaking_changes_detected: bool
    recommendation_rationale: str


def validate_phase2_result(data: dict) -> Phase2Result:
    try:
        return Phase2Result.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"Invalid phase 2 result: {exc}") from exc


def validate_phase3_result(data: dict) -> Phase3Result:
    try:
        return Phase3Result.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"Invalid phase 3 result: {exc}") from exc


class CVEFinding(BaseModel):
    """Structured CVE finding produced by the cve-interpreter subagent."""

    cve_id: str
    severity: str = "unknown"
    status: str
    determination_method: str = "cpe_range"
    description: str = ""


class AuditState(TypedDict):
    """LangGraph state schema for the top-level audit orchestrator graph."""

    packages: list[dict]
    package_results: Annotated[list, operator.add]
    synthesis: dict
    run_id: str
