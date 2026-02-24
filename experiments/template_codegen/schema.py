"""Experiment-local schema — adds summary_version determination_method."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError


class CVEEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cve_id: str
    severity: Literal["critical", "high", "medium", "low", "unknown"]
    summary: str
    status: Literal["affecting_pinned", "not_relevant", "needs_interpretation"]
    determination_method: Literal["cpe_range", "agent_interpretation", "heuristic", "summary_version"]


class PackageAuditResult(BaseModel):
    """Final per-package result: findings + analysis + recommendation."""
    model_config = ConfigDict(extra="ignore")
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
    breaking_changes_detected: bool
    recommendation_rationale: str


def validate_package_result(data: dict) -> PackageAuditResult:
    try:
        return PackageAuditResult.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"Invalid package audit result: {exc}") from exc
