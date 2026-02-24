from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

if TYPE_CHECKING:
    from langchain_core.language_models import BaseChatModel
    from src.sandbox.docker_sandbox import DockerSandbox


@dataclass
class AuditContext:
    """Mutable context bag threaded through the step_* functions in subagent.py."""
    package: str
    pinned_version: str
    llm: "BaseChatModel"
    sandbox: "DockerSandbox"
    tool_catalog_summary: str
    messages: list = field(default_factory=list)
    script_source: str = ""
    parsed_output: dict | None = None
    last_error: str = ""
    attempt: int = 0
    audit_data: dict = field(default_factory=dict)
    token_usage: dict = field(default_factory=lambda: {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})
    token_savings: dict = field(default_factory=dict)
    supplemental_calls: int = 0
    servers_used: set = field(default_factory=set)
    # Phase B (PTD)
    phase_b_skipped: bool = False
    phase_b_tools_loaded: list = field(default_factory=list)
    phase_b_script: str = ""


class CVEEntry(BaseModel):
    model_config = ConfigDict(extra="ignore")
    cve_id: str
    severity: Literal["critical", "high", "medium", "low", "unknown"]
    summary: str
    status: Literal["affecting_pinned", "not_relevant", "needs_interpretation"]
    determination_method: Literal["cpe_range", "agent_interpretation", "heuristic", "summary_version"]


class AuditFindings(BaseModel):
    """Core audit data: CVEs, versions, changelog — output from sandbox execution."""
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


class PackageAuditResult(AuditFindings):
    """Final per-package result: findings + analysis + recommendation."""
    breaking_changes_detected: bool
    recommendation_rationale: str


def validate_findings(data: dict) -> AuditFindings:
    try:
        return AuditFindings.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"Invalid audit findings: {exc}") from exc


def validate_package_result(data: dict) -> PackageAuditResult:
    try:
        return PackageAuditResult.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"Invalid package audit result: {exc}") from exc
