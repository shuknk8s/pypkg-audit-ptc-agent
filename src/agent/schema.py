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
    phase2_data: dict = field(default_factory=dict)
    token_usage: dict = field(default_factory=lambda: {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})
    token_savings: dict = field(default_factory=dict)
    supplemental_calls: int = 0
    servers_used: set = field(default_factory=set)


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


