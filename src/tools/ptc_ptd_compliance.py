"""PTC and PTD compliance validation.

This module provides runtime checks that verify the two core architectural
invariants of the audit system:

PTC (Programmatic Tool Calls)
  Tool ToolMessage content must be compact summaries only.
  The full raw API response must be at ptc_data_path, not in the message.

PTD (Progressive Tool Discovery)
  The agent must read tool doc files before calling each tool.
  Doc files must exist in the agent filesystem before the first tool call.

These checks are used in tests and can be attached as callbacks to the
LangGraph graph to emit warnings during a live run.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import structlog

log = structlog.get_logger(__name__)

# Fields that MUST be present in a valid PTC compact summary
_PTC_REQUIRED_FIELDS = {
    "nvd_cve_search": {"ptc_data_path", "package", "version", "total_found", "affecting_pinned"},
    "pypi_package_info": {"ptc_data_path", "name", "latest_version"},
    "github_release_notes": {"ptc_data_path", "repository", "from_version", "to_version", "release_count"},
}

# Maximum token budget for a valid PTC compact summary (rough chars/4 estimate)
_PTC_MAX_SUMMARY_CHARS = 600  # ~150 tokens — anything larger is a PTC violation

# PTD doc filenames that must be pre-loaded before each tool's first use
PTD_REQUIRED_DOCS = {
    "nvd_cve_search": "nvd_tool.md",
    "pypi_package_info": "pypi_tool.md",
    "github_release_notes": "github_tool.md",
}


class PTCViolation(Exception):
    """Raised when a tool response fails PTC compliance."""


class PTDViolation(Exception):
    """Raised when PTD doc was not read before tool use."""


def validate_ptc_response(tool_name: str, response: dict) -> None:
    """Assert that a tool response is a valid PTC compact summary.

    Raises PTCViolation if:
    - Required compact fields are missing
    - Response is too large to be a compact summary
    - Response contains deeply nested raw API data structures

    Args:
        tool_name: Name of the tool that produced the response.
        response: The dict returned by the @tool function.

    Raises:
        PTCViolation: if the response violates PTC constraints.
    """
    required = _PTC_REQUIRED_FIELDS.get(tool_name, set())
    missing = required - set(response.keys())
    if missing:
        raise PTCViolation(
            f"[PTC] {tool_name} response missing required compact fields: {missing}. "
            f"Got keys: {set(response.keys())}"
        )

    if "ptc_data_path" not in response:
        raise PTCViolation(
            f"[PTC] {tool_name} response has no ptc_data_path. "
            "Full data must be written to disk, not returned in ToolMessage."
        )

    serialized = json.dumps(response)
    if len(serialized) > _PTC_MAX_SUMMARY_CHARS:
        raise PTCViolation(
            f"[PTC] {tool_name} compact summary is {len(serialized)} chars "
            f"(limit {_PTC_MAX_SUMMARY_CHARS}). This is a PTC violation — "
            "raw data must be at ptc_data_path, not in the ToolMessage."
        )

    log.info(
        "ptc_compliant",
        tool=tool_name,
        summary_chars=len(serialized),
        ptc_data_path=response.get("ptc_data_path"),
    )


def validate_ptc_data_written(tool_name: str, response: dict) -> None:
    """Assert that the full PTC data file actually exists on disk.

    Args:
        tool_name: Name of the tool.
        response: The compact summary returned by the tool.

    Raises:
        PTCViolation: if ptc_data_path does not exist or is empty.
    """
    path_str = response.get("ptc_data_path")
    if not path_str:
        raise PTCViolation(f"[PTC] {tool_name}: ptc_data_path is missing from response.")

    path = Path(path_str)
    if not path.exists():
        raise PTCViolation(
            f"[PTC] {tool_name}: ptc_data_path '{path}' does not exist. "
            "Full data was not written to disk."
        )

    if path.stat().st_size == 0:
        raise PTCViolation(
            f"[PTC] {tool_name}: ptc_data_path '{path}' is empty."
        )

    log.info("ptc_data_verified", tool=tool_name, path=str(path), size=path.stat().st_size)


def check_ptd_doc_exists(tool_name: str, docs_dir: Path) -> None:
    """Assert that the PTD doc file for a tool exists in the agent filesystem.

    Args:
        tool_name: Name of the tool.
        docs_dir: Path to the /audit/docs/ directory in the agent filesystem.

    Raises:
        PTDViolation: if the required doc file is not present.
    """
    doc_filename = PTD_REQUIRED_DOCS.get(tool_name)
    if not doc_filename:
        return

    doc_path = docs_dir / doc_filename
    if not doc_path.exists():
        raise PTDViolation(
            f"[PTD] {tool_name}: doc file '{doc_filename}' not found at '{docs_dir}'. "
            "PTD doc files must be pre-loaded before tool first use. "
            "Ensure _bootstrap_ptd_docs() was called after sandbox.start()."
        )

    log.info("ptd_doc_verified", tool=tool_name, doc=str(doc_path))


def run_compliance_checks(
    tool_name: str,
    response: dict,
    *,
    docs_dir: Path | None = None,
    strict: bool = False,
) -> list[str]:
    """Run all PTC and PTD compliance checks for a tool call.

    Non-strict mode logs violations as warnings. Strict mode raises on first violation.

    Args:
        tool_name: Name of the tool that was called.
        response: The dict returned by the @tool function.
        docs_dir: Optional path to check PTD doc presence.
        strict: If True, raise on first violation instead of collecting warnings.

    Returns:
        List of violation messages (empty if fully compliant).
    """
    violations: list[str] = []

    checks = [
        lambda: validate_ptc_response(tool_name, response),
        lambda: validate_ptc_data_written(tool_name, response),
    ]
    if docs_dir is not None:
        checks.append(lambda: check_ptd_doc_exists(tool_name, docs_dir))

    for check in checks:
        try:
            check()
        except (PTCViolation, PTDViolation) as exc:
            msg = str(exc)
            violations.append(msg)
            if strict:
                raise
            log.warning("compliance_violation", message=msg)

    if not violations:
        log.info("compliance_passed", tool=tool_name)

    return violations
