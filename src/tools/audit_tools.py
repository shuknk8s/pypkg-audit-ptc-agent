"""LangChain @tool wrappers for NVD, PyPI, and GitHub audit sources.

PTC (Programmatic Tool Calls) enforcement
------------------------------------------
Every tool in this module writes the FULL raw API response to a local temp file
and returns ONLY a compact summary dict as the ToolMessage content. This ensures
raw tool response data (potentially thousands of tokens) NEVER enters the LLM
context window.

The compact summary contains:
  - ptc_data_path: absolute path where the full data was written
  - key aggregate fields only (counts, version strings, boolean flags)

To access full data, the agent uses read_file(ptc_data_path).

PTD (Progressive Tool Discovery) enforcement
---------------------------------------------
Tool docstrings are intentionally minimal — they describe purpose and PTC return
shape only. Full API documentation (response schemas, error handling, usage
patterns) lives in src/tools/docs/ and is pre-loaded into the agent filesystem
at startup as /audit/docs/{tool}_tool.md.

Agents MUST call read_file('/audit/docs/{tool}_tool.md') before using a tool
for the first time. This is enforced by the system prompt, not the framework.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path

from langchain_core.tools import tool

from src.mcp_servers.nvd import search_cves
from src.mcp_servers.pypi import get_package_metadata
from src.mcp_servers.github_api import get_release_notes as _get_release_notes

_PTC_DIR = Path(tempfile.gettempdir()) / "ptc_audit"
_PTC_DIR.mkdir(parents=True, exist_ok=True)

_BREAKING_KEYWORDS = frozenset(
    ["breaking", "deprecated", "removed", "migration", "incompatible"]
)


def _safe_slug(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", s)


def _write_ptc(filename: str, data: dict) -> Path:
    """Write full API response to a temp file and return its path."""
    path = _PTC_DIR / filename
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# NVD CVE search
# ---------------------------------------------------------------------------

@tool
def nvd_cve_search(package_name: str, version: str) -> dict:
    """Search NVD for CVEs affecting a package version.

    PTD: Read /audit/docs/nvd_tool.md before first use.
    PTC: Full response written to ptc_data_path. Only compact summary returned.

    Args:
        package_name: PyPI package name (e.g. "requests").
        version: Pinned version string (e.g. "2.28.0").

    Returns compact PTC summary — see /audit/docs/nvd_tool.md for full schema.
    """
    raw = search_cves(package_name, version)

    slug = _safe_slug(f"{package_name}_{version}")
    ptc_path = _write_ptc(f"{slug}_nvd.json", raw)

    results = raw.get("results") or []
    affecting = [r for r in results if r.get("status") == "affecting_pinned"]
    not_relevant = [r for r in results if r.get("status") == "not_relevant"]
    needs_interp = [r for r in results if r.get("status") == "needs_interpretation"]

    severity_counts: dict[str, int] = {}
    for r in affecting:
        sev = str(r.get("severity", "unknown")).lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    compact: dict = {
        "ptc_data_path": str(ptc_path),
        "package": package_name,
        "version": version,
        "total_found": len(results),
        "affecting_pinned": len(affecting),
        "not_relevant": len(not_relevant),
        "needs_interpretation": len(needs_interp),
        "severity_counts": severity_counts,
        "source": "nvd",
    }
    if raw.get("error"):
        compact["error"] = raw["error"]
    return compact


# ---------------------------------------------------------------------------
# PyPI package metadata
# ---------------------------------------------------------------------------

@tool
def pypi_package_info(package_name: str) -> dict:
    """Fetch PyPI metadata for a Python package.

    PTD: Read /audit/docs/pypi_tool.md before first use.
    PTC: Full response written to ptc_data_path. Only compact summary returned.

    Args:
        package_name: PyPI package name (e.g. "requests").

    Returns compact PTC summary — see /audit/docs/pypi_tool.md for full schema.
    """
    raw = get_package_metadata(package_name)

    slug = _safe_slug(package_name)
    ptc_path = _write_ptc(f"{slug}_pypi.json", raw)

    compact: dict = {
        "ptc_data_path": str(ptc_path),
        "name": raw.get("name", package_name),
        "latest_version": raw.get("latest_version"),
        "github_repository": raw.get("github_repository"),
        "source": "pypi",
    }
    if raw.get("error"):
        compact["error"] = raw["error"]
    return compact


# ---------------------------------------------------------------------------
# GitHub release notes
# ---------------------------------------------------------------------------

@tool
def github_release_notes(repo: str, from_version: str, to_version: str) -> dict:
    """Fetch GitHub release notes between two version tags.

    PTD: Read /audit/docs/github_tool.md before first use.
    PTC: Full response written to ptc_data_path. Only compact summary returned.

    Args:
        repo: GitHub repository as "owner/repo" (e.g. "psf/requests").
              Use "unknown/<package>" if owner is not yet known.
        from_version: Pinned version tag (e.g. "2.28.0").
        to_version: Target/latest version tag (e.g. "2.32.3").

    Returns compact PTC summary — see /audit/docs/github_tool.md for full schema.
    """
    if "/" in repo:
        owner, name = repo.split("/", 1)
    else:
        owner, name = "unknown", repo

    raw = _get_release_notes(owner, name, from_version, to_version)

    slug = _safe_slug(f"{name}_{from_version}_{to_version}")
    ptc_path = _write_ptc(f"{slug}_github.json", raw)

    notes = raw.get("notes") or []
    joined = " ".join(notes).lower()
    found_keywords = sorted(kw for kw in _BREAKING_KEYWORDS if kw in joined)

    compact: dict = {
        "ptc_data_path": str(ptc_path),
        "repository": raw.get("repository", repo),
        "from_version": from_version,
        "to_version": to_version,
        "release_count": len(notes),
        "breaking_hints_found": bool(found_keywords),
        "breaking_keywords": found_keywords,
        "source": "github_api",
    }
    if raw.get("error"):
        compact["error"] = raw["error"]
    return compact


# ---------------------------------------------------------------------------
# PTD doc paths — used by pipeline.py to pre-upload to agent filesystem
# ---------------------------------------------------------------------------

PTD_DOC_FILES: dict[str, Path] = {
    "nvd_tool.md": Path(__file__).parent / "docs" / "nvd_tool.md",
    "pypi_tool.md": Path(__file__).parent / "docs" / "pypi_tool.md",
    "github_tool.md": Path(__file__).parent / "docs" / "github_tool.md",
}
