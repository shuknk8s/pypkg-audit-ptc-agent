"""Per-package auditor subagent definition.

Creates a compiled LangGraph graph that performs CVE and changelog analysis for a
single Python package using the DockerBackend for sandbox code execution and three
LangChain @tool wrappers for NVD, PyPI, and GitHub data.
"""

from __future__ import annotations

from deepagents import SubAgent, create_deep_agent
from deepagents.backends.composite import CompositeBackend
from deepagents.backends.state import StateBackend

from src.sandbox.docker_backend import DockerBackend
from src.tools.audit_tools import github_release_notes, nvd_cve_search, pypi_package_info

PACKAGE_AUDITOR_SYSTEM_PROMPT = """
You are a dependency security auditor operating under two mandatory architectural constraints.

═══════════════════════════════════════════════════════════
PTD — Progressive Tool Discovery (MANDATORY)
═══════════════════════════════════════════════════════════
Before calling any tool for the first time in a session, you MUST read its
documentation file using read_file(). These files are pre-loaded at startup:

  read_file("/audit/docs/pypi_tool.md")    — before first pypi_package_info call
  read_file("/audit/docs/nvd_tool.md")     — before first nvd_cve_search call
  read_file("/audit/docs/github_tool.md")  — before first github_release_notes call

Do NOT call a tool without reading its doc file first. This is not optional.

═══════════════════════════════════════════════════════════
PTC — Programmatic Tool Calls (MANDATORY)
═══════════════════════════════════════════════════════════
Each tool returns a COMPACT summary. The full raw API response is already
written to a file at the path in ptc_data_path. You MUST NOT read that file
unless you specifically need detailed CVE or changelog text for delegation.

NEVER treat tool response data as working context. Work from the compact
summary fields only (counts, version strings, boolean flags, severity_counts).

PTC VIOLATION — these actions are FORBIDDEN:
  ✗ Reading ptc_data_path just to confirm what the compact summary already says
  ✗ Quoting or paraphrasing raw NVD/PyPI/GitHub data in your working messages
  ✗ Storing raw API response content in any write_file() call
  ✗ Passing raw tool response data to subagents — pass file paths instead

═══════════════════════════════════════════════════════════
Audit protocol (execute in this exact order)
═══════════════════════════════════════════════════════════
1. PTD: read_file("/audit/docs/pypi_tool.md")
2. PTC: pypi_package_info({package}) → use compact: latest_version, github_repository
3. PTD: read_file("/audit/docs/nvd_tool.md")
4. PTC: nvd_cve_search({package}, {pinned_version}) → use compact: affecting_pinned, severity_counts, needs_interpretation
5. PTD: read_file("/audit/docs/github_tool.md")
6. PTC: github_release_notes({github_repository}, {pinned_version}, {latest_version}) → use compact: breaking_hints_found, breaking_keywords
7. If needs_interpretation > 0: task("interpret CVEs at {nvd_ptc_data_path} for {package}=={pinned_version}", "cve-interpreter")
8. If breaking_hints_found: task("analyse changelog at {github_ptc_data_path} for {package} {pinned_version}→{latest_version}", "changelog-analyst")
9. Compute risk_rating from severity_counts (critical/high ≥ 2 → high; 1 → medium; 0 → low)
10. write_file("/audit/results/{package}.json", structured_findings_json)

structured_findings_json fields: package, pinned_version, latest_version,
versions_behind, cves_affecting_pinned, cves_not_relevant, total_cves_found,
changelog_analysis, breaking_changes_detected, risk_rating, upgrade_recommendation,
recommendation_rationale.
""".strip()

CVE_INTERPRETER_SYSTEM_PROMPT = """
You are a CVE security analyst operating under PTC constraints.

You receive a task message containing a FILE PATH to the NVD data, not raw CVE data.
Use read_file(path) to load only the CVEs with status "needs_interpretation".

For each ambiguous CVE, determine: affecting_pinned | not_relevant.
Base your determination on CPE version ranges, patch notes, and advisory text.

PTC rule: after reading the file, do NOT quote or repeat raw CVE text in your output.
Output ONLY a compact JSON list. No explanation, no markdown, no raw data.

Output schema:
[
  {
    "cve_id": "CVE-XXXX-XXXXX",
    "status": "affecting_pinned | not_relevant",
    "determination_method": "agent_interpretation",
    "severity": "critical|high|medium|low|unknown",
    "rationale": "one sentence"
  }
]
""".strip()

CHANGELOG_ANALYST_SYSTEM_PROMPT = """
You are a software compatibility analyst operating under PTC constraints.

You receive a task message containing a FILE PATH to the GitHub release notes data.
Use read_file(path) to load the release notes.

Identify breaking changes, deprecations, and removals across all releases in the range.

PTC rule: after reading the file, do NOT quote raw release note text in your output.
Output ONLY a compact JSON object. No explanation.

Output schema:
{
  "breaking_changes_detected": true | false,
  "changelog_analysis": "one paragraph — evidence-based summary only",
  "breaking_change_details": ["str — one item per breaking change found"],
  "recommendation_rationale": "one paragraph — upgrade risk and suggested approach"
}
""".strip()

cve_interpreter: SubAgent = {
    "name": "cve-interpreter",
    "description": "Determines whether ambiguous CVEs affect a specific pinned version",
    "system_prompt": CVE_INTERPRETER_SYSTEM_PROMPT,
    "tools": [],
    "model": "gpt-4o-mini",
    "middleware": [],
    "interrupt_on": {},
    "skills": [],
}

changelog_analyst: SubAgent = {
    "name": "changelog-analyst",
    "description": "Analyses release notes for breaking changes between two package versions",
    "system_prompt": CHANGELOG_ANALYST_SYSTEM_PROMPT,
    "tools": [],
    "model": "gpt-4o-mini",
    "middleware": [],
    "interrupt_on": {},
    "skills": [],
}


def create_package_auditor_subagent(docker_backend: DockerBackend):
    """Return a compiled LangGraph graph for per-package security auditing.

    DockerBackend provides the execute() sandbox tool. CompositeBackend routes
    /audit/ paths to an ephemeral StateBackend so result JSON never re-enters
    the LLM context window (PTC invariant).

    StateBackend requires a ToolRuntime injected at execution time, so we pass a
    backend factory callable instead of a pre-constructed backend instance.

    Args:
        docker_backend: A DockerBackend wrapping a DockerSandbox instance.

    Returns:
        A langgraph.graph.state.CompiledStateGraph ready to stream events.
    """

    def _make_backend(runtime):
        return CompositeBackend(
            default=docker_backend,
            routes={
                "/audit/": StateBackend(runtime),
            },
        )

    return create_deep_agent(
        model="gpt-4o",
        backend=_make_backend,
        tools=[nvd_cve_search, pypi_package_info, github_release_notes],
        subagents=[cve_interpreter, changelog_analyst],
        system_prompt=PACKAGE_AUDITOR_SYSTEM_PROMPT,
    )
