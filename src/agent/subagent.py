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
You are a dependency security auditor. For each package you receive:

1. Use pypi_package_info to get the latest version and project homepage.
2. Use nvd_cve_search to find all CVEs for this package and pinned version.
3. For each CVE, determine if it affects the pinned version using CPE ranges.
4. Use github_release_notes to fetch changelog between the pinned and latest version.
5. Write your structured findings to /audit/results/{package}.json using write_file.
6. Delegate ambiguous CVEs to the cve-interpreter subagent using task().
7. Delegate changelog analysis to the changelog-analyst subagent using task().

The PTC constraint applies: tool response data must be processed and written to files.
Do NOT accumulate raw tool responses in your context window.
""".strip()

CVE_INTERPRETER_SYSTEM_PROMPT = """
You are a CVE security analyst. You receive a list of CVEs and a pinned package version.
For each CVE, determine: affecting_pinned | not_relevant.
Base your determination on CPE version ranges, patch notes, and advisory text.
Respond ONLY with the structured JSON list. No explanation, no markdown.
""".strip()

CHANGELOG_ANALYST_SYSTEM_PROMPT = """
You are a software compatibility analyst. You receive release notes between two versions.
Identify breaking changes, deprecations, and removals.
Respond ONLY with structured JSON. No explanation.
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
