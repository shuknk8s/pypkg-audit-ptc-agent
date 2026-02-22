"""Audit pipeline: orchestrator graph + sandbox lifecycle.

Creates the top-level LangGraph orchestrator that fans out to per-package
auditor subagents via SubAgentMiddleware, with SummarizationMiddleware to
prevent context overflow across large requirement sets.

PTD bootstrap
-------------
At startup, the three PTD doc files from src/tools/docs/ are written into the
agent's filesystem at /audit/docs/. This makes them available for the agent
to read_file() on demand before each tool's first use, satisfying the PTD
(Progressive Tool Discovery) constraint without injecting them eagerly into
the system prompt.
"""

from __future__ import annotations

from deepagents import create_deep_agent
from deepagents.backends.state import StateBackend
from deepagents.middleware.subagents import CompiledSubAgent

from src.agent.subagent import create_package_auditor_subagent
from src.config.loaders import load_from_file
from src.sandbox.docker_sandbox import DockerSandbox

ORCHESTRATOR_SYSTEM_PROMPT = """
You are a multi-package dependency security audit orchestrator.
You receive a list of Python packages with their pinned versions in your first message.

Steps:
1. Parse the package list from the user message (format: pkg==version, one per line).
2. Use write_todos to plan the audit — one todo per package.
3. For each package, call task("Audit package <pkg>==<version>. Return ONLY a compact JSON object (no markdown, no prose) with these exact keys: package, pinned_version, latest_version, versions_behind, total_cves_found, cves_affecting_pinned, cves_not_relevant, changelog_analysis, breaking_changes_detected, risk_rating (low|medium|high), upgrade_recommendation, recommendation_rationale.", "package-auditor")
   Call as many tasks in PARALLEL as possible.
4. Each task() call returns the subagent's compact JSON for that package.
   Parse each result and add to your package_results list.
5. After all tasks complete, return a final JSON message with exactly these keys:
   {
     "package_results": [ <list of per-package audit dicts from step 4> ],
     "synthesis": {
       "prioritized_packages": [ <sorted by risk descending, each item has: rank, package, risk_rating, total_cves_found, versions_behind, upgrade_recommendation> ],
       "detailed_summary": "<one paragraph cross-package summary>"
     }
   }

IMPORTANT: Your final message MUST be valid JSON only. No markdown code fences, no prose.
""".strip()


def create_audit_pipeline(config_path: str = "config.yaml"):
    """Build the orchestrator graph.

    The orchestrator uses StateBackend so all read_file/write_file calls operate
    on the LangGraph state 'files' channel. This ensures:
    - PTD docs pre-loaded in the initial input state are readable by both orchestrator
      and per-package subagents (deepagents copies parent state to child on task()).
    - Results written by subagents propagate back to the orchestrator state.

    Note: create_deep_agent adds SubAgentMiddleware and SummarizationMiddleware
    internally when subagents are provided; do not pass them explicitly.

    Args:
        config_path: Path to config.yaml (default: "config.yaml").

    Returns:
        Tuple of (orchestrator_graph, sandbox). sandbox is kept for DockerSandbox
        lifecycle management but is no longer used for agent file operations.
    """
    config = load_from_file(config_path)
    sandbox = DockerSandbox(image=config.docker.image)

    package_auditor_graph = create_package_auditor_subagent()

    package_auditor_spec: CompiledSubAgent = {
        "name": "package-auditor",
        "description": "Audits a single Python package for CVEs and changelog breaking changes. Returns compact JSON.",
        "runnable": package_auditor_graph,
    }

    orchestrator = create_deep_agent(
        model="gpt-4o",
        backend=lambda runtime: StateBackend(runtime),
        subagents=[package_auditor_spec],
        system_prompt=ORCHESTRATOR_SYSTEM_PROMPT,
    )

    return orchestrator, sandbox
