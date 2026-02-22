"""Audit pipeline: orchestrator graph + sandbox lifecycle.

Creates the top-level LangGraph orchestrator that fans out to per-package
auditor subagents via SubAgentMiddleware, with SummarizationMiddleware to
prevent context overflow across large requirement sets.
"""

from __future__ import annotations

from deepagents import SubAgent, create_deep_agent
from deepagents.backends.filesystem import FilesystemBackend
from deepagents.middleware.subagents import CompiledSubAgent, SubAgentMiddleware
from deepagents.middleware.summarization import SummarizationMiddleware

from src.agent.subagent import create_package_auditor_subagent
from src.config.loaders import load_from_file
from src.sandbox.docker_backend import DockerBackend
from src.sandbox.docker_sandbox import DockerSandbox

ORCHESTRATOR_SYSTEM_PROMPT = """
You are a multi-package dependency security audit orchestrator.
You receive a list of Python packages with their pinned versions.

Steps:
1. Use write_todos to plan the audit — one todo per package.
2. For each package, use task(f"audit {package}=={version}", "package-auditor")
   to delegate to the package auditor subagent.
3. Wait for all package audits to complete.
4. Read all results from /audit/results/ using read_file.
5. Synthesize a cross-package risk summary with upgrade priority ordering.
6. Return a JSON object with keys: package_results (list), synthesis (dict).

Maintain the PTC invariant: raw tool data stays in files, not in your context window.
""".strip()


def create_audit_pipeline(config_path: str = "config.yaml"):
    """Build the orchestrator graph and a DockerSandbox (not yet started).

    Composes:
    - DockerSandbox → DockerBackend → per-package auditor subagent graph
    - Orchestrator deep agent with SubAgentMiddleware + SummarizationMiddleware

    Note: CompiledSubAgent is used (not SubAgent) to pass the pre-built per-package
    graph as the runnable — this is the correct deepagents API for pre-compiled graphs.
    The design doc used a `_runnable` key inside SubAgent which does not exist; the
    actual API uses CompiledSubAgent(name, description, runnable).

    Args:
        config_path: Path to config.yaml (default: "config.yaml").

    Returns:
        Tuple of (orchestrator_graph, sandbox). Call sandbox.start() before invoking.
    """
    config = load_from_file(config_path)
    sandbox = DockerSandbox(image=config.docker.image)
    docker_backend = DockerBackend(sandbox)

    package_auditor_graph = create_package_auditor_subagent(docker_backend)

    package_auditor_spec: CompiledSubAgent = {
        "name": "package-auditor",
        "description": "Audits a single Python package for CVEs and changelog breaking changes",
        "runnable": package_auditor_graph,
    }

    # Orchestrator uses a local FilesystemBackend (no Docker) — it only delegates
    # via task() and reads synthesis results.
    # Note: create_deep_agent adds SubAgentMiddleware and SummarizationMiddleware
    # internally when subagents are provided; passing them explicitly causes a
    # "duplicate middleware" error. The internal SummarizationMiddleware trigger
    # defaults are adequate (fraction-of-context based).
    orchestrator_backend = FilesystemBackend(virtual_mode=True)

    orchestrator = create_deep_agent(
        model="gpt-4o",
        backend=orchestrator_backend,
        subagents=[package_auditor_spec],
        system_prompt=ORCHESTRATOR_SYSTEM_PROMPT,
    )
    return orchestrator, sandbox
