# Agent Implementation Prompt

> Copy-paste this entire prompt to the implementing agent.

---

## Your task

You are implementing a Python dependency security auditor that uses LangChain Deep Agents
(`deepagents` library, built on LangGraph). The repository scaffold already exists at
`dep-audit-deepagent/`. Your job is to implement exactly 6 tasks in order, test each one
before proceeding to the next, and commit after each passing task.

## Non-negotiable rule: verify every API before writing code

A `Docs by LangChain` MCP server is configured in `.cursor/mcp.json`. It exposes:

```
SearchDocsByLangChain(query: str) -> str
```

**Call this tool before writing any line that uses a `deepagents`, `langgraph`, or
`langchain_core` API.** The code examples in `DEEP-AGENT-DESIGN.md` are research
snapshots — the live doc is authoritative. If the doc shows a different signature,
use the live doc and note the difference in a comment.

---

## Repository state when you start

### Files that exist and are correct — do not modify

```
src/sandbox/docker_backend.py     ← DockerBackend — implements SandboxBackendProtocol fully
src/sandbox/docker_sandbox.py     ← DockerSandbox — container lifecycle
src/mcp_servers/nvd.py            ← NVD CVE search logic
src/mcp_servers/pypi.py           ← PyPI metadata logic
src/mcp_servers/github_api.py     ← GitHub release notes logic
src/agent/schema.py               ← Phase2Result / Phase3Result Pydantic models
src/agent/synthesizer.py          ← cross-package risk synthesis (deterministic + LLM)
src/agent/planner.py              ← parse_requirements_input() — parses requirements.txt
src/agent/llm.py                  ← get_chat_model() — ChatOpenAI factory
src/config/core.py                ← CoreConfig, LLMConfig Pydantic models
src/config/loaders.py             ← load_from_file() — loads config.yaml
config.yaml                       ← runtime config (docker image, LLM model, MCP servers)
Dockerfile                        ← sandbox image
```

### Files that exist but are broken and must be rewritten

```
audit.py   ← imports src.agent.pipeline.run_multi_package_audit (does not exist yet)
            ← rich terminal UI code (_render_rich_output, tables, panels) is KEEP-WORTHY
            ← the progress_callback system must be replaced with LangGraph .astream()
```

### Files that do not exist yet — you create them

```
src/tools/audit_tools.py          ← Task 1
src/agent/subagent.py             ← Task 2
src/agent/pipeline.py             ← Task 3
audit.py (rewrite)                ← Task 4
```

---

## Tasks — implement in strict order

---

### Task 1 — `src/tools/audit_tools.py`

**Before writing:** `SearchDocsByLangChain("langchain_core tools @tool decorator BaseTool docstring schema")`

Wrap the three MCP server functions as LangChain `@tool` functions. The business logic
lives in `src/mcp_servers/` — do not duplicate it, just call it.

Each tool docstring is the agent's schema description. Write it to include:
- What arguments mean
- What the return dict contains
- What error keys may appear

```python
# src/tools/audit_tools.py
from langchain_core.tools import tool
from src.mcp_servers.nvd import search_cves          # verify function name first
from src.mcp_servers.pypi import get_package_info    # verify function name first
from src.mcp_servers.github_api import get_release_notes  # verify function name first

@tool
def nvd_cve_search(package_name: str, version: str) -> dict: ...

@tool
def pypi_package_info(package_name: str) -> dict: ...

@tool
def github_release_notes(repo: str, from_version: str, to_version: str) -> dict: ...
```

**Verify the exact function names in the mcp_servers files before using them.**

**Test before proceeding:**
```bash
python -c "
from src.tools.audit_tools import nvd_cve_search, pypi_package_info, github_release_notes
print('name:', nvd_cve_search.name)
print('args schema:', nvd_cve_search.args_schema.schema())
print('ok')
"
```
Must exit 0 with tool name and schema printed. Fix any import errors before proceeding.

---

### Task 2 — `src/agent/subagent.py`

**Before writing:**
- `SearchDocsByLangChain("deepagents create_deep_agent parameters model backend tools subagents system_prompt")`
- `SearchDocsByLangChain("deepagents SubAgent TypedDict required optional fields")`
- `SearchDocsByLangChain("deepagents CompositeBackend StateBackend routes")`

Create `create_package_auditor_subagent(docker_backend: DockerBackend)` that returns a
compiled LangGraph graph. This is the per-package agent. It receives a `DockerBackend`
instance (which already implements `SandboxBackendProtocol`) and wraps it in a
`CompositeBackend` so audit results are written to LangGraph state (not Docker filesystem).

Also define in this file:
- `cve_interpreter: SubAgent` — focused subagent, no tools, gpt-4o-mini, interprets ambiguous CVEs
- `changelog_analyst: SubAgent` — focused subagent, no tools, gpt-4o-mini, identifies breaking changes

The per-package subagent system prompt must preserve the PTC invariant:
_tool response data must be processed and written to files, not accumulated in context_.

Refer to `DEEP-AGENT-DESIGN.md` section "4. Per-package subagent definition" for the
full system prompt and structure. Verify all API signatures against live docs first.

**Test before proceeding:**
```bash
python -c "
from src.sandbox.docker_sandbox import DockerSandbox
from src.sandbox.docker_backend import DockerBackend
from src.agent.subagent import create_package_auditor_subagent
# DockerSandbox does not need to be running for graph construction
backend = DockerBackend(DockerSandbox(image='dep-audit-deepagent:latest'))
graph = create_package_auditor_subagent(backend)
print('graph type:', type(graph).__name__)
print('ok')
"
```
Must exit 0 and print a LangGraph compiled graph type (e.g. `CompiledStateGraph`).

---

### Task 3 — `src/agent/pipeline.py`

**Before writing:**
- `SearchDocsByLangChain("deepagents SubAgentMiddleware parameters subagents default_model general_purpose_agent")`
- `SearchDocsByLangChain("deepagents SummarizationMiddleware trigger keep model")`
- `SearchDocsByLangChain("deepagents create_deep_agent middleware parameter")`

Create `create_audit_pipeline(config_path: str = "config.yaml")` that returns
`(orchestrator_graph, sandbox)`.

The orchestrator:
- Uses `SubAgentMiddleware` with the package auditor as sole subagent
- Uses `SummarizationMiddleware` with `trigger=("fraction", 0.80)`
- Has `TodoListMiddleware` via `create_deep_agent` defaults (verify this is automatic)
- System prompt instructs it to: plan with `write_todos` → delegate each package via
  `task()` → read results → synthesize → return final JSON

Do NOT call `sandbox.start()` inside `create_audit_pipeline()`. That is the CLI's job.

Refer to `DEEP-AGENT-DESIGN.md` section "5. Orchestrator agent" for the full
orchestrator system prompt.

**Test before proceeding:**
```bash
python -c "
from src.agent.pipeline import create_audit_pipeline
graph, sandbox = create_audit_pipeline()
print('graph type:', type(graph).__name__)
print('ok')
"
```
Must exit 0. Docker does not need to be running — this only constructs the graph.

Then run the Makefile target:
```bash
make smoke-pipeline
```
Must print the graph type and exit 0.

---

### Task 4 — Rewrite `audit.py`

**Before writing:**
- `SearchDocsByLangChain("langgraph compiled graph astream events streaming")`
- `SearchDocsByLangChain("langchain LangChainTracer LANGCHAIN_API_KEY tracing setup")`

The existing `audit.py` has valuable code to keep:
- `_render_rich_output()` — rich tables showing per-package results, synthesis, and
  the final prioritized upgrade plan. **Keep this function almost unchanged.**
- `build_parser()` — argument parsing. Keep and extend.
- `_write_savings_markdown()` — token savings report. Keep but adapt to new data shape.

What changes:
- Replace `run_multi_package_audit(progress_callback=...)` with:
  1. `graph, sandbox = create_audit_pipeline(config)`
  2. `sandbox.start()` in a try/finally
  3. `async for event in graph.astream({"packages": package_specs, "run_id": run_id})`
  4. Update rich panels from stream events (replace the progress_callback system)
- Add structlog configuration at top of file (one-time setup)
- Add `LangChainTracer` only when `LANGCHAIN_API_KEY` is in environment
- Replace `logging.basicConfig` with structlog

The stream events from a LangGraph graph are dicts with node names as keys. Read the
live docs to understand the exact event shape before writing the streaming loop.

**Test before proceeding:**
```bash
python audit.py --help
```
Must exit 0 and print usage.

```bash
python -c "
import ast, sys
with open('audit.py') as f:
    ast.parse(f.read())
print('syntax ok')
"
```
Must exit 0.

---

### Task 5 — Update `src/agent/schema.py`

**Before writing:**
- `SearchDocsByLangChain("langgraph TypedDict state Annotated operator reducer parallel")`

Extend `schema.py` to add:
1. `CVEFinding` Pydantic model (if not already present) — used by `Phase2Result`
2. `AuditState` TypedDict — the LangGraph state that flows through the orchestrator

```python
from typing import TypedDict, Annotated
import operator

class AuditState(TypedDict):
    packages: list[dict]                            # input
    package_results: Annotated[list, operator.add]  # accumulated via reducer
    synthesis: dict
    run_id: str
```

Do not remove existing models (`Phase2Result`, `Phase3Result`) — `synthesizer.py` uses them.

**Test before proceeding:**
```bash
python -c "
from src.agent.schema import Phase2Result, Phase3Result, AuditState
# Verify AuditState is a TypedDict
import typing
hints = typing.get_type_hints(AuditState)
print('AuditState keys:', list(hints.keys()))
print('ok')
"
```
Must print the 4 expected keys.

---

### Task 6 — Update `pyproject.toml` and run full lint

Verify these dependencies are present with correct names:
- `deepagents` — verify exact PyPI package name via `SearchDocsByLangChain("deepagents pip install package name pypi")`
- `langgraph>=0.2.0`
- `langchain-core>=0.3.0`
- `langchain-openai>=1.1.10`
- `structlog>=24.0.0`
- `rich>=14.3.3`

Remove `mcp>=1.0.0` if it was only used by the old `mcp_registry.py` (which no longer exists).

**Test before proceeding:**
```bash
make lint
```
Must exit 0 with no ruff errors across `src/` and `tests/`.

---

## End-to-end test

After all 6 tasks pass their individual tests, run the full smoke test:

```bash
# 1. Build the sandbox image
make build

# 2. Run against the small test fixture (2 packages)
python audit.py requirements.txt

# 3. Run against the real test fixture (6 packages)
python audit.py requirements-real-test.txt
```

**What to verify in the output:**
- [ ] Rich terminal UI renders (planner table, per-package panels, synthesis table)
- [ ] Orchestrator agent calls `task()` for each package (visible in logs or LangSmith)
- [ ] Per-package subagent uses `nvd_cve_search`, `pypi_package_info`, `github_release_notes`
- [ ] Results include `risk_rating`, `total_cves_found`, `upgrade_recommendation`
- [ ] Final synthesis shows prioritized packages by risk
- [ ] No Python tracebacks in output
- [ ] `token-savings-report.md` is written (if savings data is available)

If `LANGCHAIN_API_KEY` is set, open the LangSmith trace URL and verify the full graph
is visible with all node transitions.

---

## Commit strategy

Commit after each task passes its test. Do not batch multiple tasks into one commit.
Use this format:

```
task-1: add @tool wrappers for NVD/PyPI/GitHub audit tools
task-2: add create_package_auditor_subagent() with DockerBackend + subagents
task-3: add create_audit_pipeline() orchestrator with SubAgentMiddleware
task-4: rewrite audit.py to use LangGraph astream instead of progress_callback
task-5: extend schema.py with CVEFinding and AuditState TypedDict
task-6: update pyproject.toml deps, lint clean
chore: end-to-end smoke test passing
```

---

## Key files to read before starting

1. `DEEP-AGENT-DESIGN.md` — full component design with code examples (verify against live docs)
2. `src/sandbox/docker_backend.py` — understand `SandboxBackendProtocol` contract (already implemented)
3. `src/agent/schema.py` — existing Pydantic models you must not break
4. `src/agent/synthesizer.py` — understand `synthesize_results()` signature (called by orchestrator)
5. `src/mcp_servers/nvd.py`, `pypi.py`, `github_api.py` — check exact function names before wrapping
