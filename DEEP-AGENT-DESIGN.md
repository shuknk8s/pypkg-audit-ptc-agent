# Deep Agent Architecture Design
## Replacing the Manual Orchestration Mess with LangChain Deep Agents

**Date:** 2026-02-21  
**Source:** Research via Context7 `/langchain-ai/deepagents` (315 snippets, High reputation)  
**Context:** Architectural redesign of `ptc-v4-dep-gap-agentic` to use the Deep Agents framework correctly

---

## Agent Implementation Instructions

> **This section is for the implementing agent. Read it before touching any code.**

### Mandatory: Use the LangChain Docs MCP server for every API call

A `Docs by LangChain` MCP server is configured at project level in `.cursor/mcp.json`. It exposes a single tool:

```
SearchDocsByLangChain(query: str) -> str
```

**You MUST call `SearchDocsByLangChain` before writing any line of code that uses a Deep Agents or LangChain API.** The code examples in this document were derived from research snapshots and may have stale signatures. The MCP server returns live, authoritative documentation.

Mandatory lookups before implementing each task:

| Task | Required doc query before coding |
|---|---|
| Task 1 — `@tool` wrappers | `"langchain_core tools @tool decorator function signature"` |
| Task 2 — `with_structured_output` | `"ChatOpenAI with_structured_output Pydantic BaseModel"` |
| Task 3 — `create_deep_agent` | `"deepagents create_deep_agent parameters backend tools subagents"` |
| Task 4 — `SubAgent` TypedDict | `"deepagents SubAgent TypedDict required fields model middleware"` |
| Task 5 — `SubAgentMiddleware` | `"deepagents SubAgentMiddleware parameters default_model subagents"` |
| Task 6 — `SummarizationMiddleware` | `"deepagents SummarizationMiddleware trigger keep parameters"` |
| Task 7 — `CompositeBackend` | `"deepagents CompositeBackend routes StateBackend FilesystemBackend"` |
| Task 8 — `AuditState` TypedDict | `"langgraph TypedDict state Annotated operator.add reducer"` |
| Task 9 — LangSmith tracing | `"langchain LangChainTracer LangSmith project tracing setup"` |

If a doc lookup returns a different signature than what this document shows, **the live doc is authoritative**. Update the implementation accordingly and note the discrepancy in a code comment.

---

### Pre-flight checklist

Before starting Task 1, verify the following. Do not proceed until all pass:

- [ ] `.env` is in `.gitignore` — if not, add it now before any commit
- [ ] `deepagents` is in `pyproject.toml` dependencies
- [ ] `langchain-core`, `langchain-openai`, `langgraph` are in `pyproject.toml` dependencies
- [ ] Run `pip show deepagents` inside the project venv — confirm version installed
- [ ] Run `SearchDocsByLangChain("deepagents version changelog")` — confirm you are coding against the installed version

---

### Atomic task list

Execute in order. Each task has a definition of done. Do not start the next task until the current one passes its check.

---

#### Task 1 — Delete dead code

**Files to delete entirely:**
- `src/core/tool_generator.py`
- `src/core/mcp_registry.py`
- `src/core/parity.py`
- `src/mcp_servers/search.py`

**Lines to delete from files that survive:**
- `src/agent/subagent.py` — delete `_extract_code_block()`, `_parse_json_from_text()`, `_run_subagent_inner()`, `_check_ptd_compliance()`, `MAX_CODEGEN_RETRIES`, `MAX_SUPPLEMENTAL_CALLS`, `SUBAGENT_TIMEOUT_SECONDS`, `_PTD_SERVERS`
- `src/agent/executor.py` — delete `_parse_json_stdout()`, `_container_server_configs()`, `_mcp_server_uploads()`
- `src/agent/pipeline.py` — delete entire file body (will be rewritten in Task 5)
- `src/agent/prompts.py` — delete `build_codegen_prompt()`, `build_iteration_prompt()` (codegen prompts). Keep `build_system_prompt()` only as a reference, it will be superseded.

**Definition of done:** `rg "asyncio.gather\|tool_generator\|MCPRegistry\|_run_subagent_inner\|_parse_json_stdout\|_extract_code_block" src/` returns zero matches.

---

#### Task 2 — Create `src/tools/audit_tools.py`

**Before writing:** call `SearchDocsByLangChain("langchain_core tools @tool decorator BaseTool")`.

Wrap the three surviving MCP server functions as `@tool` functions. The server logic in `nvd.py`, `pypi.py`, `github_api.py` is preserved — only the call interface changes.

Each tool docstring is its schema description for the agent. Write it precisely: what the tool accepts, what it returns, what errors it may produce.

**Definition of done:** `python -c "from src.tools.audit_tools import nvd_cve_search, pypi_package_info, github_release_notes; print('ok')"` exits 0.

---

#### Task 3 — Extend `src/agent/schema.py`

**Before writing:** call `SearchDocsByLangChain("langgraph TypedDict state Annotated operator reducer")`.

Add `CVEFinding` (if not present), extend `Phase2Result` to use it, add `AuditState` TypedDict. Do not remove existing `Phase3Result` — it is still used in `synthesizer.py`.

**Definition of done:** `python -c "from src.agent.schema import Phase2Result, AuditState, CVEFinding; print('ok')"` exits 0.

---

#### Task 4 — Rewrite `src/agent/subagent.py` as `create_package_auditor_subagent()`

**Before writing:** call `SearchDocsByLangChain("deepagents create_deep_agent backend tools subagents system_prompt")` and `SearchDocsByLangChain("deepagents CompositeBackend StateBackend routes")`.

This function takes a `DockerBackend` instance and returns a compiled LangGraph graph. `DockerBackend` requires zero changes. Define the `cve_interpreter` and `changelog_analyst` `SubAgent` TypedDicts in this file.

Verify the `SubAgent` TypedDict required fields against the live doc before writing the dicts.

**Definition of done:** `python -c "from src.sandbox.docker_sandbox import DockerSandbox; from src.sandbox.docker_backend import DockerBackend; from src.agent.subagent import create_package_auditor_subagent; print(type(create_package_auditor_subagent(DockerBackend(DockerSandbox(image='test')))).__name__)"` — should print `CompiledStateGraph` or equivalent LangGraph compiled graph type.

---

#### Task 5 — Rewrite `src/agent/pipeline.py` as `create_audit_pipeline()`

**Before writing:** call `SearchDocsByLangChain("deepagents SubAgentMiddleware parameters subagents general_purpose_agent")` and `SearchDocsByLangChain("deepagents SummarizationMiddleware trigger keep")`.

`create_audit_pipeline()` must return `(orchestrator_graph, sandbox)`. The orchestrator uses `SubAgentMiddleware` with the package auditor as the sole subagent. Add `SummarizationMiddleware` with `trigger=("fraction", 0.80)`.

Do not call `sandbox.start()` inside this function — that is the CLI's responsibility.

**Definition of done:** `python -c "from src.agent.pipeline import create_audit_pipeline; g, _ = create_audit_pipeline(); print('ok')"` exits 0 (sandbox does not need to be running for graph construction).

---

#### Task 6 — Update `audit.py` entrypoint

**Before writing:** call `SearchDocsByLangChain("langchain LangChainTracer LANGCHAIN_TRACING_V2 project_name")`.

Remove the `run_multi_package_audit()` call. Call `create_audit_pipeline()` instead. Configure structlog once at the top of `audit.py`. Set up `LangChainTracer` only when `LANGCHAIN_API_KEY` is present in environment (do not crash when it is absent).

The `ProgressCallback` pattern is deleted — streaming comes from the LangGraph graph directly via `.astream()`.

**Definition of done:** `python audit.py --help` exits 0. `python audit.py requirements.txt --dry-run` (if that flag exists) constructs the graph and exits without starting Docker.

---

#### Task 7 — Update `pyproject.toml`

Add or update dependencies:
- `deepagents` (verify exact package name via `SearchDocsByLangChain("deepagents install pip package name")`)
- `langchain-core`
- `langchain-openai`  
- `langgraph`
- `structlog`

Remove dependencies that are no longer imported: any MCP client library used by the old `mcp_registry.py`.

**Definition of done:** `pip install -e .` completes without errors. `rg "import" src/ | grep -v "^Binary"` — no import resolves to a missing package.

---

#### Task 8 — Fix `.gitignore`

Add to `.gitignore` if not present:
```
.env
*.env
.env.*
!.env.example
```

Create `.env.example`:
```
OPENAI_API_KEY=sk-...
GITHUB_TOKEN=ghp_...
LANGCHAIN_API_KEY=ls__...   # optional, enables LangSmith tracing
LANGCHAIN_TRACING_V2=true   # optional
```

**Definition of done:** `git status` does not show `.env` as a tracked or untracked file that would be committed.

---

#### Final verification

Run the smoke test against a single package:

```bash
make smoke
# or
python audit.py requirements.txt
```

Check:
1. LangGraph graph is constructed without error
2. Docker sandbox starts
3. Orchestrator agent calls `task()` to delegate to package auditor
4. Package auditor agent calls the `@tool` functions (nvd, pypi, github)
5. Results are written to `/audit/results/`
6. Final synthesis is returned

If LangSmith is configured, open the trace URL printed in logs and verify the full graph is visible.

---

## What the Current Code Actually Is

Before designing the replacement, be precise about what the current code does wrong.

### The fan-out is a lie

```python
# pipeline.py:120-121
tasks = [_run_one(spec) for spec in package_specs]
package_results = list(await asyncio.gather(*tasks))
```

This is `asyncio.gather()`. It is not a multi-agent system. It is not a graph. It has no state schema, no edges, no checkpoints, no observability. If one package fails halfway through, the entire run is gone. There is no way to resume, replay, or inspect what happened. This is a Python function call wearing a multi-agent costume.

### The subagent is a manually-written ReAct loop

`_run_subagent_inner()` in `subagent.py` is 244 lines of hand-rolled logic that reimplements what Deep Agents' native ReAct loop does automatically:

| Manual code in `subagent.py` | What Deep Agents does instead |
|---|---|
| Step 1: `llm.ainvoke(messages)` → extract code block (lines 256–267) | Agent natively decides to write and call `execute(command)` |
| Steps 2–3: write script → `aexecute()` → parse JSON (lines 269–306) | `DockerBackend.execute()` is the agent's tool — no script write/execute loop |
| Retry loop with `MAX_CODEGEN_RETRIES = 2` (line 26, hardcoded) | Agent replans via `TodoListMiddleware` when execution fails |
| Step 5: second `llm.ainvoke()` for CVE interpretation (lines 372–425) | A dedicated `"cve-interpreter"` subagent with its own clean context |
| Step 6: third `llm.ainvoke()` for changelog analysis (lines 427–462) | A dedicated `"changelog-analyst"` subagent with its own clean context |
| Message list grows with every retry — no context management | `SummarizationMiddleware` triggers at 85% context fill automatically |
| Results returned as Python return values | Written to `FilesystemBackend` — never enters LLM context again |
| `_parse_json_stdout` + `_parse_json_from_text` fragile regex parsing | `llm.with_structured_output(Phase2Result)` — Pydantic validated, no regex |

### `DockerBackend` already implements the right contract — and nothing uses it

```python
# docker_backend.py:8-15  — correct import, wrong usage
from deepagents.backends.protocol import (
    EditResult, ExecuteResponse, FileDownloadResponse,
    FileUploadResponse, SandboxBackendProtocol, WriteResult,
)

class DockerBackend(SandboxBackendProtocol):  # correct contract
    ...
```

`DockerBackend` correctly implements `SandboxBackendProtocol` in full. Every method is there: `execute`, `read`, `write`, `edit`, `glob_info`, `grep_raw`, `upload_files`, `download_files`. 

`create_deep_agent(backend=DockerBackend(sandbox))` is a **one-line change** that would give every per-package subagent the `execute()` tool natively, replace the manual codegen loop, and unlock the entire framework. It is not being used.

---

## The Correct Architecture

### Concept

```
audit.py (CLI)
└── OrchestratorAgent          ← create_deep_agent() with SubAgentMiddleware
    │   TodoListMiddleware      ← plans the audit steps before acting
    │   FilesystemMiddleware    ← writes intermediate state to /audit/{run_id}/
    │   SummarizationMiddleware ← prevents context overflow across many packages
    │
    ├── task("audit requests==2.31.0", "package-auditor")
    ├── task("audit flask==2.0.1",     "package-auditor")
    └── task("audit numpy==1.24.0",    "package-auditor")
         │
         └── PackageAuditorSubagent   ← create_deep_agent(backend=DockerBackend())
                 │   execute()        ← DockerBackend.execute() — sandbox tool
                 │   read_file()      ← reads tool docs on demand (PTD)
                 │   write_file()     ← writes intermediate results
                 │   MCP tools        ← nvd_search, pypi_info, github_releases
                 │
                 └── task("interpret CVEs for requests==2.31.0", "cve-interpreter")
                 └── task("analyse changelog requests 2.31→2.32", "changelog-analyst")
                          │
                          └── CVEInterpreterSubagent   ← focused context, no code execution
                          └── ChangelogAnalystSubagent ← focused context, no code execution
```

### Why this is better

Every node is a real LangGraph graph node. The entire execution is:
- **Checkpointable** — a 20-package audit that fails on package 15 resumes from package 15
- **Streamable** — progress events flow from the graph naturally, not from a hand-rolled callback
- **Observable** — LangGraph Studio shows the full graph, every state transition, every tool call
- **Traceable** — LangSmith tracing is automatic, no instrumentation needed
- **Context-safe** — `SummarizationMiddleware` prevents the silent context overflow risk in the current retry loop

---

## Component Design

### 1. `DockerBackend` — no changes needed

`DockerBackend` already implements `SandboxBackendProtocol` completely. It is the one thing in the codebase that is correct. Pass it directly to `create_deep_agent()`.

```python
# src/sandbox/docker_backend.py — already correct, zero changes
from deepagents.backends.protocol import SandboxBackendProtocol, ExecuteResponse
class DockerBackend(SandboxBackendProtocol): ...
```

### 2. MCP servers as LangChain tools

The NVD, PyPI, and GitHub MCP servers currently run as separate processes inside the Docker container and the LLM generates Python code to call them. Instead, wrap them as proper `@tool` functions and bind them to the per-package subagent:

```python
# src/tools/audit_tools.py

from langchain_core.tools import tool
from src.mcp_servers.nvd import search_cves
from src.mcp_servers.pypi import get_package_info
from src.mcp_servers.github_api import get_release_notes


@tool
def nvd_cve_search(package_name: str, version: str) -> dict:
    """Search NVD for CVEs affecting a specific package version.
    Returns list of CVEs with severity, description, and CPE ranges."""
    return search_cves(package_name, version)


@tool
def pypi_package_info(package_name: str) -> dict:
    """Fetch PyPI metadata for a package.
    Returns latest version, release history, and project URLs."""
    return get_package_info(package_name)


@tool
def github_release_notes(repo: str, from_version: str, to_version: str) -> dict:
    """Fetch GitHub release notes between two versions.
    Returns changelog entries, breaking change indicators."""
    return get_release_notes(repo, from_version, to_version)
```

This is a direct replacement for `tool_generator.py`, which generates these same wrappers dynamically as strings and uploads them into Docker. The dynamic code generation was only needed because LangChain tools weren't being used.

### 3. Structured output replaces regex JSON parsing

The current code has two fragile parsers:
- `_parse_json_stdout()` in `executor.py` — parses LLM-generated script stdout  
- `_parse_json_from_text()` in `subagent.py` — regex-strips markdown fences then `json.loads()`

Both are replaced by:

```python
# src/agent/llm.py

from langchain_openai import ChatOpenAI
from src.agent.schema import Phase2Result

def get_structured_model(llm_config: LLMConfig) -> Runnable:
    llm = ChatOpenAI(
        model=llm_config.model,
        temperature=llm_config.temperature,
    )
    return llm.with_structured_output(Phase2Result)
```

`with_structured_output()` uses OpenAI function calling under the hood. The model is constrained to produce valid JSON matching the Pydantic schema. No regex, no `try/except json.loads`, no code block extraction. The entire `_extract_code_block()`, `_parse_json_from_text()`, and `_parse_json_stdout()` functions are deleted.

### 4. Per-package subagent definition

```python
# src/agent/subagents.py

from deepagents import SubAgent, create_deep_agent, SubAgentMiddleware
from deepagents.backends.composite import CompositeBackend
from deepagents.backends import StateBackend
from src.sandbox.docker_backend import DockerBackend
from src.tools.audit_tools import nvd_cve_search, pypi_package_info, github_release_notes


PACKAGE_AUDITOR_SYSTEM_PROMPT = """
You are a dependency security auditor. For each package you receive:

1. Use pypi_package_info to get the latest version and release history.
2. Use nvd_cve_search to find all CVEs for this package.
3. For each CVE, determine if it affects the pinned version using CPE ranges.
4. Use github_release_notes to fetch changelog between pinned and latest version.
5. Write your structured findings to /audit/results/{package}.json using write_file.
6. Delegate ambiguous CVEs to cve-interpreter subagent using task().
7. Delegate changelog analysis to changelog-analyst subagent using task().

The PTC constraint applies: tool response data must be processed and written to files.
Do NOT accumulate raw tool responses in your context window.
"""

CVE_INTERPRETER_SYSTEM_PROMPT = """
You are a CVE security analyst. You receive a list of CVEs and a pinned package version.
For each CVE, determine: affecting_pinned | not_relevant.
Base your determination on CPE version ranges, patch notes, and advisory text.
Respond ONLY with the structured JSON list. No explanation, no markdown.
"""

CHANGELOG_ANALYST_SYSTEM_PROMPT = """
You are a software compatibility analyst. You receive release notes between two versions.
Identify breaking changes, deprecations, and removals.
Respond ONLY with structured JSON. No explanation.
"""


cve_interpreter: SubAgent = {
    "name": "cve-interpreter",
    "description": "Determines whether ambiguous CVEs affect a specific pinned version",
    "system_prompt": CVE_INTERPRETER_SYSTEM_PROMPT,
    "tools": [],
    "model": "gpt-4o-mini",  # fast, cheap, focused task
}

changelog_analyst: SubAgent = {
    "name": "changelog-analyst",
    "description": "Analyses release notes for breaking changes between two package versions",
    "system_prompt": CHANGELOG_ANALYST_SYSTEM_PROMPT,
    "tools": [],
    "model": "gpt-4o-mini",
}


def create_package_auditor_subagent(docker_backend: DockerBackend):
    """
    Returns a compiled LangGraph graph for per-package security auditing.
    DockerBackend provides the execute() tool for sandbox code execution.
    The CompositeBackend routes workspace paths to Docker and results to state.
    """
    backend = CompositeBackend(
        default=docker_backend,           # sandbox filesystem for code execution
        routes={
            "/audit/": StateBackend(),    # ephemeral audit results in LangGraph state
        }
    )
    return create_deep_agent(
        model="gpt-4o",
        backend=backend,
        tools=[nvd_cve_search, pypi_package_info, github_release_notes],
        subagents=[cve_interpreter, changelog_analyst],
        system_prompt=PACKAGE_AUDITOR_SYSTEM_PROMPT,
    )
```

### 5. Orchestrator agent replaces `pipeline.py`

```python
# src/agent/pipeline.py  (rewritten)

from deepagents import create_deep_agent, SubAgent, SubAgentMiddleware
from deepagents.middleware.summarization import SummarizationMiddleware
from src.agent.subagents import create_package_auditor_subagent
from src.sandbox.docker_backend import DockerBackend
from src.sandbox.docker_sandbox import DockerSandbox
from src.config.loaders import load_from_file


ORCHESTRATOR_SYSTEM_PROMPT = """
You are a multi-package dependency security audit orchestrator.
You receive a list of Python packages with their pinned versions.

Steps:
1. Use write_todos to plan the audit — one todo per package.
2. For each package, use task(f"audit {package}=={version}", "package-auditor") 
   to delegate to the package auditor subagent.
3. Wait for all package audits to complete.
4. Read all results from /audit/results/*.json
5. Synthesize a cross-package risk summary with upgrade priority ordering.
6. Write the final report to /audit/report.json

Maintain the PTC invariant: raw tool data stays in the sandbox.
"""


def create_audit_pipeline(config_path: str = "config.yaml"):
    config = load_from_file(config_path)
    sandbox = DockerSandbox(image=config.docker.image)
    docker_backend = DockerBackend(sandbox)
    package_auditor = create_package_auditor_subagent(docker_backend)

    package_auditor_spec: SubAgent = {
        "name": "package-auditor",
        "description": "Audits a single Python package for CVEs and changelog breaking changes",
        "system_prompt": "",  # defined inside create_package_auditor_subagent
        "tools": [],
        "middleware": [],
        # Pass the pre-built subagent graph as the runnable
        "_runnable": package_auditor,
    }

    orchestrator = create_deep_agent(
        model="gpt-4o",
        subagents=[package_auditor_spec],
        middleware=[
            SummarizationMiddleware(
                model="gpt-4o-mini",
                trigger=("fraction", 0.80),
                keep=("fraction", 0.15),
            )
        ],
        system_prompt=ORCHESTRATOR_SYSTEM_PROMPT,
    )
    return orchestrator, sandbox
```

### 6. Structured state schema

The current `schema.py` has `Phase2Result` and `Phase3Result` as Pydantic models used only for validation after the fact. In the Deep Agents design, these become the structured output target for `with_structured_output()` and the state type for the LangGraph graph:

```python
# src/agent/schema.py  (extended)

from typing import TypedDict, Annotated
from pydantic import BaseModel, Field
import operator


class CVEFinding(BaseModel):
    cve_id: str
    severity: str
    status: str  # "affecting_pinned" | "not_relevant" | "needs_interpretation"
    determination_method: str
    description: str = ""


class Phase2Result(BaseModel):
    package: str
    pinned_version: str
    latest_version: str | None
    versions_behind: int
    cves_affecting_pinned: list[CVEFinding] = Field(default_factory=list)
    cves_not_relevant: list[CVEFinding] = Field(default_factory=list)
    needs_interpretation: list[CVEFinding] = Field(default_factory=list)
    total_cves_found: int
    changelog_analysis: str = ""
    breaking_changes_detected: bool = False
    risk_rating: str = "low"
    upgrade_recommendation: str = ""
    recommendation_rationale: str = ""


# LangGraph state — flows through the orchestrator graph
class AuditState(TypedDict):
    packages: list[dict]                            # input: [{package, pinned_version}]
    package_results: Annotated[list, operator.add]  # accumulated results from subagents
    synthesis: dict                                  # final cross-package report
    run_id: str
```

### 7. Logging — standardise to structlog with LangSmith

Remove `logging.getLogger(__name__)` in `subagent.py`. Deep Agents + LangGraph emit structured traces automatically to LangSmith. For local structured logging, configure structlog once in `audit.py` and it propagates everywhere:

```python
# audit.py (top-level config, replaces per-file logger setup)

import structlog
from langchain.callbacks import LangChainTracer

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ]
)

# LangSmith tracing — free, automatic, no instrumentation
tracer = LangChainTracer(project_name="ptc-dep-audit")
```

Every `llm.ainvoke()` call in the graph automatically logs to LangSmith with full input/output, token counts, latency, and chain structure. The 8 locations in the codebase with no logging and the structlog/stdlib inconsistency become irrelevant.

---

## What Gets Deleted

| File / Component | Lines | Why deleted |
|---|---|---|
| `_run_subagent_inner()` in `subagent.py` | 244 | Replaced by Deep Agent's native ReAct loop |
| `_extract_code_block()` | 8 | No more LLM-generated scripts to parse |
| `_parse_json_from_text()` | 17 | `with_structured_output()` |
| `_parse_json_stdout()` in `executor.py` | ~20 | Same |
| `tool_generator.py` | 100+ | Tools are `@tool` functions, not generated strings |
| `mcp_registry.py` | ~120 | MCP servers become `@tool` wrappers, not subprocess connections |
| `asyncio.gather()` fan-out in `pipeline.py` | 40 | `SubAgentMiddleware` with `task()` |
| Manual retry loop (MAX_CODEGEN_RETRIES) | ~30 | Agent replans natively |
| Manual timeout wrapper | ~20 | LangGraph built-in execution timeout |
| `search.py` stub | 30 | Delete — it returns empty results and pretends otherwise |
| `parity.py` | ~50 | Delete — never called from anywhere |

Rough estimate: **~700 lines of manual orchestration code deleted**, replaced by configuration and `@tool` function definitions.

---

## What the Token Savings Argument Becomes

The PTC + PTD token savings mechanism is **still valid** and actually becomes stronger:

- **PTC (Prompt Tool Calls)**: Instead of LLM-generated scripts writing JSON to stdout and the host parsing it, the per-package subagent writes results to `/audit/results/{package}.json` via `write_file()`. The data never enters any LLM context window. This is PTC at the framework level, not the hack level.

- **PTD (Prompt Tool Docs)**: `FilesystemMiddleware` gives the agent `read_file()`. The agent reads MCP tool docs from disk only when it needs them — this is PTD as a first-class framework capability, not a hardcoded `open("/app/tools/docs/...")` in LLM-generated scripts.

- **SummarizationMiddleware** adds a third savings dimension: long retry conversations get summarised before they overflow, which the current implementation cannot do at all.

The token savings story goes from "we wrote a hack that avoids ReAct overhead" to "we use the framework-level PTC/PTD primitives correctly."

---

## Migration Priority

1. **Replace `_run_subagent_inner()` with `create_package_auditor_subagent(DockerBackend())`** — this is the highest-leverage change. It eliminates the manual codegen loop, the fragile JSON parsing, the hardcoded retry count, and the context overflow risk in one move. `DockerBackend` requires zero changes.

2. **Replace `asyncio.gather()` with `SubAgentMiddleware`** — the orchestrator becomes a real graph with checkpointing and observability.

3. **Replace `tool_generator.py` + `mcp_registry.py` with `@tool` functions** — NVD, PyPI, and GitHub servers become proper LangChain tools, not subprocess-managed MCP processes whose clients are generated as Python strings.

4. **Add `with_structured_output(Phase2Result)`** — delete all JSON regex parsing.

5. **Configure structlog + LangSmith** — observability for free, replaces the 12 `except Exception` broad catches that currently swallow errors silently.

---

## Summary

The current codebase implements `SandboxBackendProtocol` correctly and has good domain logic (CVE filtering, changelog analysis, risk rating). The infrastructure around it is the problem. It manually reimplements the orchestration, planning, context management, retry logic, structured output parsing, and fan-out that `create_deep_agent()` provides out of the box. The fix is not to add more code — it is to delete the manual plumbing and let the framework do its job.
