# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Dev Commands

```bash
uv pip install -e ".[dev]"                  # Install with dev dependencies
uv sync                                      # Sync dependencies from lockfile
docker build -t pypkg-audit-ptc-agent:latest .  # Build sandbox Docker image
uv run python audit.py requirements.txt      # Run audit (add --json for JSON-only output)
uv run pytest tests/ -v                      # Run all tests
uv run pytest tests/test_ptd_selection.py::test_ptd_token_savings_measurable -v  # Single test
uv run ruff check src/ tests/               # Lint
```

The Makefile wraps these: `make install`, `make build`, `make test`, `make lint`.

## Architecture

This is a token-efficient Python package vulnerability auditor using two key patterns:

### PTC (Programmatic Tool Calling)
The LLM writes a Python script (not ReAct tool calls). The script executes inside a Docker sandbox, calls MCP tools directly, and returns only a compact JSON summary via a base64 marker (`__PTC_JSON_B64__`). Raw tool responses never leave the container, saving token cost.

### PTD (Progressive Tool Discovery)
Tool loading is two-phase. **Phase A** always runs with 3 core tools (nvd, pypi, github_api) plus a lightweight ~50-token catalog of 4 Phase B tools (epss, osv, scorecard, deps_dev). The LLM outputs a `_tools_needed` list. **Phase B** loads full schemas only for requested tools (or skips entirely if the list is empty).

### Execution Flow
1. `audit.py` → `pipeline.py`: parse requirements, start one shared Docker container, connect to MCP servers, generate tool wrappers, upload to container
2. Per-package (parallel via `asyncio.gather`): 9 sequential step functions in `subagent.py` mutate an `AuditContext` dataclass — codegen → execute with retry → Phase B codegen → Phase B execute → compute savings → validate findings → interpret CVEs → analyze changelog → finalize
3. Synthesis: deterministic cross-package report, Rich terminal UI, markdown savings report

### MCP Server Architecture
- **Host side**: `MCPRegistry` connects to 7 MCP servers via stdio JSON-RPC, discovers schemas once
- **Container side**: Generated `mcp_client.py` spawns MCP servers as subprocesses on first tool call; server configs rewritten from `uv run python -m ...` (host) to `python3 /app/mcp_servers/<name>.py` (container)
- Servers are FastMCP implementations in `src/mcp_servers/`

### NVD CVE Classification (three-tier deterministic filtering)
The `search_cves` tool in `src/mcp_servers/nvd.py` classifies CVEs before they reach the LLM:
1. **CPE exact match** (`cpe_range`): extracts CPE product field (parts[4]) and checks version range via `_is_in_range()` → `affecting_pinned` or `not_relevant`
2. **CPE exclusion** (`heuristic`): if a CVE has CPE data for other products but NOT ours → `not_relevant` (eliminates false positives like Xen FLASK CVEs appearing in Flask results)
3. **Summary version parsing** (`summary_version`): parses version ranges from CVE description text ("before X", "prior to X", etc.) → `affecting_pinned` or `not_relevant`
4. Only CVEs with no CPE data at all and no parseable version in summary remain as `needs_interpretation` → sent to LLM

### Key Patterns
- **Step functions** (not an agent framework): `subagent.py` has 9 independent async functions, no ReAct loop
- **Code extraction**: LLM output in \`\`\`python fences, extracted via regex
- **MCP envelope decoding**: scripts must unwrap `response["content"][0]["text"]` from every tool call
- **LLM risk rating**: assessed by LLM using CVE severity context and few-shot examples, with deterministic fallback
- **Token savings accounting**: PTC savings = raw response chars / 4; PTD savings = (4 - loaded_count) * 85 - 50

## Configuration

`config.yaml` defines Docker settings, MCP server list (name/command/args/env/tool_exposure_mode), and runtime params. Parsed via Pydantic models in `src/config/core.py`. Env vars like `${GITHUB_TOKEN}` resolved at container startup.

Required env vars (see `.env.example`): `OPENAI_API_KEY`, optionally `GITHUB_TOKEN`.

## Testing Conventions

Tests validate structural correctness (no agent framework imports), schema defaults, retry logic, and PTD compliance (selective schema loading, token math). Tests use `unittest.mock` / `AsyncMock` — no live Docker or API calls needed.
