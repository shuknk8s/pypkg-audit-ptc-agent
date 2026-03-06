![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue) ![License: MIT](https://img.shields.io/badge/License-MIT-green) ![Release](https://img.shields.io/github/v/release/shuknk8s/pypkg-audit-ptc-agent)
# pypkg-audit-ptc-agent

A Python package security auditor that demonstrates two **MCP-based context engineering patterns** — techniques for controlling what enters the LLM context window when agents use tools.

Traditional agent architectures use a **ReAct loop** (reason-act-observe cycles where the LLM calls one tool at a time and every response flows back into the prompt). This project replaces that pattern with two alternatives built on top of [MCP (Model Context Protocol)](https://modelcontextprotocol.io), the open standard for connecting LLMs to external tools:

- **Programmatic Tool Calling (PTC)** — the LLM writes a Python script instead of making individual tool calls. The script runs inside a Docker sandbox, calls MCP tools directly, and returns only a compact JSON summary. Raw tool responses never enter the LLM context window.
- **Progressive Tool Discovery (PTD)** — tool schemas load on demand. The LLM first sees a lightweight catalog (~50 tokens) describing available Phase B tools, then selects which ones it needs. Full schemas load only for requested tools. Clean packages skip Phase B entirely (0 extra schema tokens).

## How It Works

### PTC: code generation replaces round-trips

In a ReAct loop, N tool calls means N round-trips through the LLM — each raw response enters the context window as prompt tokens. PTC replaces this with a single code-generation call:

```
ReAct (traditional):        PTC (this project):
LLM → tool₁ → LLM          LLM → generates Python script
LLM → tool₂ → LLM                    │
LLM → tool₃ → LLM            Docker Sandbox
  ...N round-trips            ┌───────────────────┐
  all responses in context    │ script calls tools │
                              │ MCP servers reply  │
                              │ raw data stays here│
                              └────────┬───────────┘
                                 compact JSON only
                                       │
                                       ▼
                                 Risk assessment
```

### PTD: schema loading on demand

Phase A always runs with 3 core tools (nvd, pypi, github_api) plus a lightweight ~50-token catalog describing 4 Phase B tools. The LLM outputs a `_tools_needed` list. Phase B loads full schemas only for requested tools — or skips entirely if the list is empty.

## Quick Start

### Prerequisites

- Python 3.12+
- Docker
- OpenAI API key

### Setup

```bash
# Clone and install
git clone https://github.com/shuknk8s/pypkg-audit-ptc-agent.git
cd pypkg-audit-ptc-agent
uv sync

# Configure
cp .env.example .env
# Edit .env with your OPENAI_API_KEY and optionally GITHUB_TOKEN

# Build the sandbox image
docker build -t pypkg-audit-ptc-agent:latest .
```

### Run

```bash
# Audit a requirements file
uv run python audit.py requirements.txt

# Full demo with 6 packages
uv run python audit.py requirements-real-test.txt

# JSON output
uv run python audit.py requirements.txt --json
```

### Example Input

```
requests==2.28.1
flask==2.2.2
django==4.2.0
urllib3==1.26.6
jinja2==3.0.3
pyyaml==5.4.1
```

### Example Output

| Package | Affecting CVEs | Scanned | Risk |
|---------|---------------|---------|------|
| requests==2.28.1 | 0 | 50 | low |
| flask==2.2.2 | 0 | 50 | low |
| django==4.2.0 | 43 | 50 | high |
| urllib3==1.26.6 | 5 | 17 | high |
| jinja2==3.0.3 | 3 | 37 | medium |
| pyyaml==5.4.1 | 0 | 6 | low |

## What It Produces

For each package:

- **CVE scan** via NVD with three-tier deterministic filtering:
  1. CPE exact match — checks if pinned version is in the vulnerable range
  2. CPE exclusion — filters out CVEs that NVD tied to other products (e.g., Xen FLASK != Python Flask)
  3. Summary version parsing — extracts version ranges from CVE descriptions
- **Version gap** — current vs latest, how many versions behind
- **Changelog analysis** — breaking changes detection from GitHub release notes
- **Risk rating** — LLM-assessed (critical/high/medium/low) using CVE severity context and few-shot examples, with deterministic fallback
- **Upgrade recommendation** with rationale

Only CVEs with no CPE data and no parseable version range reach the LLM for interpretation.

## MCP Servers

The audit tools are implemented as [MCP](https://modelcontextprotocol.io) servers — the standardized interface that lets the LLM-generated scripts call tools the same way on host or inside the Docker sandbox. 7 FastMCP servers communicate via JSON-RPC over stdio:

| Server | Phase | Data Source |
|--------|-------|-------------|
| `nvd` | Core | NVD CVE API with three-tier deterministic filtering |
| `pypi` | Core | PyPI package metadata |
| `github_api` | Core | GitHub release notes |
| `epss` | B | FIRST EPSS exploit probability scores |
| `osv` | B | OSV vulnerability database |
| `deps_dev` | B | deps.dev dependency info |
| `scorecard` | B | OpenSSF Security Scorecard |

Core tools run on every audit. Phase B tools load only when the LLM requests them based on findings.

## Token Savings

On the 6-package test suite, PTC+PTD achieves a **51% combined token reduction** vs an estimated ReAct baseline:

- **27,793 actual tokens** vs **59,942 estimated ReAct tokens** (30,759 saved)
- **PTC** contributes 50.2% — raw tool responses stay inside the sandbox
- **PTD** contributes 1.1% — unused tool schemas never loaded

Per-package savings vary with data volume: pyyaml (few NVD results) saves 23%, while jinja2 (large NVD payload) saves 62%. A detailed token savings report is generated after each run.

## Development

```bash
# Run tests
uv run pytest tests/ -v

# Lint
uv run ruff check src/ tests/
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed diagrams and design documentation.

## License

MIT
