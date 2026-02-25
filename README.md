# pypkg-audit-ptc-agent

A Python package security auditor that uses **Programmatic Tool Calling (PTC)** and **Progressive Tool Discovery (PTD)** to minimize LLM token usage while producing accurate vulnerability assessments.

Instead of a traditional ReAct loop where every tool call round-trips through the LLM, the LLM writes a Python script once. That script runs inside a Docker sandbox, calls MCP tools directly, and returns a compact JSON summary. Raw tool responses never enter the LLM context window.

## How It Works

```
requirements.txt ──> audit.py ──> LLM writes Python script
                                        │
                                        ▼
                                  Docker Sandbox
                                  ┌─────────────────┐
                                  │ Generated script │
                                  │ calls MCP tools: │
                                  │  - NVD (CVEs)    │
                                  │  - PyPI (versions)│
                                  │  - GitHub (notes) │
                                  └────────┬─────────┘
                                           │
                                    compact JSON only
                                           │
                                           ▼
                                  Risk assessment + report
```

**PTC** keeps raw tool responses inside the sandbox — the LLM never sees them.

**PTD** loads tool schemas on demand — the LLM sees a lightweight catalog (~50 tokens) of Phase B tools and selects what it needs. Clean packages skip Phase B entirely.

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

7 FastMCP servers communicate via JSON-RPC over stdio:

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

The system reports two categories of savings vs a traditional ReAct baseline:

- **PTC savings** — raw tool responses (NVD CVE data, PyPI metadata, release notes) stay inside the sandbox instead of flowing into the LLM context window
- **PTD savings** — tool schemas load only for tools the LLM selects; clean packages skip Phase B entirely (0 extra tokens)

A token savings report is generated after each run.

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
