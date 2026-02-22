# Token Savings Report — PTC + PTD vs Traditional ReAct

**Generated:** 2026-02-22 21:02 UTC  
**Architecture:** Programmatic Tool Calling (PTC) + Progressive Tool Discovery (PTD)  
**Baseline:** Estimated traditional ReAct / function-calling loop

## How the savings work

**PTC savings** — In a traditional ReAct loop every tool call round-trips through the LLM:
raw tool responses (NVD CVEs, PyPI metadata, GitHub release notes) flow back into the
context window as prompt tokens. With PTC the LLM writes a Python script once; the script
runs inside a Docker sandbox, calls all tools, and returns only a compact JSON summary.
The raw responses never enter the LLM context window.

**PTD savings** — Previously the codegen prompt injected ~700 tokens of tool API docs on
every call (markdown docs + hardcoded response shapes). With PTD Level 2 those docs are
replaced by a shared `TOOL RESPONSE SHAPES` block in the system prompt (~200 tokens,
paid once). Net saving: ~500 tokens per codegen call.

## Results

| Package | Actual tokens (PTC+PTD) | Est. ReAct baseline | PTC saved (tool resp) | PTC % | PTD saved (doc inject) | PTD % | Combined saved % |
|---------|------------------------|---------------------|-----------------------|-------|------------------------|-------|------------------|
| requests | 2,455 | 8,583 | 5,428 | 63.2% | 500 | 5.8% | **69.1%** |
| flask | 2,385 | 8,988 | 5,903 | 65.7% | 500 | 5.6% | **71.2%** |
| django | 2,474 | 8,628 | 5,454 | 63.2% | 500 | 5.8% | **69.0%** |
| urllib3 | 2,582 | 6,717 | 3,435 | 51.1% | 500 | 7.4% | **58.6%** |
| jinja2 | 2,566 | 11,172 | 7,906 | 70.8% | 500 | 4.5% | **75.2%** |
| pyyaml | 2,496 | 4,222 | 1,026 | 24.3% | 500 | 11.8% | **36.1%** |
| **TOTAL** | **14,958** | **48,310** | **29,152** | **60.3%** | **3,000** | **6.2%** | **66.6%** |

## Key numbers

- **Combined token reduction:** 66.6% vs estimated ReAct baseline
- **PTC contribution:** 60.3% — tool responses kept inside sandbox
- **PTD contribution:** 6.2% — per-call doc injection eliminated
- **Actual tokens spent:** 14,958 across 6 package(s)
- **Estimated ReAct cost:** 48,310 tokens
- **Total tokens saved:** 32,152

> **Estimation methodology:** ReAct baseline = actual PTC tokens + sandbox payload size ÷ 4
> (chars-to-tokens approximation for raw tool responses that would have entered the LLM
> context window) + 700 tokens for per-call doc injection that PTD eliminates.
