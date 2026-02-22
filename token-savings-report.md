# Token Savings Report — PTC + PTD vs Traditional ReAct

**Generated:** 2026-02-22 21:28 UTC  
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
| requests | 3,383 | 9,511 | 5,428 | 57.1% | 500 | 5.3% | **62.3%** |
| flask | 3,366 | 10,643 | 6,577 | 61.8% | 500 | 4.7% | **66.5%** |
| django | 3,351 | 9,540 | 5,489 | 57.5% | 500 | 5.2% | **62.8%** |
| urllib3 | 3,357 | 7,522 | 3,465 | 46.1% | 500 | 6.6% | **52.7%** |
| jinja2 | 3,396 | 12,019 | 7,923 | 65.9% | 500 | 4.2% | **70.1%** |
| pyyaml | 3,350 | 5,088 | 1,038 | 20.4% | 500 | 9.8% | **30.2%** |
| **TOTAL** | **20,203** | **54,323** | **29,920** | **55.1%** | **3,000** | **5.5%** | **60.6%** |

## Key numbers

- **Combined token reduction:** 60.6% vs estimated ReAct baseline
- **PTC contribution:** 55.1% — tool responses kept inside sandbox
- **PTD contribution:** 5.5% — per-call doc injection eliminated
- **Actual tokens spent:** 20,203 across 6 package(s)
- **Estimated ReAct cost:** 54,323 tokens
- **Total tokens saved:** 32,920

> **Estimation methodology:** ReAct baseline = actual PTC tokens + sandbox payload size ÷ 4
> (chars-to-tokens approximation for raw tool responses that would have entered the LLM
> context window) + 700 tokens for per-call doc injection that PTD eliminates.
