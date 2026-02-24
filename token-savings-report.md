# Token Savings Report — PTC + PTD vs Traditional ReAct

**Generated:** 2026-02-24 00:52 UTC  
**Architecture:** Programmatic Tool Calling (PTC) + Progressive Tool Discovery (PTD)  
**Baseline:** Estimated traditional ReAct / function-calling loop

## How the savings work

**PTC savings** — In a traditional ReAct loop every tool call round-trips through the LLM:
raw tool responses (NVD CVEs, PyPI metadata, GitHub release notes) flow back into the
context window as prompt tokens. With PTC the LLM writes a Python script once; the script
runs inside a Docker sandbox, calls all tools, and returns only a compact JSON summary.
The raw responses never enter the LLM context window.

**PTD savings** — Real progressive tool discovery: the core codegen prompt includes only
a lightweight catalog of Phase B tools (~50 tokens). The LLM selects which tools it needs
based on core audit data. Full schemas load ONLY for requested tools in a second codegen
call. Clean packages skip Phase B entirely. Savings vary per package.

## Results

| Package | Actual tokens (PTC+PTD) | Est. ReAct baseline | PTC saved (tool resp) | PTC % | PTD saved (doc inject) | PTD % | Combined saved % |
|---------|------------------------|---------------------|-----------------------|-------|------------------------|-------|------------------|
| requests | 4,266 | 9,484 | 4,878 | 51.4% | 120 | 1.3% | **52.7%** |
| **TOTAL** | **4,266** | **9,484** | **4,878** | **51.4%** | **120** | **1.3%** | **52.7%** |

## Key numbers

- **Combined token reduction:** 52.7% vs estimated ReAct baseline
- **PTC contribution:** 51.4% — tool responses kept inside sandbox
- **PTD contribution:** 1.3% — per-call doc injection eliminated
- **Actual tokens spent:** 4,266 across 1 package(s)
- **Estimated ReAct cost:** 9,484 tokens
- **Total tokens saved:** 4,998

> **Estimation methodology:** ReAct baseline = actual PTC tokens + sandbox payload size ÷ 4
> (chars-to-tokens approximation for raw tool responses that would have entered the LLM
> context window) + 450 tokens for eager tool doc injection that PTD eliminates.
