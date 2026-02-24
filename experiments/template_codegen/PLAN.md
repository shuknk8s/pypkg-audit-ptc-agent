# LLM Codegen E2E Experiment

## Goal

Test that the current pipeline's LLM codegen produces working scripts by running
the full flow end-to-end: LLM generates code → code executes in Docker sandbox →
live MCP servers return real data → Pydantic validation passes.

## Structure

```
experiments/template_codegen/
├── PLAN.md                # This file
├── codegen.py             # LLM code generation (Phase A + Phase B)
├── template_pipeline.py   # Pipeline: setup → LLM codegen → execute → parse → validate
├── run_experiment.py      # CLI entrypoint
└── README.md              # How to run, success criteria
```

## Flow

1. **codegen.py** — Calls the same LLM (gpt-4o-mini) with the same prompts
   (`build_system_prompt`, `build_codegen_prompt`, `build_phase_b_prompt`) as
   the main pipeline. Extracts the generated Python script from code fences.

2. **template_pipeline.py** — Reuses real infrastructure from the main codebase
   (DockerSandbox, MCPRegistry, ToolGenerator). Per package:
   a. LLM generates Phase A script → write to container → execute → parse output
   b. Extract `_tools_needed` from parsed output
   c. If non-empty: LLM generates Phase B script → execute → parse → merge
   d. Apply deterministic narrative + validate with `PackageAuditResult`

3. **run_experiment.py** — CLI that accepts a requirements file, runs the pipeline,
   reports pass/fail per package, and dumps full JSON results.

## Success Criteria

- LLM-generated scripts execute in the Docker sandbox without errors
- Pydantic validation (`PackageAuditResult`) passes for each package
- Results contain real CVE/version data from live MCP servers
