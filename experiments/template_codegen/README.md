# LLM Codegen E2E Experiment

## What this tests

This experiment validates that the current pipeline's LLM codegen works
end-to-end. It uses the same LLM (gpt-4o-mini) with the same prompts to
generate Python audit scripts, then executes them in the real Docker sandbox
against live MCP servers.

The experiment proves the generated code:
- Parses as valid Python
- Executes without errors in the Docker sandbox
- Correctly calls MCP tools and decodes their envelope responses
- Produces structured output that passes Pydantic validation
- Contains real CVE/version data from live servers

## How to run

```bash
# 1. Build the Docker sandbox image (if not already built)
docker build -t pypkg-audit-ptc-agent:latest .

# 2. Run the experiment (requires OPENAI_API_KEY in .env)
uv run python experiments/template_codegen/run_experiment.py requirements.txt

# With verbose logging:
uv run python experiments/template_codegen/run_experiment.py requirements.txt -v

# Show the generated scripts:
uv run python experiments/template_codegen/run_experiment.py requirements.txt --show-scripts

# With a custom config:
uv run python experiments/template_codegen/run_experiment.py requirements.txt --config config.yaml
```

## Success criteria

1. LLM-generated scripts execute in the Docker sandbox without errors
2. Pydantic validation (`PackageAuditResult`) passes for each package
3. Results contain real CVE/version data from live MCP servers

## Architecture

- **`codegen.py`** — Calls the LLM with the same prompts as the main pipeline
  (`build_system_prompt`, `build_codegen_prompt`, `build_phase_b_prompt`).
  Extracts generated Python from code fences.
- **`template_pipeline.py`** — Reuses `DockerSandbox`, `MCPRegistry`, `ToolGenerator`
  from the main codebase. Orchestrates: LLM codegen → execute → parse → validate.
- **`run_experiment.py`** — CLI entrypoint that parses requirements and runs
  the pipeline.
