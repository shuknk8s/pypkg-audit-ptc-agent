IMAGE_NAME := dep-audit-deepagent
IMAGE_TAG := latest

.PHONY: build test smoke lint install

install:
	uv pip install -e ".[dev]"

build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

lint:
	uv run ruff check src/ tests/

test:
	uv run pytest tests/ -q

smoke:
	uv run python -c "from src.sandbox.docker_sandbox import DockerSandbox; s=DockerSandbox(); s.start(); r=s.execute(\"python3 -c \\\"print('ok')\\\"\"); print(r.output.strip()); s.stop()"

smoke-pipeline:
	uv run python -c "from src.agent.pipeline import create_audit_pipeline; g, _ = create_audit_pipeline(); print(type(g).__name__)"
