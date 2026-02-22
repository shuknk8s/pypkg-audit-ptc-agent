IMAGE_NAME := ptc-v4-dep-gap
IMAGE_TAG := latest

.PHONY: build test smoke

build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

test:
	uv run pytest tests/ -q

smoke:
	uv run python -c "from src.sandbox.docker_sandbox import DockerSandbox; s=DockerSandbox(); s.start(); r=s.execute(\"python3 -c \\\"print('ok')\\\"\"); print(r.output.strip()); s.stop()"
