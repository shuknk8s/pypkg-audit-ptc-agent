IMAGE_NAME := pypkg-audit-ptc-agent
IMAGE_TAG := latest

.PHONY: build test lint install

install:
	uv pip install -e ".[dev]"

build:
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

lint:
	uv run ruff check src/ tests/

test:
	uv run pytest tests/ -q

