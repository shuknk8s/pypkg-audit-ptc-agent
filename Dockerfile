FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    curl \
    ripgrep \
    jq \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    mv /root/.local/bin/uv /usr/local/bin/uv

RUN mkdir -p /app/tools /app/tools/docs /app/code /app/results /app/data /app/mcp_servers

ENV PYTHONPATH=/app
WORKDIR /app

COPY pyproject.toml .
RUN uv sync --no-dev --no-install-project

CMD ["tail", "-f", "/dev/null"]
