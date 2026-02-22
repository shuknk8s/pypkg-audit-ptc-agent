from pathlib import Path

import yaml

from src.config.core import CoreConfig


DEFAULT_CONFIG = {
    "docker": {
        "image": "ptc-v4-dep-gap:latest",
        "container_name": "ptc-v4-dep-gap-sandbox",
        "auto_remove": False,
        "network_mode": "bridge",
    },
    "mcp": {
        "servers": [
            {
                "name": "nvd",
                "description": "NVD CVE API server",
                "command": "uv",
                "args": ["run", "python", "-m", "src.mcp_servers.nvd"],
                "env": {},
                "tool_exposure_mode": "summary",
            },
            {
                "name": "pypi",
                "description": "PyPI package metadata server",
                "command": "uv",
                "args": ["run", "python", "-m", "src.mcp_servers.pypi"],
                "env": {},
                "tool_exposure_mode": "summary",
            },
            {
                "name": "github_api",
                "description": "GitHub API server",
                "command": "uv",
                "args": ["run", "python", "-m", "src.mcp_servers.github_api"],
                "env": {"GITHUB_TOKEN": "${GITHUB_TOKEN}"},
                "tool_exposure_mode": "summary",
            },
            {
                "name": "search",
                "description": "Search API server",
                "command": "uv",
                "args": ["run", "python", "-m", "src.mcp_servers.search"],
                "env": {"TAVILY_API_KEY": "${TAVILY_API_KEY}"},
                "tool_exposure_mode": "summary",
            },
        ],
        "tool_discovery_enabled": True,
        "lazy_load": True,
        "tool_exposure_mode": "summary",
    },
    "runtime": {
        "max_run_seconds": 240,
        "quality_report_enabled": True,
    },
    "llm": {
        "model": "gpt-4o-mini",
        "temperature": 0.0,
        "max_tokens": 4096,
        "seed": 42,
        "top_p": 1.0,
    },
}


def load_from_file(config_path: str = "config.yaml") -> CoreConfig:
    path = Path(config_path)
    if not path.exists():
        return CoreConfig(**DEFAULT_CONFIG)
    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    return CoreConfig(**raw)
