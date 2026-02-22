"""Audit pipeline — single shared Docker container, all packages in parallel.

Identical approach to ptc-v4-dep-gap-agentic:
  - One DockerSandbox started once, stopped once
  - Tools uploaded once
  - All packages run concurrently via asyncio.gather() sharing the same sandbox
  - Each package writes to its own script path: /app/code/phase2_<pkg>.py
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from uuid import uuid4

import structlog

from src.agent.events import AuditEvent, EventBus
from src.agent.executor import _container_server_configs, _mcp_server_uploads
from src.agent.schema import validate_phase3_result
from src.agent.subagent import run_package_subagent
from src.agent.tool_catalog import build_tool_catalog_summary
from src.config.loaders import load_from_file
from src.core.mcp_registry import MCPRegistry
from src.core.tool_generator import ToolGenerator
from src.sandbox.docker_sandbox import DockerSandbox

logger = structlog.get_logger()

ProgressCallback = Callable[[str, dict], Awaitable[None] | None]


async def _emit(cb: ProgressCallback | None, event: str, payload: dict,
                bus: EventBus | None = None) -> None:
    if cb is not None:
        maybe = cb(event, payload)
        if asyncio.iscoroutine(maybe):
            await maybe
    if bus is not None:
        await bus.emit(AuditEvent(
            event_type=event,
            package=payload.get("package", ""),
            data=payload,
        ))


async def run_all_packages(
    packages: list[tuple[str, str]],
    config_path: str = "config.yaml",
    progress_callback: ProgressCallback | None = None,
    event_bus: EventBus | None = None,
) -> list[dict]:
    config = load_from_file(config_path)
    package_specs = [{"package": p, "pinned_version": v} for p, v in packages]

    await _emit(progress_callback, "main_start", {
        "total_packages": len(package_specs),
        "packages": package_specs,
    }, bus=event_bus)
    await _emit(progress_callback, "main_bootstrap", {"message": "starting_sandbox"}, bus=event_bus)

    # One container for all packages — same as ptc-v4-dep-gap-agentic
    container_name = f"{config.docker.container_name}-{uuid4().hex[:8]}"
    sandbox = await asyncio.get_event_loop().run_in_executor(
        None, lambda: DockerSandbox(config.docker.image, container_name)
    )
    await _emit(progress_callback, "main_bootstrap", {"message": "sandbox_started"}, bus=event_bus)

    registry = MCPRegistry(config.mcp.servers)
    await registry.connect_all()
    await _emit(progress_callback, "main_bootstrap", {"message": "mcp_connected"}, bus=event_bus)

    try:
        tools_by_server = registry.get_tools_by_server()
        server_configs = _container_server_configs(config.mcp.servers)
        mcp_uploads = _mcp_server_uploads(config.mcp.servers)
        generator = ToolGenerator()

        # Upload tools once into the shared container
        generated = generator.generate_all(tools_by_server, server_configs)
        tool_uploads = [
            (f"/app/tools/{name}", content.encode("utf-8"))
            for name, content in generated.items()
        ]
        await sandbox.aupload_files(tool_uploads + mcp_uploads)

        tool_catalog_summary = build_tool_catalog_summary(tools_by_server)

        await _emit(progress_callback, "main_ready", {
            "servers": [s.name for s in config.mcp.servers],
            "packages": package_specs,
        }, bus=event_bus)

        async def _run_one(spec: dict) -> dict:
            package = str(spec["package"])
            pinned = str(spec["pinned_version"])
            await _emit(progress_callback, "subagent_start", {
                "package": package, "pinned_version": pinned,
            }, bus=event_bus)
            try:
                result = await run_package_subagent(
                    package=package,
                    pinned_version=pinned,
                    sandbox=sandbox,
                    tool_catalog_summary=tool_catalog_summary,
                    llm_config=config.llm,
                    progress_callback=progress_callback,
                    event_bus=event_bus,
                )
                await _emit(progress_callback, "subagent_complete", {
                    "package": package,
                    "risk_rating": result.get("risk_rating"),
                    "total_cves_found": result.get("total_cves_found"),
                    "cves_affecting_count": len(result.get("cves_affecting_pinned") or []),
                }, bus=event_bus)
                return result
            except Exception as exc:
                await _emit(progress_callback, "subagent_error", {
                    "package": package, "error": str(exc),
                }, bus=event_bus)
                return validate_phase3_result({
                    "package": package,
                    "pinned_version": pinned,
                    "latest_version": None,
                    "versions_behind": 0,
                    "cves_affecting_pinned": [],
                    "cves_not_relevant": [],
                    "needs_interpretation": [],
                    "total_cves_found": 0,
                    "changelog_analysis": f"Fallback due to error: {exc}",
                    "changelog_excerpts": [],
                    "upgrade_recommendation": "Retry after infrastructure stabilizes.",
                    "risk_rating": "low",
                    "changelog": {"notes": []},
                    "breaking_changes_detected": False,
                    "recommendation_rationale": "Deterministic fallback.",
                }).model_dump()

        tasks = [_run_one(spec) for spec in package_specs]
        package_results = list(await asyncio.gather(*tasks))

    finally:
        await _emit(progress_callback, "main_disconnecting", {}, bus=event_bus)
        await registry.disconnect_all()
        await _emit(progress_callback, "main_stopping_sandbox", {}, bus=event_bus)
        await asyncio.get_event_loop().run_in_executor(None, sandbox.stop)

    await _emit(progress_callback, "main_synthesizing", {}, bus=event_bus)
    await _emit(progress_callback, "main_complete", {}, bus=event_bus)

    return package_results
