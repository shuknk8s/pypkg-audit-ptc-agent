"""LLM codegen E2E experiment pipeline.

Uses the real LLM to generate audit scripts (same prompts as the main pipeline),
then executes them in the Docker sandbox with live MCP servers. This tests that
the current codegen implementation produces working scripts end-to-end.

Compatible with the original audit.py progress_callback interface so the Rich
live UI works unchanged.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import Awaitable, Callable
from uuid import uuid4

from pathlib import Path

from src.agent.executor import (
    _container_server_configs,
    _parse_json_stdout,
)
from langchain_core.messages import HumanMessage, SystemMessage

from src.agent.llm import get_chat_model
from src.agent.prompts import build_iteration_prompt
from src.agent.subagent import (
    _apply_structured_narrative,
    _merge_phase_b,
    _parse_json_from_text,
    _syntax_check,
)
from src.agent.tool_catalog import build_tool_catalog_summary
from src.config.loaders import load_from_file
from src.core.mcp_registry import MCPRegistry
from src.core.tool_generator import ToolGenerator
from src.sandbox.docker_sandbox import DockerSandbox

# Experiment-local overrides (schema with summary_version, improved prompt)
from experiments.template_codegen.schema import validate_package_result
from experiments.template_codegen.prompts import build_interpretation_prompt
from experiments.template_codegen.codegen import generate_phase_a, generate_phase_b, regenerate_from_error

# Path to experiment-local MCP servers (with retry + heuristic improvements)
_LOCAL_MCP_DIR = Path(__file__).resolve().parent / "mcp_servers"

MAX_PHASE_A_RETRIES = 2  # matches main pipeline
MAX_PHASE_B_RETRIES = 1  # matches main pipeline


def _experiment_mcp_uploads(config_servers: list) -> list[tuple[str, bytes]]:
    """Upload experiment-local MCP servers (with retry + heuristic) instead of src/ originals."""
    uploads: list[tuple[str, bytes]] = []
    for server in config_servers:
        args = server.args
        module_name = None
        if "-m" in args:
            idx = args.index("-m")
            if idx + 1 < len(args):
                module_name = args[idx + 1]
        if module_name and module_name.startswith("src.mcp_servers."):
            script_name = module_name.split(".")[-1] + ".py"
            local_path = _LOCAL_MCP_DIR / script_name
            if local_path.exists():
                content = local_path.read_text(encoding="utf-8")
                # Strip experiment import paths — container runs standalone
                content = content.replace(
                    "from experiments.template_codegen.mcp_servers.retry import get_with_retry",
                    "",
                ).replace(
                    "from experiments.template_codegen.mcp_servers.retry import post_with_retry",
                    "",
                )
                # Inline the retry helper at the top of the file
                retry_code = (_LOCAL_MCP_DIR / "retry.py").read_text(encoding="utf-8")
                # Remove the module docstring and imports from retry.py, keep just the functions
                content = retry_code + "\n" + content
                uploads.append((f"/app/mcp_servers/{script_name}", content.encode("utf-8")))
            else:
                # Fall back to src/ original for servers we didn't copy
                from src.agent.executor import _mcp_server_uploads as _orig_uploads
                for path, data in _orig_uploads([server]):
                    uploads.append((path, data))
    return uploads

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, dict], Awaitable[None] | None]


def _safe_name(package: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", package)


async def _emit(cb: ProgressCallback | None, event: str, payload: dict) -> None:
    if cb is not None:
        maybe = cb(event, payload)
        if asyncio.iscoroutine(maybe):
            await maybe


async def run_codegen_pipeline(
    packages: list[tuple[str, str]],
    config_path: str = "config.yaml",
    progress_callback: ProgressCallback | None = None,
) -> list[dict]:
    """Run the full audit pipeline using LLM-generated code.

    Emits the same progress events as the original pipeline so audit.py's
    Rich live UI works unchanged.
    """
    config = load_from_file(config_path)
    package_specs = [{"package": p, "pinned_version": v} for p, v in packages]

    await _emit(progress_callback, "main_start", {
        "total_packages": len(package_specs),
        "packages": package_specs,
    })

    # --- Bootstrap: sandbox + MCP ---
    await _emit(progress_callback, "main_bootstrap", {"message": "starting_sandbox"})
    container_name = f"{config.docker.container_name}-exp-{uuid4().hex[:8]}"
    sandbox = await asyncio.get_event_loop().run_in_executor(
        None, lambda: DockerSandbox(config.docker.image, container_name)
    )
    await _emit(progress_callback, "main_bootstrap", {"message": "sandbox_started"})

    await _emit(progress_callback, "main_bootstrap", {"message": "mcp_connecting"})
    registry = MCPRegistry(config.mcp.servers)
    await registry.connect_all()
    await _emit(progress_callback, "main_bootstrap", {"message": "mcp_connected"})

    try:
        # --- Generate and upload tool wrappers ---
        tools_by_server = registry.get_tools_by_server()
        server_configs = _container_server_configs(config.mcp.servers)
        mcp_uploads = _experiment_mcp_uploads(config.mcp.servers)
        generator = ToolGenerator()
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
        })

        # --- Run per-package ---
        async def _run_one(spec: dict) -> dict:
            package = str(spec["package"])
            pinned = str(spec["pinned_version"])
            await _emit(progress_callback, "subagent_start", {
                "package": package, "pinned_version": pinned,
            })
            try:
                result = await _run_one_package(
                    sandbox, package, pinned,
                    tool_catalog_summary=tool_catalog_summary,
                    llm_config=config.llm,
                    progress_callback=progress_callback,
                )
                await _emit(progress_callback, "subagent_complete", {
                    "package": package,
                    "risk_rating": result.get("risk_rating"),
                    "total_cves_found": result.get("total_cves_found"),
                    "cves_affecting_count": len(result.get("cves_affecting_pinned") or []),
                })
                return result
            except Exception as exc:
                await _emit(progress_callback, "subagent_error", {
                    "package": package, "error": str(exc),
                })
                return _fallback_result(package, pinned, str(exc))

        tasks = [_run_one(spec) for spec in package_specs]
        package_results = list(await asyncio.gather(*tasks))

    finally:
        await _emit(progress_callback, "main_disconnecting", {})
        await registry.disconnect_all()
        await _emit(progress_callback, "main_stopping_sandbox", {})
        await asyncio.get_event_loop().run_in_executor(None, sandbox.stop)

    await _emit(progress_callback, "main_synthesizing", {})
    await _emit(progress_callback, "main_complete", {})

    return package_results


async def _run_one_package(
    sandbox: DockerSandbox,
    package: str,
    pinned_version: str,
    *,
    tool_catalog_summary: str,
    llm_config,
    progress_callback: ProgressCallback | None = None,
) -> dict:
    """Run LLM codegen + execute for a single package, with retry on failure."""
    safe = _safe_name(package)

    # --- Phase A: LLM generates script ---
    await _emit(progress_callback, "subagent_update", {
        "package": package, "stage": "llm_codegen",
    })
    phase_a_script, phase_a_raw, messages = await generate_phase_a(
        package, pinned_version,
        tool_catalog_summary=tool_catalog_summary,
        llm_config=llm_config,
    )

    # --- Phase A: execute with retry ---
    script_path = f"/app/code/phase_a_{safe}.py"
    parsed = None
    last_error = ""

    for attempt in range(1 + MAX_PHASE_A_RETRIES):
        # Syntax pre-check
        syntax_err = _syntax_check(phase_a_script, package)
        if syntax_err:
            last_error = f"SyntaxError in generated script: {syntax_err}"
            logger.warning("[Phase A] %s: syntax error (attempt %d): %s", package, attempt, syntax_err)
            if attempt < MAX_PHASE_A_RETRIES:
                await _emit(progress_callback, "subagent_update", {
                    "package": package, "stage": f"retry_{attempt + 1}",
                })
                phase_a_script = await regenerate_from_error(last_error, messages, llm_config)
            continue

        await _emit(progress_callback, "subagent_update", {
            "package": package, "stage": "script_execution",
        })
        await sandbox.awrite(script_path, phase_a_script)
        exec_result = await asyncio.to_thread(sandbox.execute, f"python3 {script_path}")

        if exec_result.exit_code == 0:
            try:
                parsed = _parse_json_stdout(exec_result.output)
                break
            except Exception as parse_exc:
                last_error = f"JSON parse error: {parse_exc}. Output: {(exec_result.output or '')[:500]}"
        else:
            last_error = (exec_result.output or "")[:3000]

        logger.warning("[Phase A] %s: execution failed (attempt %d): %s", package, attempt, last_error[:300])
        if attempt < MAX_PHASE_A_RETRIES:
            await _emit(progress_callback, "subagent_update", {
                "package": package, "stage": f"retry_{attempt + 1}",
            })
            phase_a_script = await regenerate_from_error(last_error, messages, llm_config)

    if parsed is None:
        raise RuntimeError(
            f"Phase A failed after {1 + MAX_PHASE_A_RETRIES} attempts: {last_error[:500]}"
        )

    # --- Phase B: progressive tool discovery ---
    raw_tools = parsed.get("_tools_needed", [])
    valid_tools = {"epss", "osv", "scorecard", "deps_dev"}
    tools_needed = []
    for t in raw_tools:
        server = t.split("/")[0] if isinstance(t, str) else ""
        if server in valid_tools and server not in tools_needed:
            tools_needed.append(server)

    if tools_needed:
        await _emit(progress_callback, "subagent_update", {
            "package": package, "stage": "phase_b_codegen",
        })

        core_json = json.dumps(parsed, ensure_ascii=False)
        await sandbox.awrite(f"/app/code/core_results_{safe}.json", core_json)

        phase_b_script, phase_b_raw, pb_messages = await generate_phase_b(
            package, pinned_version,
            core_results=parsed,
            tools_needed=tools_needed,
            tool_catalog_summary=tool_catalog_summary,
            llm_config=llm_config,
        )

        if phase_b_script:
            phase_b_path = f"/app/code/phase_b_{safe}.py"

            for pb_attempt in range(1 + MAX_PHASE_B_RETRIES):
                # Syntax pre-check
                syntax_err = _syntax_check(phase_b_script, package)
                if syntax_err:
                    logger.warning("[Phase B] %s: syntax error (attempt %d): %s", package, pb_attempt, syntax_err)
                    if pb_attempt < MAX_PHASE_B_RETRIES and pb_messages:
                        phase_b_script = await regenerate_from_error(
                            f"Phase B script syntax error: {syntax_err}", pb_messages, llm_config
                        )
                        continue
                    break

                await _emit(progress_callback, "subagent_update", {
                    "package": package, "stage": "phase_b_execution",
                    "phase_b_tools": tools_needed,
                })
                await sandbox.awrite(phase_b_path, phase_b_script)
                b_result = await asyncio.to_thread(
                    sandbox.execute, f"python3 {phase_b_path}"
                )

                if b_result.exit_code == 0:
                    try:
                        phase_b_output = _parse_json_stdout(b_result.output)
                        _merge_phase_b(parsed, phase_b_output)
                        core_tools = parsed.get("_tools_called", [])
                        pb_tools = phase_b_output.get("_tools_called", [])
                        if isinstance(core_tools, list) and isinstance(pb_tools, list):
                            parsed["_tools_called"] = list(set(core_tools + pb_tools))
                        break
                    except Exception as exc:
                        logger.warning("[Phase B] %s: parse error: %s", package, exc)
                        break  # parse error is not retryable
                else:
                    error_output = (b_result.output or "")[:3000]
                    logger.warning("[Phase B] %s: failed (attempt %d, exit %d): %s",
                                  package, pb_attempt, b_result.exit_code, error_output[:300])
                    if pb_attempt < MAX_PHASE_B_RETRIES and pb_messages:
                        phase_b_script = await regenerate_from_error(error_output, pb_messages, llm_config)
                        continue
                    break
    else:
        await _emit(progress_callback, "subagent_update", {
            "package": package, "stage": "phase_b_skipped",
        })

    # --- CVE interpretation (same as main pipeline's step_interpret_cves) ---
    needs_interp = parsed.get("needs_interpretation", [])
    if needs_interp:
        try:
            llm = get_chat_model(llm_config=llm_config)
            analyst_system_msg = SystemMessage(
                content=(
                    "You are a security analyst. "
                    "Respond ONLY with valid JSON — no Python code, no markdown fences, no explanation."
                ),
            )
            interp_msg = HumanMessage(
                content=build_interpretation_prompt(package, pinned_version, needs_interp[:15])
            )
            interp_response = await llm.ainvoke([analyst_system_msg, interp_msg])
            interpreted = _parse_json_from_text(interp_response.content)
            new_affecting = []
            new_not_relevant = []
            if isinstance(interpreted, list):
                for item in interpreted:
                    if not isinstance(item, dict):
                        continue
                    item.setdefault("determination_method", "agent_interpretation")
                    if item.get("status") == "affecting_pinned":
                        new_affecting.append(item)
                    else:
                        item["status"] = "not_relevant"
                        new_not_relevant.append(item)
            # Overflow beyond batch limit
            for cve in needs_interp[15:]:
                cve = dict(cve)
                cve["status"] = "not_relevant"
                cve["determination_method"] = "agent_interpretation"
                new_not_relevant.append(cve)
            parsed.setdefault("cves_affecting_pinned", []).extend(new_affecting)
            parsed.setdefault("cves_not_relevant", []).extend(new_not_relevant)
            parsed["needs_interpretation"] = []
            parsed["total_cves_found"] = (
                len(parsed.get("cves_affecting_pinned", []))
                + len(parsed.get("cves_not_relevant", []))
            )
            logger.info("[Interp] %s: %d affecting, %d not_relevant",
                       package, len(new_affecting), len(new_not_relevant))
        except Exception as exc:
            logger.warning("[Interp] %s failed: %s", package, str(exc)[:200])

    # --- Validate + finalize ---
    await _emit(progress_callback, "subagent_update", {
        "package": package, "stage": "done",
    })

    for str_field in ("upgrade_recommendation", "changelog_analysis"):
        if parsed.get(str_field) is None:
            parsed[str_field] = ""
    for int_field in ("versions_behind", "total_cves_found"):
        if parsed.get(int_field) is None:
            parsed[int_field] = 0
    if parsed.get("changelog_excerpts") is None:
        parsed["changelog_excerpts"] = []
    if parsed.get("changelog") is None:
        parsed["changelog"] = {"notes": []}

    _apply_structured_narrative(parsed, package, pinned_version)
    parsed.setdefault("breaking_changes_detected", False)
    parsed.setdefault("recommendation_rationale", "")

    validated = validate_package_result(parsed)
    result = validated.model_dump()
    result["_llm_codegen"] = True
    result["_phase_b_tools"] = tools_needed
    return result


def _fallback_result(package: str, pinned_version: str, error: str) -> dict:
    """Deterministic fallback when a package audit fails entirely."""
    fallback = {
        "package": package,
        "pinned_version": pinned_version,
        "latest_version": None,
        "versions_behind": 0,
        "cves_affecting_pinned": [],
        "cves_not_relevant": [],
        "needs_interpretation": [],
        "total_cves_found": 0,
        "changelog_analysis": f"Experiment fallback: {error}",
        "changelog_excerpts": [],
        "upgrade_recommendation": "Retry after fixing codegen or infrastructure.",
        "risk_rating": "low",
        "changelog": {"notes": []},
        "breaking_changes_detected": False,
        "recommendation_rationale": "Deterministic fallback from experiment pipeline.",
    }
    return validate_package_result(fallback).model_dump()
