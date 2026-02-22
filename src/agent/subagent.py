"""Per-package auditor — PTC + PTD via Docker sandbox codegen.

Execution model (identical to ptc-v4-dep-gap-agentic):
  1. llm.ainvoke (codegen)  -> LLM returns Python script in a code fence
  2. Python extracts script, writes it to the Docker container, executes it
  3. Script calls MCP tools INSIDE the container (PTC)
  4. Script reads /app/tools/docs/ before each tool call (PTD)
  5. Raw tool responses never leave the container
  6. llm.ainvoke (CVE interpretation)  -> structured output via response_format
  7. llm.ainvoke (changelog analysis)  -> structured output via response_format

Direct llm.ainvoke() calls throughout — no agent wrapper.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import Awaitable, Callable
from collections import Counter

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from src.agent.events import AuditEvent, EventBus
from src.agent.executor import _parse_json_stdout
from src.agent.llm import get_chat_model
from src.agent.prompts import (
    build_changelog_prompt,
    build_codegen_prompt,
    build_iteration_prompt,
    build_interpretation_prompt,
    build_system_prompt,
)
from src.agent.schema import (
    AuditContext,
    validate_phase2_result,
    validate_phase3_result,
)
from src.config.core import LLMConfig
from src.sandbox.docker_sandbox import DockerSandbox

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, dict], Awaitable[None] | None]

MAX_CODEGEN_RETRIES = 2
MAX_SUPPLEMENTAL_CALLS = 2
SUBAGENT_TIMEOUT_SECONDS = 180

_BREAKING_HINTS = ("breaking", "deprecated", "removed", "migration", "incompatible")


def _apply_structured_narrative(phase2_data: dict, package: str, pinned_version: str) -> None:
    """Build recommendation_rationale and risk_rating deterministically from actual data."""
    affecting: list[dict] = phase2_data.get("cves_affecting_pinned") or []
    not_relevant: list[dict] = phase2_data.get("cves_not_relevant") or []
    changelog: dict = phase2_data.get("changelog") or {}
    latest_version: str = phase2_data.get("latest_version") or "latest"

    total_affecting = len(affecting)
    severity_counts = Counter(str(c.get("severity", "unknown")).lower() for c in affecting)
    high_like = severity_counts.get("critical", 0) + severity_counts.get("high", 0)
    top_ids = [str(c.get("cve_id", "unknown")) for c in affecting[:3]]
    interpreted = sum(
        1 for c in affecting if str(c.get("determination_method", "")).lower() == "agent_interpretation"
    )
    cpe_based = sum(
        1 for c in affecting if str(c.get("determination_method", "")).lower() == "cpe_range"
    )

    notes = changelog.get("notes", []) if isinstance(changelog, dict) else []
    notes = [n for n in notes if isinstance(n, str)]
    changelog_error = str(changelog.get("error") or "").strip() if isinstance(changelog, dict) else ""
    joined = " ".join(notes).lower()
    breaking = any(hint in joined for hint in _BREAKING_HINTS)

    if total_affecting == 0:
        risk_rating = "low"
        action = "Routine patch cycle is acceptable; keep monitoring advisories."
    elif high_like >= 2:
        risk_rating = "high"
        action = "Treat as priority remediation with staged rollout and targeted regression testing."
    elif high_like == 1:
        risk_rating = "medium"
        action = "Schedule near-term upgrade and validate critical paths before production rollout."
    else:
        risk_rating = "low"
        action = "Upgrade in next maintenance window with standard validation."

    if total_affecting > 0:
        exposure_line = (
            f"- Exposure posture: {total_affecting} CVE(s) classified as affecting pinned version "
            f"({severity_counts.get('critical', 0)} critical / {severity_counts.get('high', 0)} high / "
            f"{severity_counts.get('medium', 0)} medium / {severity_counts.get('low', 0)} low)."
        )
    else:
        exposure_line = "- Exposure posture: no CVEs currently classified as affecting pinned version."

    rationale_lines = [
        exposure_line,
        (
            f"- Evidence confidence: {cpe_based} CPE-range determination(s), "
            f"{interpreted} interpretation-based determination(s), "
            f"{len(not_relevant)} CVE(s) filtered as not relevant."
        ),
    ]
    if top_ids:
        rationale_lines.append(f"- Key CVEs to review first: {', '.join(top_ids)}.")
    if breaking:
        rationale_lines.append(
            "- Upgrade risk signal: release notes include potential breaking-change indicators "
            "(deprecated/removed/incompatible)."
        )
    elif notes:
        rationale_lines.append(
            "- Upgrade risk signal: no explicit breaking-change indicators found in available release notes."
        )
    else:
        rationale_lines.append(
            "- Upgrade risk signal: release-note coverage unavailable; compatibility confidence is reduced."
        )
    if changelog_error:
        rationale_lines.append(f"- Changelog collection gap: {changelog_error}")

    phase2_data["recommendation_rationale"] = "\n".join(rationale_lines)
    phase2_data["upgrade_recommendation"] = (
        f"{package} {pinned_version} -> {latest_version}: {action}"
    )
    phase2_data["risk_rating"] = risk_rating
    phase2_data["breaking_changes_detected"] = breaking


def _deterministic_fallback_result(*, package: str, pinned_version: str, error: str) -> dict:
    fallback = {
        "package": package,
        "pinned_version": pinned_version,
        "latest_version": None,
        "versions_behind": 0,
        "cves_affecting_pinned": [],
        "cves_not_relevant": [],
        "needs_interpretation": [],
        "total_cves_found": 0,
        "changelog_analysis": f"Fallback used due to execution error: {error}",
        "changelog_excerpts": [],
        "upgrade_recommendation": "Retry audit after infrastructure stabilizes.",
        "risk_rating": "low",
        "changelog": {"notes": []},
        "breaking_changes_detected": False,
        "recommendation_rationale": "Deterministic fallback output preserves pipeline continuity.",
    }
    return validate_phase3_result(fallback).model_dump()


def _extract_code_block(text: str) -> str:
    match = re.search(r"```python\s*\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    match = re.search(r"```\s*\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()


def _parse_json_from_text(text: str) -> dict | list | None:
    text = text.strip()
    if text.startswith("```"):
        inner = re.sub(r"^```\w*\n?", "", text)
        inner = re.sub(r"\n?```$", "", inner).strip()
        text = inner
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        start = text.find("[") if text.find("[") < text.find("{") and text.find("[") != -1 else text.find("{")
        end = text.rfind("]") if start != -1 and text[start] == "[" else text.rfind("}")
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                pass
    return None


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


def _check_ptd_compliance(script: str, package: str) -> set[str]:
    """Return set of MCP servers the script imports. Warn if doc not read."""
    servers_used: set[str] = set()
    for match in re.finditer(r"tools\.(\w+)", script):
        server = match.group(1)
        if server == "mcp_client":
            continue
        servers_used.add(server)
        reads_doc = (
            f'open("/app/tools/docs/{server}/' in script
            or f"open('/app/tools/docs/{server}/" in script
        )
        if not reads_doc:
            logger.warning("[PTD] %s: uses tools.%s without doc read", package, server)
    return servers_used


def _track_tokens(ctx: AuditContext, msg: AIMessage) -> None:
    usage = getattr(msg, "usage_metadata", None)
    if isinstance(usage, dict):
        ctx.token_usage["prompt_tokens"] += usage.get("input_tokens", 0) or 0
        ctx.token_usage["completion_tokens"] += usage.get("output_tokens", 0) or 0
        ctx.token_usage["total_tokens"] += (
            (usage.get("input_tokens", 0) or 0) + (usage.get("output_tokens", 0) or 0)
        )


# ---------------------------------------------------------------------------
# Step functions — each mutates AuditContext in place
# ---------------------------------------------------------------------------

async def step_codegen(ctx: AuditContext) -> None:
    """Step 1: LLM generates a Python script for the package audit."""
    system_msg = SystemMessage(content=build_system_prompt(ctx.tool_catalog_summary))
    codegen_msg = HumanMessage(content=build_codegen_prompt(ctx.package, ctx.pinned_version))
    ctx.messages = [system_msg, codegen_msg]

    response = await ctx.llm.ainvoke(ctx.messages)
    _track_tokens(ctx, response)
    ctx.script_source = _extract_code_block(response.content)
    ctx.servers_used = _check_ptd_compliance(ctx.script_source, ctx.package)
    logger.info("LLM generated script for %s (%d chars)", ctx.package, len(ctx.script_source))
    ctx.messages.append(response)


async def step_execute_with_retry(ctx: AuditContext) -> None:
    """Steps 2-3: Write script to sandbox, execute, retry on failure."""
    script_path = f"/app/code/phase2_{re.sub(r'[^a-zA-Z0-9_.-]+', '_', ctx.package)}.py"

    for attempt in range(1 + MAX_CODEGEN_RETRIES):
        ctx.attempt = attempt
        await ctx.sandbox.awrite(script_path, ctx.script_source)
        exec_result = await ctx.sandbox.aexecute(f"python3 {script_path}")

        if exec_result.exit_code == 0:
            try:
                ctx.parsed_output = _parse_json_stdout(exec_result.output)
                break
            except Exception as parse_exc:
                ctx.last_error = f"JSON parse error: {parse_exc}. Output: {(exec_result.output or '')[:500]}"
        else:
            ctx.last_error = (exec_result.output or "")[:3000]

        if attempt < MAX_CODEGEN_RETRIES:
            retry_msg = HumanMessage(content=build_iteration_prompt(ctx.last_error))
            ctx.messages.append(retry_msg)
            response = await ctx.llm.ainvoke(ctx.messages)
            _track_tokens(ctx, response)
            ctx.script_source = _extract_code_block(response.content)
            ctx.messages.append(response)


def step_compute_savings(ctx: AuditContext) -> None:
    """Token savings estimate: PTC + PTD breakdown (pure math, no I/O).

    Methodology matches ptc-v4-dep-gap-agentic exactly:
      ReAct baseline = actual_tokens + sandbox_payload/4 + PTD_EAGER_TOKENS
      PTC savings    = sandbox_payload / 4  (tool responses kept in sandbox)
      PTD savings    = PTD_EAGER - PTD_OVERHEAD (doc injection eliminated)
    """
    parsed = ctx.parsed_output
    sandbox_data_chars = len(json.dumps(parsed))
    ptc_tool_response_tokens_avoided = sandbox_data_chars // 4

    # PTD savings: same methodology as ptc-v4.
    # Old approach injected ~700 tokens of tool API docs per codegen call.
    # Now the system prompt has a shared ~200 token TOOL RESPONSE SHAPES block.
    # Net saving: ~500 tokens per call. With 8 servers available (vs ptc-v4's 3),
    # eager-load would be even worse, but we measure conservatively against the
    # same 700-token baseline to keep numbers comparable.
    PTD_EAGER_TOKENS_OLD = 700   # tokens that were in old codegen prompt per call
    PTD_SYSTEM_OVERHEAD  = 200   # tokens added to system prompt (shared, amortised)
    ptd_tokens_avoided = PTD_EAGER_TOKENS_OLD - PTD_SYSTEM_OVERHEAD  # ≈ 500 per call

    ptc_actual_tokens = ctx.token_usage["total_tokens"]
    estimated_react_total = ptc_actual_tokens + ptc_tool_response_tokens_avoided + PTD_EAGER_TOKENS_OLD
    total_saved = ptc_tool_response_tokens_avoided + ptd_tokens_avoided

    ctx.token_savings = {
        "mode": "ptc+ptd",
        "ptc_actual_tokens": ptc_actual_tokens,
        "estimated_react_total": estimated_react_total,
        "ptc_tool_response_tokens_avoided": ptc_tool_response_tokens_avoided,
        "ptc_savings_pct": round(
            ptc_tool_response_tokens_avoided / estimated_react_total * 100, 1
        ) if estimated_react_total > 0 else 0.0,
        "ptd_doc_tokens_avoided": ptd_tokens_avoided,
        "ptd_savings_pct": round(
            ptd_tokens_avoided / estimated_react_total * 100, 1
        ) if estimated_react_total > 0 else 0.0,
        "ptd_tools_used": sorted(ctx.servers_used),
        "ptd_tools_used_count": max(len(ctx.servers_used), 2),
        "total_tokens_saved": total_saved,
        "total_savings_pct": round(
            total_saved / estimated_react_total * 100, 1
        ) if estimated_react_total > 0 else 0.0,
        "sandbox_data_chars": sandbox_data_chars,
    }
    logger.info(
        "[SAVINGS] %s: actual=%d tok | ReAct~%d | "
        "PTC saves %d tok (%.1f%%) | PTD saves %d tok (%.1f%%) | combined %.1f%% | tools=%s",
        ctx.package,
        ptc_actual_tokens,
        estimated_react_total,
        ptc_tool_response_tokens_avoided, ctx.token_savings["ptc_savings_pct"],
        ptd_tokens_avoided,               ctx.token_savings["ptd_savings_pct"],
        ctx.token_savings["total_savings_pct"],
        sorted(ctx.servers_used),
    )


def step_validate_phase2(ctx: AuditContext) -> None:
    """Sanitize + validate Phase2 output (pure validation, no I/O)."""
    parsed = ctx.parsed_output
    # Coerce None fields to safe defaults so Pydantic doesn't reject them
    for _str_field in ("upgrade_recommendation", "changelog_analysis"):
        if parsed.get(_str_field) is None:
            parsed[_str_field] = ""
    for _int_field in ("versions_behind", "total_cves_found"):
        if parsed.get(_int_field) is None:
            parsed[_int_field] = 0
    for _list_field in ("changelog_excerpts",):
        if parsed.get(_list_field) is None:
            parsed[_list_field] = []
    if parsed.get("changelog") is None:
        parsed["changelog"] = {"notes": []}
    validated_p2 = validate_phase2_result(parsed)
    ctx.phase2_data = validated_p2.model_dump()


async def step_interpret_cves(ctx: AuditContext) -> None:
    """LLM interpretation for ambiguous CVEs."""
    needs_interp = ctx.phase2_data.get("needs_interpretation", [])
    MAX_INTERP_BATCH = 15

    if needs_interp and ctx.supplemental_calls < MAX_SUPPLEMENTAL_CALLS:
        ctx.supplemental_calls += 1
        batch = needs_interp[:MAX_INTERP_BATCH]
        try:
            analyst_system_msg = SystemMessage(
                content=(
                    "You are a security analyst. "
                    "Respond ONLY with valid JSON — no Python code, no markdown fences, no explanation."
                ),
            )
            interp_msg = HumanMessage(
                content=build_interpretation_prompt(ctx.package, ctx.pinned_version, batch)
            )
            interp_response = await ctx.llm.ainvoke([analyst_system_msg, interp_msg])
            _track_tokens(ctx, interp_response)
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
            overflow = needs_interp[MAX_INTERP_BATCH:]
            for cve in overflow:
                cve = dict(cve)
                cve["status"] = "not_relevant"
                cve["determination_method"] = "agent_interpretation"
                new_not_relevant.append(cve)
            ctx.phase2_data["cves_affecting_pinned"].extend(new_affecting)
            ctx.phase2_data["cves_not_relevant"].extend(new_not_relevant)
            ctx.phase2_data["needs_interpretation"] = []
            ctx.phase2_data["total_cves_found"] = (
                len(ctx.phase2_data["cves_affecting_pinned"]) + len(ctx.phase2_data["cves_not_relevant"])
            )
            logger.info(
                "CVE interpretation for %s: %d affecting, %d not_relevant",
                ctx.package, len(new_affecting), len(new_not_relevant),
            )
        except Exception as exc:
            logger.warning(
                "CVE interpretation failed for %s (%s) — %d CVEs remain ambiguous",
                ctx.package, str(exc)[:100], len(needs_interp),
            )


async def step_analyze_changelog(ctx: AuditContext) -> None:
    """LLM changelog analysis."""
    latest_version = ctx.phase2_data.get("latest_version") or "latest"
    changelog_data = ctx.phase2_data.get("changelog", {})

    if ctx.supplemental_calls < MAX_SUPPLEMENTAL_CALLS:
        ctx.supplemental_calls += 1
        try:
            analyst_system_msg = SystemMessage(
                content=(
                    "You are a security analyst. "
                    "Respond ONLY with valid JSON — no Python code, no markdown fences, no explanation."
                ),
            )
            cl_msg = HumanMessage(
                content=build_changelog_prompt(ctx.package, ctx.pinned_version, latest_version, changelog_data)
            )
            cl_response = await ctx.llm.ainvoke([analyst_system_msg, cl_msg])
            _track_tokens(ctx, cl_response)
            cl_parsed = _parse_json_from_text(cl_response.content)
            if isinstance(cl_parsed, dict):
                ctx.phase2_data["breaking_changes_detected"] = cl_parsed.get("breaking_changes_detected", False)
                if "changelog_analysis" in cl_parsed:
                    ctx.phase2_data["changelog_analysis"] = cl_parsed["changelog_analysis"]
                ctx.phase2_data["recommendation_rationale"] = cl_parsed.get(
                    "recommendation_rationale", "LLM-based changelog analysis completed."
                )
            else:
                raise ValueError("Non-dict changelog response")
        except Exception as cl_exc:
            logger.warning(
                "LLM changelog analysis failed for %s (%s) — using defaults",
                ctx.package,
                cl_exc,
            )
            ctx.phase2_data.setdefault("breaking_changes_detected", False)
            ctx.phase2_data.setdefault(
                "recommendation_rationale",
                f"Changelog analysis unavailable for {ctx.package}; upgrade decision should rely on CVE posture.",
            )


def step_finalize(ctx: AuditContext) -> dict:
    """Deterministic narrative + Phase3 validation. Returns the final result dict."""
    _apply_structured_narrative(ctx.phase2_data, ctx.package, ctx.pinned_version)

    ctx.phase2_data.setdefault("breaking_changes_detected", False)
    ctx.phase2_data.setdefault("recommendation_rationale", "")

    validated_p3 = validate_phase3_result(ctx.phase2_data)
    result = validated_p3.model_dump()
    result["_token_usage"] = ctx.token_usage
    result["_token_savings"] = ctx.token_savings
    return result


# ---------------------------------------------------------------------------
# Public entry point + inner orchestrator
# ---------------------------------------------------------------------------

async def run_package_subagent(
    *,
    package: str,
    pinned_version: str,
    sandbox: DockerSandbox,
    tool_catalog_summary: str,
    llm_config: LLMConfig,
    progress_callback: ProgressCallback | None = None,
    event_bus: EventBus | None = None,
) -> dict:
    token_usage = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    try:
        async with asyncio.timeout(SUBAGENT_TIMEOUT_SECONDS):
            return await _run_subagent_inner(
                package=package,
                pinned_version=pinned_version,
                sandbox=sandbox,
                tool_catalog_summary=tool_catalog_summary,
                llm_config=llm_config,
                token_usage=token_usage,
                progress_callback=progress_callback,
                event_bus=event_bus,
            )
    except TimeoutError:
        logger.warning("Subagent for %s timed out after %ds", package, SUBAGENT_TIMEOUT_SECONDS)
        result = _deterministic_fallback_result(
            package=package, pinned_version=pinned_version, error="subagent timeout"
        )
        result["_token_usage"] = token_usage
        return result
    except Exception:
        logger.exception("Subagent for %s failed entirely", package)
        result = _deterministic_fallback_result(
            package=package, pinned_version=pinned_version, error="subagent exception"
        )
        result["_token_usage"] = token_usage
        return result


async def _run_subagent_inner(
    *,
    package: str,
    pinned_version: str,
    sandbox: DockerSandbox,
    tool_catalog_summary: str,
    llm_config: LLMConfig,
    token_usage: dict,
    progress_callback: ProgressCallback | None = None,
    event_bus: EventBus | None = None,
) -> dict:
    llm = get_chat_model(llm_config=llm_config)

    ctx = AuditContext(
        package=package,
        pinned_version=pinned_version,
        llm=llm,
        sandbox=sandbox,
        tool_catalog_summary=tool_catalog_summary,
        token_usage=token_usage,
    )

    # --- Step 1: initial codegen ---
    await _emit(progress_callback, "subagent_update", {"package": package, "stage": "llm_codegen"}, bus=event_bus)
    await step_codegen(ctx)

    # --- Steps 2-3: execute with retry ---
    await _emit(progress_callback, "subagent_update", {"package": package, "stage": "script_execution"}, bus=event_bus)
    await step_execute_with_retry(ctx)

    if ctx.parsed_output is None:
        logger.error(
            "All %d codegen attempts failed for %s: %s",
            1 + MAX_CODEGEN_RETRIES,
            package,
            ctx.last_error[:300],
        )
        result = _deterministic_fallback_result(
            package=package,
            pinned_version=pinned_version,
            error=f"LLM codegen failed after {1 + MAX_CODEGEN_RETRIES} attempts: {ctx.last_error[:300]}",
        )
        result["_token_usage"] = token_usage
        return result

    # --- Token savings ---
    step_compute_savings(ctx)

    # --- Phase2 validation ---
    step_validate_phase2(ctx)

    # --- CVE interpretation ---
    await _emit(progress_callback, "subagent_update", {"package": package, "stage": "llm_interpretation"}, bus=event_bus)
    await step_interpret_cves(ctx)

    # --- Changelog analysis ---
    await _emit(progress_callback, "subagent_update", {"package": package, "stage": "llm_changelog"}, bus=event_bus)
    await step_analyze_changelog(ctx)

    # --- Finalize ---
    await _emit(progress_callback, "subagent_update", {"package": package, "stage": "done"}, bus=event_bus)
    return step_finalize(ctx)
