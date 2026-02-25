"""Per-package auditor — PTC + PTD via Docker sandbox codegen.

Execution model:
  1. llm.ainvoke (codegen)  -> LLM returns Python script in a code fence
  2. Python extracts script, writes it to the Docker container, executes it
  3. Script calls MCP tools INSIDE the container (PTC)
  4. Script reads /app/tools/docs/ once per tool before first use (PTD)
  5. Raw tool responses never leave the container
  6. llm.ainvoke (CVE interpretation)  -> structured JSON output
  7. llm.ainvoke (changelog analysis)  -> structured JSON output

Direct llm.ainvoke() calls throughout — no agent wrapper.
"""
from __future__ import annotations

import ast
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
    build_phase_b_prompt,
    build_system_prompt,
)
from src.agent.schema import (
    AuditContext,
    validate_findings,
    validate_package_result,
)
from src.config.core import LLMConfig
from src.sandbox.docker_sandbox import DockerSandbox

logger = logging.getLogger(__name__)

ProgressCallback = Callable[[str, dict], Awaitable[None] | None]

MAX_CODEGEN_RETRIES = 2
MAX_SUPPLEMENTAL_CALLS = 2
SUBAGENT_TIMEOUT_SECONDS = 300

_BREAKING_HINTS = ("breaking", "deprecated", "removed", "migration", "incompatible")


def _apply_structured_narrative(audit_data: dict, package: str, pinned_version: str) -> None:
    """Build recommendation_rationale and risk_rating deterministically from actual data."""
    affecting: list[dict] = audit_data.get("cves_affecting_pinned") or []
    not_relevant: list[dict] = audit_data.get("cves_not_relevant") or []
    changelog: dict = audit_data.get("changelog") or {}
    latest_version: str = audit_data.get("latest_version") or "latest"

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

    audit_data["recommendation_rationale"] = "\n".join(rationale_lines)
    audit_data["upgrade_recommendation"] = (
        f"{package} {pinned_version} -> {latest_version}: {action}"
    )
    audit_data["risk_rating"] = risk_rating
    audit_data["breaking_changes_detected"] = breaking


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
    return validate_package_result(fallback).model_dump()


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
    """Return set of MCP servers the script statically references.

    Warn if any tool is imported without a preceding doc read.
    Note: this is static analysis of the script source — it finds tools
    that COULD be used, including those inside conditional branches.
    Actual runtime usage may be a subset (progressive discovery).
    """
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


def _extract_runtime_tools(parsed_output: dict) -> set[str]:
    """Extract which tools actually executed at runtime from the sandbox output.

    The sandbox script can include a '_tools_called' list in the output JSON.
    If absent, fall back to heuristic: check which enrichment fields are populated.
    """
    # Explicit tracking (if the LLM included it)
    explicit = parsed_output.get("_tools_called")
    if isinstance(explicit, list):
        return set(explicit)

    # Heuristic: check what data is present
    runtime: set[str] = {"nvd", "pypi", "github_api"}  # core tools
    # Phase B tool evidence
    for cve in (parsed_output.get("cves_affecting_pinned") or []):
        if isinstance(cve, dict) and cve.get("epss_score") is not None:
            runtime.add("epss")
            break
    if parsed_output.get("osv_results") or parsed_output.get("_osv_data"):
        runtime.add("osv")
    if parsed_output.get("scorecard_data") or parsed_output.get("_scorecard"):
        runtime.add("scorecard")
    if parsed_output.get("dependency_info") or parsed_output.get("_deps_dev"):
        runtime.add("deps_dev")
    return runtime


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
    logger.info("LLM generated script for %s (%d chars, servers=%s)", ctx.package, len(ctx.script_source), sorted(ctx.servers_used))
    ctx.messages.append(response)


def _syntax_check(script: str, package: str) -> str | None:
    """Quick ast.parse check — catches syntax errors before Docker round-trip.

    Returns None if valid, or the error message if invalid.
    """
    try:
        ast.parse(script)
        return None
    except SyntaxError as e:
        return f"line {e.lineno}: {e.msg}"


async def step_execute_with_retry(ctx: AuditContext) -> None:
    """Steps 2-3: Write script to sandbox, execute, retry on failure."""
    script_path = f"/app/code/phase2_{re.sub(r'[^a-zA-Z0-9_.-]+', '_', ctx.package)}.py"

    for attempt in range(1 + MAX_CODEGEN_RETRIES):
        ctx.attempt = attempt

        # Pre-flight syntax check — avoids a Docker round-trip on obvious errors
        syntax_err = _syntax_check(ctx.script_source, ctx.package)
        if syntax_err:
            logger.warning("Syntax error in generated script for %s: %s", ctx.package, syntax_err)
            ctx.last_error = f"SyntaxError in generated script: {syntax_err}"
            if attempt < MAX_CODEGEN_RETRIES:
                retry_msg = HumanMessage(content=build_iteration_prompt(ctx.last_error))
                ctx.messages.append(retry_msg)
                response = await ctx.llm.ainvoke(ctx.messages)
                _track_tokens(ctx, response)
                ctx.script_source = _extract_code_block(response.content)
                ctx.messages.append(response)
            continue

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


def _merge_phase_b(core: dict, phase_b: dict) -> None:
    """Merge Phase B enrichment data into core results (in-place)."""
    # EPSS scores on CVEs
    phase_b_cves = phase_b.get("cves_affecting_pinned", [])
    if isinstance(phase_b_cves, list):
        epss_map = {}
        for cve in phase_b_cves:
            if isinstance(cve, dict) and cve.get("epss_score") is not None:
                epss_map[cve.get("cve_id")] = cve.get("epss_score")
        for cve in (core.get("cves_affecting_pinned") or []):
            if isinstance(cve, dict) and cve.get("cve_id") in epss_map:
                cve["epss_score"] = epss_map[cve["cve_id"]]
    # OSV / scorecard / deps_dev enrichment
    for key in ("osv_results", "_osv_data", "scorecard_data", "_scorecard",
                "dependency_info", "_deps_dev"):
        if phase_b.get(key):
            core[key] = phase_b[key]


async def step_codegen_phase_b(ctx: AuditContext) -> None:
    """Phase B: LLM writes enrichment script using only the tools it requested."""
    raw_tools = ctx.parsed_output.get("_tools_needed", [])
    logger.info("[PTD] %s: raw _tools_needed from LLM: %s", ctx.package, raw_tools)
    valid_tools = {"epss", "osv", "scorecard", "deps_dev"}
    # Accept both "epss" and "epss/get_exploit_probability" formats
    tools_needed = []
    for t in raw_tools:
        server = t.split("/")[0] if isinstance(t, str) else ""
        if server in valid_tools and server not in tools_needed:
            tools_needed.append(server)

    if not tools_needed:
        ctx.phase_b_skipped = True
        ctx.phase_b_tools_loaded = []
        logger.info("[PTD] %s: Phase B skipped — no tools requested by LLM", ctx.package)
        return

    ctx.phase_b_tools_loaded = tools_needed
    logger.info("[PTD] %s: Phase B tools requested by LLM: %s", ctx.package, tools_needed)

    # Write core results to sandbox file so Phase B script reads from disk
    # (avoids embedding huge base64 strings in the prompt that the LLM breaks)
    core_json = json.dumps(ctx.parsed_output, ensure_ascii=False)
    safe_name = re.sub(r'[^a-zA-Z0-9_.-]+', '_', ctx.package)
    await ctx.sandbox.awrite(f"/app/code/core_results_{safe_name}.json", core_json)

    prompt = build_phase_b_prompt(
        package_name=ctx.package,
        pinned_version=ctx.pinned_version,
        core_results=ctx.parsed_output,
        tools_needed=tools_needed,
    )
    if prompt is None:
        ctx.phase_b_skipped = True
        return

    system_msg = SystemMessage(content=build_system_prompt(ctx.tool_catalog_summary))
    phase_b_msg = HumanMessage(content=prompt)
    response = await ctx.llm.ainvoke([system_msg, phase_b_msg])
    _track_tokens(ctx, response)
    ctx.phase_b_script = _extract_code_block(response.content)
    logger.info("[PTD] %s: Phase B script generated (%d chars)", ctx.package, len(ctx.phase_b_script))


async def step_execute_phase_b(ctx: AuditContext) -> None:
    """Execute Phase B enrichment script in sandbox, with one retry on failure."""
    if ctx.phase_b_skipped or not ctx.phase_b_script:
        return

    script_path = f"/app/code/phase_b_{re.sub(r'[^a-zA-Z0-9_.-]+', '_', ctx.package)}.py"
    # Build the conversation context once — retry needs the original Phase B prompt
    phase_b_prompt = build_phase_b_prompt(
        package_name=ctx.package,
        pinned_version=ctx.pinned_version,
        core_results=ctx.parsed_output,
        tools_needed=ctx.phase_b_tools_loaded,
    )
    system_msg = SystemMessage(content=build_system_prompt(ctx.tool_catalog_summary))
    messages = [system_msg, HumanMessage(content=phase_b_prompt)]

    for attempt in range(2):  # 1 initial + 1 retry
        syntax_err = _syntax_check(ctx.phase_b_script, ctx.package)
        if syntax_err:
            logger.warning("[PTD] %s: Phase B syntax error (attempt %d): %s", ctx.package, attempt, syntax_err)
            if attempt == 0:
                retry_msg = HumanMessage(content=build_iteration_prompt(f"Phase B script syntax error: {syntax_err}"))
                messages.append(retry_msg)
                response = await ctx.llm.ainvoke(messages)
                _track_tokens(ctx, response)
                ctx.phase_b_script = _extract_code_block(response.content)
                messages.append(response)
                continue
            return  # give up after retry

        await ctx.sandbox.awrite(script_path, ctx.phase_b_script)
        exec_result = await ctx.sandbox.aexecute(f"python3 {script_path}")

        if exec_result.exit_code == 0:
            try:
                phase_b_output = _parse_json_stdout(exec_result.output)
                _merge_phase_b(ctx.parsed_output, phase_b_output)
                phase_b_tools = phase_b_output.get("_tools_called", [])
                core_tools = ctx.parsed_output.get("_tools_called", [])
                if isinstance(core_tools, list) and isinstance(phase_b_tools, list):
                    ctx.parsed_output["_tools_called"] = list(set(core_tools + phase_b_tools))
                logger.info("[PTD] %s: Phase B executed successfully", ctx.package)
                return  # success
            except Exception as exc:
                logger.warning("[PTD] %s: Phase B output parse error: %s", ctx.package, str(exc)[:200])
                return  # parse error is not retryable
        else:
            error_output = (exec_result.output or "")[:3000]
            logger.warning("[PTD] %s: Phase B execution failed (attempt %d, exit %d): %s",
                          ctx.package, attempt, exec_result.exit_code, error_output[:300])
            if attempt == 0:
                retry_msg = HumanMessage(content=build_iteration_prompt(error_output))
                messages.append(retry_msg)
                response = await ctx.llm.ainvoke(messages)
                _track_tokens(ctx, response)
                ctx.phase_b_script = _extract_code_block(response.content)
                messages.append(response)
                continue
            return  # give up after retry


def step_compute_savings(ctx: AuditContext) -> None:
    """Token savings estimate: PTC + PTD breakdown (pure math, no I/O).

    PTC: raw tool responses stay in sandbox, never enter LLM context.
    PTD: tool docs are read at runtime in the sandbox, not injected into the
         LLM codegen prompt.  Progressive = the script only reads docs for
         tools it actually needs based on intermediate results.

    ReAct baseline = actual_tokens + sandbox_payload/4 + eager_doc_tokens
    PTC savings    = sandbox_payload / 4
    PTD savings    = eager_doc_tokens - system_overhead
    """
    parsed = ctx.parsed_output
    sandbox_data_chars = len(json.dumps(parsed))
    ptc_tool_response_tokens_avoided = sandbox_data_chars // 4

    # PTD token savings — real per-package accounting.
    #
    # Without PTD (eager): codegen prompt would inject full schemas for ALL
    # Phase B tools upfront = N_PHASE_B_TOOLS * TOKENS_PER_PHASE_B_SCHEMA.
    #
    # With real PTD: core prompt has only a lightweight catalog (~50 tokens).
    # Phase B schemas load ONLY for tools the LLM requested after seeing
    # core results. Savings = schemas we didn't load.
    #
    # Per-package variance:
    # - Clean package (0 Phase B tools) → saves all Phase B schema tokens
    # - CVE-heavy package (3 tools) → saves only 1 tool's schema tokens
    N_PHASE_B_TOOLS = 4              # epss, osv, scorecard, deps_dev
    TOKENS_PER_PHASE_B_SCHEMA = 85   # measured: epss~93, osv~75, scorecard~92, deps_dev~80
    CATALOG_OVERHEAD = 50            # lightweight catalog in core prompt

    # Static analysis: tools referenced in the script (includes conditional branches)
    static_tools = ctx.servers_used
    # Runtime analysis: tools that actually executed (from output data)
    runtime_tools = _extract_runtime_tools(parsed)

    n_available = 8  # total tools (core + Phase B)
    n_runtime = len(runtime_tools)

    # Phase B schemas the LLM requested (0 for clean packages, up to 4 for CVE-heavy)
    n_phase_b_loaded = len(ctx.phase_b_tools_loaded)
    eager_phase_b_tokens = N_PHASE_B_TOOLS * TOKENS_PER_PHASE_B_SCHEMA  # 340
    ptd_tokens_avoided = max(eager_phase_b_tokens - (n_phase_b_loaded * TOKENS_PER_PHASE_B_SCHEMA) - CATALOG_OVERHEAD, 0)

    ptc_actual_tokens = ctx.token_usage["total_tokens"]
    estimated_react_total = ptc_actual_tokens + ptc_tool_response_tokens_avoided + eager_phase_b_tokens
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
        "ptd_tools_static": sorted(static_tools),
        "ptd_tools_runtime": sorted(runtime_tools),
        "ptd_tools_available": n_available,
        "ptd_tools_skipped": n_available - n_runtime,
        "ptd_phase_b_tools_loaded": ctx.phase_b_tools_loaded,
        "ptd_phase_b_skipped": ctx.phase_b_skipped,
        "total_tokens_saved": total_saved,
        "total_savings_pct": round(
            total_saved / estimated_react_total * 100, 1
        ) if estimated_react_total > 0 else 0.0,
        "sandbox_data_chars": sandbox_data_chars,
    }
    logger.info(
        "[SAVINGS] %s: actual=%d tok | ReAct~%d | "
        "PTC saves %d tok (%.1f%%) | PTD saves %d tok (%.1f%%) | combined %.1f%% | "
        "phase_b_loaded=%s | runtime_tools=%s",
        ctx.package,
        ptc_actual_tokens,
        estimated_react_total,
        ptc_tool_response_tokens_avoided, ctx.token_savings["ptc_savings_pct"],
        ptd_tokens_avoided,               ctx.token_savings["ptd_savings_pct"],
        ctx.token_savings["total_savings_pct"],
        ctx.phase_b_tools_loaded,
        sorted(runtime_tools),
    )


def step_validate_findings(ctx: AuditContext) -> None:
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
    validated_p2 = validate_findings(parsed)
    ctx.audit_data = validated_p2.model_dump()
    logger.info(
        "VALIDATE_DEBUG %s: affecting=%d, not_relevant=%d, needs_interp=%d, ids_affecting=%s",
        ctx.package,
        len(ctx.audit_data.get("cves_affecting_pinned", [])),
        len(ctx.audit_data.get("cves_not_relevant", [])),
        len(ctx.audit_data.get("needs_interpretation", [])),
        [c.get("cve_id") for c in ctx.audit_data.get("cves_affecting_pinned", []) if isinstance(c, dict)],
    )


async def step_interpret_cves(ctx: AuditContext) -> None:
    """LLM interpretation for ambiguous CVEs."""
    needs_interp = ctx.audit_data.get("needs_interpretation", [])
    MAX_INTERP_BATCH = 15

    if needs_interp and ctx.supplemental_calls < MAX_SUPPLEMENTAL_CALLS:
        ctx.supplemental_calls += 1
        batch = needs_interp[:MAX_INTERP_BATCH]
        logger.info(
            "INTERP_DEBUG %s: %d needs_interpretation CVEs, ids=%s",
            ctx.package, len(batch),
            [c.get("cve_id") for c in batch if isinstance(c, dict)],
        )
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
            logger.info(
                "INTERP_DEBUG %s: raw LLM response=%s",
                ctx.package, interp_response.content[:500],
            )
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
            ctx.audit_data["cves_affecting_pinned"].extend(new_affecting)
            ctx.audit_data["cves_not_relevant"].extend(new_not_relevant)
            ctx.audit_data["needs_interpretation"] = []
            ctx.audit_data["total_cves_found"] = (
                len(ctx.audit_data["cves_affecting_pinned"]) + len(ctx.audit_data["cves_not_relevant"])
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
    latest_version = ctx.audit_data.get("latest_version") or "latest"
    changelog_data = ctx.audit_data.get("changelog", {})

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
                ctx.audit_data["breaking_changes_detected"] = cl_parsed.get("breaking_changes_detected", False)
                if "changelog_analysis" in cl_parsed:
                    ctx.audit_data["changelog_analysis"] = cl_parsed["changelog_analysis"]
                ctx.audit_data["recommendation_rationale"] = cl_parsed.get(
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
            ctx.audit_data.setdefault("breaking_changes_detected", False)
            ctx.audit_data.setdefault(
                "recommendation_rationale",
                f"Changelog analysis unavailable for {ctx.package}; upgrade decision should rely on CVE posture.",
            )


def step_finalize(ctx: AuditContext) -> dict:
    """Deterministic narrative + Phase3 validation. Returns the final result dict."""
    _apply_structured_narrative(ctx.audit_data, ctx.package, ctx.pinned_version)

    ctx.audit_data.setdefault("breaking_changes_detected", False)
    ctx.audit_data.setdefault("recommendation_rationale", "")

    validated_p3 = validate_package_result(ctx.audit_data)
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

    await _emit(progress_callback, "subagent_update", {"package": package, "stage": "llm_codegen"}, bus=event_bus)
    await step_codegen(ctx)

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

    # --- Phase B: progressive tool discovery ---
    await _emit(progress_callback, "subagent_update", {"package": package, "stage": "phase_b_codegen"}, bus=event_bus)
    await step_codegen_phase_b(ctx)
    if not ctx.phase_b_skipped:
        tools_label = ", ".join(ctx.phase_b_tools_loaded)
        await _emit(progress_callback, "subagent_update", {
            "package": package, "stage": "phase_b_execution",
            "phase_b_tools": ctx.phase_b_tools_loaded,
        }, bus=event_bus)
        await step_execute_phase_b(ctx)
    else:
        await _emit(progress_callback, "subagent_update", {
            "package": package, "stage": "phase_b_skipped",
        }, bus=event_bus)

    # --- Token savings ---
    step_compute_savings(ctx)

    # --- Phase2 validation ---
    step_validate_findings(ctx)

    # --- CVE interpretation ---
    await _emit(progress_callback, "subagent_update", {"package": package, "stage": "llm_interpretation"}, bus=event_bus)
    await step_interpret_cves(ctx)

    # --- Changelog analysis ---
    await _emit(progress_callback, "subagent_update", {"package": package, "stage": "llm_changelog"}, bus=event_bus)
    await step_analyze_changelog(ctx)

    # --- Finalize ---
    await _emit(progress_callback, "subagent_update", {"package": package, "stage": "done"}, bus=event_bus)
    return step_finalize(ctx)
