"""LLM-based code generation for Phase A and Phase B audit scripts.

Calls the same LLM with the same prompts as the main pipeline, captures
the generated Python scripts, and returns them for execution.
"""
from __future__ import annotations

import re

from langchain_core.messages import HumanMessage, SystemMessage

from src.agent.llm import get_chat_model
from src.agent.prompts import (
    build_codegen_prompt,
    build_iteration_prompt,
    build_system_prompt,
)
from src.config.core import LLMConfig


def _extract_code_block(text: str) -> str:
    """Same extraction logic as subagent.py."""
    match = re.search(r"```python\s*\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    match = re.search(r"```\s*\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()


async def generate_phase_a(
    package: str,
    pinned_version: str,
    tool_catalog_summary: str,
    llm_config: LLMConfig | None = None,
) -> tuple[str, str, list]:
    """Have the LLM generate a Phase A audit script.

    Returns (script_source, raw_llm_response, messages) where messages
    is the conversation history for use in retry regeneration.
    """
    llm = get_chat_model(llm_config=llm_config)
    system = build_system_prompt(tool_catalog_summary)
    user = build_codegen_prompt(package, pinned_version)
    messages = [SystemMessage(content=system), HumanMessage(content=user)]

    response = await llm.ainvoke(messages)
    messages.append(response)
    raw = response.content
    script = _extract_code_block(raw)
    return script, raw, messages


async def generate_phase_b(
    package: str,
    pinned_version: str,
    core_results: dict,
    tools_needed: list[str],
    tool_catalog_summary: str,
    llm_config: LLMConfig | None = None,
) -> tuple[str | None, str | None, list | None]:
    """Phase B enrichment is already included in Phase A prompt.

    Returns (None, None, None) — Phase A script already calls EPSS, OSV,
    scorecard, deps_dev as part of the mandatory enrichment block.
    """
    return None, None, None


async def regenerate_from_error(
    error_output: str,
    previous_messages: list,
    llm_config: LLMConfig | None = None,
) -> str:
    """Send the error back to the LLM and get a corrected script.

    Appends the iteration prompt to the conversation history so the LLM
    can see its previous attempt and the resulting error.
    """
    llm = get_chat_model(llm_config=llm_config)
    retry_msg = HumanMessage(content=build_iteration_prompt(error_output))
    previous_messages.append(retry_msg)
    response = await llm.ainvoke(previous_messages)
    previous_messages.append(response)
    return _extract_code_block(response.content)
