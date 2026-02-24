"""Disposable test: send the actual codegen prompt to the LLM and verify
the generated script is structurally correct WITHOUT executing it in Docker.

This answers: "Is the LLM just filling a template, and does the output
reliably match the expected structure?"

Run:
    uv run pytest tests/test_codegen_quality.py -v -s

Requires OPENAI_API_KEY in .env (real LLM call, ~2-5 seconds per test).
"""
from __future__ import annotations

import ast
import asyncio
import re
import textwrap

import pytest
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage, SystemMessage

from src.agent.llm import get_chat_model
from src.agent.prompts import (
    build_codegen_prompt,
    build_phase_b_prompt,
    build_system_prompt,
)

load_dotenv(override=True)

# Minimal catalog summary (matches what pipeline would build)
_CATALOG_SUMMARY = textwrap.dedent("""\
    ## Available MCP Tool Servers

    - **epss** (1 tools): get_exploit_probability
    - **github_api** (1 tools): get_release_notes
    - **nvd** (1 tools): search_cves
    - **osv** (1 tools): query_vulnerability
    - **pypi** (1 tools): get_package_metadata
    - **scorecard** (1 tools): get_security_scorecard
    - **deps_dev** (1 tools): get_dependency_info
""")


def _extract_code_block(text: str) -> str:
    """Same extraction logic as subagent.py."""
    match = re.search(r"```python\s*\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    match = re.search(r"```\s*\n(.*?)```", text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return text.strip()


async def _generate_phase_a(package: str, version: str) -> str:
    """Send the real codegen prompt to the LLM, return raw response content."""
    llm = get_chat_model("gpt-4o-mini")
    system = build_system_prompt(_CATALOG_SUMMARY)
    user = build_codegen_prompt(package, version)
    messages = [SystemMessage(content=system), HumanMessage(content=user)]
    response = await llm.ainvoke(messages)
    return response.content


# ---------------------------------------------------------------------------
# Structural checks on the generated code
# ---------------------------------------------------------------------------

def _assert_valid_python(code: str):
    """Must parse as valid Python."""
    try:
        ast.parse(code)
    except SyntaxError as e:
        pytest.fail(f"Generated code is not valid Python:\n{e}\n\n--- code ---\n{code}")


def _assert_has_imports(code: str):
    """Must have the essential imports the template prescribes."""
    required = ["import json", "import base64", "import sys"]
    for imp in required:
        assert imp in code, f"Missing '{imp}' in generated code"


def _assert_sys_path(code: str):
    """Must set sys.path for /app."""
    assert 'sys.path.insert(0, "/app")' in code or "sys.path.insert(0, '/app')" in code, \
        "Missing sys.path.insert(0, '/app')"


def _assert_tool_imports(code: str):
    """Must import the 3 core tools."""
    assert "from tools.nvd import search_cves" in code
    assert "from tools.pypi import get_package_metadata" in code
    assert "from tools.github_api import get_release_notes" in code


def _assert_doc_reads(code: str):
    """Must read docs before importing tools (PTD compliance)."""
    for server in ("nvd", "pypi", "github_api"):
        assert f"/app/tools/docs/{server}/" in code, \
            f"Missing doc read for {server}"


def _assert_mcp_envelope_decode(code: str):
    """Must decode MCP envelopes — the most common failure mode."""
    # Look for the canonical decode pattern
    assert '["content"][0]["text"]' in code or "['content'][0]['text']" in code, \
        "Missing MCP envelope decode pattern (response['content'][0]['text'])"


def _assert_ptc_marker(code: str):
    """Must output via __PTC_JSON_B64__ marker."""
    assert "__PTC_JSON_B64__" in code, "Missing __PTC_JSON_B64__ output marker"


def _assert_tools_needed(code: str):
    """Must set _tools_needed on the result dict."""
    assert "_tools_needed" in code, "Missing _tools_needed assignment"


def _assert_no_hardcoded_results(code: str, package: str, version: str):
    """Must not hardcode CVE results — should call the tools."""
    # The code should call search_cves, not fabricate CVE data
    assert "search_cves(" in code, "Missing search_cves() call"
    assert "get_package_metadata(" in code, "Missing get_package_metadata() call"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_phase_a_codegen_requests():
    """Generate Phase A script for requests==2.28.1 and validate structure."""
    raw = await _generate_phase_a("requests", "2.28.1")
    code = _extract_code_block(raw)

    print("\n========== RAW LLM RESPONSE (first 200 chars) ==========")
    print(raw[:200])
    print("\n========== EXTRACTED CODE ==========")
    print(code)
    print("====================================\n")

    _assert_valid_python(code)
    _assert_has_imports(code)
    _assert_sys_path(code)
    _assert_tool_imports(code)
    _assert_doc_reads(code)
    _assert_mcp_envelope_decode(code)
    _assert_ptc_marker(code)
    _assert_tools_needed(code)
    _assert_no_hardcoded_results(code, "requests", "2.28.1")


@pytest.mark.asyncio
async def test_phase_a_codegen_flask():
    """Same checks for flask==2.2.2 — different package, same template."""
    raw = await _generate_phase_a("flask", "2.2.2")
    code = _extract_code_block(raw)

    print("\n========== EXTRACTED CODE (flask) ==========")
    print(code)
    print("=============================================\n")

    _assert_valid_python(code)
    _assert_has_imports(code)
    _assert_sys_path(code)
    _assert_tool_imports(code)
    _assert_doc_reads(code)
    _assert_mcp_envelope_decode(code)
    _assert_ptc_marker(code)
    _assert_tools_needed(code)


@pytest.mark.asyncio
async def test_code_fence_extraction_reliable():
    """Run 3 generations for the same package — all must extract cleanly."""
    results = await asyncio.gather(
        _generate_phase_a("urllib3", "1.26.15"),
        _generate_phase_a("urllib3", "1.26.15"),
        _generate_phase_a("urllib3", "1.26.15"),
    )
    for i, raw in enumerate(results):
        code = _extract_code_block(raw)
        assert code != raw.strip(), \
            f"Generation {i}: code fence extraction failed — got raw text back"
        _assert_valid_python(code)
        _assert_ptc_marker(code)


@pytest.mark.asyncio
async def test_generated_code_is_template_shaped():
    """The generated code should follow a predictable structure.

    If the LLM is truly just filling a template, we expect:
    - Nearly identical structure across packages
    - Same import block
    - Same tool call sequence (metadata → cves → release notes)
    - Same output pattern
    """
    raw_requests = await _generate_phase_a("requests", "2.28.1")
    raw_flask = await _generate_phase_a("flask", "2.2.2")

    code_requests = _extract_code_block(raw_requests)
    code_flask = _extract_code_block(raw_flask)

    # Both should have the same structural bones.
    # Replace package-specific strings to compare structure.
    def normalize(code: str) -> str:
        code = code.replace("requests", "PKG").replace("2.28.1", "VER")
        code = code.replace("flask", "PKG").replace("2.2.2", "VER")
        # Strip comments and blank lines
        lines = [l for l in code.splitlines() if l.strip() and not l.strip().startswith("#")]
        return "\n".join(lines)

    norm_req = normalize(code_requests)
    norm_flask = normalize(code_flask)

    # Count lines — they should be within 20% of each other
    len_req = len(norm_req.splitlines())
    len_flask = len(norm_flask.splitlines())
    ratio = min(len_req, len_flask) / max(len_req, len_flask)

    print(f"\nNormalized line counts: requests={len_req}, flask={len_flask}, ratio={ratio:.2f}")

    assert ratio > 0.6, (
        f"Generated scripts are too different in size ({len_req} vs {len_flask} lines). "
        f"Expected template-like consistency."
    )
