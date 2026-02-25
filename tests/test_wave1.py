"""Structural verification — step functions importable, AuditContext defaults, no agent framework."""
import ast
import pathlib
from unittest.mock import AsyncMock, MagicMock

import pytest


def test_no_create_agent():
    source = pathlib.Path("src/agent/subagent.py").read_text()
    assert "create_agent" not in source
    assert "from langchain.agents" not in source


def test_step_functions_importable():
    from src.agent.subagent import (
        step_codegen,
        step_execute_with_retry,
        step_compute_savings,
        step_validate_findings,
        step_interpret_cves,
        step_analyze_changelog,
        step_finalize,
    )
    assert callable(step_codegen)
    assert callable(step_execute_with_retry)
    assert callable(step_compute_savings)
    assert callable(step_validate_findings)
    assert callable(step_interpret_cves)
    assert callable(step_analyze_changelog)
    assert callable(step_finalize)


def test_audit_context():
    from src.agent.schema import AuditContext

    ctx = AuditContext(
        package="test",
        pinned_version="1.0.0",
        llm=None,
        sandbox=None,
        tool_catalog_summary="",
    )
    assert ctx.attempt == 0
    assert ctx.parsed_output is None
    assert ctx.token_usage["total_tokens"] == 0
    assert ctx.messages == []
    assert ctx.script_source == ""
    assert ctx.last_error == ""
    assert ctx.audit_data == {}
    assert ctx.token_savings == {}
    assert ctx.supplemental_calls == 0


@pytest.mark.asyncio
async def test_step_execute_with_retry():
    from src.agent.schema import AuditContext
    from src.agent.subagent import step_codegen, step_execute_with_retry

    mock_llm = AsyncMock()
    mock_response = MagicMock()
    mock_response.content = '```python\nprint("hello")\n```'
    mock_response.usage_metadata = {"input_tokens": 10, "output_tokens": 5}
    mock_llm.ainvoke = AsyncMock(return_value=mock_response)

    mock_sandbox = AsyncMock()
    fail_result = MagicMock()
    fail_result.exit_code = 1
    fail_result.output = "NameError: name 'foo' is not defined"

    success_result = MagicMock()
    success_result.exit_code = 0
    success_result.output = '{"package": "test", "pinned_version": "1.0.0"}'

    mock_sandbox.aexecute = AsyncMock(side_effect=[fail_result, success_result])
    mock_sandbox.awrite = AsyncMock()

    ctx = AuditContext(
        package="test-pkg",
        pinned_version="1.0.0",
        llm=mock_llm,
        sandbox=mock_sandbox,
        tool_catalog_summary="tools here",
    )

    await step_codegen(ctx)
    await step_execute_with_retry(ctx)

    assert ctx.parsed_output is not None
    assert ctx.parsed_output["package"] == "test"
    assert ctx.attempt == 1
    assert mock_sandbox.aexecute.call_count == 2


def test_no_langgraph_dep():
    toml = pathlib.Path("pyproject.toml").read_text()
    assert "langgraph" not in toml
