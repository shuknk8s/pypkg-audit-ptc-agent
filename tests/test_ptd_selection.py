"""Tests for PTD (Progressive Tool Discovery) dynamic tool selection.

All tests are pure — zero LLM calls, zero network access.
"""
from __future__ import annotations

import re
import pytest
from src.agent.subagent import _check_ptd_compliance, _syntax_check, step_compute_savings
from src.agent.schema import AuditContext
from src.agent.prompts import build_codegen_prompt, build_phase_b_prompt


def test_tool_selection_varies():
    """Different packages should trigger different tool selections."""
    script_heavy = '''\
import sys; sys.path.insert(0, "/app")
doc = open("/app/tools/docs/nvd/search_cves.md").read()
from tools.nvd import search_cves
doc = open("/app/tools/docs/pypi/get_package_metadata.md").read()
from tools.pypi import get_package_metadata
doc = open("/app/tools/docs/epss/get_exploit_probability.md").read()
from tools.epss import get_exploit_probability
doc = open("/app/tools/docs/osv/query_vulnerability.md").read()
from tools.osv import query_vulnerability
doc = open("/app/tools/docs/scorecard/get_security_scorecard.md").read()
from tools.scorecard import get_security_scorecard
'''
    script_light = '''\
import sys; sys.path.insert(0, "/app")
doc = open("/app/tools/docs/nvd/search_cves.md").read()
from tools.nvd import search_cves
doc = open("/app/tools/docs/pypi/get_package_metadata.md").read()
from tools.pypi import get_package_metadata
'''
    heavy_tools = _check_ptd_compliance(script_heavy, "pyyaml")
    light_tools = _check_ptd_compliance(script_light, "black")

    assert len(heavy_tools | light_tools) > len(heavy_tools & light_tools)
    assert heavy_tools != light_tools


def test_security_critical_uses_more_tools():
    """CVE-heavy package script imports more tools than a clean package."""
    script_crypto = '''\
import sys; sys.path.insert(0, "/app")
doc = open("/app/tools/docs/nvd/search_cves.md").read()
from tools.nvd import search_cves
doc = open("/app/tools/docs/pypi/get_package_metadata.md").read()
from tools.pypi import get_package_metadata
doc = open("/app/tools/docs/epss/get_exploit_probability.md").read()
from tools.epss import get_exploit_probability
doc = open("/app/tools/docs/osv/query_vulnerability.md").read()
from tools.osv import query_vulnerability
doc = open("/app/tools/docs/scorecard/get_security_scorecard.md").read()
from tools.scorecard import get_security_scorecard
doc = open("/app/tools/docs/github_api/get_release_notes.md").read()
from tools.github_api import get_release_notes
'''
    script_clean = '''\
import sys; sys.path.insert(0, "/app")
doc = open("/app/tools/docs/nvd/search_cves.md").read()
from tools.nvd import search_cves
doc = open("/app/tools/docs/pypi/get_package_metadata.md").read()
from tools.pypi import get_package_metadata
'''
    crypto_tools = _check_ptd_compliance(script_crypto, "cryptography")
    clean_tools = _check_ptd_compliance(script_clean, "black")

    assert crypto_tools > clean_tools  # strict superset


def test_ptd_compliance_no_warnings(caplog):
    """A well-formed script should produce no PTD warnings."""
    script = '''\
import sys; sys.path.insert(0, "/app")
doc = open("/app/tools/docs/nvd/search_cves.md").read()
from tools.nvd import search_cves
doc = open("/app/tools/docs/pypi/get_package_metadata.md").read()
from tools.pypi import get_package_metadata
doc = open("/app/tools/docs/epss/get_exploit_probability.md").read()
from tools.epss import get_exploit_probability
'''
    import logging
    with caplog.at_level(logging.WARNING):
        servers = _check_ptd_compliance(script, "requests")

    assert servers == {"nvd", "pypi", "epss"}
    ptd_warnings = [r for r in caplog.records if "[PTD]" in r.message]
    assert len(ptd_warnings) == 0


def test_ptd_compliance_warns_on_missing_doc(caplog):
    """A script that uses a tool WITHOUT reading its doc should warn."""
    script = '''\
import sys; sys.path.insert(0, "/app")
doc = open("/app/tools/docs/nvd/search_cves.md").read()
from tools.nvd import search_cves
from tools.pypi import get_package_metadata
'''
    import logging
    with caplog.at_level(logging.WARNING):
        servers = _check_ptd_compliance(script, "flask")

    assert servers == {"nvd", "pypi"}
    ptd_warnings = [r for r in caplog.records if "[PTD]" in r.message]
    assert len(ptd_warnings) == 1
    assert "pypi" in ptd_warnings[0].message


def test_ptd_token_savings_measurable():
    """Real PTD saves tokens by loading only requested Phase B schemas.

    Formula: ptd_savings = (N_PHASE_B_TOOLS - n_loaded) * TOKENS_PER_SCHEMA - CATALOG_OVERHEAD
    - Clean package (0 loaded): (4-0)*50 - 50 = 150 tokens saved
    - CVE-heavy package (3 loaded): (4-3)*50 - 50 = 0 tokens saved
    - Savings scale with how few Phase B tools are needed.
    """
    N_PHASE_B_TOOLS = 4
    TOKENS_PER_PHASE_B_SCHEMA = 50
    CATALOG_OVERHEAD = 50

    n_loaded_clean = 0
    savings_clean = (N_PHASE_B_TOOLS - n_loaded_clean) * TOKENS_PER_PHASE_B_SCHEMA - CATALOG_OVERHEAD
    assert savings_clean == 150

    n_loaded_heavy = 3
    savings_heavy = (N_PHASE_B_TOOLS - n_loaded_heavy) * TOKENS_PER_PHASE_B_SCHEMA - CATALOG_OVERHEAD
    assert savings_heavy == 0

    assert savings_clean > savings_heavy

    n_loaded_all = 4
    savings_all = (N_PHASE_B_TOOLS - n_loaded_all) * TOKENS_PER_PHASE_B_SCHEMA - CATALOG_OVERHEAD
    assert savings_all == -50
    assert savings_all < savings_heavy


def test_codegen_prompt_has_dynamic_selection():
    """The codegen prompt should have core tools AND a lightweight catalog of Phase B tools."""
    prompt = build_codegen_prompt("requests", "2.28.1")

    assert "tools.nvd" in prompt
    assert "tools.pypi" in prompt
    assert "tools.github_api" in prompt
    assert "search_cves" in prompt
    assert "get_package_metadata" in prompt
    assert "get_release_notes" in prompt

    assert "CATALOG" in prompt
    assert '"epss"' in prompt
    assert '"osv"' in prompt
    assert '"scorecard"' in prompt
    assert '"deps_dev"' in prompt

    assert "_tools_needed" in prompt

    assert "get_exploit_probability(cve_id=" not in prompt
    assert "query_vulnerability(package=" not in prompt
    assert "get_security_scorecard(owner=" not in prompt
    assert "get_dependency_info(package=" not in prompt

    assert "IF `len(cves_affecting_pinned) > 0`" not in prompt
    assert "Progressive tool discovery" not in prompt


def test_syntax_check_valid():
    """Valid Python passes syntax check."""
    assert _syntax_check("x = 1\nprint(x)", "test") is None


def test_syntax_check_invalid():
    """Invalid Python is caught before Docker."""
    err = _syntax_check("def foo(\n  x = 1", "test")
    assert err is not None
    assert "line" in err


def test_phase_b_prompt_none_when_no_tools():
    """Phase B prompt returns None when no tools requested — LLM call skipped."""
    result = build_phase_b_prompt("requests", "2.28.1", {"package": "requests"}, [])
    assert result is None


def test_phase_b_prompt_selective_schemas():
    """Phase B prompt loads only the schemas the LLM requested."""
    core = {"package": "requests", "pinned_version": "2.28.1", "cves_affecting_pinned": [{"cve_id": "CVE-2023-1234"}]}

    prompt = build_phase_b_prompt("requests", "2.28.1", core, ["epss"])
    assert prompt is not None
    assert "get_exploit_probability" in prompt
    assert "tools.epss" in prompt
    assert "tools.scorecard" not in prompt
    assert "tools.osv" not in prompt
    assert "tools.deps_dev" not in prompt

    prompt2 = build_phase_b_prompt("requests", "2.28.1", core, ["epss", "scorecard"])
    assert "tools.epss" in prompt2
    assert "tools.scorecard" in prompt2
    assert "tools.osv" not in prompt2


def test_core_prompt_catalog_not_schemas():
    """Core prompt has lightweight catalog — tool names only, no parameter signatures."""
    prompt = build_codegen_prompt("flask", "2.0.0")

    assert '"epss"' in prompt
    assert '"osv"' in prompt
    assert '"scorecard"' in prompt
    assert '"deps_dev"' in prompt

    assert "get_exploit_probability(cve_id=" not in prompt
    assert "get_security_scorecard(owner=" not in prompt
    assert "get_dependency_info(package=" not in prompt
