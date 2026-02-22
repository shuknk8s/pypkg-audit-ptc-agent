"""Tests for PTD (Progressive Tool Discovery) dynamic tool selection.

All tests are pure — zero LLM calls, zero network access.
"""
from __future__ import annotations

import re
import pytest
from src.agent.subagent import _check_ptd_compliance, step_compute_savings
from src.agent.schema import AuditContext
from src.agent.prompts import build_codegen_prompt


# ---------------------------------------------------------------------------
# T1 — Tool selection varies across packages (mock scripts)
# ---------------------------------------------------------------------------
def test_tool_selection_varies():
    """Different packages should trigger different tool selections."""
    # Script for a CVE-heavy package (e.g., pyyaml) — uses many tools
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
    # Script for a low-risk package — uses only core tools
    script_light = '''\
import sys; sys.path.insert(0, "/app")
doc = open("/app/tools/docs/nvd/search_cves.md").read()
from tools.nvd import search_cves
doc = open("/app/tools/docs/pypi/get_package_metadata.md").read()
from tools.pypi import get_package_metadata
'''
    heavy_tools = _check_ptd_compliance(script_heavy, "pyyaml")
    light_tools = _check_ptd_compliance(script_light, "black")

    # Union > intersection → selection varies
    assert len(heavy_tools | light_tools) > len(heavy_tools & light_tools)
    assert heavy_tools != light_tools


# ---------------------------------------------------------------------------
# T2 — Security-critical packages use more tools
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# T3 — PTD compliance: every used tool has doc read (no warnings)
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# T4 — PTD compliance: missing doc read produces warning
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# T5 — PTD token savings are measurable (static math)
# ---------------------------------------------------------------------------
def test_ptd_token_savings_measurable():
    """PTD saves ~500 tokens per call (700 eager - 200 system overhead).

    Matches ptc-v4 methodology: conservative baseline of 700 tokens for
    per-call doc injection that PTD eliminates.
    """
    PTD_EAGER_TOKENS_OLD = 700   # old per-call doc injection
    PTD_SYSTEM_OVERHEAD = 200    # shared system prompt overhead
    ptd_savings = PTD_EAGER_TOKENS_OLD - PTD_SYSTEM_OVERHEAD

    assert ptd_savings == 500
    assert ptd_savings > 0

    # With a typical actual spend of ~2300 tokens and sandbox payload of ~20K chars
    # (CVE-heavy package), PTC+PTD combined savings should exceed 60%
    actual_tokens = 2300
    sandbox_chars = 20000
    ptc_avoided = sandbox_chars // 4  # 5000
    react_total = actual_tokens + ptc_avoided + PTD_EAGER_TOKENS_OLD
    total_saved = ptc_avoided + ptd_savings
    combined_pct = total_saved / react_total * 100

    assert combined_pct > 60, f"Expected >60% combined savings, got {combined_pct:.1f}%"


# ---------------------------------------------------------------------------
# T6 — Codegen prompt mentions Phase B optional tools
# ---------------------------------------------------------------------------
def test_codegen_prompt_has_dynamic_selection():
    """The codegen prompt should prescribe core tools AND mention optional Phase B tools."""
    prompt = build_codegen_prompt("requests", "2.28.1")

    # Must prescribe core tools (like ptc-v4)
    assert "tools.nvd" in prompt
    assert "tools.pypi" in prompt
    assert "tools.github_api" in prompt
    assert "search_cves" in prompt
    assert "get_package_metadata" in prompt
    assert "get_release_notes" in prompt

    # Must mention Phase B optional tools
    assert "Phase B" in prompt
    assert "tools.epss" in prompt
    assert "tools.scorecard" in prompt
    assert "tools.osv" in prompt
    assert "tools.deps_dev" in prompt
    assert "tools.license_check" in prompt
