"""PTC + PTD compliant prompts — real Progressive Tool Discovery.

The LLM is asked to write a Python script (returned in a code fence).
Python code extracts it, writes it to the Docker container, and executes it.
Raw tool responses never leave the container (PTC).

Real PTD: Phase A sees only a lightweight catalog of Phase B tools (name +
one-line description, NO schemas).  The LLM outputs _tools_needed.  Phase B
prompt loads full schemas ONLY for tools the LLM requested.
"""
import json
import re
from textwrap import dedent


def _safe_name(package_name: str) -> str:
    return re.sub(r'[^a-zA-Z0-9_.-]+', '_', package_name)

_OUTPUT_SCHEMA_DOC = dedent("""\
    {
      "package": "<str>",
      "pinned_version": "<str>",
      "latest_version": "<str | null>",
      "versions_behind": "<int>",
      "cves_affecting_pinned": [<CVEEntry>, ...],
      "cves_not_relevant": [<CVEEntry>, ...],
      "needs_interpretation": [<CVEEntry>, ...],
      "total_cves_found": "<int>",
      "changelog_analysis": "<str>",
      "changelog_excerpts": ["<str>", ...],
      "upgrade_recommendation": "<str>",
      "risk_rating": "low | medium | high | critical",
      "changelog": { "notes": [...] }
    }

    CVEEntry = {
      "cve_id": "<str>",
      "severity": "critical | high | medium | low | unknown",
      "summary": "<str>",
      "status": "affecting_pinned | not_relevant | needs_interpretation",
      "determination_method": "cpe_range | agent_interpretation | heuristic"
    }""")

_OUTPUT_INSTRUCTION = (
    'Before outputting, add tool call tracking to the result:\n'
    '  from tools.mcp_client import get_tools_called\n'
    '  result["_tools_called"] = get_tools_called()\n'
    'Then output the final JSON via the base64 marker exactly like this:\n'
    '  print("__PTC_JSON_B64__" + base64.b64encode(json.dumps(result).encode("utf-8")).decode("ascii"))\n'
    'Do NOT print any other JSON or unstructured text to stdout — only the marker line.'
)


def build_system_prompt(tool_catalog_summary: str) -> str:
    return dedent(f"""\
        You are a security audit agent that writes Python scripts executed inside a Docker sandbox.
        The sandbox has pre-installed tool wrappers that call MCP servers over JSON-RPC.

        RULES:
        - Write a single, self-contained Python script. No interactive input, no network calls besides tool wrappers.
        - The script must import `json`, `base64`, and `sys`, then `sys.path.insert(0, "/app")`.
        - Tool responses are MCP envelopes: {{"content":[{{"text":"<json-string>"}}],"isError":false}}.
          You MUST decode them: parse response["content"][0]["text"] as JSON.
        - {_OUTPUT_INSTRUCTION}

        TOOL DOCUMENTATION:
        - Each tool has a markdown reference at /app/tools/docs/<server>/<tool>.md
        - Before calling any tool for the first time, read its doc:
            doc = open("/app/tools/docs/<server>/<tool>.md").read()
        - Examples:
            open("/app/tools/docs/nvd/search_cves.md").read()
            open("/app/tools/docs/pypi/get_package_metadata.md").read()
            open("/app/tools/docs/github_api/get_release_notes.md").read()
        - The doc tells you the exact parameter names, types, and the decoded response shape.

        TOOL RESPONSE SHAPES (after decoding the MCP envelope):

        search_cves decoded payload:
          {{"package": "requests", "version": "2.28.1",
            "results": [{{"cve_id": "CVE-...", "severity": "medium", "cvss_score": 6.1,
              "summary": "...", "status": "affecting_pinned", "determination_method": "cpe_range"}}],
            "source": "nvd"}}
        Access CVEs via payload["results"] — NOT payload["cves"].
        Each CVE already has "status" and "determination_method" — use them directly.

        get_package_metadata decoded payload:
          {{"latest_version": "2.32.5", "github_repository": "psf/requests", "home_page": "..."}}

        get_release_notes decoded payload:
          {{"notes": ["v2.29.0: ...", "v2.30.0: ..."], "error": null}}
        Notes may be empty. If "error" is set, use empty list for changelog_excerpts.

        OUTPUT SCHEMA (AuditFindings):
        {_OUTPUT_SCHEMA_DOC}

        {tool_catalog_summary}""")


def build_codegen_prompt(package_name: str, pinned_version: str) -> str:
    return dedent(f"""\
        Write a Python script to audit **{package_name}=={pinned_version}**.

        The script must follow ALL steps below. Read each tool's doc before use:
        `doc = open("/app/tools/docs/<server>/<tool>.md").read()`

        Core audit:
        1. `sys.path.insert(0, "/app")`.
        2. Read docs and import core tools:
           `doc = open("/app/tools/docs/nvd/search_cves.md").read()`
           `from tools.nvd import search_cves`
           `doc = open("/app/tools/docs/pypi/get_package_metadata.md").read()`
           `from tools.pypi import get_package_metadata`
           `doc = open("/app/tools/docs/github_api/get_release_notes.md").read()`
           `from tools.github_api import get_release_notes`
        3. Call `get_package_metadata(package="{package_name}")` → latest_version, github_repository.
        4. Call `search_cves(package="{package_name}", version="{pinned_version}")` → CVEs.
        5. Call `get_release_notes(owner, repo, from_version="{pinned_version}", to_version=latest)` → changelog.
        6. Decode every MCP envelope: `json.loads(response["content"][0]["text"])`.
        7. Partition CVEs into cves_affecting_pinned, cves_not_relevant, needs_interpretation
           based on the "status" field already present in each CVE entry from the NVD tool.
           Normalize each CVE to the CVEEntry schema (cve_id, severity, summary, status, determination_method).
        8. Compute versions_behind, total_cves_found, risk_rating, upgrade_recommendation.

        Tool selection:
        9. Based on the data collected, set `result["_tools_needed"]` to a list of
           server names from the catalog below. Full schemas will be loaded in a
           follow-up step — you are only selecting here.

           CATALOG (server name → when to request):
           - "epss"      — EPSS exploit-probability scores. Request when ANY CVEs are in cves_affecting_pinned.
           - "osv"       — OSV database cross-reference. Request when ANY CVEs are in cves_affecting_pinned.
           - "scorecard" — OpenSSF repo scorecard. Request when github_repository is available.
           - "deps_dev"  — Dependency tree from deps.dev. Request when versions_behind >= 3.

           Set `result["_tools_needed"]` to a Python list of the server name strings
           you need, e.g. `["epss", "osv"]`.  Use `[]` ONLY when none of the
           conditions above are met (zero affecting CVEs, no repo, fewer than 3
           versions behind).

        Output:
        10. Output the result as JSON via the __PTC_JSON_B64__ marker.

        ## Error handling
        - Wrap each tool call in try/except. On failure, use empty results and continue.
        - If github_repository is missing or doesn't contain "/", skip get_release_notes.
        - `versions_behind`: compute as the rough distance between pinned and latest version tuples.
        - `risk_rating`: "critical" if >=3 affecting CVEs with critical/high severity;
          "high" if >=2 affecting; "medium" if 1 affecting; "low" otherwise.

        Return ONLY the Python script inside a ```python code fence.""")


_PHASE_B_SCHEMAS = {
    "epss": dedent("""\
        Read doc and import:
          doc = open("/app/tools/docs/epss/get_exploit_probability.md").read()
          from tools.epss import get_exploit_probability
        For each CVE in core_results["cves_affecting_pinned"] (up to 5):
          call get_exploit_probability(cve_id=cve["cve_id"])
          Decoded response: {"cve_id": "...", "epss_score": 0.05, "percentile": 0.87}
          Store epss_score on the CVE dict."""),
    "osv": dedent("""\
        Read doc and import:
          doc = open("/app/tools/docs/osv/query_vulnerability.md").read()
          from tools.osv import query_vulnerability
        Call query_vulnerability(package="{package_name}", version="{pinned_version}")
        Decoded response: {"vulnerabilities": [...], "source": "osv"}
        Store as result["osv_results"]."""),
    "scorecard": dedent("""\
        Read doc and import:
          doc = open("/app/tools/docs/scorecard/get_security_scorecard.md").read()
          from tools.scorecard import get_security_scorecard
        Extract owner, repo from core_results["github_repository"] (split on "/").
        Call get_security_scorecard(owner=owner, repo=repo)
        Decoded response: {"overall_score": 7.5, "checks": [...]}
        Store as result["scorecard_data"]."""),
    "deps_dev": dedent("""\
        Read doc and import:
          doc = open("/app/tools/docs/deps_dev/get_dependency_info.md").read()
          from tools.deps_dev import get_dependency_info
        Call get_dependency_info(package="{package_name}", version="{pinned_version}")
        Decoded response: {"dependencies": [...], "version_info": {...}}
        Store as result["dependency_info"]."""),
}


def build_phase_b_prompt(
    package_name: str,
    pinned_version: str,
    core_results: dict,
    tools_needed: list[str],
) -> str | None:
    """Build Phase B codegen prompt with schemas ONLY for tools the LLM requested.

    Returns None if tools_needed is empty (caller skips Phase B entirely).
    Core results are passed via a sandbox file (not embedded in prompt) to avoid
    the LLM breaking long base64 strings across lines.
    """
    if not tools_needed:
        return None

    # Build tool instructions for only the requested tools
    tool_sections = []
    for tool_name in tools_needed:
        schema = _PHASE_B_SCHEMAS.get(tool_name)
        if schema:
            rendered = schema.replace("{package_name}", package_name).replace("{pinned_version}", pinned_version)
            tool_sections.append(f"### {tool_name}\n{rendered}")

    if not tool_sections:
        return None

    tools_block = "\n\n".join(tool_sections)

    return dedent(f"""\
        Write a Python script to enrich the audit of **{package_name}=={pinned_version}**
        using the Phase B tools below.

        1. `sys.path.insert(0, "/app")`
        2. Load core results from the JSON file written by Phase A:
           ```
           import json
           core = json.loads(open("/app/code/core_results_{_safe_name(package_name)}.json").read())
           result = dict(core)
           ```
        3. Run ONLY these tools (wrap each in try/except):

        {tools_block}

        4. Decode every MCP envelope: `json.loads(response["content"][0]["text"])`.
        5. Add tool call tracking:
           `from tools.mcp_client import get_tools_called`
           `result["_tools_called"] = get_tools_called()`
        6. Output via __PTC_JSON_B64__ marker.

        Return ONLY the Python script inside a ```python code fence.""")


def build_iteration_prompt(error_output: str) -> str:
    truncated = error_output[:3000]
    return dedent(f"""\
        The previous script failed during sandbox execution. Here is the error output:

        ```
        {truncated}
        ```

        Fix the script and return the corrected version inside a ```python code fence.
        Common issues:
        - Forgetting to decode MCP envelope (response["content"][0]["text"])
        - Missing sys.path.insert(0, "/app")
        - KeyError on tool response fields — if a tool call failed, verify you read its documentation
          first: open("/app/tools/docs/<server>/<tool>.md").read() before calling the tool
        - Wrong parameter names — the doc at /app/tools/docs/<server>/<tool>.md has the exact signature
        - Non-JSON characters in output (print only the __PTC_JSON_B64__ marker line)""")


def build_interpretation_prompt(
    package_name: str,
    pinned_version: str,
    ambiguous_cves: list[dict],
) -> str:
    cve_json = json.dumps(ambiguous_cves, indent=2, ensure_ascii=False)
    return dedent(f"""\
        You are a vulnerability analyst. Determine whether each CVE below actually affects \
        the **{package_name}** package at version **{pinned_version}**.

        CRITICAL: Many CVEs returned by keyword search are about OTHER projects that merely \
        use or mention {package_name}. A CVE is "not_relevant" if:
        - The CVE is about a different product/project (e.g. "OnyxForum", "Mealie", "APTRS") \
        that happens to use {package_name} as a dependency
        - The vulnerability is in application code, not in the {package_name} library itself
        - The summary describes a bug in a specific app's usage of {package_name}, not a flaw \
        in {package_name} core

        A CVE is "affecting_pinned" ONLY if the vulnerability is in the {package_name} library \
        itself and applies to version {pinned_version}.

        For each CVE, decide:
        - "affecting_pinned" if the vulnerability is in {package_name} itself and applies to {pinned_version}
        - "not_relevant" otherwise

        Return a JSON array where each element has:
        {{
          "cve_id": "<id>",
          "severity": "<severity>",
          "summary": "<original summary>",
          "status": "affecting_pinned" or "not_relevant",
          "determination_method": "agent_interpretation"
        }}

        Ambiguous CVEs:
        ```json
        {cve_json}
        ```

        Return ONLY valid JSON — no markdown fences, no explanation.""")


def build_changelog_prompt(
    package_name: str,
    pinned_version: str,
    latest_version: str,
    changelog: dict,
) -> str:
    notes = changelog.get("notes", []) if isinstance(changelog, dict) else []
    error = changelog.get("error") if isinstance(changelog, dict) else None
    if not notes and not error:
        changelog_summary = "No changelog excerpts were available from the release notes API."
    elif error:
        changelog_summary = f"Changelog retrieval had an error: {error}. Notes collected: {len(notes)}."
    else:
        changelog_summary = json.dumps(notes[:5], indent=2, ensure_ascii=False)[:3000]

    return dedent(f"""\
        Analyze the upgrade path from **{package_name} {pinned_version}** to **{latest_version}** \
        for breaking changes and upgrade risk.

        Release notes / changelog excerpts:
        {changelog_summary}

        Based on the data available (or lack thereof), return ONLY a valid JSON object:
        {{
          "breaking_changes_detected": true | false,
          "changelog_analysis": "<1-3 sentence analysis of what the notes reveal, or state that no notes were available>",
          "recommendation_rationale": "<concise upgrade rationale based on available evidence>"
        }}

        Do NOT wrap the JSON in markdown fences. Return raw JSON only.""")
