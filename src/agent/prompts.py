"""PTC + PTD compliant prompts — identical pattern to ptc-v4-dep-gap-agentic.

The LLM is asked to write a Python script (returned in a code fence).
Python code extracts it, writes it to the Docker container, and executes it.
Raw tool responses never leave the container (PTC).
The script reads docs from /app/tools/docs/ (PTD).
"""
import json
from textwrap import dedent

_PHASE2_SCHEMA_DOC = dedent("""\
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
    'Output the final JSON via the base64 marker exactly like this:\n'
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

        OUTPUT SCHEMA (Phase2Result):
        {_PHASE2_SCHEMA_DOC}

        {tool_catalog_summary}""")


def build_codegen_prompt(package_name: str, pinned_version: str) -> str:
    return dedent(f"""\
        Write a Python script to audit **{package_name}=={pinned_version}**.

        The script must:
        1. `sys.path.insert(0, "/app")` then import from `tools.nvd`, `tools.pypi`, `tools.github_api`.
        2. Before calling ANY tool for the first time, read its doc file:
           `doc = open("/app/tools/docs/<server>/<tool>.md").read()`
           You MUST do this for every tool — core and Phase B alike. Example:
           ```
           doc = open("/app/tools/docs/nvd/search_cves.md").read()
           from tools.nvd import search_cves
           doc = open("/app/tools/docs/pypi/get_package_metadata.md").read()
           from tools.pypi import get_package_metadata
           doc = open("/app/tools/docs/github_api/get_release_notes.md").read()
           from tools.github_api import get_release_notes
           ```
        3. Call `get_package_metadata(package_name="{package_name}")` to get latest_version and github_repository.
        4. Call `search_cves(package_name="{package_name}", version="{pinned_version}")` for CVEs.
        5. Call `get_release_notes(owner=<owner>, repo=<repo>, from_version="{pinned_version}", to_version=<latest>)` for changelog.
        6. Decode every tool response — they return MCP envelopes, NOT raw data.
           Use: `json.loads(response["content"][0]["text"])` to get the payload.
        7. Partition CVEs into cves_affecting_pinned, cves_not_relevant, needs_interpretation
           based on the "status" field already present in each CVE entry from the NVD tool.
           Normalize each CVE to the CVEEntry schema (cve_id, severity, summary, status, determination_method).
        8. Compute versions_behind, total_cves_found, risk_rating, upgrade_recommendation.
        9. Output the result as JSON via the __PTC_JSON_B64__ marker.

        ## Phase B — Enrichment (ALWAYS include this code block):
        After steps 3-5, the script MUST include the following Phase B enrichment.
        These calls are wrapped in try/except so failures are harmless, but the code
        MUST be present. Copy this pattern into your script after the core steps:

        ```
        # --- Phase B enrichment ---
        doc = open("/app/tools/docs/epss/get_exploit_probability.md").read()
        from tools.epss import get_exploit_probability
        doc = open("/app/tools/docs/osv/query_vulnerability.md").read()
        from tools.osv import query_vulnerability
        doc = open("/app/tools/docs/scorecard/get_security_scorecard.md").read()
        from tools.scorecard import get_security_scorecard
        doc = open("/app/tools/docs/deps_dev/get_dependency_info.md").read()
        from tools.deps_dev import get_dependency_info
        doc = open("/app/tools/docs/license_check/check_license.md").read()
        from tools.license_check import check_license

        # EPSS scores for affecting CVEs
        for cve in cves_affecting_pinned[:5]:
            try:
                epss_resp = get_exploit_probability(cve_id=cve["cve_id"])
                epss_data = json.loads(epss_resp["content"][0]["text"])
                cve["epss_score"] = epss_data.get("epss_score")
            except Exception:
                pass

        # OSV cross-reference
        try:
            osv_resp = query_vulnerability(package="{package_name}", version="{pinned_version}")
            osv_data = json.loads(osv_resp["content"][0]["text"])
        except Exception:
            osv_data = {{"results": []}}

        # Scorecard (if GitHub repo found)
        scorecard_data = {{}}
        if github_repository and "/" in github_repository:
            try:
                sc_resp = get_security_scorecard(owner=owner, repo=repo)
                scorecard_data = json.loads(sc_resp["content"][0]["text"])
            except Exception:
                pass

        # deps.dev dependency info
        try:
            dd_resp = get_dependency_info(package="{package_name}", version="{pinned_version}")
            dd_data = json.loads(dd_resp["content"][0]["text"])
        except Exception:
            dd_data = {{}}

        # License check
        try:
            lic_resp = check_license(package="{package_name}")
            lic_data = json.loads(lic_resp["content"][0]["text"])
        except Exception:
            lic_data = {{}}
        ```

        Phase B results do NOT change the output schema — use them to inform risk_rating
        and upgrade_recommendation text.

        ## Error handling
        - Wrap each tool call in try/except. On failure, use empty results and continue.
        - If github_repository is missing or doesn't contain "/", skip get_release_notes and GitHub-dependent tools.
        - `versions_behind`: compute as the rough distance between pinned and latest version tuples.
        - `risk_rating`: "critical" if >=3 affecting CVEs with critical/high severity;
          "high" if >=2 affecting; "medium" if 1 affecting; "low" otherwise.

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
        **{package_name}=={pinned_version}**.

        For each CVE, decide:
        - "affecting_pinned" if the vulnerability applies to version {pinned_version}
        - "not_relevant" if the vulnerability does not apply

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
