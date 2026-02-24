"""Experiment-local prompts — improved interpretation prompt."""
import json
from textwrap import dedent


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
