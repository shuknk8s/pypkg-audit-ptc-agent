#!/usr/bin/env python3
"""CLI entrypoint for the LLM codegen E2E experiment.

Has the LLM generate audit scripts (same prompts as main pipeline), executes
them in the Docker sandbox with live MCP servers, and validates the results.

Usage:
    uv run python experiments/template_codegen/run_experiment.py requirements.txt
    uv run python experiments/template_codegen/run_experiment.py requirements.txt --config config.yaml
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

# Ensure repo root is on path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from src.agent.planner import parse_requirements_input
from experiments.template_codegen.template_pipeline import run_codegen_pipeline


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="LLM codegen E2E experiment — tests the current pipeline's codegen",
    )
    p.add_argument("requirements_file", help="Path to requirements.txt (pkg==version lines)")
    p.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    p.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    p.add_argument("--show-scripts", action="store_true", help="Print generated scripts")
    return p


async def run(args: argparse.Namespace) -> int:
    # Parse requirements
    req_path = Path(args.requirements_file)
    if not req_path.exists():
        print(f"Error: {req_path} not found", file=sys.stderr)
        return 1

    specs = parse_requirements_input(req_path.read_text())
    packages = [(s["package"], s["pinned_version"]) for s in specs]

    print(f"LLM codegen E2E experiment: {len(packages)} package(s)")
    for pkg, ver in packages:
        print(f"  - {pkg}=={ver}")
    print()

    # Run pipeline
    results = await run_codegen_pipeline(packages, config_path=args.config)

    # Report
    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    all_passed = True
    for r in results:
        pkg = r.get("package", "?")
        ver = r.get("pinned_version", "?")
        latest = r.get("latest_version", "?")
        cves = len(r.get("cves_affecting_pinned", []))
        risk = r.get("risk_rating", "?")
        behind = r.get("versions_behind", 0)
        is_llm = r.get("_llm_codegen", False)
        pb_tools = r.get("_phase_b_tools", [])

        # A result "passes" if it came from LLM codegen and has real data
        has_data = latest is not None or r.get("total_cves_found", 0) > 0
        status = "PASS" if (is_llm and has_data) else "FAIL"
        if not is_llm:
            all_passed = False
        if not has_data:
            status = "WARN"

        print(f"\n[{status}] {pkg}=={ver}")
        print(f"  latest={latest}, versions_behind={behind}, risk={risk}")
        print(f"  CVEs affecting: {cves}, total: {r.get('total_cves_found', 0)}")
        print(f"  Phase B tools: {pb_tools or '(none)'}")

        if args.show_scripts and r.get("_phase_a_script"):
            print(f"\n  --- Phase A script ({len(r['_phase_a_script'])} chars) ---")
            for line in r["_phase_a_script"].splitlines()[:30]:
                print(f"    {line}")
            if len(r["_phase_a_script"].splitlines()) > 30:
                print(f"    ... ({len(r['_phase_a_script'].splitlines()) - 30} more lines)")

    print("\n" + "=" * 60)
    print(f"Overall: {'ALL PASSED' if all_passed else 'SOME FAILED'}")
    print("=" * 60)

    # Dump full JSON (without the embedded scripts for readability)
    print("\n--- Full JSON output ---")
    clean_results = []
    for r in results:
        clean = {k: v for k, v in r.items() if k != "_phase_a_script"}
        clean_results.append(clean)
    print(json.dumps(clean_results, indent=2, default=str))

    return 0 if all_passed else 1


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    )

    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
