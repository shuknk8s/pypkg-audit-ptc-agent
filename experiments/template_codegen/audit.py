#!/usr/bin/env python3
"""Experiment audit entrypoint — uses LLM codegen pipeline from experiments/.

Same Rich UI and CLI as the original audit.py, but uses the experiment's
run_codegen_pipeline instead of the main run_all_packages.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure repo root is on sys.path so src.* imports work
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

# Prevent stale .pyc files
sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"

import structlog
from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

# === THE KEY DIFFERENCE: import experiment pipeline instead of main pipeline ===
from experiments.template_codegen.template_pipeline import run_codegen_pipeline
from src.agent.planner import parse_requirements_input
from src.agent.synthesizer import synthesize_results

_log_file = open("audit-debug.log", "w", encoding="utf-8")  # noqa: SIM115
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.JSONRenderer(),
    ],
    logger_factory=structlog.WriteLoggerFactory(file=_log_file),
)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    handlers=[logging.StreamHandler(_log_file)],
    force=True,
)

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Experiment audit — LLM codegen E2E via Docker sandbox"
    )
    parser.add_argument(
        "requirements_file",
        help="Requirements file with pinned entries (pkg==version)",
    )
    parser.add_argument(
        "--model",
        choices=["openai", "local"],
        default="openai",
        help="Synthesis mode: openai (default) or local deterministic",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Config file path (default: config.yaml)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print raw JSON instead of rich terminal tables.",
    )
    parser.add_argument(
        "--show-llm-narrative",
        action="store_true",
        help="Also render LLM narrative panel (off by default).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable INFO logging from sub-agents.",
    )
    return parser


def _render_rich_output(result: dict) -> None:
    planner = result.get("planner", {}) or {}
    package_rows = result.get("package_results", []) or []
    synthesis = result.get("synthesis", {}) or {}
    prioritized = synthesis.get("prioritized_packages", []) or []

    planner_table = Table(title="Main Agent — Planner", box=box.ROUNDED)
    planner_table.add_column("Package", style="cyan")
    planner_table.add_column("Pinned Version")
    for item in planner.get("packages", []) or []:
        planner_table.add_row(
            str(item.get("package", "")), str(item.get("pinned_version", ""))
        )
    console.print(planner_table)

    def _compact_narrative(text: str) -> str:
        raw = str(text or "").strip()
        if not raw:
            return "N/A"
        parts = []
        for line in raw.splitlines():
            s = line.strip()
            if not s:
                continue
            if s.startswith("- "):
                s = s[2:].strip()
            parts.append(s)
        return " | ".join(parts)

    sub_table = Table(
        title="Sub-Agents — Per Package Assessment (LLM Codegen Experiment)",
        box=box.ROUNDED,
        show_lines=True,
    )
    sub_table.add_column("Package", style="cyan")
    sub_table.add_column("Pinned")
    sub_table.add_column("Latest")
    sub_table.add_column("Behind", justify="right")
    sub_table.add_column("CVEs", justify="right")
    sub_table.add_column("Risk", justify="center")
    sub_table.add_column("Recommendation")
    sub_table.add_column("Narrative (Evidence)")
    for row in package_rows:
        sub_table.add_row(
            str(row.get("package", "")),
            str(row.get("pinned_version", "")),
            str(row.get("latest_version") or "N/A"),
            str(row.get("versions_behind") or 0),
            str(row.get("total_cves_found") or 0),
            str(row.get("risk_rating") or "unknown").upper(),
            str(row.get("upgrade_recommendation") or ""),
            _compact_narrative(str(row.get("recommendation_rationale") or "")),
        )
    console.print(sub_table)

    final_table = Table(title="Final Prioritized Upgrade Plan", box=box.ROUNDED)
    final_table.add_column("Rank", justify="right")
    final_table.add_column("Package", style="cyan")
    final_table.add_column("Risk", justify="center")
    final_table.add_column("CVEs", justify="right")
    final_table.add_column("Versions Behind", justify="right")
    final_table.add_column("Recommendation (Per Package)")
    for row in prioritized:
        final_table.add_row(
            str(row.get("rank", "")),
            str(row.get("package", "")),
            str(row.get("risk_rating", "unknown")).upper(),
            str(row.get("total_cves_found", 0)),
            str(row.get("versions_behind", 0)),
            str(row.get("upgrade_recommendation", "")),
        )
    console.print(final_table)

    detailed = synthesis.get("detailed_summary")
    if detailed:
        console.print(
            Panel(
                str(detailed),
                title="Main Agent — Detailed Risk Synthesis",
                border_style="yellow",
            )
        )


async def run(
    requirements_file: str,
    model: str,
    config: str,
    as_json: bool,
    show_llm_narrative: bool,
) -> int:
    req_path = Path(requirements_file)
    if not req_path.exists():
        console.print(f"[red]Error:[/red] requirements file not found: {requirements_file}")
        return 2
    requirements_input = req_path.read_text(encoding="utf-8")
    package_specs = parse_requirements_input(requirements_input)
    packages = [str(spec.get("package")) for spec in package_specs]
    package_pairs = [(str(s["package"]), str(s["pinned_version"])) for s in package_specs]

    main_lines: list[str] = ["Bootstrapping experiment pipeline..."]
    completion_counter: list[int] = [0]
    pkg_state: dict[str, dict] = {
        pkg: {
            "status": "waiting",
            "detail": "queued",
            "logs": ["queued"],
            "risk_rating": "",
            "completion_order": 0,
        }
        for pkg in packages
    }

    def _make_display() -> Group:
        import shutil

        term_width = shutil.get_terminal_size((120, 24)).columns
        main_panel = Panel(
            "\n".join(main_lines[-6:]) or "[dim]waiting...[/dim]",
            title="[bold cyan]◆ experiment[/bold cyan]",
            border_style="cyan",
            width=term_width,
        )
        cols = 3
        col_w = max(24, (term_width - cols + 1) // cols)
        panels = []
        for pkg in packages:
            st = pkg_state[pkg]
            status = st["status"]
            risk = st.get("risk_rating", "")
            if status == "done":
                border = {"high": "red", "medium": "yellow"}.get(risk, "green")
                ind = "X" if risk == "high" else ("!" if risk == "medium" else "V")
            elif status == "running":
                border, ind = "yellow", "*"
            elif status == "error":
                border, ind = "red", "X"
            else:
                border, ind = "white", "o"
            logs = "\n".join(f"[dim]{l}[/dim]" for l in st["logs"][-3:])
            detail = st["detail"]
            if status == "done":
                rc = {"high": "red", "medium": "yellow", "low": "green"}.get(
                    risk, "white"
                )
                body = f"{logs}\n[bold {rc}]{detail[:col_w-4]}[/bold {rc}]"
            elif status == "error":
                body = f"{logs}\n[red]{detail[:col_w-4]}[/red]"
            else:
                body = f"{logs}\n[yellow]{detail[:col_w-4]}[/yellow]"
            order = st.get("completion_order", 0)
            order_tag = f"  [dim]#{order}[/dim]" if order else ""
            panels.append(
                Panel(
                    body,
                    title=f"[bold {border}]{ind} {pkg}[/bold {border}]{order_tag}",
                    border_style=border,
                    width=col_w,
                )
            )
        grid = Table.grid(padding=(0, 0))
        for _ in range(cols):
            grid.add_column(width=col_w)
        for i in range(0, len(panels), cols):
            row = list(panels[i : i + cols])
            while len(row) < cols:
                row.append("")
            grid.add_row(*row)
        return Group(main_panel, grid)

    async def _on_progress(event: str, payload: dict) -> None:
        if event == "main_start":
            main_lines.append(
                f"Planner parsed {payload.get('total_packages', 0)} package(s)"
            )
        elif event == "main_bootstrap":
            msg = payload.get("message", "")
            main_lines.append(
                {
                    "starting_sandbox": "Starting sandbox container...",
                    "sandbox_started": "Sandbox ready",
                    "mcp_connecting": "Connecting MCP servers...",
                    "mcp_connected": "MCP servers connected",
                }.get(msg, msg)
            )
        elif event == "main_ready":
            servers = ", ".join(payload.get("servers", []))
            main_lines.append(f"MCP connected once: {servers}")
            main_lines.append("Experiment dispatched LLM codegen agents")
        elif event == "subagent_start":
            pkg = str(payload.get("package"))
            if pkg in pkg_state:
                pkg_state[pkg]["status"] = "running"
                pkg_state[pkg]["detail"] = f"pinned {payload.get('pinned_version')}"
                pkg_state[pkg]["logs"].append(
                    "Phase A: LLM generating audit script"
                )
        elif event == "subagent_update":
            pkg = str(payload.get("package"))
            if pkg in pkg_state:
                stage = str(payload.get("stage", "running"))
                phase_b_tools = payload.get("phase_b_tools", [])
                if stage == "phase_b_execution" and phase_b_tools:
                    label = f"Phase B: querying {', '.join(phase_b_tools)}"
                else:
                    label = {
                        "llm_codegen": "LLM generating audit script",
                        "script_execution": "executing in sandbox",
                        "phase_b_codegen": "Phase B: LLM generating enrichment",
                        "phase_b_skipped": "Phase B: skipped (no tools needed)",
                        "done": "finalising result",
                    }.get(stage, stage.replace("_", " "))
                pkg_state[pkg]["status"] = "running"
                pkg_state[pkg]["detail"] = label
                pkg_state[pkg]["logs"].append(label)
        elif event == "subagent_complete":
            pkg = str(payload.get("package"))
            if pkg in pkg_state:
                risk = str(payload.get("risk_rating") or "unknown").lower()
                total = payload.get("total_cves_found", 0)
                affecting = payload.get("cves_affecting_count", total)
                completion_counter[0] += 1
                pkg_state[pkg]["status"] = "done"
                pkg_state[pkg]["risk_rating"] = risk
                pkg_state[pkg]["completion_order"] = completion_counter[0]
                pkg_state[pkg]["detail"] = (
                    f"risk={risk.upper()}  {affecting} affecting / {total} scanned"
                )
                pkg_state[pkg]["logs"].append("audit complete")
                main_lines.append(
                    f"V {pkg}: {risk.upper()} ({affecting} affecting CVEs)"
                )
        elif event == "subagent_error":
            pkg = str(payload.get("package"))
            if pkg in pkg_state:
                pkg_state[pkg]["status"] = "error"
                pkg_state[pkg]["detail"] = str(payload.get("error", ""))[:80]
                pkg_state[pkg]["logs"].append("failed")
                main_lines.append(f"X {pkg}: error -- fallback used")
        elif event == "main_disconnecting":
            main_lines.append("Disconnecting MCP servers...")
        elif event == "main_stopping_sandbox":
            main_lines.append("Stopping sandbox...")
        elif event == "main_synthesizing":
            main_lines.append("Synthesizing cross-package plan")
        elif event == "main_complete":
            main_lines.append("Run complete")

    # === Use experiment pipeline instead of run_all_packages ===
    if as_json:
        package_results = await run_codegen_pipeline(package_pairs, config)
    else:
        with Live(
            _make_display(),
            console=console,
            refresh_per_second=8,
            vertical_overflow="visible",
            transient=False,
        ) as live:

            async def _cb(event: str, payload: dict) -> None:
                await _on_progress(event, payload)
                live.update(_make_display())

            package_results = await run_codegen_pipeline(
                package_pairs, config, progress_callback=_cb
            )
            live.update(_make_display())

    synthesis = await synthesize_results(package_results, use_llm=False)
    output = {
        "planner": {"packages": package_specs, "total_packages": len(package_specs)},
        "package_results": package_results,
        "synthesis": synthesis,
    }
    if as_json:
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        _render_rich_output(output)
        if show_llm_narrative:
            narrative = output.get("synthesis", {}).get("llm_narrative")
            if narrative:
                console.print(
                    Panel(
                        str(narrative),
                        title="Main Agent — LLM Narrative",
                        border_style="cyan",
                    )
                )
    return 0


def main() -> int:
    args = build_parser().parse_args()
    if args.verbose:
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(name)s] %(message)s",
        )
    return asyncio.run(
        run(
            args.requirements_file,
            args.model,
            args.config,
            args.json,
            args.show_llm_narrative,
        )
    )


if __name__ == "__main__":
    raise SystemExit(main())
