#!/usr/bin/env python3
"""PTC v4 dependency-gap audit entrypoint."""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from rich import box
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from src.agent.planner import parse_requirements_input
from src.agent.pipeline import run_multi_package_audit

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="PTC v4 dependency-gap audit")
    parser.add_argument("requirements_file", help="Requirements file with pinned entries (pkg==version)")
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
        help="Also render LLM narrative panel (off by default to avoid duplicate synthesis).",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable INFO logging from sub-agents (script generation, CVE interpretation, changelog).",
    )
    return parser


def _write_savings_markdown(
    rows_with_savings: list,
    pkg_savings_map: dict,
    total_actual: int,
    total_react: int,
    total_ptc_saved: int,
    ptc_pct: float,
    total_ptd_saved: int,
    ptd_pct: float,
    overall_pct: float,
) -> None:
    """Write the token savings report to token-savings-report.md."""
    out = Path("token-savings-report.md")
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# Token Savings Report — PTC + PTD vs Traditional ReAct",
        "",
        f"**Generated:** {ts}  ",
        f"**Architecture:** Programmatic Tool Calling (PTC) + Progressive Tool Discovery (PTD)  ",
        f"**Baseline:** Estimated traditional ReAct / function-calling loop",
        "",
        "## How the savings work",
        "",
        "**PTC savings** — In a traditional ReAct loop every tool call round-trips through the LLM:",
        "raw tool responses (NVD CVEs, PyPI metadata, GitHub release notes) flow back into the",
        "context window as prompt tokens. With PTC the LLM writes a Python script once; the script",
        "runs inside a Docker sandbox, calls all tools, and returns only a compact JSON summary.",
        "The raw responses never enter the LLM context window.",
        "",
        "**PTD savings** — Previously the codegen prompt injected ~700 tokens of tool API docs on",
        "every call (markdown docs + hardcoded response shapes). With PTD Level 2 those docs are",
        "replaced by a shared `TOOL RESPONSE SHAPES` block in the system prompt (~200 tokens,",
        "paid once). Net saving: ~500 tokens per codegen call.",
        "",
        "## Results",
        "",
        "| Package | Actual tokens (PTC+PTD) | Est. ReAct baseline | PTC saved (tool resp) | PTC % | PTD saved (doc inject) | PTD % | Combined saved % |",
        "|---------|------------------------|---------------------|-----------------------|-------|------------------------|-------|------------------|",
    ]

    for row in rows_with_savings:
        pkg = str(row.get("package", ""))
        s = pkg_savings_map[pkg]
        lines.append(
            f"| {pkg} "
            f"| {s.get('ptc_actual_tokens', 0):,} "
            f"| {s.get('estimated_react_total', 0):,} "
            f"| {s.get('ptc_tool_response_tokens_avoided', 0):,} "
            f"| {s.get('ptc_savings_pct', 0.0):.1f}% "
            f"| {s.get('ptd_doc_tokens_avoided', 0):,} "
            f"| {s.get('ptd_savings_pct', 0.0):.1f}% "
            f"| **{s.get('total_savings_pct', 0.0):.1f}%** |"
        )

    lines += [
        f"| **TOTAL** | **{total_actual:,}** | **{total_react:,}** "
        f"| **{total_ptc_saved:,}** | **{ptc_pct:.1f}%** "
        f"| **{total_ptd_saved:,}** | **{ptd_pct:.1f}%** "
        f"| **{overall_pct:.1f}%** |",
        "",
        "## Key numbers",
        "",
        f"- **Combined token reduction:** {overall_pct:.1f}% vs estimated ReAct baseline",
        f"- **PTC contribution:** {ptc_pct:.1f}% — tool responses kept inside sandbox",
        f"- **PTD contribution:** {ptd_pct:.1f}% — per-call doc injection eliminated",
        f"- **Actual tokens spent:** {total_actual:,} across {len(rows_with_savings)} package(s)",
        f"- **Estimated ReAct cost:** {total_react:,} tokens",
        f"- **Total tokens saved:** {total_ptc_saved + total_ptd_saved:,}",
        "",
        "> **Estimation methodology:** ReAct baseline = actual PTC tokens + sandbox payload size ÷ 4",
        "> (chars-to-tokens approximation for raw tool responses that would have entered the LLM",
        "> context window) + 700 tokens for per-call doc injection that PTD eliminates.",
    ]

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    console.print(f"\n[dim]Token savings report written to[/dim] [cyan]{out.resolve()}[/cyan]")


def _render_rich_output(result: dict) -> None:
    planner = result.get("planner", {}) or {}
    package_rows = result.get("package_results", []) or []
    synthesis = result.get("synthesis", {}) or {}
    prioritized = synthesis.get("prioritized_packages", []) or []

    planner_table = Table(title="Main Agent — Planner", box=box.ROUNDED)
    planner_table.add_column("Package", style="cyan")
    planner_table.add_column("Pinned Version")
    for item in planner.get("packages", []) or []:
        planner_table.add_row(str(item.get("package", "")), str(item.get("pinned_version", "")))
    console.print(planner_table)

    def _compact_narrative(text: str) -> str:
        raw = str(text or "").strip()
        if not raw:
            return "N/A"
        # Keep one-row readability by turning bullet lines into a delimited sentence.
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
        title="Sub-Agents — Per Package Assessment",
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
        console.print(Panel(str(detailed), title="Main Agent — Detailed Risk Synthesis", border_style="yellow"))

    # Build a per-package savings lookup keyed by package name (fixes zip-alignment bug)
    pkg_savings_map = {
        r.get("package", ""): r.get("_token_savings")
        for r in package_rows
        if r.get("_token_savings")
    }
    if pkg_savings_map:
        savings_rows = [pkg_savings_map[r.get("package", "")] for r in package_rows if r.get("package", "") in pkg_savings_map]
        rows_with_savings = [r for r in package_rows if r.get("package", "") in pkg_savings_map]

        total_actual    = sum(s.get("ptc_actual_tokens", 0) for s in savings_rows)
        total_react     = sum(s.get("estimated_react_total", 0) for s in savings_rows)
        total_ptc_saved = sum(s.get("ptc_tool_response_tokens_avoided", 0) for s in savings_rows)
        total_ptd_saved = sum(s.get("ptd_doc_tokens_avoided", 0) for s in savings_rows)
        total_saved     = total_ptc_saved + total_ptd_saved
        overall_pct     = round(total_saved / total_react * 100, 1) if total_react > 0 else 0.0
        ptc_pct         = round(total_ptc_saved / total_react * 100, 1) if total_react > 0 else 0.0
        ptd_pct         = round(total_ptd_saved / total_react * 100, 1) if total_react > 0 else 0.0

        savings_table = Table(
            title="Token Savings Report — PTC + PTD vs Estimated Traditional ReAct",
            box=box.ROUNDED,
            show_lines=True,
        )
        savings_table.add_column("Package", style="cyan")
        savings_table.add_column("Actual\n(PTC+PTD)", justify="right")
        savings_table.add_column("Est. ReAct\nBaseline", justify="right")
        savings_table.add_column("PTC Saved\n(tool resp)", justify="right", style="yellow")
        savings_table.add_column("PTC %", justify="right", style="yellow")
        savings_table.add_column("PTD Saved\n(doc inject)", justify="right", style="blue")
        savings_table.add_column("PTD %", justify="right", style="blue")
        savings_table.add_column("Combined\nSaved %", justify="right", style="green")

        for row in rows_with_savings:
            s = pkg_savings_map[row.get("package", "")]
            savings_table.add_row(
                str(row.get("package", "")),
                str(s.get("ptc_actual_tokens", 0)),
                str(s.get("estimated_react_total", 0)),
                str(s.get("ptc_tool_response_tokens_avoided", 0)),
                f"{s.get('ptc_savings_pct', 0.0):.1f}%",
                str(s.get("ptd_doc_tokens_avoided", 0)),
                f"{s.get('ptd_savings_pct', 0.0):.1f}%",
                f"[bold green]{s.get('total_savings_pct', 0.0):.1f}%[/bold green]",
            )

        savings_table.add_section()
        savings_table.add_row(
            "[bold]TOTAL[/bold]",
            f"[bold]{total_actual}[/bold]",
            f"[bold]{total_react}[/bold]",
            f"[bold yellow]{total_ptc_saved}[/bold yellow]",
            f"[bold yellow]{ptc_pct:.1f}%[/bold yellow]",
            f"[bold blue]{total_ptd_saved}[/bold blue]",
            f"[bold blue]{ptd_pct:.1f}%[/bold blue]",
            f"[bold green]{overall_pct:.1f}%[/bold green]",
        )
        console.print(savings_table)

        console.print(
            "\n[dim]PTC savings[/dim] — In a traditional ReAct loop every tool call round-trips "
            "through the LLM: raw tool responses (NVD CVEs, PyPI metadata, GitHub release notes) "
            "flow back into the context window as prompt tokens. With PTC the LLM writes a Python "
            "script once; the script runs inside a Docker sandbox, calls all tools, and returns "
            "only a compact JSON summary. The raw responses never enter the LLM context window.\n\n"
            "[dim]PTD savings[/dim] — Previously the codegen prompt injected ~700 tokens of tool "
            "API docs on every call (markdown docs + hardcoded response shapes). With PTD Level 2 "
            "those docs are replaced by a shared TOOL RESPONSE SHAPES block in the system prompt "
            "(~200 tokens, paid once). Net saving: ~500 tokens per codegen call."
        )

        _write_savings_markdown(rows_with_savings, pkg_savings_map, total_actual, total_react,
                                total_ptc_saved, ptc_pct, total_ptd_saved, ptd_pct, overall_pct)


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
    main_lines: list[str] = ["Bootstrapping main agent..."]
    completion_counter: list[int] = [0]
    pkg_state: dict[str, dict] = {
        pkg: {"status": "waiting", "detail": "queued", "logs": ["queued"], "risk_rating": "", "completion_order": 0} for pkg in packages
    }

    def _make_progress_display() -> Group:
        import shutil
        term_width = shutil.get_terminal_size((120, 24)).columns

        main_body = "\n".join(main_lines[-6:]) or "[dim]waiting...[/dim]"
        main_panel = Panel(
            main_body,
            title="[bold cyan]◆ main[/bold cyan]",
            border_style="cyan",
            width=term_width,
        )

        # Build per-package panels with explicit column width
        cols_per_row = 3
        col_width = max(24, (term_width - cols_per_row + 1) // cols_per_row)

        pkg_panels = []
        for pkg in packages:
            st = pkg_state[pkg]["status"]
            detail = pkg_state[pkg]["detail"]
            logs = pkg_state[pkg]["logs"][-3:]
            risk = pkg_state[pkg].get("risk_rating", "")
            if st == "done":
                if risk == "high":
                    border = "red"
                    indicator = "✗"
                elif risk == "medium":
                    border = "yellow"
                    indicator = "!"
                else:
                    border = "green"
                    indicator = "✓"
            elif st == "running":
                border = "yellow"
                indicator = "◆"
            elif st == "error":
                border = "red"
                indicator = "✗"
            else:
                border = "white"
                indicator = "○"
            if st == "done":
                risk_color = {"high": "red", "medium": "yellow", "low": "green"}.get(risk, "white")
                detail_line = f"[bold {risk_color}]{detail[:col_width - 4]}[/bold {risk_color}]"
                log_lines = "\n".join(f"[dim]{l}[/dim]" for l in logs)
                body = f"{log_lines}\n{detail_line}" if log_lines else detail_line
            elif st == "error":
                detail_line = f"[red]{detail[:col_width - 4]}[/red]"
                log_lines = "\n".join(f"[dim]{l}[/dim]" for l in logs)
                body = f"{log_lines}\n{detail_line}" if log_lines else detail_line
            else:
                body = "\n".join(f"[dim]{l}[/dim]" for l in logs) + f"\n[yellow]{detail[:col_width - 4]}[/yellow]"
            order = pkg_state[pkg].get("completion_order", 0)
            order_tag = f"  [dim]#{order}[/dim]" if order else ""
            pkg_panels.append(
                Panel(
                    body,
                    title=f"[bold {border}]{indicator} {pkg}[/bold {border}]{order_tag}",
                    border_style=border,
                    width=col_width,
                )
            )

        # Tile panels into rows using Table.grid with explicit column widths
        grid = Table.grid(padding=(0, 0))
        for _ in range(cols_per_row):
            grid.add_column(width=col_width)
        for i in range(0, len(pkg_panels), cols_per_row):
            row = list(pkg_panels[i : i + cols_per_row])
            while len(row) < cols_per_row:
                row.append("")
            grid.add_row(*row)

        return Group(main_panel, grid)

    async def _on_progress(event: str, payload: dict) -> None:
        if event == "main_start":
            main_lines.append(f"Planner parsed {payload.get('total_packages', 0)} package(s)")
        elif event == "main_bootstrap":
            msg = payload.get("message", "")
            label = {
                "starting_sandbox": "Starting Docker sandbox...",
                "sandbox_started":  "Sandbox ready",
                "mcp_connected":    "MCP servers connected",
            }.get(msg, msg)
            main_lines.append(label)
        elif event == "main_ready":
            servers = ", ".join(payload.get("servers", []))
            main_lines.append(f"MCP connected once: {servers}")
            main_lines.append("Main agent dispatched sub-agents")
        elif event == "subagent_start":
            pkg = str(payload.get("package"))
            if pkg in pkg_state:
                pkg_state[pkg]["status"] = "running"
                pkg_state[pkg]["detail"] = f"pinned {payload.get('pinned_version')}"
                pkg_state[pkg]["logs"].append("querying NVD + PyPI + GitHub")
        elif event == "subagent_update":
            pkg = str(payload.get("package"))
            if pkg in pkg_state:
                stage = str(payload.get("stage", "running"))
                label = {
                    "llm_codegen":          "generating audit script",
                    "script_execution":     "executing in sandbox",
                    "llm_interpretation":   "interpreting CVEs",
                    "llm_changelog":        "analysing changelog",
                    "done":                 "finalising result",
                }.get(stage, stage.replace("_", " "))
                pkg_state[pkg]["status"] = "running"
                pkg_state[pkg]["detail"] = label
                pkg_state[pkg]["logs"].append(label)
        elif event == "subagent_complete":
            pkg = str(payload.get("package"))
            if pkg in pkg_state:
                risk = str(payload.get("risk_rating") or "unknown").upper()
                total = payload.get("total_cves_found", 0)
                affecting = payload.get("cves_affecting_count", total)
                completion_counter[0] += 1
                pkg_state[pkg]["status"] = "done"
                pkg_state[pkg]["risk_rating"] = str(payload.get("risk_rating") or "").lower()
                pkg_state[pkg]["completion_order"] = completion_counter[0]
                pkg_state[pkg]["detail"] = f"risk={risk}  {affecting} affecting / {total} scanned"
                pkg_state[pkg]["logs"].append("audit complete")
                main_lines.append(f"✓ {pkg}: {risk} ({affecting} affecting CVEs)")
        elif event == "subagent_error":
            pkg = str(payload.get("package"))
            if pkg in pkg_state:
                pkg_state[pkg]["status"] = "error"
                pkg_state[pkg]["detail"] = str(payload.get("error", ""))[:120]
                pkg_state[pkg]["logs"].append("failed")
                main_lines.append(f"{pkg} failed; fallback emitted")
        elif event == "main_disconnecting":
            main_lines.append("Disconnecting MCP servers...")
        elif event == "main_stopping_sandbox":
            main_lines.append("Stopping sandbox...")
        elif event == "main_synthesizing":
            main_lines.append("Main agent synthesizing cross-package plan")
        elif event == "main_complete":
            main_lines.append("Run complete")

    if as_json:
        result = await run_multi_package_audit(
            requirements_input=requirements_input,
            config_path=config,
            use_llm_synthesizer=(model == "openai"),
        )
    else:
        with Live(
            _make_progress_display(),
            console=console,
            refresh_per_second=8,
            vertical_overflow="visible",
            transient=False,
        ) as live:
            async def _progress_and_refresh(event: str, payload: dict) -> None:
                await _on_progress(event, payload)
                live.update(_make_progress_display())

            result = await run_multi_package_audit(
                requirements_input=requirements_input,
                config_path=config,
                use_llm_synthesizer=(model == "openai"),
                progress_callback=_progress_and_refresh,
            )
            live.update(_make_progress_display())
    output = {
        "main_agent": result.get("main_agent", {}),
        "sub_agents": result.get("sub_agents", []),
        "planner": result.get("planner", {}),
        "package_results": result.get("package_results", []),
        "synthesis": result.get("synthesis", {}),
    }
    if as_json:
        print(json.dumps(output, indent=2, ensure_ascii=False))
    else:
        _render_rich_output(output)
        if show_llm_narrative:
            narrative = output.get("synthesis", {}).get("llm_narrative")
            if narrative:
                console.print(Panel(str(narrative), title="Main Agent — LLM Narrative", border_style="cyan"))
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
