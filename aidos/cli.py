from __future__ import annotations

import asyncio
import sys

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

BANNER = r"""
     █████╗ ██╗██████╗  ██████╗ ███████╗
    ██╔══██╗██║██╔══██╗██╔═══██╗██╔════╝
    ███████║██║██║  ██║██║   ██║███████╗
    ██╔══██║██║██║  ██║██║   ██║╚════██║
    ██║  ██║██║██████╔╝╚██████╔╝███████║
    ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝

    Autonomous LLM-Driven Stress Testing Agent
    The AI that thinks like an attacker.
"""


@click.command()
@click.argument("target")
@click.option("--max-turns", default=50, help="Maximum agent reasoning turns.")
@click.option("--model", default="gemini-2.5-flash", help="Gemini model to use.")
@click.option("--trace-file", default="", help="Path to JSONL trace output file.")
@click.option("--enforce-coverage/--no-enforce-coverage", default=True, help="Steer agent to cover recon, analysis, attack, monitoring, reporting.")
@click.option("--yes", "-y", is_flag=True, help="Skip authorization confirmation.")
def main(target: str, max_turns: int, model: str, trace_file: str, enforce_coverage: bool, yes: bool):
    import os

    if not os.environ.get("GEMINI_API_KEY"):
        console.print("[red]GEMINI_API_KEY not set. Export it and try again.[/red]")
        sys.exit(1)

    console.print(Text(BANNER, style="bold cyan"))

    from aidos.tools import ToolState
    probe = ToolState()
    installed = probe.detect_tools()

    tools_table = Table(show_header=False, box=None, padding=(0, 1))
    tools_table.add_column(style="bold green", width=20)
    tools_table.add_column(style="dim")

    categories = {
        "L7 Flood": ["bombardier", "wrk", "vegeta", "k6", "siege", "ab"],
        "L4 Packet": ["hping3"],
        "Slow-Rate": ["slowhttptest"],
        "Recon": ["nmap", "masscan", "nuclei", "nikto", "ffuf", "gobuster", "curl"],
        "Crypto": ["sslyze"],
        "DNS": ["dnsrecon", "dnsenum"],
    }

    for category, tools in categories.items():
        found = [t for t in tools if t in installed]
        missing = [t for t in tools if t not in installed]
        line = ""
        if found:
            line += " ".join(f"[green]{t}[/green]" for t in found)
        if missing:
            if line:
                line += " "
            line += " ".join(f"[red dim]{t}[/red dim]" for t in missing)
        tools_table.add_row(category, line)

    console.print(Panel(tools_table, title="[bold]Arsenal[/bold]", border_style="yellow"))
    console.print(f"  [bold]{len(installed)}[/bold] tools loaded + built-in HTTP flood, slowloris, slow POST")
    console.print()

    console.print(Panel(
        "[bold red]AUTHORIZED TESTING ONLY[/bold red]\n\n"
        "This tool executes real attacks that WILL impact target availability.\n"
        "SYN floods, connection exhaustion, application-layer attacks.\n"
        "Only run against systems you own or have written authorization to test.\n"
        "Unauthorized use is a criminal offense.",
        border_style="red",
    ))

    console.print(f"  Target:     [bold white]{target}[/bold white]")
    console.print(f"  Model:      [dim]{model}[/dim]")
    console.print(f"  Max turns:  [dim]{max_turns}[/dim]")
    console.print(f"  Coverage:   [dim]{'enforced' if enforce_coverage else 'best-effort'}[/dim]")
    console.print()

    if not yes:
        if not click.confirm("I have authorization to test this target"):
            console.print("[yellow]Aborted.[/yellow]")
            sys.exit(0)
        console.print()

    from aidos.agent import run_agent
    report = asyncio.run(
        run_agent(
            target_url=target,
            max_turns=max_turns,
            model=model,
            trace_file=trace_file or None,
            enforce_coverage=enforce_coverage,
        )
    )

    risk = report.get("overall_risk", "UNKNOWN")
    findings_count = len(report.get("findings", []))
    severity_counts = report.get("severity_counts", {})
    sev_str = " | ".join(f"{k}: {v}" for k, v in severity_counts.items()) if severity_counts else "none"
    coverage_missing = report.get("coverage_missing", [])
    coverage_str = "complete" if not coverage_missing else ", ".join(coverage_missing)

    console.print()
    console.print(Panel(
        f"[bold]Risk: {risk}[/bold]\n"
        f"Findings: {findings_count} ({sev_str})\n"
        f"Requests sent: {report.get('total_requests_sent', 0)}\n"
        f"Duration: {report.get('duration_seconds', 0)}s\n"
        f"Coverage missing: {coverage_str}\n"
        f"Report: {report.get('html_report_path', 'N/A')}\n"
        f"Trace: {report.get('trace_path', 'N/A')}",
        title="[bold cyan]Assessment Complete[/bold cyan]",
        border_style="cyan",
    ))


if __name__ == "__main__":
    main()
