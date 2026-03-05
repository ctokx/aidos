from __future__ import annotations

import html
import json
import time
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEVERITY_COLORS = {"CRITICAL": "red bold", "HIGH": "red", "MEDIUM": "yellow", "LOW": "blue", "INFO": "dim"}


def generate_report(
    target_url: str,
    findings: list[dict],
    tech_stack: dict,
    endpoints: list[dict],
    total_requests: int,
    duration: float,
    turns: int,
    tool_calls: int,
) -> dict:
    findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 5))

    severity_counts = {}
    for f in findings_sorted:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    if any(f["severity"] == "CRITICAL" for f in findings_sorted):
        overall_risk = "CRITICAL"
    elif any(f["severity"] == "HIGH" for f in findings_sorted):
        overall_risk = "HIGH"
    elif any(f["severity"] == "MEDIUM" for f in findings_sorted):
        overall_risk = "MEDIUM"
    elif findings_sorted:
        overall_risk = "LOW"
    else:
        overall_risk = "NONE"

    report = {
        "target": target_url,
        "overall_risk": overall_risk,
        "severity_counts": severity_counts,
        "findings": findings_sorted,
        "tech_stack": tech_stack,
        "endpoints_discovered": len(endpoints),
        "total_requests_sent": total_requests,
        "duration_seconds": round(duration, 2),
        "agent_turns": turns,
        "tool_calls": tool_calls,
    }

    _print_terminal_report(report)
    html_path = _write_html_report(report)
    report["html_report_path"] = html_path

    return report


def _print_terminal_report(report: dict):
    console.print()
    console.print(Panel(
        Text("AIDOS ASSESSMENT REPORT", style="bold white", justify="center"),
        border_style="cyan",
        padding=(1, 2),
    ))

    summary = Table(show_header=False, box=None, padding=(0, 2))
    summary.add_column(style="bold")
    summary.add_column()
    summary.add_row("Target", report["target"])
    risk_style = SEVERITY_COLORS.get(report["overall_risk"], "white")
    summary.add_row("Overall Risk", Text(report["overall_risk"], style=risk_style))
    summary.add_row("Endpoints Found", str(report["endpoints_discovered"]))
    summary.add_row("Requests Sent", str(report["total_requests_sent"]))
    summary.add_row("Duration", f"{report['duration_seconds']}s")
    summary.add_row("Agent Turns", str(report["agent_turns"]))
    summary.add_row("Tool Calls", str(report["tool_calls"]))

    if report["tech_stack"]:
        tech = report["tech_stack"]
        summary.add_row("Server", tech.get("server", "unknown"))
        summary.add_row("WAF", tech.get("waf", "none"))
        summary.add_row("CDN", tech.get("cdn", "unknown"))

    console.print(summary)
    console.print()

    if report["findings"]:
        findings_table = Table(title="Findings", border_style="cyan", show_lines=True)
        findings_table.add_column("#", style="dim", width=3)
        findings_table.add_column("Severity", width=10)
        findings_table.add_column("Title", min_width=30)
        findings_table.add_column("Description", min_width=40)

        for f in report["findings"]:
            sev_style = SEVERITY_COLORS.get(f["severity"], "white")
            findings_table.add_row(
                str(f["id"]),
                Text(f["severity"], style=sev_style),
                f["title"],
                f["description"][:120],
            )

        console.print(findings_table)
    else:
        console.print("[green]No vulnerabilities found. Target appears resilient.[/green]")

    console.print()


def _write_html_report(report: dict) -> str:
    findings_html = ""
    for f in report["findings"]:
        sev_class = f["severity"].lower()
        evidence = html.escape(f.get("evidence", "")) if f.get("evidence") else ""
        recommendation = html.escape(f.get("recommendation", "")) if f.get("recommendation") else ""
        findings_html += f"""
        <div class="finding {sev_class}">
            <div class="finding-header">
                <span class="severity-badge {sev_class}">{html.escape(f['severity'])}</span>
                <span class="finding-title">{html.escape(f['title'])}</span>
            </div>
            <p>{html.escape(f['description'])}</p>
            {"<div class='evidence'><strong>Evidence:</strong> " + evidence + "</div>" if evidence else ""}
            {"<div class='recommendation'><strong>Recommendation:</strong> " + recommendation + "</div>" if recommendation else ""}
        </div>"""

    tech = report.get("tech_stack", {})
    tech_html = ""
    if tech:
        tech_html = f"""
        <div class="tech-stack">
            <h2>Technology Stack</h2>
            <table>
                <tr><td>Server</td><td>{html.escape(str(tech.get('server', 'unknown')))}</td></tr>
                <tr><td>Framework</td><td>{html.escape(str(tech.get('framework', 'unknown')))}</td></tr>
                <tr><td>Language</td><td>{html.escape(str(tech.get('language', 'unknown')))}</td></tr>
                <tr><td>WAF</td><td>{html.escape(str(tech.get('waf', 'none')))}</td></tr>
                <tr><td>CDN</td><td>{html.escape(str(tech.get('cdn', 'unknown')))}</td></tr>
            </table>
        </div>"""

    risk_class = report["overall_risk"].lower()

    template = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AIDOS Report - {html.escape(report['target'])}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; background: #0a0a0f; color: #e0e0e0; padding: 2rem; }}
    .header {{ text-align: center; padding: 2rem 0; border-bottom: 1px solid #1a1a2e; margin-bottom: 2rem; }}
    .header h1 {{ font-size: 2rem; color: #00d4ff; letter-spacing: 0.3em; }}
    .header .target {{ color: #888; margin-top: 0.5rem; font-size: 0.9rem; }}
    .risk-banner {{ text-align: center; padding: 1rem; margin: 1.5rem 0; border-radius: 4px; font-size: 1.2rem; font-weight: bold; letter-spacing: 0.1em; }}
    .risk-banner.critical {{ background: #ff000020; border: 1px solid #ff0000; color: #ff4444; }}
    .risk-banner.high {{ background: #ff440020; border: 1px solid #ff4400; color: #ff6644; }}
    .risk-banner.medium {{ background: #ffaa0020; border: 1px solid #ffaa00; color: #ffcc44; }}
    .risk-banner.low {{ background: #0066ff20; border: 1px solid #0066ff; color: #4488ff; }}
    .risk-banner.none {{ background: #00ff0020; border: 1px solid #00ff00; color: #44ff44; }}
    .risk-banner.info {{ background: #88888820; border: 1px solid #888; color: #aaa; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 1.5rem 0; }}
    .stat {{ background: #12121a; border: 1px solid #1a1a2e; border-radius: 4px; padding: 1rem; text-align: center; }}
    .stat .value {{ font-size: 1.5rem; color: #00d4ff; }}
    .stat .label {{ font-size: 0.75rem; color: #666; text-transform: uppercase; letter-spacing: 0.1em; margin-top: 0.3rem; }}
    h2 {{ color: #00d4ff; margin: 2rem 0 1rem; font-size: 1.1rem; letter-spacing: 0.1em; }}
    .finding {{ background: #12121a; border-left: 3px solid #333; border-radius: 0 4px 4px 0; padding: 1rem; margin: 0.8rem 0; }}
    .finding.critical {{ border-left-color: #ff0000; }}
    .finding.high {{ border-left-color: #ff4400; }}
    .finding.medium {{ border-left-color: #ffaa00; }}
    .finding.low {{ border-left-color: #0066ff; }}
    .finding.info {{ border-left-color: #888; }}
    .finding-header {{ display: flex; align-items: center; gap: 0.8rem; margin-bottom: 0.5rem; }}
    .severity-badge {{ font-size: 0.7rem; padding: 0.15rem 0.5rem; border-radius: 2px; font-weight: bold; letter-spacing: 0.05em; }}
    .severity-badge.critical {{ background: #ff000030; color: #ff4444; }}
    .severity-badge.high {{ background: #ff440030; color: #ff6644; }}
    .severity-badge.medium {{ background: #ffaa0030; color: #ffcc44; }}
    .severity-badge.low {{ background: #0066ff30; color: #4488ff; }}
    .severity-badge.info {{ background: #88888830; color: #aaa; }}
    .finding-title {{ font-weight: bold; }}
    .finding p {{ color: #bbb; font-size: 0.9rem; line-height: 1.5; }}
    .evidence, .recommendation {{ margin-top: 0.5rem; padding: 0.5rem; background: #0a0a12; border-radius: 2px; font-size: 0.85rem; color: #999; }}
    .tech-stack table {{ width: 100%; border-collapse: collapse; }}
    .tech-stack td {{ padding: 0.5rem; border-bottom: 1px solid #1a1a2e; }}
    .tech-stack td:first-child {{ color: #888; width: 150px; }}
    .footer {{ text-align: center; margin-top: 3rem; padding-top: 1rem; border-top: 1px solid #1a1a2e; color: #444; font-size: 0.8rem; }}
</style>
</head>
<body>
    <div class="header">
        <h1>AIDOS</h1>
        <div class="target">{html.escape(report['target'])}</div>
    </div>

    <div class="risk-banner {risk_class}">OVERALL RISK: {html.escape(report['overall_risk'])}</div>

    <div class="stats">
        <div class="stat"><div class="value">{len(report['findings'])}</div><div class="label">Findings</div></div>
        <div class="stat"><div class="value">{report['endpoints_discovered']}</div><div class="label">Endpoints</div></div>
        <div class="stat"><div class="value">{report['total_requests_sent']}</div><div class="label">Requests</div></div>
        <div class="stat"><div class="value">{report['duration_seconds']}s</div><div class="label">Duration</div></div>
        <div class="stat"><div class="value">{report['agent_turns']}</div><div class="label">Agent Turns</div></div>
        <div class="stat"><div class="value">{report['tool_calls']}</div><div class="label">Tool Calls</div></div>
    </div>

    {tech_html}

    <h2>Findings</h2>
    {findings_html if findings_html else '<p style="color:#666">No vulnerabilities discovered. Target appears resilient to tested attack vectors.</p>'}

    <div class="footer">Generated by AIDOS — LLM-Powered Stress Testing Agent</div>
</body>
</html>"""

    report_path = Path(f"aidos_report_{int(time.time())}.html")
    report_path.write_text(template, encoding="utf-8")
    console.print(f"[dim]HTML report saved to {report_path}[/dim]")
    return str(report_path)
