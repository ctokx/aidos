from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path

from google import genai
from google.genai import types
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from aidos.report import generate_report
from aidos.tools import STATE, TOOL_DECLARATIONS, TOOL_MAP, reset_state

console = Console()

SYSTEM_PROMPT = """You are AIDOS, an autonomous offensive stress testing agent. You are deployed by authorized security professionals to find denial-of-service vulnerabilities before real attackers do.

You are NOT a generic load testing tool. You act like a pentester:
- recon
- analysis
- attack
- monitor
- report

Rules:
- Start with detect_installed_tools.
- Use crawl_endpoints and detect_tech early.
- Benchmark and rate-limit test likely expensive endpoints.
- Use available attack tools strategically.
- Use check_alive after attacks.
- Log findings with evidence and recommendations.
"""


def _write_trace(trace_path: str | None, event: str, payload: dict | None = None) -> None:
    if not trace_path:
        return
    record = {
        "ts": round(time.time(), 3),
        "event": event,
    }
    if payload:
        record.update(payload)
    with open(trace_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")


def _coverage_status(executed_tools: set[str]) -> tuple[dict[str, bool], list[str]]:
    scan_recon_tools = {"nmap_scan", "masscan_scan", "nuclei_scan", "nikto_scan", "ffuf_fuzz", "dnsrecon_scan", "sslyze_scan"}
    analysis_tools = {"benchmark_endpoint", "test_rate_limit", "detect_waf"}
    attack_tools = {"http_flood", "bombardier_load", "vegeta_attack", "wrk_benchmark", "siege_load", "slowhttptest_attack", "hping3_flood"}

    status = {
        "arsenal_check": "detect_installed_tools" in executed_tools,
        "recon_core": {"crawl_endpoints", "detect_tech"}.issubset(executed_tools),
        "recon_scan": bool(executed_tools.intersection(scan_recon_tools)),
        "analysis": bool(executed_tools.intersection(analysis_tools)),
        "attack": bool(executed_tools.intersection(attack_tools)),
        "monitoring": "check_alive" in executed_tools,
        "reporting": "log_finding" in executed_tools,
    }
    missing = [phase for phase, done in status.items() if not done]
    return status, missing


async def run_agent(
    target_url: str,
    max_turns: int = 50,
    model: str = "gemini-2.5-flash",
    trace_file: str | None = None,
    enforce_coverage: bool = True,
) -> dict:
    reset_state()

    trace_path = trace_file or f"aidos_trace_{int(time.time())}.jsonl"
    Path(trace_path).parent.mkdir(parents=True, exist_ok=True)
    Path(trace_path).write_text("", encoding="utf-8")
    _write_trace(
        trace_path,
        "run_start",
        {
            "target": target_url,
            "model": model,
            "max_turns": max_turns,
            "enforce_coverage": enforce_coverage,
        },
    )

    client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
    tools = types.Tool(function_declarations=TOOL_DECLARATIONS)
    config = types.GenerateContentConfig(
        tools=[tools],
        system_instruction=SYSTEM_PROMPT,
        temperature=0.1,
    )

    contents = [
        types.Content(
            role="user",
            parts=[
                types.Part(
                    text=(
                        f"Target: {target_url}\n\n"
                        f"Execute a full autonomous stress testing assessment. "
                        f"Coverage requirement: before ending, complete at least one meaningful action in each phase: "
                        f"arsenal check, recon, analysis, attack, monitoring, and reporting."
                    )
                )
            ],
        )
    ]

    start_time = time.time()
    turn = 0
    tool_calls_made = 0
    executed_tools: set[str] = set()

    console.print(
        Panel(
            "[bold]Assessment initiated[/bold]\n"
            f"Target: {target_url}\n"
            f"Model: {model}\n"
            f"Max turns: {max_turns}",
            title="[bold cyan]AIDOS[/bold cyan]",
            border_style="cyan",
        )
    )

    icon_map = {
        "nmap_scan": "[RECON]",
        "masscan_scan": "[RECON]",
        "nuclei_scan": "[RECON]",
        "nikto_scan": "[RECON]",
        "ffuf_fuzz": "[RECON]",
        "crawl_endpoints": "[RECON]",
        "detect_tech": "[RECON]",
        "detect_installed_tools": "[TOOLS]",
        "http_flood": "[ATTACK]",
        "slowhttptest_attack": "[ATTACK]",
        "hping3_flood": "[ATTACK]",
        "bombardier_load": "[ATTACK]",
        "vegeta_attack": "[ATTACK]",
        "wrk_benchmark": "[ATTACK]",
        "siege_load": "[ATTACK]",
        "http_request": "[HTTP]",
        "benchmark_endpoint": "[ANALYZE]",
        "test_rate_limit": "[ANALYZE]",
        "detect_waf": "[ANALYZE]",
        "check_alive": "[MONITOR]",
        "log_finding": "[FINDING]",
        "sslyze_scan": "[TLS]",
        "dnsrecon_scan": "[DNS]",
        "run_custom_command": "[CUSTOM]",
    }

    while turn < max_turns:
        turn += 1
        _write_trace(trace_path, "turn_start", {"turn": turn})

        try:
            response = client.models.generate_content(
                model=model,
                contents=contents,
                config=config,
            )
        except Exception as e:
            console.print(f"[red]LLM error: {e}[/red]")
            _write_trace(trace_path, "llm_error", {"turn": turn, "error": str(e), "error_type": type(e).__name__})
            await asyncio.sleep(2)
            continue

        if not response.candidates:
            console.print("[yellow]Empty response. Ending.[/yellow]")
            _write_trace(trace_path, "llm_empty_candidates", {"turn": turn})
            break

        candidate = response.candidates[0]
        finish_reason = candidate.finish_reason.name if candidate.finish_reason else None
        _write_trace(trace_path, "llm_candidate", {"turn": turn, "finish_reason": finish_reason})

        if not candidate.content or not candidate.content.parts:
            console.print("[yellow]Model returned empty content for this turn. Retrying.[/yellow]")
            _write_trace(trace_path, "llm_empty_content", {"turn": turn})
            await asyncio.sleep(1)
            continue

        parts = candidate.content.parts
        has_function_call = False
        function_response_parts = []

        for part in parts:
            if part.text:
                console.print()
                console.print(
                    Panel(
                        Text(part.text, style="white"),
                        title=f"[bold cyan]AIDOS[/bold cyan] [dim]turn {turn}[/dim]",
                        border_style="cyan",
                        padding=(0, 1),
                    )
                )
                _write_trace(trace_path, "assistant_text", {"turn": turn, "text": part.text[:4000]})

            if part.function_call:
                has_function_call = True
                fc = part.function_call
                tool_calls_made += 1

                tool_name = fc.name
                tool_args = dict(fc.args) if fc.args else {}
                executed_tools.add(tool_name)

                icon = icon_map.get(tool_name, "[TOOL]")
                target_display = tool_args.get("url", tool_args.get("target", tool_args.get("host", tool_args.get("domain", ""))))
                console.print(f"  {icon} [bold yellow]{tool_name}[/bold yellow] [dim]{target_display}[/dim]")
                _write_trace(trace_path, "tool_call", {"turn": turn, "tool": tool_name, "args": tool_args})

                tool_fn = TOOL_MAP.get(tool_name)
                if tool_fn is None:
                    result = {"error": f"unknown_tool: {tool_name}"}
                else:
                    try:
                        result = await tool_fn(**tool_args)
                    except Exception as e:
                        result = {"error": str(e), "error_type": type(e).__name__}

                if tool_name == "log_finding":
                    sev = tool_args.get("severity", "").upper()
                    console.print(f"    [dim]- finding logged ({sev})[/dim]")
                elif tool_name == "detect_installed_tools":
                    installed = result.get("installed", [])
                    console.print(f"    [dim]- {len(installed)} tools: {', '.join(installed)}[/dim]")
                elif tool_name == "nuclei_scan":
                    count = result.get("vulnerabilities_found", 0)
                    console.print(f"    [dim]- nuclei findings: {count}[/dim]")
                elif tool_name == "nmap_scan":
                    ports = result.get("ports_found", [])
                    console.print(f"    [dim]- open ports: {len(ports)}[/dim]")

                result_str = json.dumps(result, default=str)
                if len(result_str) > 12000:
                    result_str = result_str[:12000] + "...(truncated)"

                _write_trace(
                    trace_path,
                    "tool_result",
                    {
                        "turn": turn,
                        "tool": tool_name,
                        "result_preview": result_str[:4000],
                    },
                )

                function_response_parts.append(
                    types.Part.from_function_response(
                        name=tool_name,
                        response={"result": result_str},
                    )
                )

        contents.append(candidate.content)

        coverage, missing = _coverage_status(executed_tools)
        _write_trace(trace_path, "coverage_status", {"turn": turn, "coverage": coverage, "missing": missing})

        if enforce_coverage and turn < max_turns and missing:
            missing_text = ", ".join(missing)
            steer_text = (
                f"Coverage status after turn {turn}: missing phases -> {missing_text}. "
                f"Prioritize missing phases now. "
                f"If attack phase has started, follow with check_alive and log_finding."
            )
            contents.append(types.Content(role="user", parts=[types.Part(text=steer_text)]))
            _write_trace(trace_path, "coverage_steer", {"turn": turn, "message": steer_text})

        if has_function_call:
            contents.append(types.Content(role="user", parts=function_response_parts))
        else:
            if enforce_coverage and turn < max_turns and missing:
                continue
            if candidate.finish_reason and candidate.finish_reason.name == "STOP":
                break

    elapsed = time.time() - start_time
    final_coverage, final_missing = _coverage_status(executed_tools)

    report = generate_report(
        target_url=target_url,
        findings=STATE.findings,
        tech_stack=STATE.tech_stack,
        endpoints=STATE.discovered_endpoints,
        total_requests=STATE.total_requests_sent,
        duration=elapsed,
        turns=turn,
        tool_calls=tool_calls_made,
    )
    report["trace_path"] = trace_path
    report["coverage"] = final_coverage
    report["coverage_missing"] = final_missing

    _write_trace(
        trace_path,
        "run_end",
        {
            "turns": turn,
            "tool_calls": tool_calls_made,
            "coverage": final_coverage,
            "coverage_missing": final_missing,
            "overall_risk": report.get("overall_risk"),
            "findings": len(report.get("findings", [])),
        },
    )

    return report
