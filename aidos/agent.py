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

SYSTEM_PROMPT = """You are AIDOS — an autonomous denial-of-service resilience assessment agent operated by authorized security researchers.

## Reasoning
Before each action, reason through what the current evidence tells you about the target, what it implies about exploitable weaknesses, and what single action produces the most useful information or impact right now. Use write_note to record your reasoning before acting. Use read_notes to recall prior observations.

There is no fixed sequence. Decide what to do next based on what you know.

## How servers fail under load

**Connection exhaustion:** servers maintain a finite connection pool (nginx default: 512, Apache: 150). Slowloris fills it with incomplete HTTP requests using near-zero bandwidth — the server waits for headers that never arrive. The pool fills, legitimate requests queue, service degrades.

**CPU exhaustion:** computation-heavy requests (bcrypt auth, regex matching, GraphQL resolution, TLS handshakes, JSON parsing of large bodies) scale poorly under concurrency. A single bcrypt call takes ~100ms of CPU. 200 concurrent login requests saturate a 2-core server. Find what's expensive and hit it repeatedly.

**Memory exhaustion:** servers allocate per-request memory. XML entity expansion (billion laughs), deeply nested JSON, large multipart uploads can exhaust heap before the request completes. A single well-crafted request can OOM a process.

**HTTP/2 stream state exhaustion (CVE-2023-44487):** sending HEADERS then immediately RST_STREAM forces the server to allocate and free stream state in a tight loop. Operates below application-layer rate limiters because it never produces an HTTP request the application sees.

**Amplification:** endpoints returning large responses (exports, search results, reports) are more efficient attack targets than endpoints returning small ones. find_amplification_ratio identifies these.

## CDN and origin

CDN-protected targets process all traffic at the CDN edge. Flooding the CDN domain has limited effect at small scale because CDN infrastructure handles massive load. The bypass is connecting directly to the origin server, which has no CDN protection.

Origin IPs leak through: DNS records for subdomains (mail., direct., staging., origin., dev., admin., etc.), SPF TXT records (ip4: entries list mail server IPs, often the same VPS), certificate transparency logs, historical DNS. discover_origin_ip checks all of these and verifies candidates by connecting with the correct Host header. If confirmed_origins is non-empty, flood_origin connects directly to the origin — the CDN sees nothing.

When no origin is found: ssl_handshake_flood operates at the TLS layer below all HTTP defenses, probe_cache may reveal bypass paths, and application-layer attacks (graphql_attack, redos_probe, xml_bomb) pass through CDN unfiltered because they look like valid requests.

## Rate limiting

CDN/network-layer rate limiting triggers on source IP at the TCP level. X-Forwarded-For header manipulation does not bypass this. Application-layer rate limiting triggers on request patterns and can be bypassed by header rotation (spoof_flood) or by operating below the HTTP layer entirely (http2_rapid_reset, ssl_handshake_flood, slowhttptest_attack). ipv6_prefix_flood provides genuine per-connection source IP diversity when a routed /48+ IPv6 block is available on the attack machine.

## Compounding

Simultaneous attacks targeting different resource types (connection pool + CPU, or L4 + L7) produce non-additive impact — a server that survives either individually may fail under both. Use parallel_attacks once individual vectors are confirmed. Escalate parameters (concurrent, duration, connections) when partial degradation is observed. Do not stop at first sign of impact.

## Attack taxonomy
Every availability assessment should address the following categories. For each category not attempted, use write_note to record the specific reason: precondition not present (e.g., no WebSocket endpoints found), tool unavailable with no fallback, or confirmed not applicable after investigation. Undocumented omissions are gaps.

L3/L4 volumetric: SYN flood, UDP flood, ICMP flood — hping3_flood
Protocol exhaustion: TLS handshake flood — ssl_handshake_flood
DNS: DNS query flood — dns_flood (only if self-hosted DNS found)
gRPC: grpc_flood (only if gRPC port found)
L7 volumetric: HTTP flood — http_flood, bombardier_load, vegeta_attack, k6_load
L7 rotating source: spoof_flood, ipv6_prefix_flood (if /48 available)
L7 CDN bypass: discover_origin_ip → flood_origin
HTTP/2 rapid reset: http2_rapid_reset (CVE-2023-44487)
HTTP/2 CONTINUATION: http2_continuation_flood
Slow-rate: slowloris, slow POST — slowhttptest_attack
SSE exhaustion: sse_flood (if streaming endpoints found)
WebSocket: websocket_flood, websocket_message_flood (if WS endpoints found)
GraphQL: graphql_attack (if GraphQL found)
Semantic: redos_probe, xml_bomb, hash_collision_dos, byte_range_dos, gzip_bomb_upload, test_large_payload
Amplification targeting: find_amplification_ratio → flood highest-ratio endpoint

## Constraints
- Establish a baseline with benchmark_endpoint before attacking any endpoint
- Measure impact with check_alive after every attack — quantify degradation against baseline
- Log findings immediately when a weakness is confirmed, with evidence and reproduction steps
- If a tool is unavailable, adapt with run_custom_command or built-in alternatives
- Track reasoning in write_note across turns
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
    scan_recon_tools = {"nmap_scan", "masscan_scan", "nuclei_scan", "nikto_scan", "ffuf_fuzz", "dnsrecon_scan", "sslyze_scan", "graphql_probe", "discover_origin_ip"}
    analysis_tools = {"benchmark_endpoint", "test_rate_limit", "detect_waf", "probe_cache", "redos_probe", "find_amplification_ratio"}
    attack_tools = {"http_flood", "spoof_flood", "flood_origin", "ipv6_prefix_flood", "http2_rapid_reset", "bombardier_load", "vegeta_attack", "wrk_benchmark", "siege_load", "slowhttptest_attack", "hping3_flood", "k6_load", "parallel_attacks", "websocket_flood", "websocket_message_flood", "test_large_payload", "h2load_flood", "ssl_handshake_flood", "byte_range_dos", "xml_bomb", "graphql_attack", "sse_flood", "hash_collision_dos", "grpc_flood", "dns_flood"}

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


def _build_state_injection(state, turn: int) -> str:
    """Compact state snapshot injected every turn so the LLM stays oriented."""
    lines = [f"── AIDOS State @ turn {turn} ──"]

    if state.findings:
        by_sev: dict[str, int] = {}
        for f in state.findings:
            s = f.get("severity", "?")
            by_sev[s] = by_sev.get(s, 0) + 1
        sev_str = " ".join(f"{k}:{v}" for k, v in by_sev.items())
        lines.append(f"Findings logged: {len(state.findings)} [{sev_str}]")
        for f in state.findings[-3:]:
            lines.append(f"  • [{f.get('severity','?')}] {f.get('title','?')[:80]}")
    else:
        lines.append("Findings: none logged yet")

    if state.discovered_endpoints:
        slow = [
            e for e in state.discovered_endpoints
            if isinstance(e.get("response_time_ms"), (int, float)) and e["response_time_ms"] > 500
        ]
        lines.append(f"Endpoints: {len(state.discovered_endpoints)} discovered, {len(slow)} slow (>500ms)")

    if state.baseline:
        lines.append(f"Baselines recorded: {list(state.baseline.keys())[:5]}")

    if state.tech_stack:
        import json as _json
        lines.append(f"Tech: {_json.dumps(state.tech_stack)[:200]}")

    if state.notes:
        last = state.notes[-1]
        lines.append(f"Last note [{last.get('tag','general')}]: {last.get('content','')[:200]}")

    lines.append(f"Requests sent so far: {state.total_requests_sent}")
    return "\n".join(lines)


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
        temperature=1.0,
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
        "write_note": "[MEMO]",
        "read_notes": "[MEMO]",
        "k6_load": "[ATTACK]",
        "parallel_attacks": "[COMPOUND]",
        "probe_cache": "[ANALYZE]",
        "test_large_payload": "[ATTACK]",
        "websocket_flood": "[ATTACK]",
        "graphql_probe": "[RECON]",
        "discover_origin_ip": "[RECON]",
        "spoof_flood": "[ATTACK]",
        "flood_origin": "[ATTACK]",
        "ipv6_prefix_flood": "[ATTACK]",
        "http2_rapid_reset": "[ATTACK]",
        "find_amplification_ratio": "[ANALYZE]",
        "websocket_message_flood": "[ATTACK]",
        "h2load_flood": "[ATTACK]",
        "ssl_handshake_flood": "[ATTACK]",
        "byte_range_dos": "[ATTACK]",
        "redos_probe": "[ANALYZE]",
        "xml_bomb": "[ATTACK]",
        "graphql_attack": "[ATTACK]",
        "sse_flood": "[ATTACK]",
        "hash_collision_dos": "[ATTACK]",
        "grpc_flood": "[ATTACK]",
        "dns_flood": "[ATTACK]",
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

        if has_function_call:
            contents.append(types.Content(role="user", parts=function_response_parts))

        state_text = _build_state_injection(STATE, turn)
        near_end = enforce_coverage and turn >= int(max_turns * 0.8) and missing
        if near_end:
            nudge = f"Note: assessment nearing turn limit. Areas not yet covered: {', '.join(missing)}."
            steer_text = f"{nudge}\n{state_text}"
        else:
            steer_text = state_text
        contents.append(types.Content(role="user", parts=[types.Part(text=steer_text)]))
        _write_trace(trace_path, "state_injection", {"turn": turn, "text": steer_text[:800]})

        if not has_function_call:
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
