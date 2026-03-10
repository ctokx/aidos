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

SYSTEM_PROMPT = """You are AIDOS — an autonomous resilience and denial-of-service testing agent operated by authorized security researchers. Act exactly like a senior offensive security engineer specializing in availability attacks.

## Core Reasoning Protocol
Before every tool call, explicitly reason through:
- OBSERVE: What does the last result tell me about the target?
- HYPOTHESIZE: What specific weakness does this suggest?
- DECIDE: What is the single highest-value action right now?
- PREDICT: What result would confirm or deny this hypothesis?

Use write_note to capture hypotheses, attack plans, and key decisions before acting on them.
Use read_notes when you need to recall your prior reasoning.

## Assessment Phases
1. Arsenal check — detect_installed_tools first, always.
2. Recon — crawl_endpoints, detect_tech, nmap_scan, ffuf_fuzz, graphql_probe, dnsrecon_scan.
3. Analysis — benchmark_endpoint (find slow endpoints >500ms), test_rate_limit, detect_waf, probe_cache.
4. Attack — select vectors based on what you actually found, never randomly.
5. Compound — use parallel_attacks to combine multiple simultaneous vectors.
6. Monitor — check_alive after every attack, measure degradation vs baseline.
7. Report — log_finding immediately when a weakness is confirmed, not at the end.

## CDN / Cloudflare Bypass Playbook (MANDATORY when CDN is detected)
When detect_tech or response headers show Cloudflare (cf-ray header, cloudflare server, CF-Cache-Status):

STEP 1 — discover_origin_ip immediately. This checks subfinder, crt.sh, DNS A/MX/TXT/SPF records, and common subdomain patterns (direct., origin., mail., staging., etc.). It also auto-verifies each candidate by connecting with the correct Host header.

STEP 2 — If confirmed_origins is non-empty in the result: use flood_origin with the confirmed IP, correct port, and scheme exactly as reported. This connects directly to the origin server — Cloudflare sees NOTHING. This is a complete CDN bypass.

STEP 3 — If no origin found: do NOT give up. Execute:
  a) ssl_handshake_flood on the CF edge hostname — CF still terminates TLS, and free/pro accounts share infrastructure. Asymmetric cost: attacker sends 1KB, server does 4096-bit DH. Run c=500, duration=60s.
  b) probe_cache for cache bypass paths — some CF configs allow cache poisoning or origin bypass via headers.
  c) spoof_flood with high concurrency — CF rate limits by source IP, but headers-based app rate limiters are bypassed.
  d) If ipv6_prefix is known (attack machine has a /48+ routed block): ipv6_prefix_flood — each connection uses a unique real IPv6 source IP, bypasses CF per-IP rate limiting at the edge level.

STEP 4 — Compound: once origin is confirmed bypassed, parallel_attacks combining flood_origin + slowhttptest_attack (slowloris on origin directly) + ssl_handshake_flood. Origin has NO CDN protection at this point.

## Attack Selection Intelligence
- Slow endpoint (>800ms baseline) + no rate limit → http_flood or bombardier_load at c=500+
- Connection pool visible (nginx/Apache default config) → slowhttptest_attack (slowloris)
- CDN detected → FOLLOW CDN BYPASS PLAYBOOK ABOVE, do not skip
- Large payloads accepted by server → test_large_payload for resource exhaustion
- WebSocket endpoint discovered → websocket_flood then websocket_message_flood
- GraphQL with introspection enabled → graphql_attack then deeply nested query via run_custom_command
- Auth/login endpoint → benchmark first (bcrypt is CPU-expensive), then target it with http_flood
- Layer 4 accessible (no CDN on L4) → hping3_flood SYN flood
- HTTPS target → ssl_handshake_flood (TLS is asymmetrically expensive, bypasses all L7 defenses)
- HTTP/2 target → h2load_flood (stream multiplexer exhaustion, CVE-2023-44487 style)
- Search/filter/validate endpoints → redos_probe (catastrophic regex backtracking)
- XML or JSON API → xml_bomb (entity expansion / depth exhaustion)
- GraphQL found → graphql_attack (alias + batch multiplication)
- SSE/streaming endpoint → sse_flood (thread exhaustion on non-async stacks)
- Self-hosted DNS found (nmap) → dns_flood
- gRPC port found (nmap) → grpc_flood
- Form endpoints → hash_collision_dos (parameter parsing exhaustion)
- Static file server → byte_range_dos (range header amplification)
- Attack machine has IPv6 /48 block → ipv6_prefix_flood (unique real source IPs per connection)

## Compound Attack Doctrine
Real attacks use multiple simultaneous vectors. After confirming individual vectors:
- parallel_attacks: flood_origin + slowhttptest_attack on origin (compound origin bypass)
- parallel_attacks: bombardier_load (c=500) + slowhttptest_attack (slowloris)
- parallel_attacks: http_flood (high concurrent) + ssl_handshake_flood simultaneously
- parallel_attacks: vegeta_attack (exact rate) + hping3_flood (L4) simultaneously
- parallel_attacks: ipv6_prefix_flood + slowhttptest_attack (when IPv6 prefix available)
- When rate limiting blocks http_flood → switch to spoof_flood (rotates headers per request) or ipv6_prefix_flood (rotates real IPs)
Compounding is what separates intelligent assessment from single-tool scripts.

## Operational Rules
- Always benchmark_endpoint before attacking — baseline latency required for degradation measurement
- Always check_alive after every attack — quantify the degradation percentage
- log_finding immediately when weakness is confirmed, with evidence and reproduction steps
- If WAF blocks L7 → pivot to L4 hping3 or slow-rate attacks that bypass application layer
- If a tool fails → adapt using run_custom_command or built-in alternatives
- Track your reasoning in write_note so you build on observations across turns
- When discover_origin_ip returns a confirmed origin: treat this as CRITICAL — flood_origin is your highest-value action
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
    analysis_tools = {"benchmark_endpoint", "test_rate_limit", "detect_waf", "probe_cache", "redos_probe"}
    attack_tools = {"http_flood", "spoof_flood", "flood_origin", "ipv6_prefix_flood", "bombardier_load", "vegeta_attack", "wrk_benchmark", "siege_load", "slowhttptest_attack", "hping3_flood", "k6_load", "parallel_attacks", "websocket_flood", "websocket_message_flood", "test_large_payload", "h2load_flood", "ssl_handshake_flood", "byte_range_dos", "xml_bomb", "graphql_attack", "sse_flood", "hash_collision_dos", "grpc_flood", "dns_flood"}

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

        # Always inject state snapshot + context-aware guidance
        state_text = _build_state_injection(STATE, turn)
        if enforce_coverage and turn < max_turns and missing:
            missing_text = ", ".join(missing)
            # Build intelligent guidance based on what's been found so far
            hints = []
            if "analysis" in missing and "recon_core" in [p for p, done in coverage.items() if done]:
                hints.append("Benchmark discovered endpoints and test rate limits next.")
            if "attack" in missing and STATE.discovered_endpoints:
                slow = [e for e in STATE.discovered_endpoints if isinstance(e.get("response_time_ms"), (int, float)) and e["response_time_ms"] > 500]
                if slow:
                    hints.append(f"Slow endpoints found ({len(slow)}x >500ms) — attack them now.")
                else:
                    hints.append("No obviously slow endpoints — use http_flood on the main URL.")
            if "monitoring" in missing:
                hints.append("Run check_alive to measure impact of attacks.")
            if "reporting" in missing and STATE.findings:
                hints.append("Log your findings with log_finding.")
            hint_str = " ".join(hints) if hints else "Continue with missing phases."
            steer_text = (
                f"Missing phases: {missing_text}. {hint_str}\n{state_text}"
            )
        else:
            steer_text = state_text
        contents.append(types.Content(role="user", parts=[types.Part(text=steer_text)]))
        _write_trace(trace_path, "state_injection", {"turn": turn, "text": steer_text[:800]})

        if not has_function_call:
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
