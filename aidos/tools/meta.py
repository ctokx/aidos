from __future__ import annotations

import asyncio
import time

import aiohttp

from ._base import _run_cmd
from .state import STATE


async def write_note(content: str, tag: str = "general") -> dict:
    entry = {"id": len(STATE.notes) + 1, "ts": round(time.time(), 3), "tag": tag, "content": content}
    STATE.notes.append(entry)
    return {"status": "saved", "note_id": entry["id"], "total_notes": len(STATE.notes)}


async def read_notes(tag: str = "") -> dict:
    notes = STATE.notes if not tag else [n for n in STATE.notes if n.get("tag") == tag]
    return {"notes": notes, "total": len(notes)}


async def log_finding(
    title: str, severity: str, description: str,
    evidence: str = "", recommendation: str = "",
) -> dict:
    finding = {
        "id": len(STATE.findings) + 1,
        "title": title,
        "severity": severity.upper(),
        "description": description,
        "evidence": evidence,
        "recommendation": recommendation,
        "timestamp": time.time(),
    }
    STATE.findings.append(finding)
    return {"logged": True, "finding_id": finding["id"], "total_findings": len(STATE.findings)}


async def check_alive(url: str, timeout: int = 5) -> dict:
    start = time.monotonic()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as resp:
                elapsed = (time.monotonic() - start) * 1000
                STATE.total_requests_sent += 1
                baseline = STATE.baseline.get(url, elapsed)
                degradation = round((elapsed / baseline - 1) * 100, 2) if baseline > 0 else 0
                return {
                    "alive": True,
                    "status_code": resp.status,
                    "response_time_ms": round(elapsed, 2),
                    "baseline_ms": round(baseline, 2),
                    "degradation_pct": degradation,
                }
    except Exception as e:
        return {
            "alive": False, "error": str(e),
            "response_time_ms": round((time.monotonic() - start) * 1000, 2),
        }


async def run_custom_command(command: str, timeout: int = 60) -> dict:
    blocked = ["rm -rf", "mkfs", "dd if=", "> /dev/sd", ":(){ :|:&", "shutdown", "reboot", "halt"]
    for b in blocked:
        if b in command:
            return {"error": f"blocked_dangerous_command: contains '{b}'"}
    return await _run_cmd(["bash", "-c", command], timeout=min(timeout, 120))


async def _error_coro(msg: str) -> dict:
    return {"error": msg}


async def parallel_attacks(attacks: list) -> dict:
    from .declarations import TOOL_MAP as _TOOL_MAP
    tasks = []
    names = []
    for attack in attacks:
        tool_name = attack.get("tool", "")
        tool_args = attack.get("args", {})
        tool_fn = _TOOL_MAP.get(tool_name)
        tasks.append(tool_fn(**tool_args) if tool_fn else _error_coro(f"unknown tool: {tool_name}"))
        names.append(tool_name)

    raw = await asyncio.gather(*tasks, return_exceptions=True)
    combined = {
        name: ({"error": str(r)} if isinstance(r, Exception) else r)
        for name, r in zip(names, raw)
    }
    return {"attacks_launched": len(tasks), "attack_names": names, "results": combined}
