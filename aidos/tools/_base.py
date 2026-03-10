from __future__ import annotations

import asyncio

from .state import STATE


def _tool_available(name: str) -> bool:
    return name in STATE.installed_tools


async def _run_cmd(cmd: list[str], timeout: int = 120, stdin_data: str | None = None) -> dict:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if stdin_data else None,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=stdin_data.encode() if stdin_data else None),
            timeout=timeout,
        )
        return {
            "exit_code": proc.returncode,
            "stdout": stdout.decode(errors="replace")[:15000],
            "stderr": stderr.decode(errors="replace")[:5000],
        }
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return {"error": "command_timed_out", "timeout_seconds": timeout}
    except FileNotFoundError:
        return {"error": f"tool_not_found: {cmd[0]}", "hint": f"install {cmd[0]} and ensure it is in PATH"}
    except Exception as e:
        return {"error": str(e), "error_type": type(e).__name__}
