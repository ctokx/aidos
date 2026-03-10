from __future__ import annotations

import json
import re
import time
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from ._base import _run_cmd, _tool_available
from .state import STATE


async def detect_installed_tools() -> dict:
    STATE.detect_tools()
    return {
        "installed": list(STATE.installed_tools.keys()),
        "missing": [t for t in [
            "nmap", "masscan", "hping3", "nikto", "nuclei", "ffuf",
            "slowhttptest", "wrk", "bombardier", "vegeta", "k6", "siege",
            "ab", "sslyze", "dnsrecon", "curl", "h2load", "thc-ssl-dos",
            "ghz", "dnsperf", "graphql-cop", "subfinder", "shodan",
        ] if t not in STATE.installed_tools],
        "total_available": len(STATE.installed_tools),
    }


async def crawl_endpoints(url: str, depth: int = 2, max_pages: int = 50) -> dict:
    visited: set[str] = set()
    endpoints: list[dict] = []
    queue = [(url, 0)]
    parsed_base = urlparse(url)

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, limit_per_host=0)) as session:
        while queue and len(visited) < max_pages:
            current_url, current_depth = queue.pop(0)
            if current_url in visited or current_depth > depth:
                continue
            visited.add(current_url)
            try:
                start = time.monotonic()
                async with session.get(
                    current_url, timeout=aiohttp.ClientTimeout(total=8),
                    ssl=False, allow_redirects=True,
                ) as resp:
                    elapsed = time.monotonic() - start
                    body = await resp.text()
                    STATE.total_requests_sent += 1
                    ep = {
                        "url": current_url,
                        "status": resp.status,
                        "content_type": resp.headers.get("Content-Type", ""),
                        "size_bytes": len(body.encode()),
                        "response_time_ms": round(elapsed * 1000, 2),
                    }
                    endpoints.append(ep)
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
                            inputs = [
                                {"name": inp.get("name", ""), "type": inp.get("type", "text")}
                                for inp in form.find_all(["input", "textarea", "select"])
                            ]
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


async def detect_tech(url: str) -> dict:
    from .analysis import http_request
    result = await http_request(url)
    if "error" in result:
        return result

    headers = result.get("headers", {})
    tech: dict = {
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

    cdn_map = {
        "cf-ray": "cloudflare", "x-amz-cf-id": "aws_cloudfront",
        "x-served-by": "fastly", "x-akamai-transformed": "akamai",
        "x-cache": "cdn_cached", "x-cdn": "generic_cdn",
    }
    for header, cdn_name in cdn_map.items():
        if any(header.lower() == k.lower() for k in headers):
            tech["cdn"] = cdn_name

    powered = headers.get("X-Powered-By", "").lower()
    if "php" in powered:
        tech["language"] = "php"
    elif "asp.net" in powered:
        tech["language"] = "asp.net"
    elif "express" in powered:
        tech["framework"] = "express"
        tech["language"] = "node.js"

    cookies = headers.get("Set-Cookie", "")
    if "PHPSESSID" in cookies:
        tech["language"] = "php"
    elif "JSESSIONID" in cookies:
        tech["language"] = "java"
    elif "csrftoken" in cookies:
        tech["framework"] = "django"
        tech["language"] = "python"

    security_headers = [
        "Strict-Transport-Security", "X-Frame-Options",
        "X-Content-Type-Options", "Content-Security-Policy",
    ]
    tech["security_headers_present"] = [h for h in security_headers if headers.get(h)]
    tech["security_headers_missing"] = [h for h in security_headers if not headers.get(h)]

    STATE.tech_stack = tech
    return tech


async def nmap_scan(
    target: str, scan_type: str = "service_version",
    ports: str = "", scripts: str = "", extra_args: str = "",
) -> dict:
    if not _tool_available("nmap"):
        return {"error": "nmap not installed"}

    cmd = ["nmap", "-oX", "-"]
    type_flags = {
        "service_version": ["-sV", "-sC"],
        "syn_scan": ["-sS"],
        "udp_scan": ["-sU", "--top-ports", "50"],
        "aggressive": ["-A", "-T4"],
        "vuln_scan": ["--script", "vuln"],
        "os_detect": ["-O"],
        "firewall_evasion": ["-sS", "-f", "--data-length", "50"],
    }
    cmd += type_flags.get(scan_type, ["-sV"])
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
        if "portid=" not in line:
            continue
        m = {
            "port": re.search(r'portid="(\d+)"', line),
            "protocol": re.search(r'protocol="(\w+)"', line),
            "state": re.search(r'state="(\w+)"', line),
            "service": re.search(r'name="([^"]*)"', line),
            "product": re.search(r'product="([^"]*)"', line),
            "version": re.search(r'version="([^"]*)"', line),
        }
        if m["port"] and m["state"]:
            ports_found.append({k: (v.group(1) if v else "") for k, v in m.items()})

    return {
        "target": target, "scan_type": scan_type,
        "ports_found": ports_found, "raw_output": output[:8000],
    }


async def masscan_scan(target: str, ports: str = "0-65535", rate: int = 1000) -> dict:
    if not _tool_available("masscan"):
        return {"error": "masscan not installed"}

    cmd = ["masscan", target, "-p", ports, "--rate", str(min(rate, 100000)), "-oJ", "-"]
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

    return {"target": target, "rate": rate, "open_ports": open_ports, "total_open": len(open_ports)}


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
        if line.strip().startswith("{"):
            try:
                e = json.loads(line.strip())
                vulns.append({
                    "template_id": e.get("template-id", ""),
                    "name": e.get("info", {}).get("name", ""),
                    "severity": e.get("info", {}).get("severity", ""),
                    "matched_at": e.get("matched-at", ""),
                    "description": e.get("info", {}).get("description", "")[:500],
                })
            except json.JSONDecodeError:
                continue

    return {"target": target, "vulnerabilities_found": len(vulns), "vulnerabilities": vulns}


async def nikto_scan(target: str, tuning: str = "") -> dict:
    if not _tool_available("nikto"):
        return {"error": "nikto not installed"}

    cmd = ["nikto", "-h", target, "-Format", "json", "-output", "-"]
    if tuning:
        cmd += ["-Tuning", tuning]
    result = await _run_cmd(cmd, timeout=600)
    if "error" in result:
        return result
    return {"target": target, "raw_output": result["stdout"][:10000]}


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

    try:
        data = json.loads(result["stdout"])
        findings = [
            {
                "url": r.get("url", ""), "status": r.get("status", 0),
                "length": r.get("length", 0), "words": r.get("words", 0),
            }
            for r in data.get("results", [])
        ]
        return {"url_pattern": url, "results_found": len(findings), "results": findings[:200]}
    except json.JSONDecodeError:
        return {"raw_output": result["stdout"][:5000]}


async def sslyze_scan(target: str) -> dict:
    if not _tool_available("sslyze"):
        return {"error": "sslyze not installed"}

    result = await _run_cmd(["sslyze", "--json_out=-", target], timeout=120)
    if "error" in result:
        return result

    try:
        data = json.loads(result["stdout"])
        sr = data.get("server_scan_results", [{}])[0]
        scan_results = sr.get("scan_result", {})
        return {"target": target, "tls_versions": list(scan_results.keys()), "raw_summary": result["stdout"][:8000]}
    except Exception:
        return {"target": target, "raw_output": result["stdout"][:5000]}


async def dnsrecon_scan(domain: str, scan_type: str = "std") -> dict:
    if not _tool_available("dnsrecon"):
        return {"error": "dnsrecon not installed"}

    result = await _run_cmd(["dnsrecon", "-d", domain, "-t", scan_type, "-j", "-"], timeout=120)
    if "error" in result:
        return result

    try:
        records = [
            {"type": r.get("type", ""), "name": r.get("name", ""), "address": r.get("address", "")}
            for r in json.loads(result["stdout"])
        ]
        return {"domain": domain, "records": records, "total": len(records)}
    except Exception:
        return {"raw_output": result["stdout"][:5000]}


async def graphql_probe(url: str) -> dict:
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    candidates = [
        "/graphql", "/api/graphql", "/gql", "/query", "/api/query",
        "/v1/graphql", "/graphiql", "/api/v1/graphql", "/api/v2/graphql",
    ]
    found: list[dict] = []

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, limit_per_host=0)) as session:
        for path in candidates:
            endpoint = base + path
            try:
                introspection = '{"query":"{ __schema { types { name fields { name } } } }"}'
                start = time.monotonic()
                async with session.post(
                    endpoint, data=introspection,
                    headers={"Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=8), ssl=False,
                ) as r:
                    elapsed = (time.monotonic() - start) * 1000
                    STATE.total_requests_sent += 1
                    body = await r.text()
                    if r.status == 200 and ("data" in body or "__schema" in body or "errors" in body):
                        entry: dict = {
                            "endpoint": endpoint,
                            "status": r.status,
                            "response_ms": round(elapsed, 2),
                            "introspection_enabled": "__schema" in body,
                            "response_size": len(body),
                        }
                        nested = '{"query":"{ __schema { types { fields { type { fields { type { fields { type { name } } } } } } } } }"}'
                        try:
                            s2 = time.monotonic()
                            async with session.post(
                                endpoint, data=nested,
                                headers={"Content-Type": "application/json"},
                                timeout=aiohttp.ClientTimeout(total=15), ssl=False,
                            ) as r2:
                                entry["nested_query_ms"] = round((time.monotonic() - s2) * 1000, 2)
                                entry["nested_query_works"] = r2.status == 200
                                STATE.total_requests_sent += 1
                        except Exception:
                            pass
                        found.append(entry)
            except Exception:
                pass

    return {
        "base_url": base,
        "graphql_found": found,
        "has_graphql": len(found) > 0,
        "introspection_enabled": any(e.get("introspection_enabled") for e in found),
        "recommendation": (
            "GraphQL with introspection — flood with deeply nested queries to exhaust CPU"
            if found else "No GraphQL endpoints found"
        ),
    }


async def discover_origin_ip(domain: str) -> dict:
    parsed = urlparse(domain if "://" in domain else f"https://{domain}")
    hostname = parsed.hostname or domain.split("/")[0]
    parent = hostname.split(".", 1)[-1] if hostname.count(".") >= 2 else hostname
    results: dict = {"hostname": hostname, "methods": {}}
    candidate_ips: set[str] = set()
    ip_re = re.compile(r"\b(\d{1,3}\.){3}\d{1,3}\b")

    if _tool_available("subfinder"):
        r = await _run_cmd(["subfinder", "-d", hostname, "-silent", "-o", "-"], timeout=60)
        subs = [s.strip() for s in r.get("stdout", "").splitlines() if s.strip()]
        results["methods"]["subfinder_subdomains"] = subs[:50]
    else:
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, limit_per_host=0)) as session:
                async with session.get(
                    f"https://crt.sh/?q=%25.{hostname}&output=json",
                    timeout=aiohttp.ClientTimeout(total=20), ssl=True,
                ) as r:
                    if r.status == 200:
                        certs = await r.json(content_type=None)
                        names: set[str] = set()
                        for cert in certs[:300]:
                            for name in cert.get("name_value", "").split("\n"):
                                name = name.strip().lstrip("*.")
                                if name and parent in name:
                                    names.add(name)
                        results["methods"]["crtsh_subdomains"] = list(names)[:50]
        except Exception as e:
            results["methods"]["crtsh_error"] = str(e)

    subdomains = (
        results["methods"].get("subfinder_subdomains") or
        results["methods"].get("crtsh_subdomains") or []
    )

    if _tool_available("dig"):
        for rtype in ["A", "MX", "TXT", "NS", "AAAA"]:
            r = await _run_cmd(["dig", "+short", rtype, hostname], timeout=8)
            out = r.get("stdout", "").strip()
            if out:
                results["methods"][f"dns_{rtype}"] = out
                for ip in ip_re.findall(out):
                    candidate_ips.add(ip)

        spf_ips: list[str] = []
        txt_out = results["methods"].get("dns_TXT", "")
        if txt_out:
            for entry in re.findall(r"ip4:([\d./]+)", txt_out):
                ip = entry.split("/")[0]
                spf_ips.append(ip)
                candidate_ips.add(ip)
        if spf_ips:
            results["methods"]["spf_ips"] = spf_ips

        resolved: dict[str, str] = {}
        for sub in subdomains[:20]:
            r = await _run_cmd(["dig", "+short", "A", sub], timeout=5)
            out = r.get("stdout", "").strip()
            if out and not out.startswith(";;"):
                resolved[sub] = out
                for ip in ip_re.findall(out):
                    candidate_ips.add(ip)
        if resolved:
            results["methods"]["subdomain_resolved"] = resolved

        origin_patterns = [
            "direct", "origin", "real", "mail", "smtp", "ftp", "cpanel",
            "dev", "staging", "backend", "api", "admin", "webmail",
            "beta", "test", "old", "www2", "app", "portal", "ns1", "ns2",
        ]
        pattern_hits: dict[str, str] = {}
        for prefix in origin_patterns:
            sub = f"{prefix}.{parent}"
            r = await _run_cmd(["dig", "+short", "A", sub], timeout=4)
            out = r.get("stdout", "").strip()
            if out and not out.startswith(";;"):
                pattern_hits[sub] = out
                for ip in ip_re.findall(out):
                    candidate_ips.add(ip)
        if pattern_hits:
            results["methods"]["origin_pattern_subdomains"] = pattern_hits

    if _tool_available("shodan"):
        r = await _run_cmd(["shodan", "host", hostname], timeout=20)
        results["methods"]["shodan"] = r.get("stdout", "")[:2000]

    cdn_prefixes = [
        "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
        "172.64.", "172.65.", "172.66.", "172.67.", "172.68.", "172.69.",
        "13.32.", "13.33.", "13.34.", "13.35.", "13.224.", "13.225.",
        "151.101.", "23.235.", "23.236.", "23.237.", "198.41.", "162.158.",
        "108.162.", "190.93.", "188.114.", "197.234.", "198.41.",
    ]
    non_cdn = [ip for ip in candidate_ips if not any(ip.startswith(p) for p in cdn_prefixes)]

    verified_origins: list[dict] = []
    if non_cdn:
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0, limit_per_host=0)) as session:
            for ip in non_cdn[:15]:
                for port, scheme in [(443, "https"), (80, "http"), (8443, "https"), (8080, "http")]:
                    try:
                        start = time.monotonic()
                        async with session.get(
                            f"{scheme}://{ip}:{port}/",
                            headers={"Host": hostname, "User-Agent": "Mozilla/5.0"},
                            ssl=False,
                            timeout=aiohttp.ClientTimeout(total=5),
                            allow_redirects=False,
                        ) as r:
                            elapsed = (time.monotonic() - start) * 1000
                            if r.status not in (000,):
                                verified_origins.append({
                                    "ip": ip, "port": port, "scheme": scheme,
                                    "status": r.status,
                                    "response_ms": round(elapsed, 2),
                                    "server": r.headers.get("Server", ""),
                                    "confirmed": r.status in (200, 301, 302, 403, 404, 401),
                                })
                                break
                    except Exception:
                        continue

    confirmed = [v for v in verified_origins if v.get("confirmed")]
    results["verified_origins"] = verified_origins
    results["confirmed_origins"] = confirmed
    results["all_candidate_ips"] = sorted(candidate_ips)
    results["likely_origin_ips"] = [v["ip"] for v in confirmed] or non_cdn[:10]

    if confirmed:
        best = confirmed[0]
        results["recommendation"] = (
            f"CONFIRMED: {best['ip']}:{best['port']} responded to Host:{hostname} "
            f"(HTTP {best['status']}, {best['response_ms']}ms) — "
            f"run flood_origin with origin_ip={best['ip']} host={hostname} port={best['port']} scheme={best['scheme']}"
        )
    elif non_cdn:
        results["recommendation"] = (
            f"Unverified non-CDN IPs: {non_cdn[:3]} — try flood_origin with host={hostname}, "
            f"then check_alive to confirm impact"
        )
    else:
        results["recommendation"] = (
            "No origin IP leaked. Target has good CDN hygiene. "
            "Use ssl_handshake_flood on CF edge (TLS termination is expensive even at CF scale), "
            "or probe_cache for bypass paths."
        )
    return results
