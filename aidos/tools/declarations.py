from __future__ import annotations

from .recon import (
    detect_installed_tools, crawl_endpoints, detect_tech,
    nmap_scan, masscan_scan, nuclei_scan, nikto_scan, ffuf_fuzz,
    sslyze_scan, dnsrecon_scan, graphql_probe, discover_origin_ip,
)
from .analysis import http_request, benchmark_endpoint, test_rate_limit, detect_waf, probe_cache, redos_probe
from .flood_l7 import (
    http_flood, spoof_flood, flood_origin, ipv6_prefix_flood,
    bombardier_load, vegeta_attack, wrk_benchmark, siege_load, k6_load, h2load_flood,
)
from .flood_l4 import hping3_flood, ssl_handshake_flood, grpc_flood, dns_flood
from .slow import slowhttptest_attack, sse_flood
from .app import (
    websocket_flood, websocket_message_flood, graphql_attack,
    xml_bomb, byte_range_dos, hash_collision_dos, test_large_payload,
)
from .meta import write_note, read_notes, log_finding, check_alive, run_custom_command, parallel_attacks


TOOL_DECLARATIONS = [
    {
        "name": "detect_installed_tools",
        "description": "Detect which offensive security tools are installed. Call this FIRST to know your arsenal.",
        "parameters": {"type": "object", "properties": {}},
    },
    {
        "name": "http_request",
        "description": "Send a single HTTP request. Returns status, headers, body preview, response time.",
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
        "description": "Spider the website to discover all endpoints, forms, API routes. Returns URLs with response times.",
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
        "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]},
    },
    {
        "name": "nmap_scan",
        "description": "Nmap port/service scan. Modes: service_version, syn_scan, udp_scan, aggressive, vuln_scan, os_detect, firewall_evasion.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "scan_type": {"type": "string", "enum": ["service_version", "syn_scan", "udp_scan", "aggressive", "vuln_scan", "os_detect", "firewall_evasion"]},
                "ports": {"type": "string"},
                "scripts": {"type": "string"},
                "extra_args": {"type": "string"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "masscan_scan",
        "description": "Ultra-fast port scanner. Use for full port range discovery.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "ports": {"type": "string"},
                "rate": {"type": "integer"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "nuclei_scan",
        "description": "Template-based vulnerability scanner. Detects CVEs, misconfigurations, exposures.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "severity": {"type": "string"},
                "templates": {"type": "string"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "nikto_scan",
        "description": "Web server vulnerability scanner. Checks for dangerous files, outdated software, misconfigs.",
        "parameters": {
            "type": "object",
            "properties": {"target": {"type": "string"}, "tuning": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "ffuf_fuzz",
        "description": "Fast web fuzzer. Directory bruteforce, parameter fuzzing, hidden endpoint discovery.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "wordlist": {"type": "string"},
                "method": {"type": "string"},
                "filter_status": {"type": "string"},
                "extra_args": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "sslyze_scan",
        "description": "SSL/TLS vulnerability scanner. Detects weak ciphers, Heartbleed, ROBOT, misconfigs.",
        "parameters": {
            "type": "object",
            "properties": {"target": {"type": "string"}},
            "required": ["target"],
        },
    },
    {
        "name": "dnsrecon_scan",
        "description": "DNS reconnaissance. Enumerate records, find subdomains, attempt zone transfers.",
        "parameters": {
            "type": "object",
            "properties": {"domain": {"type": "string"}, "scan_type": {"type": "string"}},
            "required": ["domain"],
        },
    },
    {
        "name": "graphql_probe",
        "description": "Find GraphQL endpoints and test introspection. Measures nested query cost.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "discover_origin_ip",
        "description": "Find real origin IP behind CDN using subfinder, crt.sh, MX/SPF/A records, and shodan. Required before CDN bypass attacks.",
        "parameters": {
            "type": "object",
            "properties": {"domain": {"type": "string"}},
            "required": ["domain"],
        },
    },
    {
        "name": "benchmark_endpoint",
        "description": "Measure endpoint latency with N sequential requests. Returns avg/p95/p99. Find expensive endpoints.",
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
        "description": "Detect WAF by sending SQLi, XSS, traversal, XXE probes and analyzing block responses.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "probe_cache",
        "description": "Test CDN cache bypass techniques. Find methods to reach origin directly.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "redos_probe",
        "description": "Probe for ReDoS vulnerabilities. Sends backtracking payloads and measures slowdown. A single request can block a thread for seconds.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}, "param": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "http_flood",
        "description": "L7 HTTP flood. Built-in async engine, no external tools. High concurrency request flood.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "method": {"type": "string"},
                "concurrent": {"type": "integer"},
                "duration_seconds": {"type": "integer"},
                "headers": {"type": "object"},
                "body": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "spoof_flood",
        "description": "Header-rotating HTTP flood. Rotates User-Agent and X-Forwarded-For per request to simulate distributed traffic and bypass per-IP rate limiting. Use when rate limiting is detected.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "concurrent": {"type": "integer"},
                "duration_seconds": {"type": "integer"},
                "method": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "flood_origin",
        "description": "Bypass CDN by flooding origin IP directly. Connects to origin_ip with Host header set to the real domain. Use after discover_origin_ip returns confirmed or likely origin IPs.",
        "parameters": {
            "type": "object",
            "properties": {
                "origin_ip": {"type": "string", "description": "Real origin IP from discover_origin_ip"},
                "host": {"type": "string", "description": "Original domain name (for Host header)"},
                "port": {"type": "integer"},
                "path": {"type": "string"},
                "scheme": {"type": "string", "enum": ["http", "https"]},
                "concurrent": {"type": "integer"},
                "duration_seconds": {"type": "integer"},
            },
            "required": ["origin_ip", "host"],
        },
    },
    {
        "name": "ipv6_prefix_flood",
        "description": "L7 flood using a routed IPv6 prefix — each TCP connection binds to a different source IPv6 address from the prefix. Genuinely different source IPs at the packet level, bypasses per-IP CDN/WAF rate limiting. Requires the IPv6 prefix to be routed to this machine (any colo /48 works).",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "ipv6_prefix": {"type": "string", "description": "e.g. '2001:db8:1234::/48'"},
                "concurrent": {"type": "integer", "description": "parallel workers, each using a unique source IP"},
                "duration_seconds": {"type": "integer"},
                "method": {"type": "string"},
                "body": {"type": "string"},
            },
            "required": ["url", "ipv6_prefix"],
        },
    },
    {
        "name": "bombardier_load",
        "description": "High-performance HTTP load generator with precise JSON metrics.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "connections": {"type": "integer"},
                "duration_seconds": {"type": "integer"},
                "method": {"type": "string"},
                "body": {"type": "string"},
                "rate": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "vegeta_attack",
        "description": "Constant-rate HTTP load generator. Exposes latency degradation under precise sustained load.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "rate": {"type": "integer"},
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
        "description": "High-performance HTTP benchmark. Low overhead, accurate latency measurement.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "threads": {"type": "integer"},
                "connections": {"type": "integer"},
                "duration_seconds": {"type": "integer"},
                "script": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "siege_load",
        "description": "Multi-threaded HTTP load testing.",
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
        "name": "k6_load",
        "description": "k6 virtual user load test. Realistic traffic patterns.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "vus": {"type": "integer"},
                "duration_seconds": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "h2load_flood",
        "description": "HTTP/2 multiplexed stream flood. Opens N connections each with M concurrent streams. CVE-2023-44487 style. h2load primary, bombardier --http2 fallback.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "connections": {"type": "integer"},
                "streams": {"type": "integer"},
                "duration_seconds": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "slowhttptest_attack",
        "description": "Slow HTTP attacks. Types: slowloris, slow_post, slow_read, range. Exhausts connection pools with minimal bandwidth. Bypasses rate limiters and WAFs.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "attack_type": {"type": "string", "enum": ["slowloris", "slow_post", "slow_read", "range"]},
                "num_connections": {"type": "integer"},
                "duration_seconds": {"type": "integer"},
                "rate": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "hping3_flood",
        "description": "L4 packet flood. Types: syn, udp, icmp, ack, rst, xmas, fin. Raw packet attacks that bypass all application defenses.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "port": {"type": "integer"},
                "flood_type": {"type": "string", "enum": ["syn", "udp", "icmp", "ack", "rst", "xmas", "fin"]},
                "duration_seconds": {"type": "integer"},
                "extra_args": {"type": "string"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "ssl_handshake_flood",
        "description": "TLS handshake flood. ~100x more expensive for server than attacker. Bypasses all L7 rate limiting. thc-ssl-dos primary, built-in async fallback.",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "port": {"type": "integer"},
                "connections": {"type": "integer"},
                "duration_seconds": {"type": "integer"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "grpc_flood",
        "description": "gRPC flood using ghz. Uses server reflection to discover calls automatically when no proto file is available.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "call": {"type": "string"},
                "duration_seconds": {"type": "integer"},
                "insecure": {"type": "boolean"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "dns_flood",
        "description": "DNS query flood against a nameserver. dnsperf primary, built-in UDP fallback. Use after nmap identifies self-hosted DNS.",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "query_type": {"type": "string", "enum": ["A", "AAAA", "MX", "NS", "ANY"]},
                "duration_seconds": {"type": "integer"},
                "rate": {"type": "integer"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "websocket_flood",
        "description": "Open and hold many WebSocket connections to exhaust server connection pool.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "num_connections": {"type": "integer"},
                "duration_seconds": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "websocket_message_flood",
        "description": "Hold WebSocket connections open AND flood with messages. Tests message processing throughput under concurrent load.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "num_connections": {"type": "integer"},
                "duration_seconds": {"type": "integer"},
                "messages_per_second": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "sse_flood",
        "description": "Server-Sent Events connection exhaustion. Holds many SSE connections open — blocks one thread per connection on non-async stacks (Django, Rails, Spring).",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "num_connections": {"type": "integer"},
                "duration_seconds": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "graphql_attack",
        "description": "GraphQL alias and batch attacks. Multiplies server CPU by batch_size per single HTTP request. graphql-cop primary, built-in fallback.",
        "parameters": {
            "type": "object",
            "properties": {
                "endpoint": {"type": "string"},
                "query": {"type": "string"},
                "batch_size": {"type": "integer"},
            },
            "required": ["endpoint"],
        },
    },
    {
        "name": "xml_bomb",
        "description": "XML Billion Laughs entity expansion and deeply nested JSON. A single request can exhaust server memory if parsers are unconfigured.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "byte_range_dos",
        "description": "Range header amplification attack. Sends Range: bytes=0-0,1-1,...,N-N forcing server to serve N byte ranges per request. Amplifies server CPU/IO Nx with no extra attacker bandwidth.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "num_ranges": {"type": "integer"},
                "concurrent": {"type": "integer"},
                "duration_seconds": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "hash_collision_dos",
        "description": "POST body with thousands of parameters to exhaust hash-table parsing. Also uses known PHP hash collision keys for O(n^2) lookup degradation.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "num_params": {"type": "integer"},
                "duration_seconds": {"type": "integer"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "test_large_payload",
        "description": "Resource exhaustion via large request bodies. Finds server upload/processing limits.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "payload_size_kb": {"type": "integer"},
                "method": {"type": "string", "enum": ["POST", "PUT", "PATCH"]},
            },
            "required": ["url"],
        },
    },
    {
        "name": "redos_probe",
        "description": "Probe for Regular Expression DoS. Sends catastrophic backtracking payloads and measures response time slowdown.",
        "parameters": {
            "type": "object",
            "properties": {
                "url": {"type": "string"},
                "param": {"type": "string"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "check_alive",
        "description": "Health check. Is target responding? Measures degradation vs baseline.",
        "parameters": {
            "type": "object",
            "properties": {"url": {"type": "string"}, "timeout": {"type": "integer"}},
            "required": ["url"],
        },
    },
    {
        "name": "log_finding",
        "description": "Record a security finding immediately when a weakness is confirmed.",
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
        "description": "Run any shell command. Use for tools not directly integrated.",
        "parameters": {
            "type": "object",
            "properties": {"command": {"type": "string"}, "timeout": {"type": "integer"}},
            "required": ["command"],
        },
    },
    {
        "name": "write_note",
        "description": "Write to your reasoning scratchpad. Record hypotheses, observations, and strategy decisions BEFORE acting on them.",
        "parameters": {
            "type": "object",
            "properties": {
                "content": {"type": "string"},
                "tag": {"type": "string", "description": "hypothesis | strategy | finding | observation"},
            },
            "required": ["content"],
        },
    },
    {
        "name": "read_notes",
        "description": "Read your scratchpad notes. Call when you need to recall prior observations or attack strategy.",
        "parameters": {
            "type": "object",
            "properties": {"tag": {"type": "string"}},
        },
    },
    {
        "name": "parallel_attacks",
        "description": "Launch MULTIPLE attack tools simultaneously. The compound attack capability — combine L7 flood + slowloris + TLS flood at the same time. Always try this after confirming individual vectors work.",
        "parameters": {
            "type": "object",
            "properties": {
                "attacks": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "tool": {"type": "string"},
                            "args": {"type": "object"},
                        },
                        "required": ["tool", "args"],
                    },
                },
            },
            "required": ["attacks"],
        },
    },
]


TOOL_MAP: dict = {
    "detect_installed_tools": detect_installed_tools,
    "http_request": http_request,
    "crawl_endpoints": crawl_endpoints,
    "detect_tech": detect_tech,
    "nmap_scan": nmap_scan,
    "masscan_scan": masscan_scan,
    "nuclei_scan": nuclei_scan,
    "nikto_scan": nikto_scan,
    "ffuf_fuzz": ffuf_fuzz,
    "sslyze_scan": sslyze_scan,
    "dnsrecon_scan": dnsrecon_scan,
    "graphql_probe": graphql_probe,
    "discover_origin_ip": discover_origin_ip,
    "benchmark_endpoint": benchmark_endpoint,
    "test_rate_limit": test_rate_limit,
    "detect_waf": detect_waf,
    "probe_cache": probe_cache,
    "redos_probe": redos_probe,
    "http_flood": http_flood,
    "spoof_flood": spoof_flood,
    "flood_origin": flood_origin,
    "ipv6_prefix_flood": ipv6_prefix_flood,
    "bombardier_load": bombardier_load,
    "vegeta_attack": vegeta_attack,
    "wrk_benchmark": wrk_benchmark,
    "siege_load": siege_load,
    "k6_load": k6_load,
    "h2load_flood": h2load_flood,
    "slowhttptest_attack": slowhttptest_attack,
    "hping3_flood": hping3_flood,
    "ssl_handshake_flood": ssl_handshake_flood,
    "grpc_flood": grpc_flood,
    "dns_flood": dns_flood,
    "websocket_flood": websocket_flood,
    "websocket_message_flood": websocket_message_flood,
    "sse_flood": sse_flood,
    "graphql_attack": graphql_attack,
    "xml_bomb": xml_bomb,
    "byte_range_dos": byte_range_dos,
    "hash_collision_dos": hash_collision_dos,
    "test_large_payload": test_large_payload,
    "check_alive": check_alive,
    "log_finding": log_finding,
    "run_custom_command": run_custom_command,
    "write_note": write_note,
    "read_notes": read_notes,
    "parallel_attacks": parallel_attacks,
}
