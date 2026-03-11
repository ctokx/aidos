
<p align="center">
  <pre align="center">
     █████╗ ██╗██████╗  ██████╗ ███████╗
    ██╔══██╗██║██╔══██╗██╔═══██╗██╔════╝
    ███████║██║██║  ██║██║   ██║███████╗
    ██╔══██║██║██║  ██║██║   ██║╚════██║
    ██║  ██║██║██████╔╝╚██████╔╝███████║
    ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝
  </pre>
</p>

> Run assessments only on infrastructure you own or have written authorization to test.

---

## What it is

AIDOS is an LLM-orchestrated denial-of-service resilience assessment agent. It uses Gemini as a reasoning engine to autonomously conduct multi-phase availability assessments: reconnaissance, fingerprinting, analysis, attack execution, impact measurement, and report generation — without human input between steps.

The research motivation is whether an LLM agent can replicate the decision-making process of a human security engineer performing availability testing: selecting attack vectors based on observed target characteristics, adapting strategy based on results, and compounding multiple simultaneous vectors.

---

## Tools (49)

### Recon
| Tool | Description |
|---|---|
| `detect_installed_tools` | Inventories available system tools |
| `crawl_endpoints` | Spiders the site, collects URLs, forms, response times |
| `detect_tech` | Fingerprints server, CDN, WAF, framework, language from headers |
| `nmap_scan` | Port/service scan. Modes: service_version, syn, udp, aggressive, vuln, os, firewall_evasion |
| `masscan_scan` | Full port range scan |
| `nuclei_scan` | CVE and misconfiguration templates |
| `nikto_scan` | Web server vulnerability scan |
| `ffuf_fuzz` | Directory and parameter fuzzing |
| `sslyze_scan` | TLS version, cipher, renegotiation vulnerabilities |
| `dnsrecon_scan` | DNS enumeration, zone transfer attempt |
| `graphql_probe` | Finds GraphQL endpoints, tests introspection, measures nested query cost |
| `discover_origin_ip` | Enumerates real origin IP behind CDN via subfinder, crt.sh, DNS A/MX/TXT/SPF records, and common subdomain patterns (direct., origin., mail., staging., etc.). Verifies each candidate by connecting with the correct Host header and confirming a valid HTTP response. |

### Analysis
| Tool | Description |
|---|---|
| `http_request` | Single HTTP request, full response inspection |
| `benchmark_endpoint` | N sequential requests, returns avg/p95/p99 latency |
| `test_rate_limit` | Rapid sequential requests, detects 429 and records block threshold |
| `detect_waf` | SQLi/XSS/traversal/XXE probes, detects block patterns |
| `probe_cache` | Tests CDN cache bypass techniques: random param, range header, pragma, XFF variants |
| `redos_probe` | Sends catastrophic backtracking regex payloads, measures response time change |
| `find_amplification_ratio` | Scans all discovered endpoints for response/request size ratio. Identifies highest-cost flood targets — an endpoint returning 500KB per 100-byte request is more efficient to flood than one returning 200 bytes. |

### L7 Flood
| Tool | Description |
|---|---|
| `http_flood` | Async HTTP flood, built-in, no external tools required |
| `spoof_flood` | HTTP flood with rotating User-Agent and X-Forwarded-For per request |
| `flood_origin` | Connects directly to origin IP with Host header set to the real domain, bypassing CDN |
| `ipv6_prefix_flood` | Each connection binds to a different source IPv6 from a routed prefix. Genuine per-connection source IP diversity at L7. **Requires a /48+ IPv6 block routed to the attack machine.** |
| `http2_rapid_reset` | CVE-2023-44487 built-in implementation. No external tools required. Opens N persistent HTTP/2 connections and sends HEADERS+RST_STREAM pairs continuously. Server must allocate and free stream state for each pair. Operates below application-layer rate limiters. |
| `h2load_flood` | HTTP/2 multiplexed stream flood via h2load (external). Fallback to bombardier --http2. |
| `bombardier_load` | External: bombardier |
| `vegeta_attack` | External: vegeta, constant-rate load |
| `wrk_benchmark` | External: wrk |
| `siege_load` | External: siege |
| `k6_load` | External: k6, scripted virtual user load |

### L4
| Tool | Description |
|---|---|
| `hping3_flood` | SYN, UDP, ICMP, ACK, RST, XMAS, FIN packet flood via hping3 |
| `ssl_handshake_flood` | TLS handshake flood. thc-ssl-dos primary, built-in async SSL loop fallback |
| `grpc_flood` | gRPC flood via ghz. Uses server reflection when no proto available |
| `dns_flood` | DNS query flood. dnsperf primary, built-in UDP fallback |

### Slow-rate
| Tool | Description |
|---|---|
| `slowhttptest_attack` | Slowloris, slow POST, slow read, range. slowhttptest primary, built-in fallback |
| `sse_flood` | Holds many Server-Sent Events connections open simultaneously |

### Application-layer
| Tool | Description |
|---|---|
| `websocket_flood` | Opens and holds many WebSocket connections |
| `websocket_message_flood` | Holds WebSocket connections and floods messages simultaneously |
| `graphql_attack` | Alias multiplication and batch attacks. graphql-cop primary, built-in fallback |
| `xml_bomb` | XML billion laughs entity expansion, deeply nested JSON, large array |
| `byte_range_dos` | Range header with N byte ranges per request, forces server to serve each range |
| `hash_collision_dos` | Mass POST parameters to exhaust hash-table parsing. Includes PHP hash collision keys |
| `test_large_payload` | Probes server response to increasing payload sizes |

### Meta
| Tool | Description |
|---|---|
| `parallel_attacks` | Runs multiple attack tools simultaneously |
| `check_alive` | Health check, measures current latency vs baseline |
| `log_finding` | Records a finding with severity, evidence, recommendation |
| `write_note` | LLM reasoning scratchpad |
| `read_notes` | Reads scratchpad |
| `run_custom_command` | Runs arbitrary shell command |

---

## Installation

```bash
git clone https://github.com/yourusername/aidos.git
cd aidos
pip install -e .
export GEMINI_API_KEY=your_key_here
```

### Optional external tools

```bash
# Debian/Ubuntu
apt install nmap masscan hping3 nikto slowhttptest siege dnsrecon

# Go
go install github.com/codesenberg/bombardier@latest
go install github.com/tsenart/vegeta@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Python
pip install sslyze

# HTTP/2
apt install nghttp2-client  # provides h2load
```

### Windows (Scoop)

```powershell
powershell -ExecutionPolicy Bypass -File scripts/install_windows_tools.ps1
```

---

## Usage

```bash
aidos https://target.com
aidos https://target.com --max-turns 80
aidos https://target.com --model gemini-2.5-pro
aidos https://target.com --trace-file run.jsonl
aidos https://target.com --no-enforce-coverage
```

---

## Effectiveness by target type

| Target type | Expected impact | Limiting factor |
|---|---|---|
| Self-hosted VPS/server, no CDN | High | Server resource limits |
| Cloud VM (EC2, GCP), no CDN | High if origin IP reachable | Instance size |
| Self-hosted + Cloudflare, origin IP discoverable | High via flood_origin | Origin server resources |
| Self-hosted + Cloudflare, origin IP hidden | Low–Medium | Source IP diversity |
| Managed SaaS (HubSpot, Shopify, Squarespace) | Negligible | Shared infrastructure scale |

The tool operates from a single machine. Effectiveness against CDN-protected targets depends on whether origin IP disclosure vulnerabilities exist. Against properly configured CDN with no origin exposure, the primary available vector is ssl_handshake_flood at the CDN edge and application-layer attacks that the CDN forwards (GraphQL, ReDoS, xml_bomb).

---

## License

MIT
