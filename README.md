
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

## What it does

LLM agent (Gemini) that autonomously conducts denial-of-service resilience assessments. Given a target URL it runs recon, fingerprints the stack, selects attack vectors based on findings, launches compound attacks, measures degradation, and produces a report — without human input between steps.

---

## Tools (47)

### Recon
| Tool | What it does |
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
| `discover_origin_ip` | Finds real origin IP behind CDN via subfinder, crt.sh, DNS A/MX/TXT/SPF records, common subdomain patterns (direct., origin., mail., staging., etc.), then verifies each candidate by connecting with the correct Host header |

### Analysis
| Tool | What it does |
|---|---|
| `http_request` | Single HTTP request with full response inspection |
| `benchmark_endpoint` | N sequential requests, returns avg/p95/p99 latency |
| `test_rate_limit` | Rapid requests, detects 429, records block threshold |
| `detect_waf` | SQLi/XSS/traversal/XXE probes, detects block signatures |
| `probe_cache` | Tests CDN cache bypass techniques (random param, range header, pragma, XFF) |
| `redos_probe` | Sends catastrophic backtracking payloads, measures response time slowdown |

### L7 Flood
| Tool | What it does |
|---|---|
| `http_flood` | Async HTTP flood, built-in, no external tools required |
| `spoof_flood` | HTTP flood with rotating User-Agent + X-Forwarded-For per request |
| `flood_origin` | Connects directly to origin IP with Host header set to real domain — bypasses CDN entirely |
| `ipv6_prefix_flood` | Each connection binds to a different source IPv6 from a routed prefix — genuine per-IP diversity at L7. **Requires a /48+ IPv6 block routed to the attack machine** |
| `bombardier_load` | External: bombardier |
| `vegeta_attack` | External: vegeta, constant-rate load |
| `wrk_benchmark` | External: wrk |
| `siege_load` | External: siege |
| `k6_load` | External: k6, scripted virtual user load |
| `h2load_flood` | HTTP/2 multiplexed stream flood. h2load primary, bombardier --http2 fallback |

### L4
| Tool | What it does |
|---|---|
| `hping3_flood` | SYN, UDP, ICMP, ACK, RST, XMAS, FIN packet flood |
| `ssl_handshake_flood` | TLS handshake flood, ~100x asymmetric cost. thc-ssl-dos primary, built-in async fallback |
| `grpc_flood` | gRPC flood via ghz, uses server reflection when no proto available |
| `dns_flood` | DNS query flood. dnsperf primary, built-in UDP fallback |

### Slow-rate
| Tool | What it does |
|---|---|
| `slowhttptest_attack` | Slowloris, slow POST, slow read, range. slowhttptest primary, built-in fallback |
| `sse_flood` | Holds many SSE connections open, exhausts thread pool on synchronous stacks |

### Application-layer
| Tool | What it does |
|---|---|
| `websocket_flood` | Opens and holds many WebSocket connections |
| `websocket_message_flood` | Holds WebSocket connections and floods messages simultaneously |
| `graphql_attack` | Alias multiplication and batch attacks. graphql-cop primary, built-in fallback |
| `xml_bomb` | XML billion laughs entity expansion + deeply nested JSON + 100k element array |
| `byte_range_dos` | Range header amplification — forces server to process N byte ranges per request |
| `hash_collision_dos` | Mass POST parameters to exhaust hash-table parsing, includes PHP collision keys |
| `test_large_payload` | Probes server upload limits, floods with accepted payload size |

### Meta
| Tool | What it does |
|---|---|
| `parallel_attacks` | Runs multiple attack tools simultaneously via asyncio.gather |
| `check_alive` | Health check, measures degradation vs baseline |
| `log_finding` | Records finding with severity, evidence, recommendation |
| `write_note` | LLM scratchpad for hypotheses and strategy |
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

### Optional external tools (extend coverage)

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

## License

MIT
