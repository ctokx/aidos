
<p align="center">
  <pre align="center">
     █████╗ ██╗██████╗  ██████╗ ███████╗
    ██╔══██╗██║██╔══██╗██╔═══██╗██╔════╝
    ███████║██║██║  ██║██║   ██║███████╗
    ██╔══██║██║██║  ██║██║   ██║╚════██║
    ██║  ██║██║██████╔╝╚██████╔╝███████║
    ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝
  </pre>
  <strong>AI-assisted resilience testing for web infrastructure.</strong><br>
  <sub>Autonomous LLM agent that orchestrates open-source tooling to evaluate service availability and reliability.</sub>
</p>

<p align="center">
  <a href="#why">Why</a> •
  <a href="#arsenal">Arsenal</a> •
  <a href="#installation">Install</a> •
  <a href="#usage">Usage</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#vs-everything-else">vs Everything Else</a>
</p>

---

## LEGAL DISCLAIMER

> **VISIBLE NOTICE**
> **READ THAT**
>
> AIDOS is intended for defensive reliability and resilience testing.
> Run assessments only within your approved scope and environment.
> Stress tests can affect uptime and network performance.

## Why

DoS and availability failures are hard to evaluate with single-point tools. Real-world behavior is multi-step and adaptive. Traditional assessment can be expensive or time-consuming to run manually.

AIDOS uses **Gemini** as its reasoning engine and open-source security tooling for automated, structured resilience assessment.

It doesn't blindly flood. It **thinks**:

> *"The /api/search endpoint has 1.2s avg response time, no rate limiting, and sits behind nginx without connection limits. Let me hit it with 500 concurrent connections via bombardier while simultaneously running slowloris on port 443 to exhaust the connection pool."*

That's the kind of assessment a senior pentester does. Now an LLM does it autonomously.

## Arsenal

AIDOS orchestrates the tools available on your system. The more tools installed, the broader the assessment coverage.

| Category | Tools | What They Do |
|----------|-------|-------------|
| **L7 HTTP Flood** | `bombardier` `wrk` `vegeta` `k6` `siege` `ab` + built-in async engine | Saturate application layer with precise, measured load |
| **L4 Packet Flood** | `hping3` | SYN flood, UDP flood, ACK flood, XMAS, FIN, RST — raw packet attacks that bypass all application defenses |
| **Slow-Rate** | `slowhttptest` + built-in slowloris & slow POST | Exhaust connection pools with minimal bandwidth. Bypasses rate limiters and WAFs |
| **Vuln Scanning** | `nuclei` `nikto` | Thousands of CVE templates, server misconfigurations, known exploits |
| **Recon** | `nmap` `masscan` `ffuf` `dnsrecon` | Port scanning, service fingerprinting, directory fuzzing, DNS enumeration |
| **Crypto** | `sslyze` | TLS misconfiguration, weak ciphers, renegotiation vulnerabilities |
| **Custom** | `run_custom_command` | Any CLI tool the agent decides to use. Scapy, curl, whatever it needs |

No tool installed? AIDOS adapts. It includes built-in HTTP flood, slowloris, and slow POST testing.

### Minimum (works out of the box)
```
pip install -e .
```
Built-in: HTTP flood, slowloris, slow POST, crawling, fingerprinting, benchmarking.

### Recommended (extended coverage)
```bash
# Debian/Ubuntu
apt install nmap masscan hping3 nikto slowhttptest

# Go tools
go install github.com/codesenberg/bombardier@latest
go install github.com/tsenart/vegeta@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Python tools
pip install sslyze

# Others
apt install siege dnsrecon
```

## Installation

```bash
git clone https://github.com/yourusername/aidos.git
cd aidos
pip install -e .
export GEMINI_API_KEY=your_key_here
```

### Windows quick install (Scoop)

```powershell
powershell -ExecutionPolicy Bypass -File scripts/install_windows_tools.ps1
```

Installs what is currently available via Scoop + pip: `nmap`, `nuclei`, `ffuf`, `bombardier`, `vegeta`, `k6`, `sslyze`.

## Usage

```bash
aidos https://your-target.com
```

That's it. AIDOS will:

1. Inventory its available tools
2. Recon the target (crawl, port scan, fingerprint, fuzz, vuln scan)
3. Analyze every endpoint (benchmark, rate limit check, WAF detection)
4. Attack the weakest points (L7 flood, L4 flood, slow-rate, combined)
5. Monitor impact and adapt strategy in real-time
6. Generate a detailed HTML report with all findings

### Options

```bash
aidos https://target.com --max-turns 80     # More reasoning = deeper assessment
aidos https://target.com --model gemini-2.5-pro  # Use stronger model for harder targets
aidos https://target.com --trace-file run_trace.jsonl  # Save Gemini/tool trace
aidos https://target.com --no-enforce-coverage  # Let model stop naturally
aidos https://target.com -y                  # Skip confirmation
```

`--max-turns 5` is usually recon-heavy. Use `--max-turns 20+` for broader phase coverage.
Trace files are JSONL and include Gemini text, tool calls, tool args, and result previews.

### Legal full local test (recommended)

This runs a complete end-to-end test against a **local lab target** (127.0.0.1), not a public domain:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_legal_full_test.ps1 -MaxTurns 20
```

What it does:
1. Starts `scripts/lab_target.py` on `http://127.0.0.1:8081`
2. Detects installed tools
3. Runs AIDOS with Gemini and generates an HTML report
4. Stops the lab target automatically

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│                      GEMINI LLM                         │
│                 (Autonomous Reasoning)                  │
│                                                         │
│   Observes tool results → Forms hypotheses →            │
│   Selects next action → Adapts strategy                 │
└───────────────────────┬─────────────────────────────────┘
                        │ Function Calling (24 tools)
    ┌───────────┬───────┼───────┬───────────┬─────────┐
    ▼           ▼       ▼       ▼           ▼         ▼
┌───────┐ ┌────────┐ ┌──────┐ ┌─────────┐ ┌──────┐ ┌──────┐
│ RECON │ │ANALYZE │ │L7 ATK│ │SLOW-RATE│ │L4 ATK│ │CUSTOM│
│       │ │        │ │      │ │         │ │      │ │      │
│nmap   │ │bench   │ │flood │ │slowloris│ │SYN   │ │any   │
│masscan│ │rate lim│ │bombdr│ │slow POST│ │UDP   │ │shell │
│nuclei │ │WAF det │ │vegeta│ │slow read│ │ACK   │ │cmd   │
│nikto  │ │crawl   │ │wrk   │ │range    │ │XMAS  │ │      │
│ffuf   │ │tech fp │ │siege │ │         │ │FIN   │ │      │
│sslyze │ │        │ │k6    │ │         │ │RST   │ │      │
│dnsrecn│ │        │ │      │ │         │ │      │ │      │
└───────┘ └────────┘ └──────┘ └─────────┘ └──────┘ └──────┘
    │           │       │       │           │         │
    └───────────┴───────┼───────┴───────────┴─────────┘
                        ▼
               ┌────────────────┐
               │   FINDINGS     │
               │  Terminal +    │
               │  HTML Report   │
               └────────────────┘
```

The agent doesn't follow a fixed script. It **reasons about results**:

- Port scan finds Redis on 6379 with no auth? → Direct exploitation vector logged
- `/api/search?q=` has 2s response time with no rate limit? → Floods it with 500 concurrent connections
- WAF blocks SQL injection probes but not slow POST? → Pivots to connection exhaustion
- bombardier shows 80% error rate at 200 concurrent? → Server is buckling, logs CRITICAL finding
- Target still alive after L7 flood? → Layers slowloris on top to compound the pressure

## vs Everything Else

| Tool | What It Does | What It Doesn't Do |
|------|-------------|-------------------|
| **wrk/bombardier/vegeta** | Floods one URL you specify | Doesn't know WHICH URL to flood |
| **slowhttptest** | Runs one slow attack | Doesn't combine with other vectors |
| **nmap/nuclei** | Finds vulnerabilities | Doesn't provide full resilience workflow by itself |
| **JMeter/k6/Locust** | Runs scripts you write | You have to write the scripts |
| **LOIC/HOIC** | Brute force flood | Zero intelligence, easily blocked |
| **AIDOS** | **All of the above, autonomously** | — |

AIDOS chains these tools with LLM reasoning. It does what a pentester does: recon → analyze → plan → attack → adapt → report. The LLM is the pentester.

## Example Output

```
  🔧 detect_installed_tools
    ▸ 12 tools: nmap, masscan, hping3, nuclei, bombardier, wrk, ...

  🔍 nmap_scan [aggressive] target.com
    ▸ 8 ports found

  🔍 crawl_endpoints target.com
    ▸ 47 endpoints discovered

  📊 benchmark_endpoint /api/search
    ▸ avg: 1847ms, p99: 4200ms

  📊 test_rate_limit /api/search
    ▸ no rate limiting detected

  💥 bombardier_load [c=500] target.com/api/search
    ▸ 2847 req/s | errors: 34%

  ❤️ check_alive target.com
    ▸ DEGRADED 340% (6200ms)

  📋 Finding: Unprotected heavy endpoint vulnerable to HTTP flood [CRITICAL]

  💥 slowhttptest_attack [slowloris] target.com
    ▸ target_degraded_or_down

  📋 Finding: Slowloris connection exhaustion [HIGH]
```

## License

MIT — Use it to protect your systems.

## Disclaimer

AIDOS is a defensive security and stress-testing framework for resilience validation. Use within approved scope and according to your organization’s policy and local regulations.
