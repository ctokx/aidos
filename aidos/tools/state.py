from __future__ import annotations

import shutil


class ToolState:
    def __init__(self):
        self.findings: list[dict] = []
        self.baseline: dict[str, float] = {}
        self.discovered_endpoints: list[dict] = []
        self.tech_stack: dict = {}
        self.total_requests_sent: int = 0
        self.installed_tools: dict[str, str] = {}
        self.notes: list[dict] = []

    def detect_tools(self):
        candidates = [
            "nmap", "masscan", "hping3", "nikto", "nuclei", "ffuf",
            "slowhttptest", "wrk", "bombardier", "vegeta", "k6", "siege",
            "ab", "sslyze", "dnsrecon", "dnsenum", "gobuster", "curl",
            "testssl.sh", "scapy", "h2load", "thc-ssl-dos", "ghz",
            "dnsperf", "graphql-cop", "subfinder", "shodan", "dig",
        ]
        for t in candidates:
            path = shutil.which(t)
            if path:
                self.installed_tools[t] = path
        return self.installed_tools


STATE = ToolState()


def reset_state():
    STATE.findings.clear()
    STATE.baseline.clear()
    STATE.discovered_endpoints.clear()
    STATE.tech_stack.clear()
    STATE.total_requests_sent = 0
    STATE.installed_tools.clear()
    STATE.notes.clear()
    STATE.detect_tools()
