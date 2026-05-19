"""
agents/discovery_agent.py
--------------------------
Stage 2 — MITRE ATT&CK: TA0007 Discovery

Internal network discovery. Assumes network access has already been
established (via WiFiAgent, VPN, physical connection, or given access).

WHAT THIS AGENT DOES:
    1. Auto-detects local subnet if target_scope is empty
    2. Runs ARP scan (if root) or nmap ping sweep (if not root)
    3. Runs nmap port scan against each live host
    4. Grabs banners from open ports via raw socket
    5. Fingerprints device type and vendor from ports + banner content
    6. Populates ctx.confirmed_hosts with HostRecord entries
    7. Sanitizes all banner content before LLM ingestion (prompt injection defense)

TOOLS:
    - tool_scan_network: ARP + nmap, returns list of live hosts with ports
    - tool_grab_banner: raw socket to each open port, returns banner text

LLM: Ollama/qwen2.5 (local, fast, free to run)
"""

from core.base_agent import BaseAgent, AgentRegistry
from core.engagement import EngagementContext


@AgentRegistry.register
class DiscoveryAgent(BaseAgent):
    name = "DiscoveryAgent"
    stage = "discovery"
    description = "Internal network discovery: ARP scan, port scan, banner grab, device fingerprinting."
    mitre_tactic = "TA0007"
    mitre_tactic_name = "Discovery"
    requires_network = True
    requires_llm = True

    def run(self, ctx: EngagementContext) -> EngagementContext:
        raise NotImplementedError("DiscoveryAgent.run() — implementation pending")

    def can_run(self, ctx: EngagementContext) -> tuple[bool, str]:
        return True, ""
