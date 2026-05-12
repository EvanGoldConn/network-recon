"""
agents/discovery_agent.py
--------------------------
Stage 2: Internal network discovery.

PREREQUISITES:
    - Must be on the target network (via WiFi crack, VPN, physical, etc.)
    - ctx.target_scope should be populated (or will be auto-detected)

WHAT THIS AGENT DOES:
    1. Auto-detects local subnet if target_scope is empty
    2. Runs ARP scan (if root) or nmap ping sweep (if not root) to find live hosts
    3. Runs nmap port scan against each live host
    4. Grabs banners from open ports via raw socket
    5. Fingerprints device type and vendor from ports + banner content
    6. Populates ctx.confirmed_hosts with HostRecord entries
    7. Sanitizes all banner content before LLM ingestion (prompt injection defense)

LLM ROLE:
    The discovery agent uses a local LLM (Ollama/qwen2.5) to:
    - Interpret ambiguous scan results
    - Decide which devices warrant further investigation
    - Structure the findings into a coherent summary

    The LLM never makes network connections directly. All connections
    go through tools, which enforce scope via ctx.enforce_scope().

TOOLS:
    - tool_scan_network: ARP + nmap, returns list of live hosts with ports
    - tool_grab_banner: raw socket to each open port, returns banner text

OUTPUT (written to ctx):
    - ctx.confirmed_hosts: list of HostRecord
    - ctx.target_scope: populated if it was empty (auto-detected)
    - ctx.audit_log: entry for every network connection made
"""

from core.base_agent import BaseAgent, AgentRegistry
from core.engagement import EngagementContext


@AgentRegistry.register
class DiscoveryAgent(BaseAgent):
    name = "DiscoveryAgent"
    stage = "discovery"
    description = "Internal network discovery: ARP scan, port scan, banner grab, device fingerprinting."
    requires_network = True
    requires_llm = True

    def run(self, ctx: EngagementContext) -> EngagementContext:
        # Implementation in next build session
        raise NotImplementedError("DiscoveryAgent.run() — implementation pending")

    def can_run(self, ctx: EngagementContext) -> tuple[bool, str]:
        # Need to be on a network — check we have a local interface
        # (implementation will check actual interface state)
        return True, ""
