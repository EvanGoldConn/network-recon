"""
agents/discovery_agent.py
--------------------------
Stage 2 — MITRE ATT&CK: TA0007 Discovery

Internal network discovery. Assumes network access has already been
established (via WiFiAgent, VPN, physical connection, or given access).

WHAT THIS AGENT DOES:
    1. Validates target_scope CIDR notation, auto-detects subnet if empty
    2. Calls scan_network() — ARP + port scan via nmap
    3. For each discovered host:
       a. Hard scope gate via ctx.enforce_scope(ip)
       b. Grabs banners from all open ports via grab_banner()
       c. Checks banner for suspicious injection patterns → audit log warning
       d. Wraps banner in XML tags before any LLM ingestion (prompt injection defense)
       e. Re-fingerprints vendor from banner (more accurate than port-only guess)
       f. LLM fallback via single prompt if vendor is still "unknown"
          (low-confidence warning logged to audit trail)
       g. Writes HostRecord to ctx
    4. Marks stage complete

TOOLS:
    - tool_scan_network: ARP + nmap, returns list of live hosts with ports
    - tool_grab_banner: raw socket to each open port, returns banner text

CONTROL FLOW DESIGN:
    Python drives deterministic workflow (scan, banner grab, vendor detection). 
    LLM is only invoked as last resort when identify_vendor() returns "unknown", and only for
    a single classification prompt (NOT a ReAct loop).
 
    WHY NOT ReAct HERE:
        The discovery sequence is always the same: scan → banner → classify, no branching logic 
        that needs LLM judgment. ReAct adds latency/token cost/ failure modes with no upside 
        for a fixed workflow. ReAct is used in AccessAgent where genuine reasoning
        under uncertainty is needed.
 
LLM Prompt injection defenses: see core/llm_defense.py
 
LLM: Ollama / qwen2.5:7b (local, fast, no API cost)
"""

import ipaddress
import json
 
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage
 
from core.base_agent import BaseAgent, AgentRegistry
from core.engagement import EngagementContext, HostRecord, ScopeViolationError
from core.vendors import identify_vendor, identify_device_type
from config import AGENT_MODEL
from tools import scan_network, grab_banner


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
