"""
agents/access_agent.py
-----------------------
Stage 3 — MITRE ATT&CK: TA0006 Credential Access

Camera RTSP and credential testing. Operates only on hosts identified
as cameras or NVRs by DiscoveryAgent.

WHAT THIS AGENT DOES:
    1. Filters confirmed_hosts to cameras and NVRs only
    2. Tests RTSP connectivity on port 554
    3. Tests default credentials against camera web interfaces
       - Uses vendor-specific credential lists from core/vendors.py
       - Tries credentials already in ctx.credentials_found first (reuse)
    4. Attempts RTSP stream authentication with working credentials
    5. Captures proof-of-access frame via opencv, saves to results/
    6. Writes all findings to ctx

SCOPE ENFORCEMENT (two layers):
    Layer 1: Tool checks IP is in ctx.confirmed_hosts
    Layer 2: Tool checks IP is in ctx.target_scope via enforce_scope()

PROMPT INJECTION DEFENSE:
    Banner content is wrapped in XML tags before LLM ingestion:
        <banner_data source="192.168.1.10">Hikvision-Webs</banner_data>

TOOLS:
    - tool_check_rtsp: TCP connect to port 554
    - tool_test_credentials: HTTP auth, vendor-aware paths
    - tool_capture_frame: opencv RTSP frame grab, saves JPEG artifact

LLM: Claude Haiku (better reasoning for HTTP response interpretation)
"""

from core.base_agent import BaseAgent, AgentRegistry
from core.engagement import EngagementContext


@AgentRegistry.register
class AccessAgent(BaseAgent):
    name = "AccessAgent"
    stage = "access"
    description = "Camera RTSP and credential testing, frame capture for proof of access."
    mitre_tactic = "TA0006"
    mitre_tactic_name = "Credential Access"
    requires_network = True
    requires_llm = True

    def run(self, ctx: EngagementContext) -> EngagementContext:
        raise NotImplementedError("AccessAgent.run() — implementation pending")

    def can_run(self, ctx: EngagementContext) -> tuple[bool, str]:
        if not ctx.confirmed_hosts:
            return False, "No confirmed hosts. Run DiscoveryAgent first."
        return True, ""
