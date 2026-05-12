"""
agents/access_agent.py
-----------------------
Stage 3: Camera access testing.

PREREQUISITES:
    - ctx.confirmed_hosts must be populated (run DiscoveryAgent first)
    - Only operates on hosts identified as cameras or NVRs

WHAT THIS AGENT DOES:
    1. Filters confirmed_hosts to cameras and NVRs only
    2. Tests RTSP connectivity on port 554 for each target
    3. Tests default credentials against camera web interfaces
       - Uses vendor-specific credential lists and API paths
       - Tries discovered credentials from ctx.credentials_found first
         (credential reuse from earlier in the chain)
    4. Attempts RTSP stream authentication with working credentials
    5. Captures a proof-of-access frame via opencv and saves to results/
    6. Writes all findings to ctx

SCOPE ENFORCEMENT:
    Every tool call checks ctx.enforce_scope(ip) before making a connection.
    If the LLM hallucinates an IP not in confirmed_hosts, the tool layer
    rejects it. Two layers of defense:
        Layer 1: Tool checks IP is in ctx.confirmed_hosts
        Layer 2: Tool checks IP is in ctx.target_scope via enforce_scope()

PROMPT INJECTION DEFENSE:
    Banner content captured in DiscoveryAgent is sanitized before being
    passed to this agent's LLM context. Banners are wrapped in XML tags
    to signal to the model that they are data, not instructions:
        <banner_data source="192.168.1.10">
            Hikvision-Webs
        </banner_data>

LLM ROLE:
    Uses Claude (claude-haiku) to:
    - Decide which credential combinations to try against which vendors
    - Interpret HTTP response codes and bodies
    - Structure findings into the results report

TOOLS:
    - tool_check_rtsp: TCP connect to port 554, returns open/closed
    - tool_test_credentials: HTTP auth attempt, vendor-aware paths
    - tool_capture_frame: opencv RTSP frame grab, saves JPEG artifact

OUTPUT (written to ctx):
    - ctx.credentials_found: CredentialRecord entries for each success
    - ctx.artifacts: ArtifactRecord entries for each captured frame
    - ctx.audit_log: entry for every credential attempt
    - Timestamped report written to results/
"""

from core.base_agent import BaseAgent, AgentRegistry
from core.engagement import EngagementContext


@AgentRegistry.register
class AccessAgent(BaseAgent):
    name = "AccessAgent"
    stage = "access"
    description = "Camera RTSP and credential testing, frame capture for proof of access."
    requires_network = True
    requires_llm = True

    def run(self, ctx: EngagementContext) -> EngagementContext:
        raise NotImplementedError("AccessAgent.run() — implementation pending")

    def can_run(self, ctx: EngagementContext) -> tuple[bool, str]:
        if not ctx.confirmed_hosts:
            return False, "No confirmed hosts. Run DiscoveryAgent first."
        return True, ""
