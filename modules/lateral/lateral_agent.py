"""
modules/lateral/lateral_agent.py
----------------------------------
Stage 4: Lateral movement using discovered credentials and access.

PURPOSE:
    Once cameras are accessed, use what was found to pivot deeper into
    the network. Real-world attackers don't stop at cameras — the camera
    network often connects to NVRs, NVRs connect to admin workstations,
    and credentials are frequently reused across devices.

PREREQUISITES:
    - ctx.credentials_found must be populated (run AccessAgent first)
    - ctx.confirmed_hosts must include NVRs and other non-camera devices

WHAT THIS MODULE DOES:

    Credential reuse testing:
        - Take every credential found in AccessAgent
        - Test against every other device in confirmed_hosts
        - Devices to try: NVR admin panels, router admin, any SSH services
        - WHY: password reuse is extremely common in home/SMB environments
          A camera installer who set admin/12345 on the cameras likely used
          the same password on the NVR

    NVR exploitation:
        - Gain access to NVR web interface with discovered credentials
        - Enumerate all connected cameras from NVR's device list
        - Download stored footage if accessible (proof of impact)
        - Extract full device configuration (backup files often contain
          all credentials in plaintext)

    Router/gateway enumeration:
        - Test discovered credentials against the default gateway
        - Common home router default paths: /admin, /login.cgi
        - If successful: extract DHCP table (full device inventory),
          port forwarding rules (what's exposed to internet),
          connected device list

    SSH service testing:
        - Some NVRs and cameras run SSH (especially Linux-based ones)
        - Test discovered credentials + common defaults
        - SSH access = full shell = full device compromise

    Pivot target identification:
        - From NVR config, identify any cloud services configured
          (Hikvision cloud, Dahua cloud, etc.) — these may have
          credentials stored in config
        - Identify any VPN or remote access configurations

SCOPE ENFORCEMENT:
    Same as AccessAgent — every connection checks ctx.enforce_scope().
    Lateral movement is where scope violations most commonly happen
    (accidentally touching a device that's in a different VLAN or
    subnet that wasn't in scope). Hard enforcement is critical here.

LLM ROLE:
    Uses a capable model (Claude Sonnet or similar) for:
    - Deciding which lateral targets are highest priority
    - Interpreting NVR configuration files
    - Identifying credential reuse opportunities
    - Summarizing the full attack path for the report

OUTPUT (written to ctx):
    - ctx.credentials_found: additional credentials from lateral movement
    - ctx.artifacts: NVR config files, stored footage samples
    - ctx.audit_log: full chain of every lateral connection
    - Full pivot map: how far through the network we got and how
"""

from core.base_agent import BaseAgent, AgentRegistry
from core.engagement import EngagementContext


@AgentRegistry.register
class LateralMovementAgent(BaseAgent):
    name = "LateralMovementAgent"
    stage = "lateral"
    description = "Credential reuse, NVR exploitation, router enumeration, pivot mapping."
    requires_network = True
    requires_llm = True

    def run(self, ctx: EngagementContext) -> EngagementContext:
        raise NotImplementedError("LateralMovementAgent.run() — implementation pending")

    def can_run(self, ctx: EngagementContext) -> tuple[bool, str]:
        if not ctx.credentials_found:
            return False, "No credentials available. Run AccessAgent first."
        return True, ""
