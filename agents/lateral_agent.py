"""
agents/lateral_agent.py
------------------------
Stage 4 — MITRE ATT&CK: TA0008 Lateral Movement

Credential reuse and pivoting using findings from AccessAgent.
Moves deeper into the network via NVR exploitation, router enumeration,
and SSH testing.

WHAT THIS AGENT DOES:
    1. Takes every credential in ctx.credentials_found
    2. Tests them against every other device in confirmed_hosts
    3. Accesses NVR — downloads config, enumerates all cameras
    4. Tests router/gateway admin panel with discovered credentials
    5. Tests SSH services with discovered credentials
    6. Writes additional credentials and artifacts to ctx

WHY CREDENTIAL REUSE MATTERS:
    Password reuse is extremely common in home/SMB environments.
    A camera installer who set admin/12345 on cameras likely used
    the same password on the NVR and router.

SCOPE ENFORCEMENT:
    Every connection calls ctx.enforce_scope(ip) before proceeding.
    Lateral movement is where scope violations most commonly occur —
    hard enforcement is critical here.

LLM: Claude Sonnet (most reasoning-heavy stage)

TODO: Implement run() — planned phases:
    Phase 1 — Credential reuse across all confirmed_hosts
    Phase 2 — NVR config download and camera enumeration
    Phase 3 — Router/gateway admin panel testing
    Phase 4 — SSH testing with discovered credentials
"""

from core.base_agent import BaseAgent, AgentRegistry
from core.engagement import EngagementContext


@AgentRegistry.register
class LateralMovementAgent(BaseAgent):
    name = "LateralMovementAgent"
    stage = "lateral"
    description = "Credential reuse, NVR exploitation, router enumeration, pivot mapping."
    mitre_tactic = "TA0008"
    mitre_tactic_name = "Lateral Movement"
    requires_network = True
    requires_llm = True

    def can_run(self, ctx: EngagementContext) -> tuple[bool, str]:
        if not ctx.credentials_found:
            return False, "No credentials available. Run AccessAgent first."
        return True, ""

    def run(self, ctx: EngagementContext) -> EngagementContext:
        """
        Lateral movement via credential reuse across discovered hosts.
        Implementation pending — see TODO in module docstring.
        """
        ctx.current_stage = self.stage
        ctx.log(self.name, "LateralMovementAgent — implementation pending, skipping")
        print("[LateralMovementAgent] Not yet implemented — skipping")
        ctx.mark_stage_complete(self.stage)
        return ctx