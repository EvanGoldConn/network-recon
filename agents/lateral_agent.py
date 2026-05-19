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

    def run(self, ctx: EngagementContext) -> EngagementContext:
        raise NotImplementedError("LateralMovementAgent.run() — implementation pending")

    def can_run(self, ctx: EngagementContext) -> tuple[bool, str]:
        if not ctx.credentials_found:
            return False, "No credentials available. Run AccessAgent first."
        return True, ""
