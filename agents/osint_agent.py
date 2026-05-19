"""
agents/osint_agent.py
----------------------
Stage 1 — MITRE ATT&CK: TA0043 Reconnaissance

External OSINT via Shodan. Runs before gaining internal network access.
Identifies externally exposed services — cameras, NVRs, admin panels
visible from the internet without being on the target network.

Requires SHODAN_API_KEY in .env.
"""

from core.base_agent import BaseAgent, AgentRegistry
from core.engagement import EngagementContext


@AgentRegistry.register
class OSINTAgent(BaseAgent):
    name = "OSINTAgent"
    stage = "osint"
    description = "External OSINT via Shodan: exposed cameras, NVRs, known CVEs."
    mitre_tactic = "TA0043"
    mitre_tactic_name = "Reconnaissance"
    requires_root = False
    requires_network = True
    requires_llm = True

    def run(self, ctx: EngagementContext) -> EngagementContext:
        raise NotImplementedError("OSINTAgent.run() — implementation pending")

    def can_run(self, ctx: EngagementContext) -> tuple[bool, str]:
        import os
        if not os.getenv("SHODAN_API_KEY"):
            return False, "SHODAN_API_KEY not set in .env. Get a key at account.shodan.io"
        return True, ""
