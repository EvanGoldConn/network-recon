"""
agents/wifi_agent.py
---------------------
Stage 0 — MITRE ATT&CK: TA0001 Initial Access

Physical WiFi cracking to gain initial network foothold.
Requires Linux, root, monitor-mode capable adapter, and hcxdumptool + hashcat.

See original docstring for full implementation details.
"""

from core.base_agent import BaseAgent, AgentRegistry
from core.engagement import EngagementContext
import platform
import os


@AgentRegistry.register
class WiFiAgent(BaseAgent):
    name = "WiFiAgent"
    stage = "wifi"
    description = "WiFi initial access via PMKID capture or handshake grab and offline crack."
    mitre_tactic = "TA0001"
    mitre_tactic_name = "Initial Access"
    requires_root = True
    requires_network = False
    requires_llm = False

    def run(self, ctx: EngagementContext) -> EngagementContext:
        raise NotImplementedError("WiFiAgent.run() — implementation pending (requires Linux + monitor mode adapter)")

    def can_run(self, ctx: EngagementContext) -> tuple[bool, str]:
        if platform.system() != "Linux":
            return False, "WiFiAgent requires Linux. Run inside UTM/Kali VM with USB passthrough."
        if os.geteuid() != 0:
            return False, "WiFiAgent requires root. Run with sudo."
        for tool in ["hcxdumptool", "hcxpcapngtool", "hashcat"]:
            if os.system(f"which {tool} > /dev/null 2>&1") != 0:
                return False, f"Required tool not found: {tool}. Install with: apt install {tool}"
        return True, ""
