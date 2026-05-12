"""
modules/osint/osint_agent.py
-----------------------------
Stage 1: External OSINT and Shodan reconnaissance.

PURPOSE:
    Runs before gaining internal network access. Identifies externally
    exposed services belonging to the target — things visible from the
    internet without being on the network.

    This is the difference between a black-box external engagement
    (you know only the target org/IP range) and an internal engagement
    (you're already on the network). This module handles the former.

PREREQUISITES:
    - Shodan API key in .env as SHODAN_API_KEY
    - Target IP range, domain, or organization name in ctx.target_scope
      OR provided as config at initialization

WHAT THIS MODULE DOES:

    Shodan queries:
        - Search by IP range: net:192.168.0.0/16 (example for RFC1918)
        - Search by org name: org:"Target Company"
        - Search for exposed camera interfaces:
            "Server: App-webs" (Hikvision signature)
            "WWW-Authenticate: Digest realm=DVRDVS-Webs" (Dahua)
            port:554 has_screenshot:true
            title:"Network Camera"
        - Search for exposed NVR/DVR web panels

    For each exposed service found:
        - Record IP, port, banner, service type
        - Check if port 554 (RTSP) is directly exposed to internet
        - Note: directly exposed RTSP = accessible without being on LAN
        - Attempt default credential test against exposed web interfaces
          (same logic as AccessAgent but against internet-facing services)

    CVE/vulnerability lookup:
        - For identified device models, query Shodan's CVE database
        - Flag devices with known unpatched CVEs
        - Common Hikvision CVEs: CVE-2021-36260 (RCE), CVE-2017-7921 (auth bypass)
        - Common Dahua CVEs: CVE-2021-33044, CVE-2021-33045 (auth bypass)

    DNS/subdomain enumeration (if domain provided):
        - Passive DNS via SecurityTrails or similar
        - Subdomain enumeration for finding admin panels, VPN portals

SHODAN API:
    Free tier: 100 queries/month, limited results
    Membership ($69/year): unlimited queries, full results, CVE data
    For pen-testing use, Membership is worth it.

    Python library: shodan (pip install shodan)
    API key: https://account.shodan.io/

LLM ROLE:
    Used to:
    - Interpret Shodan results and identify the most promising targets
    - Correlate external exposure with expected internal topology
      (e.g., port-forwarded NVR on external IP likely has internal cameras)
    - Generate a prioritized list of attack vectors for the next stages

OUTPUT (written to ctx):
    - ctx.exposed_services: list of externally visible services with details
    - ctx.target_scope: refined/expanded based on discovered IPs
    - ctx.audit_log: every Shodan query logged (no network traffic, but logged)
    - Flags any devices with known CVEs for targeted exploitation in later stages
"""

from core.base_agent import BaseAgent, AgentRegistry
from core.engagement import EngagementContext


@AgentRegistry.register
class OSINTAgent(BaseAgent):
    name = "OSINTAgent"
    stage = "osint"
    description = "External OSINT via Shodan: exposed cameras, NVRs, known CVEs."
    requires_root = False
    requires_network = True   # Internet access, not LAN access
    requires_llm = True

    def run(self, ctx: EngagementContext) -> EngagementContext:
        raise NotImplementedError("OSINTAgent.run() — implementation pending")

    def can_run(self, ctx: EngagementContext) -> tuple[bool, str]:
        import os
        if not os.getenv("SHODAN_API_KEY"):
            return False, "SHODAN_API_KEY not set in .env. Get a key at account.shodan.io"
        return True, ""
