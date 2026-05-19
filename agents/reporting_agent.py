"""
agents/reporting_agent.py
--------------------------
Stage 5 — Meta-layer (no MITRE tactic — this is the reporting layer)

Consumes the complete EngagementContext and produces a professional
pen-test report. Automatically maps all findings to MITRE ATT&CK tactics
using the mitre_tactic and mitre_tactic_name fields on each agent.

OUTPUT FORMATS:
    - Markdown (default)
    - HTML (styled, embeds captured frames inline)
    - PDF (professional deliverable)
    - JSON (machine-readable, for integration with other tools)

    All outputs written to results/<engagement_id>/

ENCRYPTION:
    Credentials in the report are encrypted using Fernet symmetric encryption.
    Key derived from operator passphrase at report generation time.
    WHY: Results files may be stored or accidentally exposed.
    Credentials in plaintext are a secondary liability.

REPORT SECTIONS:
    1. Executive Summary — non-technical, risk rating, top findings
    2. Attack Chain — step-by-step narrative mapped to MITRE ATT&CK
    3. Technical Findings — per vulnerability with evidence and CVEs
    4. Device Inventory — all discovered hosts with security posture
    5. Credentials Discovered — encrypted list
    6. Artifacts — embedded captured frames, config files
    7. Audit Trail — complete chain of custody from ctx.audit_log

LLM: Claude Sonnet (writes executive summary and attack narrative)
"""

from core.base_agent import BaseAgent, AgentRegistry
from core.engagement import EngagementContext


@AgentRegistry.register
class ReportingAgent(BaseAgent):
    name = "ReportingAgent"
    stage = "reporting"
    description = "Generates structured pen-test report mapped to MITRE ATT&CK from EngagementContext."
    mitre_tactic = ""
    mitre_tactic_name = "Reporting"
    requires_network = False
    requires_llm = True

    def run(self, ctx: EngagementContext) -> EngagementContext:
        raise NotImplementedError("ReportingAgent.run() — implementation pending")

    def can_run(self, ctx: EngagementContext) -> tuple[bool, str]:
        if not ctx.confirmed_hosts and not ctx.exposed_services:
            return False, "Nothing to report. Run at least one discovery stage first."
        return True, ""
