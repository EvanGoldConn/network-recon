"""
modules/reporting/reporting_agent.py
--------------------------------------
Stage 5: Automated pen-test report generation.

PURPOSE:
    Consumes the complete EngagementContext and produces a professional
    pen-test report. The report is the deliverable — everything else in
    the pipeline exists to populate it.

WHAT THIS MODULE PRODUCES:

    Executive Summary:
        - Non-technical overview of what was found and what it means
        - Risk rating: Critical/High/Medium/Low
        - Top 3 findings in plain language
        - Recommended immediate actions

    Technical Findings:
        For each vulnerability found:
        - Finding title
        - Affected devices (IP, vendor, model)
        - Vulnerability description
        - Evidence (credentials found, frames captured, config extracted)
        - CVSS score where applicable
        - Remediation steps

    Attack Chain Narrative:
        - Step-by-step account of how access was gained
        - Timeline from the audit log
        - "An attacker with physical proximity could have..."

    Device Inventory:
        - All discovered hosts with full details
        - Security posture per device

    Credentials Discovered:
        - Full list (encrypted in report, decrypted only on authorized request)

    Artifacts:
        - Embedded captured frames (proof of camera access)
        - Links to downloaded config files

    Audit Trail:
        - Complete chain of custody from audit_log
        - Every network connection made, timestamped

OUTPUT FORMATS:
    - Markdown (default, human-readable, version-control friendly)
    - HTML (styled, embeds images inline)
    - PDF (via markdown→PDF conversion, professional deliverable)
    - JSON (machine-readable, for integration with other tools)

    All outputs written to results/<engagement_id>/

ENCRYPTION:
    Credentials in the report are encrypted using Fernet symmetric encryption.
    Key is derived from an operator-provided passphrase at report generation time.
    WHY: Results files may be stored, emailed, or accidentally exposed.
    Credentials in plaintext in those files are a secondary liability.
    The report is useless to an attacker without the decryption passphrase.

LLM ROLE:
    This agent is LLM-heavy. Uses a capable model (Claude Sonnet) to:
    - Write the executive summary from structured findings
    - Generate remediation recommendations per finding
    - Write the attack narrative in clear, professional language
    - Rate severity and business impact

    The LLM receives structured data (EngagementContext as JSON) and
    produces prose. It never makes network connections at this stage.
"""

from core.base_agent import BaseAgent, AgentRegistry
from core.engagement import EngagementContext


@AgentRegistry.register
class ReportingAgent(BaseAgent):
    name = "ReportingAgent"
    stage = "reporting"
    description = "Generates structured pen-test report from EngagementContext."
    requires_network = False
    requires_llm = True

    def run(self, ctx: EngagementContext) -> EngagementContext:
        raise NotImplementedError("ReportingAgent.run() — implementation pending")

    def can_run(self, ctx: EngagementContext) -> tuple[bool, str]:
        if not ctx.confirmed_hosts and not ctx.exposed_services:
            return False, "Nothing to report. Run at least one discovery stage first."
        return True, ""
