



"""
agents/reporting_agent.py
--------------------------
Stage 5 — Reporting

Receives EngagementContext obj and produces a pen-test report to both markdown and PDF
results/reports/<engagement_id>/

WHAT THIS AGENT DOES:
    1. Populates ctx.cve_findings from vendors.py known_cves for every
       successfully accessed host (exploited=True) & every discovered camera/NVR (exploited=False)
    2. Assembles all structured data from ctx into report sections
    3. Uses Claude Sonnet to write the executive summary and per-host finding narratives 
    4. Writes Markdown report to disk
    5. Converts Markdown to PDF via weasyprint
    6. Logs report paths to ctx

REPORT SECTIONS:
    1. Engagement Metadata - ID, date, scope, mode
    2. Executive Summary — LLM-written, plain language, risk overview
    3. Hosts Discovered — full device inventory
    4. Camera/NVR Findings — per-device: vendor, CVEs, credentials, artifact
    5. Credentials Found — flagged as sensitive
    6. Artifacts — frame capture paths
    7. Audit Trail — chain of custody

LLM ROLE:
    Python assembles all structured data. LLM writes:
    - Executive summary paragraph
    - Per-host finding narrative 
    LLM never sees raw credentials, they are inserted by Python after LLM generation.

REPORT TONE:
    Plain, direct pen-test language. 
    "Camera at 192.168.1.10 was accessible using default credentials
    (admin/12345). A frame was captured confirming live stream access."

LLM: Claude Sonnet via langchain_anthropic
PDF: weasyprint (pure Python, no external dependencies)
"""

import os
import json
from datetime import datetime

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage

from core.base_agent import BaseAgent, AgentRegistry
from core.engagement import EngagementContext, CVERecord
from core.vendors import VENDOR_PROFILES
from core.llm_defense import wrap_for_llm
from config import REPORTING_MODEL, REPORTS_DIR, ARTIFACTS_DIR, VERBOSE, DEBUG, NO_REPORT


# ---------------------------------------------------------------------------
# CVE descriptions pulled 
# ---------------------------------------------------------------------------

CVE_DESCRIPTIONS = {
    "CVE-2021-36260": ("critical", "Hikvision RCE via unauthenticated HTTP request to /SDK/webLanguage endpoint"),
    "CVE-2017-7921":  ("critical", "Hikvision authentication bypass — camera accessible without valid credentials"),
    "CVE-2022-28173": ("high",     "Hikvision stack overflow in web server component"),
    "CVE-2021-33044": ("critical", "Dahua authentication bypass — affects multiple camera and NVR models"),
    "CVE-2021-33045": ("critical", "Dahua authentication bypass variant — similar scope to CVE-2021-33044"),
    "CVE-2022-30563": ("high",     "Dahua plaintext credential exposure via ONVIF interface"),
    "CVE-2018-10660": ("critical", "Axis shell command injection via HTTP API"),
    "CVE-2020-29560": ("high",     "Axis buffer overflow in web server"),
    "CVE-2018-1149":  ("critical", "Hanwha unauthenticated root shell via CGI endpoint"),
    "CVE-2018-1150":  ("high",     "Hanwha authentication bypass variant"),
}



# ---------------------------------------------------------------------------
# CVE population helper
# ---------------------------------------------------------------------------
 
def _populate_cve_findings(ctx: EngagementContext) -> None:
    """
    Populate ctx.cve_findings from vendors.py known_cves for all
    camera/NVR hosts in ctx.confirmed_hosts.
 
    Called at the start of run() before report generation.
    exploited=True for hosts where credentials were found,
    exploited=False for hosts that were discovered but not accessed.
 
    This is the "vendors.py" source, static known CVEs per vendor.
    Future: OSINTAgent will add NVD-sourced CVEs with source="nvd_api".
    """
    # Build set of IPs where we found credentials ('exploited')
    exploited_ips = {c["ip"] for c in ctx.credentials_found}
 
    for host in ctx.confirmed_hosts:
        ip = host["ip"]
        vendor = host.get("vendor", "unknown")
 
        if vendor == "unknown" or vendor not in VENDOR_PROFILES:
            continue
 
        known_cves = VENDOR_PROFILES[vendor].get("known_cves", [])
        for cve_id in known_cves:
            severity, description = CVE_DESCRIPTIONS.get(
                cve_id, ("medium", f"Known vulnerability affecting {vendor} devices")
            )
            cve = CVERecord(
                ip=ip,
                cve_id=cve_id,
                vendor=vendor,
                description=description,
                severity=severity,
                exploited=(ip in exploited_ips),
                source="vendors.py"
            )
            ctx.add_cve_finding(cve)
 
 
# ---------------------------------------------------------------------------
# LLM writing helpers
# ---------------------------------------------------------------------------
 
def _write_executive_summary(llm: ChatAnthropic, ctx: EngagementContext) -> str:
    """
    Ask Claude Sonnet to write a plain-language executive summary.
 
    Passes structured engagement stats to the LLM. Credentials are summarized as counts, never passed as actual text
    """
    camera_hosts = [
        h for h in ctx.confirmed_hosts
        if h.get("device_type") in ("camera", "nvr")
    ]
    accessed_count = len({c["ip"] for c in ctx.credentials_found})
    critical_cves = [c for c in ctx.cve_findings if c.get("severity") == "critical"]
 
    stats = {
        "total_hosts": len(ctx.confirmed_hosts),
        "cameras_nvrs_found": len(camera_hosts),
        "cameras_accessed": accessed_count,
        "credentials_found": len(ctx.credentials_found),
        "artifacts_captured": len(ctx.artifacts),
        "critical_cves": len(critical_cves),
        "vendors_found": list({h.get("vendor") for h in camera_hosts if h.get("vendor") != "unknown"}),
        "scope": ctx.target_scope or ["auto-detected"],
        "entry_method": ctx.entry_method or "given_access",
    }
 
    prompt = f"""You are writing the executive summary section of a penetration test report.
Write 2-3 short paragraphs summarizing the findings below.
 
Rules:
- Write in plain, direct language. No fancy words.
- Don't sound like AI. Write like a security consultant who did the work.
- Don't use words like "critical security posture deficiency" or "threat landscape".
- Be specific about what was found and what it means.
- Mention the vendor names and what default credentials mean in practice.
- End with a sentence about recommended remediation focus.
 
Engagement stats:
{json.dumps(stats, indent=2)}
 
Write only the summary paragraphs, no headers or labels."""
 
    try:
        response = llm.invoke([HumanMessage(content=prompt)])
        if DEBUG:
            print(f"[ReportingAgent] [DEBUG] LLM executive summary raw: {response.content[:200]}") #DEBUG
        return response.content.strip()
    except Exception as e:
        print(f"[ReportingAgent] LLM executive summary failed: {e}") #NORMAL
        return (
            f"This engagement scanned {stats['total_hosts']} hosts and found "
            f"{stats['cameras_nvrs_found']} cameras/NVRs. "
            f"{stats['cameras_accessed']} were accessed using default credentials. "
            f"See findings below for details."
        )
 
 
def _write_host_finding(llm: ChatAnthropic, host: dict, host_creds: list,
                         host_cves: list, has_artifact: bool) -> str:
    """
    Write a 1-2 sentence finding narrative for a single camera/NVR host.
    Credentials passed as counts only, not raw values.
    """
    prompt = f"""Write 1-2 sentences describing this camera finding for a pen-test report.
Plain language, no AI-speak, be specific.
 
Device: {host.get('vendor', 'unknown')} {host.get('device_type', 'device')} at {host['ip']}
Hostname: {host.get('hostname', 'unknown')}
Credentials found: {len(host_creds)} valid account(s)
Frame captured: {'yes' if has_artifact else 'no'}
CVEs applicable: {[c['cve_id'] for c in host_cves]}
 
Write only the sentences, no labels."""
 
    try:
        response = llm.invoke([HumanMessage(content=prompt)])
        return response.content.strip()
    except Exception as e:
        accessed = len(host_creds) > 0
        return (
            f"{'Accessed using default credentials.' if accessed else 'Discovered but not accessed.'}"
            f"{' Frame capture confirmed live stream access.' if has_artifact else ''}"
        )
 
 
# ---------------------------------------------------------------------------
# Markdown assembly
# ---------------------------------------------------------------------------
 
def _build_markdown(ctx: EngagementContext, exec_summary: str,
                     host_narratives: dict) -> str:
    """
    Assemble full markdown report from ctx data and LLM-written sections.
    Python controls all structure and data, LLM text inserted 
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = []
 
    # --- Header ---
    lines += [
        f"# Penetration Test Report",
        f"",
        f"**Engagement ID:** {ctx.engagement_id}  ",
        f"**Date:** {now}  ",
        f"**Scope:** {', '.join(ctx.target_scope) if ctx.target_scope else 'Auto-detected'}  ",
        f"**Entry Method:** {ctx.entry_method or 'Given Access'}  ",
        f"**Mode:** {'Mock (simulated network)' if 'mock' in ctx.engagement_id.lower() else 'Real'}  ",
        f"",
        f"---",
        f"",
    ]
 
    # --- Executive Summary ---
    lines += [
        f"## Executive Summary",
        f"",
        exec_summary,
        f"",
        f"---",
        f"",
    ]
 
    # --- Stats overview ---
    camera_hosts = [h for h in ctx.confirmed_hosts
                    if h.get("device_type") in ("camera", "nvr")]
    accessed_ips = {c["ip"] for c in ctx.credentials_found}
 
    lines += [
        f"## Findings Overview",
        f"",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total hosts discovered | {len(ctx.confirmed_hosts)} |",
        f"| Cameras / NVRs found | {len(camera_hosts)} |",
        f"| Cameras / NVRs accessed | {len(accessed_ips)} |",
        f"| Credentials found | {len(ctx.credentials_found)} |",
        f"| Frames captured | {len(ctx.artifacts)} |",
        f"| CVE findings | {len(ctx.cve_findings)} |",
        f"| Critical CVEs | {len([c for c in ctx.cve_findings if c.get('severity') == 'critical'])} |",
        f"",
        f"---",
        f"",
    ]
 
    # --- Host inventory ---
    lines += [
        f"## Host Inventory",
        f"",
        f"| IP | Hostname | Vendor | Device Type | Ports | Accessed |",
        f"|----|----------|--------|-------------|-------|----------|",
    ]
    for host in ctx.confirmed_hosts:
        ip = host["ip"]
        hostname = host.get("hostname") or "—"
        vendor = host.get("vendor") or "unknown"
        dtype = host.get("device_type") or "unknown"
        ports = ", ".join(str(p) for p in host.get("open_ports", []))
        accessed = "✓" if ip in accessed_ips else "—"
        lines.append(f"| {ip} | {hostname} | {vendor} | {dtype} | {ports} | {accessed} |")
 
    lines += ["", "---", ""]
 
    # --- Per-camera findings ---
    if camera_hosts:
        lines += [
            f"## Camera / NVR Findings",
            f"",
        ]
        for host in camera_hosts:
            ip = host["ip"]
            vendor = host.get("vendor", "unknown")
            dtype = host.get("device_type", "device")
            hostname = host.get("hostname") or ip
 
            host_creds = [c for c in ctx.credentials_found if c["ip"] == ip]
            host_cves = [c for c in ctx.cve_findings if c["ip"] == ip]
            host_artifacts = [a for a in ctx.artifacts if a["source_ip"] == ip]
 
            lines += [
                f"### {vendor.title()} {dtype.title()} — {ip}",
                f"",
                f"**Hostname:** {hostname}  ",
                f"**Vendor:** {vendor.title()}  ",
                f"**Open Ports:** {', '.join(str(p) for p in host.get('open_ports', []))}  ",
                f"",
            ]
 
            # LLM narrative
            narrative = host_narratives.get(ip, "")
            if narrative:
                lines += [narrative, ""]
 
            # CVEs
            if host_cves:
                lines += [f"**Applicable CVEs:**", ""]
                for cve in host_cves:
                    severity = cve.get("severity", "unknown").upper()
                    exploited_tag = " ⚠ **EXPLOITED**" if cve.get("exploited") else ""
                    lines.append(
                        f"- `{cve['cve_id']}` [{severity}]{exploited_tag} — {cve['description']}"
                    )
                lines.append("")
 
            # Credentials — flagged as sensitive, shown as table
            if host_creds:
                lines += [
                    f"**Credentials Found** *(sensitive)*",
                    f"",
                    f"| Username | Password | Access Level | Endpoint |",
                    f"|----------|----------|--------------|----------|",
                ]
                for cred in host_creds:
                    lines.append(
                        f"| {cred['username']} | {cred['password']} | "
                        f"{cred.get('access_level', '—')} | {cred.get('endpoint', '—')} |"
                    )
                lines.append("")
            else:
                lines += [f"**Credentials:** None found", ""]
 
            # Artifacts
            if host_artifacts:
                lines += [f"**Proof of Access:**", ""]
                for artifact in host_artifacts:
                    lines.append(f"- `{artifact['file_path']}`  ")
                    lines.append(f"  _{artifact.get('description', '')}_")
                lines.append("")
            else:
                lines += [f"**Artifacts:** None captured", ""]
 
            lines += ["---", ""]
 
    # --- CVE summary ---
    if ctx.cve_findings:
        lines += [
            f"## CVE Summary",
            f"",
            f"| CVE ID | Severity | Vendor | Exploited | Description |",
            f"|--------|----------|--------|-----------|-------------|",
        ]
        seen = set()
        for cve in ctx.cve_findings:
            key = cve["cve_id"]
            if key not in seen:
                seen.add(key)
                exploited = "Yes" if cve.get("exploited") else "No"
                lines.append(
                    f"| `{cve['cve_id']}` | {cve.get('severity','—').upper()} | "
                    f"{cve['vendor'].title()} | {exploited} | {cve['description']} |"
                )
        lines += ["", "---", ""]
 
    # --- Audit trail (abridged) ---
    lines += [
        f"## Audit Trail",
        f"",
        f"Complete chain of custody — {len(ctx.audit_log)} entries logged.",
        f"",
        f"| Timestamp | Agent | Action | Target | Result |",
        f"|-----------|-------|--------|--------|--------|",
    ]
    for entry in ctx.audit_log:
        ts = entry.get("timestamp", "")[:19].replace("T", " ")
        agent = entry.get("agent", "—")
        action = entry.get("action", "—")[:60]
        target = entry.get("target") or "—"
        result = (entry.get("result") or "—")[:40]
        lines.append(f"| {ts} | {agent} | {action} | {target} | {result} |")
 
    lines += ["", "---", ""]
    lines += [
        f"*Report generated {now} by LLM-Driven Network Recon & IoT Exploitation Framework*",
        f"*For authorized penetration testing use only.*",
    ]
 
    return "\n".join(lines)
 
 
# ---------------------------------------------------------------------------
# PDF conversion
# ---------------------------------------------------------------------------
 
def _markdown_to_pdf(markdown_text: str, output_path: str) -> bool:
    """
    Convert Markdown to PDF via weasyprint. Returns True on success, false if weasyprint not available
 
    Converts Markdown → HTML first (via markdown library),
    then HTML → PDF via weasyprint.
    """
    try:
        import markdown as md_lib
        from weasyprint import HTML
 
        # Convert markdown to HTML with table support
        html_body = md_lib.markdown(
            markdown_text,
            extensions=["tables", "fenced_code"]
        )
 
        # Wrap in minimal styled HTML
        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
    body {{ font-family: Arial, sans-serif; font-size: 11pt; 
           margin: 40px; color: #1a1a1a; line-height: 1.5; }}
    h1 {{ font-size: 20pt; border-bottom: 2px solid #333; padding-bottom: 6px; }}
    h2 {{ font-size: 14pt; border-bottom: 1px solid #ccc; 
          padding-bottom: 4px; margin-top: 28px; }}
    h3 {{ font-size: 12pt; margin-top: 20px; }}
    table {{ border-collapse: collapse; width: 100%; margin: 12px 0; font-size: 10pt; }}
    th {{ background: #333; color: white; padding: 6px 8px; text-align: left; }}
    td {{ padding: 5px 8px; border-bottom: 1px solid #ddd; }}
    tr:nth-child(even) {{ background: #f9f9f9; }}
    code {{ background: #f0f0f0; padding: 1px 4px; 
            border-radius: 3px; font-size: 10pt; }}
    hr {{ border: none; border-top: 1px solid #ccc; margin: 20px 0; }}
    em {{ color: #555; }}
</style>
</head>
<body>
{html_body}
</body>
</html>"""
 
        HTML(string=html).write_pdf(output_path)
        return True
 
    except ImportError as e:
        print(f"[ReportingAgent] PDF generation skipped — missing dependency: {e}") #NORMAL
        print(f"[ReportingAgent] Install with: pip install weasyprint markdown") #NORMAL
        return False
    except Exception as e:
        print(f"[ReportingAgent] PDF generation failed: {e}") #NORMAL
        return False
 
 
# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------
 
@AgentRegistry.register
class ReportingAgent(BaseAgent):
    name = "ReportingAgent"
    stage = "reporting"
    description = "Generates structured pen-test report mapped to MITRE ATT&CK from EngagementContext."
    mitre_tactic = ""
    mitre_tactic_name = "Reporting"
    requires_network = False
    requires_llm = True
 
    def can_run(self, ctx: EngagementContext) -> tuple[bool, str]:
        if NO_REPORT:
            return False, "Report generation disabled via --no-report flag."
        if not ctx.confirmed_hosts and not ctx.exposed_services:
            return False, "Nothing to report. Run at least one discovery stage first."
        return True, ""
 
    def run(self, ctx: EngagementContext) -> EngagementContext:
        """
        Generate Markdown a&nd PDF pen-test reports from ctx.
 
        Python assembles all structured data. LLM writes executive
        summary and per-host narratives only, doesn't get any sensitive info/creds
        """
        ctx.current_stage = self.stage
        ctx.log(self.name, "ReportingAgent started")
 
        # ----------------------------------------------------------------
        # Step 1: Populate CVE findings from vendors.py
        # ----------------------------------------------------------------
 
        print(f"[ReportingAgent] Populating CVE findings...") #NORMAL
        _populate_cve_findings(ctx)
        ctx.log(
            self.name,
            "CVE findings populated",
            result=f"{len(ctx.cve_findings)} findings from vendors.py"
        )
        if VERBOSE:
            print(f"[ReportingAgent] {len(ctx.cve_findings)} CVE findings populated") #VERBOSE
 
        # ----------------------------------------------------------------
        # Step 2: Initialize LLM
        # ----------------------------------------------------------------
 
        llm = ChatAnthropic(model=REPORTING_MODEL)
 
        # ----------------------------------------------------------------
        # Step 3: LLM writes executive summary
        # ----------------------------------------------------------------
 
        print(f"[ReportingAgent] Writing executive summary...") #NORMAL
        exec_summary = _write_executive_summary(llm, ctx)
        if VERBOSE:
            print(f"[ReportingAgent] Executive summary: {exec_summary[:100]}...") #VERBOSE
 
        # ----------------------------------------------------------------
        # Step 4: LLM writes per-host narratives
        # ----------------------------------------------------------------
 
        camera_hosts = [
            h for h in ctx.confirmed_hosts
            if h.get("device_type") in ("camera", "nvr")
        ]
 
        host_narratives = {}
        for host in camera_hosts:
            ip = host["ip"]
            if VERBOSE:
                print(f"[ReportingAgent] Writing narrative for {ip}...") #VERBOSE
 
            host_creds = [c for c in ctx.credentials_found if c["ip"] == ip]
            host_cves = [c for c in ctx.cve_findings if c["ip"] == ip]
            host_artifacts = [a for a in ctx.artifacts if a["source_ip"] == ip]
 
            narrative = _write_host_finding(
                llm, host, host_creds, host_cves, bool(host_artifacts)
            )
            host_narratives[ip] = narrative
 
        # ----------------------------------------------------------------
        # Step 5: Assemble Markdown report
        # ----------------------------------------------------------------
 
        print(f"[ReportingAgent] Assembling report...") #NORMAL
        markdown_text = _build_markdown(ctx, exec_summary, host_narratives)
 
        # ----------------------------------------------------------------
        # Step 6: Write files
        # ----------------------------------------------------------------
 
        report_dir = os.path.join(REPORTS_DIR, ctx.engagement_id)
        os.makedirs(report_dir, exist_ok=True)
 
        # Markdown
        md_path = os.path.join(report_dir, "report.md")
        with open(md_path, "w") as f:
            f.write(markdown_text)
        print(f"[ReportingAgent] ✓  Markdown report: {md_path}") #NORMAL
 
        # PDF
        pdf_path = os.path.join(report_dir, "report.pdf")
        pdf_ok = _markdown_to_pdf(markdown_text, pdf_path)
        if pdf_ok:
            print(f"[ReportingAgent] ✓  PDF report: {pdf_path}") #NORMAL
 
        # Log both paths to ctx
        ctx.log(
            self.name,
            "Report generated",
            result=f"md={md_path}" + (f" pdf={pdf_path}" if pdf_ok else " pdf=skipped")
        )
 
        ctx.mark_stage_complete(self.stage)
        return ctx
 