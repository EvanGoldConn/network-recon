"""
core/engagement.py
------------------
The EngagementContext is the single shared intelligence object that flows
through the entire attack chain. Every agent reads from it and writes to it.


DESIGN PRINCIPLES:
    1. Append-only for most fields (hosts, credentials, artifacts)
       - You never remove a discovered host or credential. History is preserved.
    2. Scope is immutable after initialization
       - confirmed_scope is set once at engagement start and never modified.
       - All agents enforce this. A pipeline-level guard enforces it too.
    3. Chain of custody is always written
       - Every action taken by every agent is logged with a timestamp.
       - This is what makes a pen-test report defensible.
    4. Serializable to JSON
       - The entire context can be saved/loaded as JSON.
       - This means engagements can be paused, resumed, or handed off.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import json
import uuid


@dataclass
class HostRecord:
    """
    Represents a single discovered host on the network.

    Populated by: DiscoveryAgent
    Consumed by: AccessAgent, LateralMovementAgent
    """
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    open_ports: list = field(default_factory=list)
    device_type: Optional[str] = None      # "hikvision_camera", "dahua_camera", "nvr", "router", "unknown"
    vendor: Optional[str] = None           # "Hikvision", "Dahua", "Axis", etc.
    banner: Optional[str] = None           # raw banner text, sanitized before LLM ingestion
    os_fingerprint: Optional[str] = None
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class CredentialRecord:
    """
    Represents a discovered working credential pair.

    Populated by: AccessAgent
    Consumed by: LateralMovementAgent (credential reuse across the chain)

    WHY CREDENTIAL REUSE MATTERS:
        People reuse passwords. A camera with admin/admin often means the NVR
        uses admin/admin too. Automatically testing discovered credentials
        against new targets is one of the highest-value things an automated
        tool can do.
    """
    ip: str
    username: str
    password: str
    service: str                           # "http", "rtsp", "ssh", etc.
    access_level: Optional[str] = None    # "admin", "viewer", "root"
    endpoint: Optional[str] = None        # the URL or port where it worked
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class ArtifactRecord:
    """
    Represents a proof-of-access artifact saved to disk.

    Examples: captured video frame (JPEG), screenshot of admin panel,
    downloaded config file, captured WPA handshake.

    Populated by: AccessAgent, WiFiModule, any agent that captures evidence
    """
    artifact_type: str                     # "frame_capture", "screenshot", "config", "handshake"
    file_path: str                         # path under results/
    source_ip: Optional[str] = None
    description: Optional[str] = None
    captured_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class AuditEntry:
    """
    A single entry in the chain of custody log.

    WHY THIS EXISTS:
        Pen-test reports need to be defensible. "The tool found credentials"
        is not defensible. "At 14:32:07 UTC, AccessAgent sent HTTP GET to
        192.168.1.10:80/ISAPI/Security/userCheck with credentials admin/12345
        and received HTTP 200" is defensible.

        Every action that touches the network gets an audit entry.
        This is also what separates a professional tool from a script.
    """
    agent: str                             # which agent took this action
    action: str                            # human-readable description
    target: Optional[str] = None          # IP or host targeted
    result: Optional[str] = None          # what happened
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class CVERecord:
    """
    Represents a CVE finding associated with a discovered host.

    Populated by: ReportingAgent (from vendors.py known_cves),
                  OSINTAgent (future.. NVD API lookup)
    Consumed by: ReportingAgent

    WHY THIS EXISTS:
        Linking CVEs to specific hosts makes the report actionable.
        "192.168.1.10 is vulnerable to CVE-2017-7921 (Critical)
        Hikvision authentication bypass, confirmed exploited" is a
        finding. A list of CVE IDs is not.

    SOURCE VALUES:
        "vendors.py"  — known CVEs from static vendor profile
        "nvd_api"     — fetched from NVD at scan time (future)
        "osint_agent" — discovered via Shodan/OSINT (future)
    """
    ip: str
    cve_id: str                            # e.g. "CVE-2017-7921"
    vendor: str                            # e.g. "hikvision"
    description: str                       # short human-readable description
    severity: str                          # "critical"/"high"/"medium"/"low"
    exploited: bool = False                # True if we confirmed access on this host
    source: str = "vendors.py"            # where this finding came from
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class EngagementContext:
    """
    The single shared intelligence object for an entire engagement.

    Flows through every stage of the attack chain. Each agent receives it,
    reads what prior agents discovered, appends its own findings, and passes
    it to the next stage.

    USAGE:
        # Start a new engagement
        ctx = EngagementContext(
            engagement_id="client-home-network-001",
            target_scope=["192.168.1.0/24"],
        )

        # Agents append to it
        ctx.add_host(HostRecord(ip="192.168.1.10", ...))
        ctx.add_credential(CredentialRecord(ip="192.168.1.10", ...))
        ctx.log("AccessAgent", "Tested credentials", target="192.168.1.10", result="success")

        # Save and resume
        ctx.save("results/engagement-001.json")
        ctx = EngagementContext.load("results/engagement-001.json")
    """

    # --- Identity ---
    # engagement_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    engagement_id: str = field(
            default_factory=lambda: f"engagement-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{str(uuid.uuid4())[:4]}"
            #UTC: default_factory=lambda: f"engagement-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}-{str(uuid.uuid4())[:4]}"
            )           
             
    
    
    #engagement-20260525-localsystemtimestamp-randomsuffix
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    # --- Scope (immutable after init) ---
    # WHY IMMUTABLE: Scope creep is both a legal liability and a security risk.
    # Once set, no agent or LLM output should be able to expand the target scope.
    target_scope: list = field(default_factory=list)   # ["192.168.1.0/24", "10.0.0.0/24"]
    excluded_ips: list = field(default_factory=list)   # always skip these

    # --- Network entry context ---
    entry_method: Optional[str] = None    # "wifi_crack", "given_access", "vpn", "shodan_exposed"
    wifi_ssid: Optional[str] = None
    wifi_passphrase: Optional[str] = None  # populated by WiFiModule if cracked

    # --- Discovered intelligence ---
    confirmed_hosts: list = field(default_factory=list)      # list of HostRecord
    credentials_found: list = field(default_factory=list)    # list of CredentialRecord
    artifacts: list = field(default_factory=list)            # list of ArtifactRecord
    exposed_services: list = field(default_factory=list)     # from OSINT/Shodan stage
    cve_findings: list = field(default_factory=list)         # list of CVERecord

    # --- Audit trail ---
    audit_log: list = field(default_factory=list)            # list of AuditEntry

    # --- Pipeline state ---
    stages_completed: list = field(default_factory=list)     # ["wifi", "osint", "discovery", "access"]
    current_stage: Optional[str] = None

    # ----------------------------------------------------------------
    # Scope enforcement
    # ----------------------------------------------------------------

    def is_in_scope(self, ip: str) -> bool:
        """
        Check if an IP is within the confirmed engagement scope.

        WHY THIS IS IN THE CONTEXT OBJECT:
            Every agent and every tool calls this before making any network
            connection. It's the single enforcement point. If it's not in
            scope, the connection never happens — regardless of what the LLM
            decided to do.

        This is the core of the scope enforcement architecture:
            Trust boundary = Python code, not LLM judgment.
        """
        import ipaddress
        if ip in self.excluded_ips:
            return False
        if not self.target_scope:
            return True  # no scope defined = allow all (useful in early discovery)
        for scope_entry in self.target_scope:
            try:
                if ipaddress.ip_address(ip) in ipaddress.ip_network(scope_entry, strict=False):
                    return True
            except ValueError:
                continue
        return False

    def enforce_scope(self, ip: str, agent_name: str):
        """
        Hard enforcement — raises if IP is out of scope.
        Called by tools before any network connection.

        Raises:
            ScopeViolationError: if the IP is not in confirmed scope
        """
        if not self.is_in_scope(ip):
            self.log(agent_name, f"SCOPE VIOLATION blocked: attempted connection to {ip}")
            raise ScopeViolationError(
                f"IP {ip} is outside engagement scope. "
                f"Defined scope: {self.target_scope}"
            )

    # ----------------------------------------------------------------
    # Mutation methods (append-only)
    # ----------------------------------------------------------------

    def add_host(self, host: HostRecord):
        """Add a discovered host. Deduplicates by IP."""
        existing_ips = [h["ip"] for h in self.confirmed_hosts]
        if host.ip not in existing_ips:
            self.confirmed_hosts.append(host.__dict__)

    def add_credential(self, cred: CredentialRecord):
        """Add a discovered credential pair."""
        self.credentials_found.append(cred.__dict__)

    def add_artifact(self, artifact: ArtifactRecord):
        """Add a proof-of-access artifact."""
        self.artifacts.append(artifact.__dict__)

    def add_exposed_service(self, service: dict):
        """Add an externally exposed service found via OSINT."""
        self.exposed_services.append(service)

    def add_cve_finding(self, cve: CVERecord):
        """Add a CVE finding. Deduplicates by ip + cve_id pair."""
        existing = [(c["ip"], c["cve_id"]) for c in self.cve_findings]
        if (cve.ip, cve.cve_id) not in existing:
            self.cve_findings.append(cve.__dict__)

    def log(self, agent: str, action: str, target: str = None, result: str = None):
        """Append to the chain of custody audit log."""
        entry = AuditEntry(agent=agent, action=action, target=target, result=result)
        self.audit_log.append(entry.__dict__)

    def mark_stage_complete(self, stage: str):
        if stage not in self.stages_completed:
            self.stages_completed.append(stage)
        self.current_stage = None

    def log_stealth_config(self):
        """
        Write the active stealth/evasion settings to the audit log at scan start.

        WHY THIS IS IN THE AUDIT LOG:
            "Scan ran with MACspoofing and decoy IPs" is material to the report and chain of custody.
            Logging it here means it's automatically included in report generation
            without any agent having to remember to write it.

        Called by: PipelineRunner before the first stage, or by DiscoveryAgent
                   at the start of its run(). Either location is fine, it happens once per engagement, early.
        """
        # Import here to avoid circular import — config imports nothing from core/
        from config import (
            QUIET, SLOW_SCAN, FRAGMENT_PACKETS, USE_DECOYS,
            SPOOF_SOURCE_PORT, RANDOMIZE_HOSTS, SPOOF_MAC
        )

        active_flags = []
        if QUIET:             active_flags.append("quiet (all stealth options)")
        if SLOW_SCAN:         active_flags.append("slow-scan (-T1)")
        if FRAGMENT_PACKETS:  active_flags.append("fragment-packets (-f)")
        if USE_DECOYS:        active_flags.append("decoys (-D RND:5)")
        if SPOOF_SOURCE_PORT: active_flags.append("spoof-source-port (--source-port 53)")
        if RANDOMIZE_HOSTS:   active_flags.append("randomize-hosts")
        if SPOOF_MAC:         active_flags.append("spoof-mac")

        if active_flags:
            self.log(
                agent="Pipeline",
                action=f"Stealth mode active — flags: {', '.join(active_flags)}",
                result="evasion options applied to scan"
            )
        else:
            self.log(
                agent="Pipeline",
                action="Stealth mode inactive — standard scan settings",
                result="no evasion options active"
            )

    # ----------------------------------------------------------------
    # Serialization
    # ----------------------------------------------------------------

    def save(self, path: str):
        """Serialize the full engagement context to JSON."""
        with open(path, "w") as f:
            json.dump(self.__dict__, f, indent=2)

    @classmethod
    def load(cls, path: str) -> "EngagementContext":
        """Deserialize an engagement context from JSON."""
        with open(path, "r") as f:
            data = json.load(f)
        ctx = cls.__new__(cls)
        ctx.__dict__.update(data)
        return ctx

    # ----------------------------------------------------------------
    # Summary
    # ----------------------------------------------------------------

    def summary(self) -> str:
        """Human-readable summary of engagement progress."""
        return (
            f"Engagement: {self.engagement_id}\n"
            f"Scope: {', '.join(self.target_scope) or 'auto-detect'}\n"
            f"Stages complete: {', '.join(self.stages_completed) or 'none'}\n"
            f"Hosts discovered: {len(self.confirmed_hosts)}\n"
            f"Credentials found: {len(self.credentials_found)}\n"
            f"Artifacts captured: {len(self.artifacts)}\n"
            f"CVE findings: {len(self.cve_findings)}\n"
            f"Audit entries: {len(self.audit_log)}\n"
        )


class ScopeViolationError(Exception):
    """
    Raised when an agent attempts to connect to an out-of-scope IP.

    This is intentionally a loud, hard failure — not a warning.
    Out-of-scope connections are a legal liability on real engagements.
    """
    pass