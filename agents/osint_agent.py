"""
agents/osint_agent.py
----------------------
Stage 1 — MITRE ATT&CK: TA0043 Reconnaissance

External OSINT via Shodan. Identifies internet-exposed cameras, NVRs,
and admin panels visible from the public internet without requiring
internal network access.

WHAT THIS AGENT DOES (current):
    Phase 1 — Public IP resolution
        Resolves the network's public-facing WAN IP via Shodan's own API.
        RFC1918 ranges (192.168.x.x) are not indexed by Shodan — we need
        the public IP to find what's actually exposed to the internet.
        → _resolve_public_ip()
            checks target_scope for existing public CIDRs first
            falls back to ipify.org (GET https://api.ipify.org) (free, no credits consumed)
            writes result to ctx.public_ip
 
    Phase 2 — Shodan host lookup
        Queries Shodan for everything it knows about the public IP.
        If the operator provided explicit public CIDRs in target_scope,
        those are queried directly instead.
        → _query_shodan_host()
            single IP  → _lookup_single_ip()  — api.host(), 1 credit
            CIDR range → _search_cidr()        — api.search(net:), 1 credit/page
 
    Phase 3 — Camera/NVR detection
        Filters Shodan results for camera-related ports and banners.
        Any camera found on the public IP that isn't already in
        ctx.confirmed_hosts gets added with source="osint".
        → _is_camera_service()  — port + banner signature check
        → _add_osint_host()     — builds HostRecord(source="osint"), deduped by ctx.add_host()
        → _vendor_from_banner() — maps banner string to vendors.py vendor key
 
    Phase 4 — CVE enrichment
        For every host already in ctx.confirmed_hosts (from DiscoveryAgent),
        queries Shodan for known CVEs associated with their vendor/banner.
        Writes CVERecord entries to ctx.cve_findings with source="osint_agent".
        → _enrich_cves()
            loops ctx.confirmed_hosts, calls api.host(ip) per host
            RFC1918 IPs expected to return "not indexed" — not an error
        → _write_cve()  — normalizes Shodan vuln dict → CVERecord, maps CVSS → severity bucket
 
    Phase 5 — Exposed service logging
        All Shodan findings (not just cameras) are written to
        ctx.exposed_services for the report's external exposure section.
        → handled inline inside _lookup_single_ip() and _search_cidr()
           every service hit calls ctx.add_exposed_service() before camera check

FUTURE (org-based recon):
    When ctx.target_org / ctx.target_domain / ctx.target_address are set,
    OSINTAgent will:
    - Query ARIN for registered IP ranges by org name
    - Query BGP/ASN data to find all announced prefixes
    - Use cert transparency (crt.sh) to map subdomains
    - Geo-filter Shodan results to a physical address
    - Add discovered CIDRs to ctx.target_scope automatically
    TODO: Implement when --org/--domain/--address flags are needed for
          a real external engagement.

SCOPE NOTE:
    OSINTAgent intentionally does NOT call ctx.enforce_scope() for public
    IP lookups. Shodan is a passive read-only query against their existing
    index — no packets are sent to the target. This is passive OSINT, not
    active scanning. Internal scope enforcement still applies to any hosts
    added to ctx that will later be actively tested.

REQUIRES:
    SHODAN_API_KEY in .env
    100 query credits/month on Membership tier is sufficient for home-lab use.
"""

import os
from config import VERBOSE, DEBUG, SHODAN_API_KEY
from core.base_agent import BaseAgent, AgentRegistry
from core.engagement import EngagementContext, HostRecord, CVERecord


# ---------------------------------------------------------------------------
# Shodan port/banner filters for camera detection
# ---------------------------------------------------------------------------

# Ports that indicate a camera or NVR when found on a public IP.
# Any Shodan result with one of these open is worth investigating.
CAMERA_PORTS = {554, 8554, 80, 8080, 8000, 443, 9000, 37777, 37778}

# Banner substrings that positively identify a camera or NVR vendor.
# Matched case-insensitively against Shodan's banner/product fields.
CAMERA_BANNER_SIGNATURES = [
    "hikvision", "dahua", "reolink", "axis", "amcrest", "hanwha",
    "wisenet", "foscam", "uniview", "vivotek", "bosch",
    "nvr", "dvr", "ipcam", "webcam", "netcam",
    "rtsp", "h264", "h.264",
]


@AgentRegistry.register
class OSINTAgent(BaseAgent):
    name = "OSINTAgent"
    stage = "osint"
    description = "External OSINT via Shodan: exposed cameras, NVRs, CVE enrichment."
    mitre_tactic = "TA0043"
    mitre_tactic_name = "Reconnaissance"
    requires_root = False
    requires_network = True
    requires_llm = False   # pure API calls, no LLM needed

    def can_run(self, ctx: EngagementContext) -> tuple[bool, str]:
        if not SHODAN_API_KEY:
            return False, "SHODAN_API_KEY not set in .env. Get a key at account.shodan.io"
        return True, ""

    def run(self, ctx: EngagementContext) -> EngagementContext:
        """
        Execute external OSINT reconnaissance via Shodan.
        """
        ctx.current_stage = self.stage
        print(f"[OSINTAgent] Starting external OSINT reconnaissance") #NORMAL

        try:
            import shodan
        except ImportError:
            print("[OSINTAgent] shodan library not installed — run: pip install shodan") #NORMAL
            ctx.log(self.name, "shodan library not installed", result="skipped")
            ctx.mark_stage_complete(self.stage)
            return ctx

        api = shodan.Shodan(SHODAN_API_KEY)

        # --- Phase 1: Resolve public IP ---
        public_ip = self._resolve_public_ip(api, ctx)
        if not public_ip:
            print("[OSINTAgent] Could not resolve public IP — Shodan host lookup skipped") #NORMAL
            ctx.log(self.name, "Public IP resolution failed", result="skipped phases 2-3")
        else:
            # --- Phase 2 & 3: Shodan host lookup + camera detection ---
            self._query_shodan_host(api, ctx, public_ip)

        # --- Phase 4: CVE enrichment for already-discovered hosts ---
        # Runs independently of public IP resolution.
        # Even if we can't find the public IP, we can still enrich
        # DiscoveryAgent hosts with Shodan CVE data.
        if ctx.confirmed_hosts:
            self._enrich_cves(api, ctx)
        else:
            print("[OSINTAgent] No confirmed hosts to enrich — CVE phase skipped") #NORMAL
            if VERBOSE: print("[OSINTAgent] Run DiscoveryAgent first to populate hosts for CVE enrichment") #VERBOSE

        ctx.log(self.name, "OSINT reconnaissance complete",
                result=f"exposed_services={len(ctx.exposed_services)}, cve_findings={len(ctx.cve_findings)}")
        ctx.mark_stage_complete(self.stage)
        print(f"[OSINTAgent] Complete — {len(ctx.exposed_services)} exposed services, " #NORMAL
              f"{len(ctx.cve_findings)} CVE findings")
        return ctx

    # ----------------------------------------------------------------
    # Phase 1 — Public IP resolution
    # ----------------------------------------------------------------

    def _resolve_public_ip(self, api, ctx: EngagementContext) -> str | None:
        """
        Resolve the network's public-facing WAN IP via Shodan.

        Uses api.myip() which asks Shodan's servers what IP they see
        our request coming from (i.e. our public WAN IP. Free, no
        query credits consumed).

        If target_scope contains public (non-RFC1918) CIDRs, those are
        used directly instead and public IP detection is skipped.

        Returns the public IP string, or None if resolution failed.
        """
        import ipaddress

        #checks if ctx.target_scope contains public (non-RFC1918) CIDR, if not, calls api.myip() to get WAN IP


        # Check if target_scope already contains public (routable) IPs.
        # If the operator passed --scope 72.x.x.x/28, use that directly.
        for scope in ctx.target_scope:
            try:
                network = ipaddress.ip_network(scope, strict=False)
                if not network.is_private:
                    print(f"[OSINTAgent] Public scope found in target_scope: {scope} — skipping auto-detect") #NORMAL
                    ctx.log(self.name, f"Using operator-provided public scope: {scope}")
                    # Return the network address as a representative IP for logging
                    ctx.public_ip = str(network.network_address)
                    return str(network.network_address)
            except ValueError:
                continue

        # Auto-detect via Shodan's myip endpoint, no credits consumed
        # api.myip() exists in the Shodan CLI but not the Python library.
        # ipify is the standard lightweight alternative: returns your public WAN IP as plain text.

        try:
            import httpx
            response = httpx.get("https://api.ipify.org", timeout=5)
            public_ip = response.text.strip()
            ctx.public_ip = public_ip
            print(f"[OSINTAgent] Public IP detected: {public_ip}") #NORMAL
            ctx.log(self.name, "Public IP resolved via ipify.org", result=public_ip)
            return public_ip
        except Exception as e:
            ctx.log(self.name, "Public IP resolution failed", result=str(e))
            return None

    # ----------------------------------------------------------------
    # Phase 2 & 3 — Shodan host lookup + camera detection
    # ----------------------------------------------------------------

    def _query_shodan_host(self, api, ctx: EngagementContext, public_ip: str):
        """
        Query Shodan for everything known about the public IP.

        Uses api.host() for single IP lookup (1 query credit).
        Parses all open ports and banners. Camera/NVR findings are
        added to ctx.confirmed_hosts. Everything goes to ctx.exposed_services.

        If target_scope contained a CIDR rather than a single IP,
        falls back to api.search() with net: filter (1 credit/page).
        """
        import ipaddress

        # Determine if we have a single IP or a CIDR to query
        try:
            ipaddress.ip_address(public_ip)
            is_single_ip = True
        except ValueError:
            is_single_ip = False

        if is_single_ip:
            self._lookup_single_ip(api, ctx, public_ip)
        else:
            # CIDR range — use net: search filter
            self._search_cidr(api, ctx, public_ip)

    def _lookup_single_ip(self, api, ctx: EngagementContext, ip: str):
        """
        Look up a single IP in Shodan. Costs 1 query credit.

        Shodan's host() returns all ports, banners, CVEs, hostnames,
        and org info Shodan has indexed for that IP.
        """
        try:
            host = api.host(ip)
            if VERBOSE: print(f"[OSINTAgent] Shodan found {len(host.get('data', []))} services on {ip}") #VERBOSE

            org    = host.get("org", "unknown")
            isp    = host.get("isp", "unknown")
            city   = host.get("city", "unknown")
            country= host.get("country_name", "unknown")

            print(f"[OSINTAgent] {ip} — org: {org}, isp: {isp}, location: {city}, {country}") #NORMAL
            ctx.log(self.name, f"Shodan host lookup: {ip}",
                    result=f"org={org}, {len(host.get('data', []))} services found")

            # Process each service Shodan has indexed on this IP
            for service in host.get("data", []):
                port    = service.get("port")
                banner  = service.get("data", "")
                product = service.get("product", "")
                vulns   = service.get("vulns", {})

                # Log everything to exposed_services for the report
                exposed_entry = {
                    "ip":      ip,
                    "port":    port,
                    "banner":  banner[:200],   # truncate — banners can be large
                    "product": product,
                    "org":     org,
                    "city":    city,
                    "country": country,
                    "vulns":   list(vulns.keys()) if vulns else [],
                    "source":  "shodan"
                }
                ctx.add_exposed_service(exposed_entry)

                if VERBOSE: print(f"[OSINTAgent] {ip}:{port} — {product or banner[:60].strip()}") #VERBOSE

                # Check if this service looks like a camera/NVR
                if self._is_camera_service(port, banner, product):
                    self._add_osint_host(ctx, ip, port, banner, product, host)
                    print(f"[OSINTAgent] ⚠  Camera/NVR detected on public IP {ip}:{port} — {product or 'unknown vendor'}") #NORMAL

                # Write any Shodan-identified CVEs to ctx
                for cve_id, cve_data in vulns.items():
                    self._write_cve(ctx, ip, cve_id, cve_data, vendor=self._vendor_from_banner(banner))

        except Exception as e:
            # Most common cause: IP not in Shodan's index (not externally visible)
            if "No information available" in str(e):
                print(f"[OSINTAgent] {ip} — not indexed by Shodan (no external exposure found)") #NORMAL
                ctx.log(self.name, f"Shodan: {ip} not indexed", result="no external exposure")
            else:
                print(f"[OSINTAgent] Shodan host lookup failed for {ip}: {e}") #NORMAL
                ctx.log(self.name, f"Shodan lookup failed: {ip}", result=str(e))

    def _search_cidr(self, api, ctx: EngagementContext, cidr: str):
        """
        Search Shodan for all devices within a CIDR range.
        Uses net: filter. Costs 1 credit per page (100 results).

        Used when target_scope contains a public CIDR rather than
        a single IP (ie a company's registered IP block).
        """
        try:
            query = f"net:{cidr}"
            if VERBOSE: print(f"[OSINTAgent] Shodan search: {query}") #VERBOSE

            results = api.search(query)
            total   = results.get("total", 0)
            matches = results.get("matches", [])

            print(f"[OSINTAgent] Shodan net:{cidr} — {total} total results, {len(matches)} returned") #NORMAL
            ctx.log(self.name, f"Shodan CIDR search: {cidr}", result=f"{total} results")

            for match in matches:
                ip      = match.get("ip_str", "")
                port    = match.get("port")
                banner  = match.get("data", "")
                product = match.get("product", "")
                org     = match.get("org", "unknown")
                vulns   = match.get("vulns", {})

                exposed_entry = {
                    "ip":      ip,
                    "port":    port,
                    "banner":  banner[:200],
                    "product": product,
                    "org":     org,
                    "vulns":   list(vulns.keys()) if vulns else [],
                    "source":  "shodan"
                }
                ctx.add_exposed_service(exposed_entry)

                if self._is_camera_service(port, banner, product):
                    self._add_osint_host(ctx, ip, port, banner, product, match)
                    print(f"[OSINTAgent] ⚠  Camera/NVR detected: {ip}:{port} — {product or 'unknown vendor'}") #NORMAL

                for cve_id, cve_data in vulns.items():
                    self._write_cve(ctx, ip, cve_id, cve_data, vendor=self._vendor_from_banner(banner))

        except Exception as e:
            print(f"[OSINTAgent] Shodan CIDR search failed for {cidr}: {e}") #NORMAL
            ctx.log(self.name, f"Shodan CIDR search failed: {cidr}", result=str(e))

    # ----------------------------------------------------------------
    # Phase 4 — CVE enrichment for DiscoveryAgent hosts
    # ----------------------------------------------------------------

    def _enrich_cves(self, api, ctx: EngagementContext):
        """
        Query Shodan for CVEs associated with each confirmed host.

        For each host DiscoveryAgent found internally, look it up in
        Shodan by IP. If Shodan has indexed it (unlikely for RFC1918
        but possible after a port-forward), pull CVE data. If not,
        we still get vendor/product info from the banner that can
        inform CVE lookups in a future NVD API phase.

        Note: Most internal 192.168.x.x hosts won't be in Shodan's index.
        This phase is more useful when confirmed_hosts contains public IPs
        added in Phase 3, or when running against a public scope.
        """
        print(f"[OSINTAgent] CVE enrichment — checking {len(ctx.confirmed_hosts)} confirmed hosts") #NORMAL

        enriched = 0
        for host_dict in ctx.confirmed_hosts:
            ip     = host_dict.get("ip", "")
            vendor = host_dict.get("vendor", "unknown")


            # Skip RFC1918 private IPs.. Shodan's API rejects them as invalid.
            # Private IPs are never in Shodan's index since they're not
            # reachable from the internet. This is expected, not an error.
            import ipaddress
            try:
                if ipaddress.ip_address(ip).is_private:
                    if VERBOSE: print(f"[OSINTAgent] {ip} — private IP, skipping Shodan lookup") #VERBOSE
                    continue
            except ValueError:
                continue



            try:
                shodan_host = api.host(ip)
                for service in shodan_host.get("data", []):
                    vulns = service.get("vulns", {})
                    for cve_id, cve_data in vulns.items():
                        self._write_cve(ctx, ip, cve_id, cve_data, vendor=vendor)
                        enriched += 1

                if VERBOSE: print(f"[OSINTAgent] {ip} — Shodan enrichment: {len(shodan_host.get('data', []))} services") #VERBOSE

            except Exception as e:
                if "No information available" in str(e):
                    # Expected for RFC1918 IPs — not an error
                    if VERBOSE: print(f"[OSINTAgent] {ip} — not in Shodan index (private IP, expected)") #VERBOSE
                else:
                    if VERBOSE: print(f"[OSINTAgent] {ip} — Shodan enrichment failed: {e}") #VERBOSE
                continue

        print(f"[OSINTAgent] CVE enrichment complete — {enriched} CVE records added") #NORMAL
        ctx.log(self.name, "CVE enrichment complete", result=f"{enriched} CVEs added from Shodan")

    # ----------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------

    def _is_camera_service(self, port: int, banner: str, product: str) -> bool:
        """
        Determine if a Shodan service result looks like a camera or NVR.

        Checks port number against known camera ports and banner/product
        strings against known camera vendor signatures.
        Both checks are used — port alone is too noisy (port 80 is everything),
        banner alone misses devices with generic HTTP banners.
        """
        banner_lower  = (banner  or "").lower()
        product_lower = (product or "").lower()
        combined      = banner_lower + " " + product_lower

        port_match   = port in CAMERA_PORTS
        banner_match = any(sig in combined for sig in CAMERA_BANNER_SIGNATURES)

        # Port 554 (RTSP) with any camera signature = very high confidence
        if port == 554 and banner_match:
            return True

        # Camera vendor in banner + any camera port = high confidence
        if banner_match and port_match:
            return True

        # Port 37777/37778 = Dahua-specific, always worth flagging
        if port in (37777, 37778):
            return True

        return False

    def _add_osint_host(self, ctx: EngagementContext, ip: str, port: int,
                        banner: str, product: str, shodan_data: dict):
        """
        Add a Shodan-discovered camera/NVR to ctx.confirmed_hosts.

        Deduplication is handled by ctx.add_host() — if DiscoveryAgent
        already found this IP internally, it won't be added again.
        source="osint" marks it as externally exposed for the report.
        """
        vendor = self._vendor_from_banner(banner + " " + product)

        host = HostRecord(
            ip=ip,
            hostname=shodan_data.get("hostnames", [None])[0] if shodan_data.get("hostnames") else None,
            open_ports=[port],
            device_type="camera" if port in (554, 8554) else "unknown",
            vendor=vendor,
            banner=banner[:500],   # cap banner length before storing
            source="osint",        # marks this as externally found
        )
        ctx.add_host(host)
        ctx.log(self.name, f"OSINT host added: {ip}:{port}",
                target=ip, result=f"vendor={vendor}, source=osint")

    def _vendor_from_banner(self, banner: str) -> str:
        """
        Extract a vendor name from a Shodan banner string.

        Simple keyword match — not a full fingerprinting pass.
        Returns 'unknown' if no vendor signature found.
        Matches against the same vendor keys used in vendors.py so
        CameraAccessAgent can look up the right credential set.
        """
        banner_lower = banner.lower()
        vendor_map = {
            "hikvision": "hikvision",
            "dahua":     "dahua",
            "reolink":   "reolink",
            "axis":      "axis",
            "amcrest":   "amcrest",
            "hanwha":    "hanwha",
            "wisenet":   "hanwha",
            "foscam":    "foscam",
            "uniview":   "uniview",
            "vivotek":   "vivotek",
            "bosch":     "bosch",
        }
        for keyword, vendor in vendor_map.items():
            if keyword in banner_lower:
                return vendor
        return "unknown"

    def _write_cve(self, ctx: EngagementContext, ip: str, cve_id: str,
                   cve_data: dict, vendor: str):
        """
        Write a Shodan-sourced CVE finding to ctx.

        Shodan's vuln data format:
            {
                "CVE-XXXX-XXXX": {
                    "cvss": 9.8,
                    "summary": "...",
                    "references": [...]
                }
            }
        We normalize this into our CVERecord format.
        """
        cvss     = cve_data.get("cvss", 0.0)
        summary  = cve_data.get("summary", "No description available")

        # Map CVSS score to severity bucket
        if cvss >= 9.0:
            severity = "critical"
        elif cvss >= 7.0:
            severity = "high"
        elif cvss >= 4.0:
            severity = "medium"
        else:
            severity = "low"

        cve = CVERecord(
            ip=ip,
            cve_id=cve_id,
            vendor=vendor,
            description=summary[:300],   # cap length
            severity=severity,
            exploited=False,             # Shodan finding only — not confirmed exploited
            source="osint_agent",
        )
        ctx.add_cve_finding(cve)
        if VERBOSE: print(f"[OSINTAgent] CVE {cve_id} ({severity}) on {ip} — {summary[:80]}") #VERBOSE