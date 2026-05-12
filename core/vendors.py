"""
core/vendors.py
----------------
Vendor fingerprinting logic and default credential database.

WHY THIS IS CENTRALIZED:
    Vendor-specific knowledge (default credentials, API paths, port signatures,
    CVE identifiers) is used by multiple agents — AccessAgent tests credentials,
    LateralMovementAgent does credential reuse, ReportingAgent cites CVEs.

    Centralizing it here means:
    - Adding a new vendor = one dict entry, not edits across 3 agents
    - Credential lists are the same everywhere (no drift)
    - Easy to update when new CVEs or default creds are published

CREDENTIAL SOURCES:
    Primary: SecLists (https://github.com/danielmiessler/SecLists)
        - Passwords/Default-Credentials/default-credentials-for-services.csv
        - Passwords/Default-Credentials/camera-default-passwords.txt
    Secondary: vendor security advisories and CVE descriptions
    Tertiary: community pen-testing resources (pentestmonkey, exploit-db)

    These are well-maintained, publicly available lists used by the
    security research community. Not scraping or guessing — documented defaults.

ADDING A NEW VENDOR:
    Add an entry to VENDOR_PROFILES with:
    - fingerprint: list of strings to look for in banners/headers
    - ports: typical open ports (used for device_type detection)
    - credentials: list of (username, password) tuples to try
    - http_auth_paths: list of URL paths to POST credentials to
    - rtsp_paths: list of RTSP stream URL patterns to try
    - known_cves: list of relevant CVE IDs (for reporting)
"""

# ---------------------------------------------------------------------------
# Vendor profiles
# ---------------------------------------------------------------------------

VENDOR_PROFILES = {

    "hikvision": {
        "display_name": "Hikvision",
        "fingerprint": [
            "hikvision", "dvr webserver", "app-webs", "dvrdvs-webs",
            "hikcentral", "ds-2", "ds-7",
        ],
        "typical_ports": [80, 443, 554, 8000, 8080],
        "credentials": [
            ("admin", "12345"),
            ("admin", "admin"),
            ("admin", ""),
            ("admin", "Admin12345"),
        ],
        "http_auth_paths": [
            "/ISAPI/Security/userCheck",
            "/ISAPI/System/status",
            "/PSIA/Custom/SelfExt/userCheck",
        ],
        "rtsp_paths": [
            "/h264/ch1/main/av_stream",
            "/h264/ch01/main/av_stream",
            "/Streaming/Channels/1",
            "/Streaming/Channels/101",
            "/stream1",
        ],
        "known_cves": [
            "CVE-2021-36260",  # Remote code execution via /SDK/webLanguage
            "CVE-2017-7921",   # Authentication bypass
            "CVE-2022-28173",  # Stack overflow
        ],
        "notes": "CVE-2021-36260 is a critical RCE present in firmware before 2021-10. "
                 "Check /SDK/webLanguage endpoint before credential testing.",
    },

    "dahua": {
        "display_name": "Dahua",
        "fingerprint": [
            "dahua", "dvr webserver", "rpc2_login", "lechange",
            "ipc-", "sd-", "nvr",
        ],
        "typical_ports": [80, 443, 554, 37777, 37778],
        "credentials": [
            ("admin", "admin"),
            ("admin", ""),
            ("admin", "123456"),
            ("888888", "888888"),
            ("666666", "666666"),
        ],
        "http_auth_paths": [
            "/RPC2_Login",
            "/RPC2",
            "/cgi-bin/magicBox.cgi?action=getSystemInfo",
        ],
        "rtsp_paths": [
            "/cam/realmonitor?channel=1&subtype=0",
            "/h264/ch1/main/av_stream",
            "/live",
        ],
        "known_cves": [
            "CVE-2021-33044",  # Authentication bypass
            "CVE-2021-33045",  # Authentication bypass variant
            "CVE-2022-30563",  # Plaintext credential exposure
        ],
        "notes": "CVE-2021-33044/33045 bypass authentication entirely on affected firmware. "
                 "Test /RPC2_Login with crafted packet before password testing.",
    },

    "axis": {
        "display_name": "Axis",
        "fingerprint": [
            "axis", "axis communications", "axis camera", "axis video",
        ],
        "typical_ports": [80, 443, 554],
        "credentials": [
            ("root", "pass"),
            ("root", "root"),
            ("admin", "admin"),
            ("viewer", "viewer"),
        ],
        "http_auth_paths": [
            "/axis-cgi/usergroup.cgi",
            "/axis-cgi/admin/param.cgi",
            "/axis-cgi/param.cgi?action=list",
        ],
        "rtsp_paths": [
            "/axis-media/media.amp",
            "/mpeg4/media.amp",
            "/mjpg/video.mjpg",
        ],
        "known_cves": [
            "CVE-2018-10660",  # Shell command injection
            "CVE-2020-29560",  # Buffer overflow
        ],
        "notes": "Older Axis cameras (pre-2016) ship with root:pass default. "
                 "Modern units prompt for password change on first boot.",
    },

    "reolink": {
        "display_name": "Reolink",
        "fingerprint": [
            "reolink", "rln", "rlc-",
        ],
        "typical_ports": [80, 443, 554, 1935, 9000],
        "credentials": [
            ("admin", ""),
            ("admin", "admin"),
            ("admin", "123456"),
        ],
        "http_auth_paths": [
            "/api.cgi?cmd=Login",
            "/cgi-bin/api.cgi?cmd=Login",
        ],
        "rtsp_paths": [
            "/h264Preview_01_main",
            "/h264Preview_01_sub",
            "/bcs/channel0_main.bcs",
        ],
        "known_cves": [],
        "notes": "Reolink uses a JSON API. Login endpoint returns a token for subsequent requests. "
                 "Admin with empty password is the most common default.",
    },

    "amcrest": {
        "display_name": "Amcrest",
        "fingerprint": [
            "amcrest", "dahua-webs",  # Amcrest is OEM Dahua
        ],
        "typical_ports": [80, 443, 554, 37777],
        "credentials": [
            ("admin", "admin"),
            ("admin", ""),
            ("admin", "YWRtaW4="),  # base64 "admin" — used in some firmwares
        ],
        "http_auth_paths": [
            "/cgi-bin/magicBox.cgi?action=getSystemInfo",
            "/RPC2_Login",
        ],
        "rtsp_paths": [
            "/cam/realmonitor?channel=1&subtype=0",
            "/h264/ch1/main/av_stream",
        ],
        "known_cves": [
            "CVE-2021-33044",  # Shared with Dahua (same firmware base)
            "CVE-2021-33045",
        ],
        "notes": "Amcrest hardware is OEM Dahua. Same CVEs and auth bypass paths apply.",
    },

    "hanwha": {
        "display_name": "Hanwha (Samsung Techwin)",
        "fingerprint": [
            "hanwha", "samsung techwin", "wisenet", "snv-", "qnv-",
        ],
        "typical_ports": [80, 443, 554, 4520],
        "credentials": [
            ("admin", "4321"),
            ("admin", "admin"),
            ("admin", ""),
        ],
        "http_auth_paths": [
            "/stw-cgi/system.cgi?msubmenu=deviceinfo&action=view",
            "/cgi-bin/cgiin.cgi",
        ],
        "rtsp_paths": [
            "/profile1/media.smp",
            "/profile2/media.smp",
            "/video1",
        ],
        "known_cves": [
            "CVE-2018-1149",   # Auth bypass in Hanwha cameras
            "CVE-2018-1150",
        ],
        "notes": "CVE-2018-1149 allows unauthenticated root shell via specific CGI endpoint.",
    },

    "generic_nvr": {
        "display_name": "Generic NVR/DVR",
        "fingerprint": [
            "nvr", "dvr", "network video recorder", "digital video recorder",
            "cross web server",
        ],
        "typical_ports": [80, 443, 554, 9000, 37777],
        "credentials": [
            ("admin", "admin"),
            ("admin", ""),
            ("admin", "12345"),
            ("admin", "123456"),
            ("root", "root"),
            ("root", ""),
            ("guest", "guest"),
            ("operator", "operator"),
            ("user", "user"),
            ("888888", "888888"),
            ("666666", "666666"),
        ],
        "http_auth_paths": [
            "/",
            "/login",
            "/admin",
            "/cgi-bin/login.cgi",
        ],
        "rtsp_paths": [
            "/stream1",
            "/channel1",
            "/cam1/h264",
            "/live/ch0",
            "/h264/ch1/main/av_stream",
        ],
        "known_cves": [],
        "notes": "Generic NVR detection. Try vendor-specific profiles first. "
                 "Many budget NVRs are unbranded Hikvision or Dahua OEM.",
    },
}

# ---------------------------------------------------------------------------
# Fingerprinting logic
# ---------------------------------------------------------------------------

def identify_vendor(banner: str, open_ports: list, hostname: str = "") -> str:
    """
    Identify the most likely vendor from available evidence.

    Args:
        banner: Raw banner text (already sanitized)
        open_ports: List of open port numbers
        hostname: Hostname or mDNS name if available

    Returns:
        Vendor key from VENDOR_PROFILES, or "unknown"

    APPROACH:
        Score each vendor by how many fingerprint strings appear in
        the available evidence. Return the highest scorer.
        Ties go to the vendor with more specific fingerprints (longer strings).
    """
    evidence = (banner + " " + hostname).lower()
    scores = {}

    for vendor_key, profile in VENDOR_PROFILES.items():
        if vendor_key == "generic_nvr":
            continue  # Generic is the fallback, not a scored candidate
        score = 0
        for fp in profile["fingerprint"]:
            if fp.lower() in evidence:
                # Longer fingerprint strings are more specific = higher score
                score += len(fp)
        if score > 0:
            scores[vendor_key] = score

    if not scores:
        # Port-based heuristic as last resort
        port_set = set(open_ports)
        if 554 in port_set and 9000 in port_set:
            return "generic_nvr"
        if 554 in port_set and 37777 in port_set:
            return "dahua"
        return "unknown"

    return max(scores, key=scores.get)


def identify_device_type(open_ports: list, vendor: str) -> str:
    """
    Determine device type (camera vs NVR vs other) from port signature.

    Returns one of:
        "camera", "nvr", "router", "unknown"
    """
    port_set = set(open_ports)

    # NVR signatures: typically has more ports, often 9000 or 37777
    if 9000 in port_set or 37777 in port_set:
        return "nvr"

    # Camera signature: 554 (RTSP) + 80 (HTTP)
    if 554 in port_set and 80 in port_set:
        return "camera"

    # Router/gateway: port 53 (DNS) or common router ports
    if 53 in port_set or (80 in port_set and 554 not in port_set and 443 in port_set):
        return "router"

    return "unknown"


def get_credentials_for_vendor(vendor_key: str) -> list:
    """
    Return the credential list for a vendor.
    Falls back to generic_nvr list if vendor unknown.

    Returns list of (username, password) tuples.
    """
    if vendor_key in VENDOR_PROFILES:
        return VENDOR_PROFILES[vendor_key]["credentials"]
    return VENDOR_PROFILES["generic_nvr"]["credentials"]


def get_rtsp_paths_for_vendor(vendor_key: str) -> list:
    """Return RTSP stream path patterns for a vendor."""
    if vendor_key in VENDOR_PROFILES:
        return VENDOR_PROFILES[vendor_key]["rtsp_paths"]
    return VENDOR_PROFILES["generic_nvr"]["rtsp_paths"]


def get_http_paths_for_vendor(vendor_key: str) -> list:
    """Return HTTP auth endpoint paths for a vendor."""
    if vendor_key in VENDOR_PROFILES:
        return VENDOR_PROFILES[vendor_key]["http_auth_paths"]
    return VENDOR_PROFILES["generic_nvr"]["http_auth_paths"]
