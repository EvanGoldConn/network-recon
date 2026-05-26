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
    - typical_ports: typical open ports (used for device_type detection)
    - credentials: list of (username, password) tuples to try
    - http_auth_paths: list of URL paths to POST credentials to
    - rtsp_paths: list of RTSP stream URL patterns to try
    - rtsp_enabled_by_default: bool — whether RTSP is on out of the box
    - snapshot_path: HTTP endpoint for single JPEG capture (fallback if RTSP disabled)
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
        # RTSP is enabled by default on Hikvision — port 554 active out of box.
        # Some models also use 10554 as an alternate default.
        "rtsp_enabled_by_default": True,
        # ISAPI snapshot endpoint — returns a single JPEG, requires Digest auth.
        # Useful as fallback if RTSP stream drops or OpenCV fails.
        "snapshot_path": "/ISAPI/Streaming/channels/1/picture",
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
        # RTSP enabled by default on port 554.
        "rtsp_enabled_by_default": True,
        # CGI snapshot endpoint — returns JPEG, requires Digest or Basic auth.
        "snapshot_path": "/cgi-bin/snapshot.cgi?channel=1",
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
        # RTSP enabled by default on port 554.
        "rtsp_enabled_by_default": True,
        # Axis VAPIX snapshot endpoint — well documented, very reliable.
        "snapshot_path": "/axis-cgi/jpg/image.cgi",
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
        # RTSP is DISABLED by default on Reolink — must be manually enabled via
        # web UI under Network > Advanced > Port Settings before port 554 opens.
        # capture_frame() uses snapshot_path as primary capture method for Reolink.
        "rtsp_enabled_by_default": False,
        # Reolink JSON API snapshot endpoint.
        # The {token} placeholder is replaced at runtime with the session token
        # returned by _try_reolink_json_auth() after successful login.
        "snapshot_path": "/cgi-bin/api.cgi?cmd=Snap&channel=0&rs={token}",
        "known_cves": [],
        "notes": "Reolink uses a JSON API. Login endpoint returns a token for subsequent requests. "
                 "Admin with empty password is the most common default. "
                 "RTSP disabled by default — enable via Network > Advanced > Port Settings.",
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
            ("admin", "YWRtaW4="),  # base64 "admin" — used in some firmwares, this is correct.
             # literal base64 string sent as password in some Amcrest JSON auth payloads
        ],
        "http_auth_paths": [
            "/cgi-bin/magicBox.cgi?action=getSystemInfo",
            "/RPC2_Login",
        ],
        "rtsp_paths": [
            "/cam/realmonitor?channel=1&subtype=0",
            "/h264/ch1/main/av_stream",
        ],
        # RTSP enabled by default — same behavior as Dahua (OEM).
        "rtsp_enabled_by_default": True,
        # Same snapshot path as Dahua — shared firmware base.
        "snapshot_path": "/cgi-bin/snapshot.cgi?channel=1",
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
        # RTSP enabled by default on port 554.
        "rtsp_enabled_by_default": True,
        # Hanwha CGI snapshot endpoint — returns JPEG.
        "snapshot_path": "/cgi-bin/cgiin.cgi?msubmenu=jpg&action=view",
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
            "/stream2",
            "/channel1",
            "/cam1/h264",
            "/live/ch0",
            "/live/ch1",
            "/h264/ch1/main/av_stream",
            "/h264/ch2/main/av_stream",
            "/cam/realmonitor?channel=1&subtype=0",  # Dahua OEM
            "/cam/realmonitor?channel=1&subtype=1",  # Dahua OEM sub-stream
            "/h264Preview_01_main",                  # Reolink/HiSilicon OEM
            "/h264Preview_01_sub",                   # Reolink/HiSilicon sub-stream
            "/video1",                               # Common budget cam
            "/video2",
            "/stream",                               # Extremely common generic
            "/live",
            "/live/stream",
            "/mediainput/h264",                      # Some Foscam/budget OEM
            "/11",                                   # Some XM/Longse chipset OEM
            "/12",                                   # XM sub-stream
        ],
        # Assume RTSP enabled by default for unknown devices — if port 554 is open
        # we attempt it. capture_frame() falls back to snapshot if RTSP fails.
        "rtsp_enabled_by_default": True,
        # Generic CGI snapshot — works on many budget NVRs and OEM Dahua devices.
        "snapshot_path": "/cgi-bin/snapshot.cgi",
        "known_cves": [],
        "notes": "Generic NVR detection. Try vendor-specific profiles first. "
                 "Many budget NVRs are unbranded Hikvision or Dahua OEM. Lots of overlap with paths",
    },
}

# ---------------------------------------------------------------------------
# Fingerprinting logic
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# MAC OUI lookup (most reliable vendor signal — hardware-assigned)
# ---------------------------------------------------------------------------
 
# OUI (Organizationally Unique Identifier) = first 3 bytes of a MAC address.
# Assigned by IEEE to manufacturers. Cannot be spoofed at Layer 2 on a LAN
# without special tools, making this the most reliable vendor signal available.
#
# Format: "AA:BB:CC" (uppercase, colon-separated) → vendor_key
#
# Sources: IEEE MA-L registry (standards-oui.ieee.org/oui/oui.txt)
# Only camera/NVR manufacturers included — this tool's target scope.
# Router/computer OUIs intentionally omitted.
#
# TODO: For broader IoT coverage, pull full OUI list from:
#   https://standards-oui.ieee.org/oui/oui.txt
#   and filter against VENDOR_PROFILES keys at load time.
 
CAMERA_OUI_MAP = { 
    # --- Hikvision (Hangzhou Hikvision Digital Technology Co., Ltd.) ---
    # One of the largest IP camera manufacturers globally, multiple OUI blocks
    "C0:56:E3": "hikvision",
    "44:19:B6": "hikvision",
    "BC:AD:28": "hikvision",
    "A4:14:37": "hikvision",
    "54:C4:15": "hikvision",
    "D0:C5:D3": "hikvision",
    "28:57:BE": "hikvision",
    "4C:BD:8F": "hikvision",
    "68:CF:FE": "hikvision",
 
    # --- Dahua Technology (Zhejiang Dahua Technology Co., Ltd.) ---
    "90:02:A9": "dahua",
    "E0:50:8B": "dahua",
    "BC:32:B2": "dahua",
    "40:62:31": "dahua",
    "1C:98:EC": "dahua",
    "70:81:05": "dahua",
 
    # --- Axis Communications ---
    # Swedish manufacturer, acquired by Canon
    "00:40:8C": "axis",
    "AC:CC:8E": "axis",
    "B8:A4:4F": "axis",
    "00:D0:1E": "axis",
 
    # --- Hanwha Vision (formerly Samsung Techwin / Wisenet) ---
    "00:09:18": "hanwha",
    "00:16:6C": "hanwha",
    "14:1A:3A": "hanwha",
    "F8:A6:D9": "hanwha",
 
    # --- Reolink (Shenzhen Reolink Technology Co., Ltd.) ---
    "B4:FB:E4": "reolink",
    "EC:71:DB": "reolink",
    "78:65:68": "reolink",
 
    # --- Amcrest (OEM Dahua, but may have own OUI blocks) ---
    "B8:26:D4": "amcrest",
 
    # --- Uniview (Zhejiang Uniview Technologies) ---
    "00:24:75": "uniview",
    "6C:E2:B4": "uniview",
 
    # --- Vivotek ---
    "00:02:D1": "vivotek",
    "AC:A2:13": "vivotek",
 
    # --- Bosch Security Systems ---
    "00:03:93": "bosch",
    "00:10:EF": "bosch",
 
    # --- Foscam ---
    "C4:D9:87": "foscam",
    "E0:62:90": "foscam",
}
 
 
def identify_vendor_from_mac(mac: str) -> str:
    """
    Identify vendor from MAC address OUI (first 3 bytes).
 
    This is the most reliable vendor signal available — OUI assignments
    are hardware-level and cannot be manipulated by firmware or banners.
    Called BEFORE banner-based identify_vendor() in the discovery pipeline.
 
    Args:
        mac: MAC address string in any common format:
             "AA:BB:CC:DD:EE:FF", "AA-BB-CC-DD-EE-FF", or "AABBCCDDEEFF"
             Case-insensitive.
 
    Returns:
        Vendor key from VENDOR_PROFILES if OUI is recognized, "unknown" otherwise.
    """
    if not mac:
        return "unknown"
 
    # Normalize to uppercase colon-separated format
    mac_clean = mac.upper().replace("-", ":").replace(".", ":")
 
    # Handle formats without separators (AABBCCDDEEFF → AA:BB:CC:DD:EE:FF)
    if ":" not in mac_clean and len(mac_clean) == 12:
        mac_clean = ":".join(mac_clean[i:i+2] for i in range(0, 12, 2))
 
    # Extract OUI — first 3 octets
    parts = mac_clean.split(":")
    if len(parts) < 3:
        return "unknown"
 
    oui = ":".join(parts[:3])
    return CAMERA_OUI_MAP.get(oui, "unknown")

# --------------------------------------------------------------------------------



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


def get_snapshot_path_for_vendor(vendor_key: str) -> str:
    """
    Return the HTTP snapshot endpoint for a vendor.
    Falls back to generic_nvr snapshot path if vendor unknown.
 
    The Reolink path contains a {token} placeholder — replace at runtime
    with the session token from _try_reolink_json_auth().
    """
    if vendor_key in VENDOR_PROFILES:
        return VENDOR_PROFILES[vendor_key]["snapshot_path"]
    return VENDOR_PROFILES["generic_nvr"]["snapshot_path"]
 
 
def is_rtsp_enabled_by_default(vendor_key: str) -> bool:
    """
    Return whether RTSP is enabled out of the box for this vendor.
 
    Used by capture_frame() to decide whether to attempt RTSP first
    or go straight to HTTP snapshot (e.g. Reolink).
    """
    if vendor_key in VENDOR_PROFILES:
        return VENDOR_PROFILES[vendor_key]["rtsp_enabled_by_default"]
    return True  # assume enabled for unknown vendors