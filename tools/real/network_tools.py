

import os
import json
import socket
import requests
import subprocess #run external CLI programs 
from requests.auth import HTTPDigestAuth, HTTPBasicAuth
import nmap
import ssl #for SSL Wrapping for 443
from config import DEFAULT_TIMEOUT, HTTP_TIMEOUT, SCAN_PORTS, NMAP_TIMEOUT
from core.vendors import (
    identify_vendor,
    identify_device_type,
    get_rtsp_paths_for_vendor,
    get_http_paths_for_vendor,
)

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
        print(f"[scan_network] Auto-detected subnet: {network_range}")


    nm = nmap.PortScanner()
    port_str = ",".join(str(p) for p in SCAN_PORTS)
    results = []


    # --- Step 2: Root path, ARP + SYN Scan ---
    # ARP > ICMP — devices can't block ARP Reqs, and gives us MAC addresses.. feed into the OUI-based vendor fingerprinting.
    
    if os.geteuid() == 0:
        print("[scan_network] Running as root — using ARP discovery + SYN scan")
        try:
            nm.scan(
                hosts=network_range,
                arguments=f"-PR -sS -p {port_str} --host-timeout {NMAP_TIMEOUT}s"
            )
        except Exception as e:
            print(f"[scan_network] Root scan failed: {e}")
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
        print("[scan_network] Non-root — skipping discovery, using -Pn TCP scan")
        try:
            nm.scan(
                hosts=network_range,
                arguments=f"-Pn -sT -p {port_str} --host-timeout {NMAP_TIMEOUT}s"
            )
        except Exception as e:
            print(f"[scan_network] Non-root scan failed: {e}")
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

            print(f"[scan_network] {ip} — ports: {open_ports}, vendor: {vendor}")

        except Exception as e:
            print(f"[scan_network] Failed to parse result for {ip}: {e}")
            continue

    print(f"[scan_network] Done — {len(results)} live hosts found")
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
    ports_to_probe = open_ports if open_ports is not None else [80, 554, 8080]

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
    # Using a set to track seen paths, list to preserve order
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

def test_credentials(ip: str, username: str, password: str, vendor: str = "generic_nvr") -> dict:
    pass

def capture_frame(): #openVC capture frame
    pass







# // ------ TESTING ------ \\
#run from root, [sudo] python -m tools.real.network_tools (-m= rul file as module from current dir)
if __name__ == "__main__":
    # Step 1: scan the network
    hosts = scan_network("")
    
    # Step 2: feed each host into grab_banner
    for host in hosts:
        banner_result = grab_banner(host["ip"], host["open_ports"])
        print(banner_result)

        # Combine all banner strings for vendor fingerprinting
        combined_banner = " ".join(banner_result["banners"].values())
        vendor = identify_vendor(combined_banner, host["open_ports"], host["hostname"] or "")
        print(f"[vendor] {host['ip']} → {vendor}")

        # Step 3: Check RTSP 
        rtsp_ports = [p for p in host["open_ports"] if p in [554, 8554, 37778]]
        if rtsp_ports:
            for rtsp_port in rtsp_ports:
                rtsp_result = check_rtsp(host["ip"], rtsp_port, vendor)
                print(rtsp_result)
        else:
            print(f"[check_rtsp] {host['ip']} — no RTSP ports open, skipping")

    # Direct RTSP test against local mediamtx instance
    rtsp_result = check_rtsp("127.0.0.1", 8554, "generic_nvr")
    print(rtsp_result)