

import os
import json
import socket
import requests
import subprocess #run external CLI programs 
from requests.auth import HTTPDigestAuth, HTTPBasicAuth
import nmap
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





def grab_banner(ip: str) -> dict:
    pass

def check_rtsp(ip: str, port: int = 554, vendor: str = "generic_nvr") -> dict:
    pass

def test_credentials(ip: str, username: str, password: str, vendor: str = "generic_nvr") -> dict:
    pass








# // ------ TESTING ------ \\
#run from root, [sudo] python -m tools.real.network_tools (-m= rul file as module from current dir)
if __name__ == "__main__":
    results = scan_network("")
    for host in results:
        print(host)