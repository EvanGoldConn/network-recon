"""
tools/langchain_tools.py
-------------------------
LangChain @tool wrappers for all network tool functions.

WHY THIS FILE EXISTS:
    LangChain agents (ReAct and others) can only call functions that have
    been decorated with @tool. If functions were decorated in each agent.py file,
    it would duplicate wrappers if 2 agents use the same tool. INstead define once here. 
  

RETURN TYPES:
    LangChain tools must return strings. Our underlying network functions
    return dicts and lists. Every wrapper converts its return value with
    json.dumps() rather than str().. json.dumps produces clean output that an LLM can reason 
    over. str() on a dict produces Python repr syntax which is harder forthe LLM to parse reliably.

MOCK/REAL TRANSPARENCY:
    All wrappers import from tools (the __init__.py swap layer), not from
    tools.real or tools.mock directly. MODE switching in .env automatically implements here,
      agents and wrappers never need to know which implementation is active.

ADDING A NEW TOOL:
    1. Implement the function in tools/real/network_tools.py
    2. Add a matching mock in tools/mock/network_tools.py
    3. Add to both import blocks in tools/__init__.py
    4. Add a @tool wrapper here with a clear docstring
"""

import json
from langchain_core.tools import tool
from tools import scan_network, grab_banner, check_rtsp, test_credentials, capture_frame


@tool
def tool_scan_network(network_range: str) -> str:
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
        network_range: CIDR range to scan, e.g. "192.168.1.0/24".
                       Pass an empty string to auto-detect the local subnet.

    Returns:
        JSON string — list of host dicts, each containing:
        ip, mac, hostname, open_ports, device_type, vendor
    """
    results = scan_network(network_range)
    return json.dumps(results)


@tool
def tool_grab_banner(ip: str, open_ports: str) -> str:
    """
    Grab HTTP/RTSP banners from open ports on a host.

    Tries each open port, sends an appropriate request (HTTP HEAD for web ports,
    RTSP OPTIONS for port 554), and reads the response headers back.
    The Server: header is where vendor strings live (e.g. "Hikvision-Webs").

    Args:
        ip:         Target IP address.
        open_ports: Comma-separated list of open port numbers as a string,
                    e.g. "80,554,8080". Pass empty string to use defaults.
                    NOTE: LangChain tool args must be strings — this wrapper
                    parses the CSV into a list before calling the underlying function.

    Returns:
        JSON string — dict with ip and banners: {port: banner_string}
    """
    # LangChain passes all args as strings — parse CSV port list back to ints
    ports = [int(p.strip()) for p in open_ports.split(",") if p.strip()] if open_ports else None
    result = grab_banner(ip, ports)
    return json.dumps(result)


@tool
def tool_check_rtsp(ip: str, port: int = 554, vendor: str = "generic_nvr") -> str:
    """
    Check if an RTSP stream is accessible on a host and find a valid stream path.

    Tries vendor-specific RTSP paths first, then falls back to generic_nvr paths.
    Deduplicates paths across both lists to avoid redundant socket connections.

    Any valid RTSP response (even 401 Unauthorized) confirms the stream exists
    authentication is AccessAgent's job.

    Args:
        ip:     Target IP address.
        port:   RTSP port to check. Defaults to 554.
        vendor: Vendor key (e.g. "hikvision", "dahua") — determines which
                stream paths to try first.

    Returns:
        JSON string — dict with ip, port, status ("open"/"closed"),
        and stream_url (the working RTSP URL, or null if none found).
    """
    result = check_rtsp(ip, port, vendor)
    return json.dumps(result)


@tool
def tool_test_credentials(ip: str, username: str, password: str,
                           vendor: str = "generic_nvr") -> str:
    """
    Test a username/password pair against a host using vendor specific auth.    

    Strategy:
    1. For each vendor-specific HTTP path, send an unauthenticated probe GET.
    2. Read the WWW-Authenticate header to auto-detect HTTP auth type (Digest v Basic).
    3. For JSON API vendors (Reolink/Dahua), route directly to vendor-specific helper.
    4. Return immediately on first success, no point testing more paths.

    Routes to the correct auth method based on vendor:
    - Hikvision/Axis/Hanwha: HTTP Digest
    - Dahua/Amcrest: proprietary RPC2 JSON POST
    - Reolink: JSON array POST, returns session token on success
    - Unknown vendors: probes for WWW-Authenticate header, tries both
    
    Args:
        ip:       Target IP address.
        username: Username to test.
        password: Password to test.
        vendor:   Vendor key — determines auth routing and endpoint paths.

    Returns:
        JSON string — dict with ip, username, password, status ("success"/"failed"),
        access_level, endpoint, auth_type, and token (Reolink only).
    """
    result = test_credentials(ip, username, password, vendor)
    return json.dumps(result)


@tool
def tool_capture_frame(ip: str, stream_url: str, username: str, password: str,
                        vendor: str = "generic_nvr", token: str = "",
                        engagement_id: str = "default") -> str:
    """
    Capture a single frame from a camera as proof of access.

    Tries RTSP first (w/ OpenCV) if the vendor has RTSP enabled by default and a stream_url is available. 
    Falls back to HTTP snapshot if RTSP fails or is disabled (e.g. Reolink with RTSP off).

    Frames are saved as JPEGs to ARTIFACTS_DIR/engagement_id/
    Named by IP & timestamp so captures don't overwrite each other.

    Args:
        ip:            Target IP address.
        stream_url:    RTSP URL from tool_check_rtsp. Pass empty string if none.
        username:      Authenticated username from tool_test_credentials.
        password:      Authenticated password from tool_test_credentials.
        vendor:        Vendor key — determines capture strategy.
        token:         Reolink session token from successful auth. Pass empty
                       string for all other vendors.
        engagement_id: Used to organize artifacts into per-engagement folders.

    Returns:
        JSON string — dict with ip, status ("captured"/"failed"),
        method ("rtsp"/"snapshot"/"mock"), and artifact_path.
    """
    # Normalize empty string token to None — underlying function expects None
    token_val = token if token else None
    stream_val = stream_url if stream_url else None

    result = capture_frame(
        ip=ip,
        stream_url=stream_val,
        username=username,
        password=password,
        vendor=vendor,
        token=token_val,
        engagement_id=engagement_id
    )
    return json.dumps(result)