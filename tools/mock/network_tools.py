"""
tools/mock/network_tools.py
----------------------------
Mock implementations of all network tool functions.

Reads from data/mock_network.json instead of touching the real network.
All function signatures match tools/real/network_tools.py exactly —
agents never know which implementation they're running.

WHY THESE SIGNATURES MUST MATCH:
    tools/__init__.py swaps real vs mock at import time based on MODE.
    If a mock function takes different args than the real one, agents
    will break the moment you switch to real mode.
"""

import json
import os
from config import MOCK_NETWORK_FILE, ARTIFACTS_DIR
from core.vendors import get_rtsp_paths_for_vendor, get_http_paths_for_vendor


def _load_network() -> list:
    """Load the mock network device list from JSON."""
    with open(MOCK_NETWORK_FILE) as f:
        return json.load(f)


def scan_network(network_range: str) -> list:
    devices = _load_network()
    results = []
    for device in devices:
        results.append({
            "ip":          device["ip"],
            "mac":         device["mac"],
            "hostname":    device["hostname"],
            "open_ports":  device["open_ports"],
            "device_type": device["device_type"],
            "vendor":      device["vendor"],       # real scan_network returns this too
        })
    return results


def grab_banner(ip: str, open_ports: list = None) -> dict:
    devices = _load_network()
    ports = open_ports if open_ports is not None else [80, 554, 8080]

    for device in devices:
        if device["ip"] == ip:
            # Put the banner on the first port, empty string on the rest.
            # Real grab_banner returns whatever each port actually responded with —
            # mock doesn't have per-port banners, so this is the closest approximation.
            banners = {port: "" for port in ports}
            if ports:
                banners[ports[0]] = device["banner"]
            return {"ip": ip, "banners": banners}

    # IP not found in mock network — return empty banners
    return {"ip": ip, "banners": {port: "" for port in ports}}


def check_rtsp(ip: str, port: int = 554, vendor: str = "generic_nvr") -> dict:
    devices = _load_network()
    for device in devices:
        if device["ip"] == ip and port in device["open_ports"]:
            # Use the first vendor-specific path for a realistic URL
            paths = get_rtsp_paths_for_vendor(vendor)
            path = paths[0] if paths else "/stream1"
            return {
                "ip":         ip,
                "port":       port,
                "status":     "open",
                "stream_url": f"rtsp://{ip}:{port}{path}"
            }

    return {"ip": ip, "port": port, "status": "closed", "stream_url": None}


def test_credentials(ip: str, username: str, password: str,
                     vendor: str = "generic_nvr") -> dict:
    default_creds = {
        ("admin", "admin"),
        ("admin", "12345"),
        ("admin", ""),
        ("root",  "root"),
    }

    paths = get_http_paths_for_vendor(vendor)
    endpoint = paths[0] if paths else "/"

    if (username, password) in default_creds:
        return {
            "ip":           ip,
            "username":     username,
            "password":     password,
            "status":       "success",
            "access_level": "admin",
            "endpoint":     endpoint,
            "auth_type":    "digest",   # most common on real cameras
            "token":        None,       # only populated for reolink in real mode
        }

    return {
        "ip":           ip,
        "username":     username,
        "password":     password,
        "status":       "failed",
        "access_level": None,
        "endpoint":     endpoint,
        "auth_type":    None,
        "token":        None,
    }


def capture_frame(ip: str, stream_url: str, username: str, password: str,
                  vendor: str = "generic_nvr", token: str = None,
                  engagement_id: str = "default") -> dict:

    from datetime import datetime

    artifact_dir = os.path.join(ARTIFACTS_DIR, engagement_id)
    os.makedirs(artifact_dir, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{ip.replace('.', '_')}_{timestamp}_mock.jpg"
    output_path = os.path.join(artifact_dir, filename)

    # Write an empty file — just a path placeholder, not a real image
    with open(output_path, "w") as f:
        f.write("")

    print(f"[capture_frame][mock] {ip} — placeholder artifact saved to {output_path}")

    return {
        "ip":           ip,
        "status":       "captured",
        "method":       "mock",
        "artifact_path": output_path,
    }