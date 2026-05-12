



import json
from config import MOCK_NETWORK_FILE

#private helper#
def _load_network():
    with open(MOCK_NETWORK_FILE) as f:
        return json.load(f)

def scan_network(network_range):
    devices = _load_network()
    results = []
    for device in devices:
        results.append({
            "ip": device["ip"],
            "mac": device["mac"],
            "hostname": device["hostname"],
            "open_ports": device["open_ports"],
            "device_type": device["device_type"]
        })
    return results

def grab_banner(ip):
    devices = _load_network()
    for device in devices:
        if device["ip"] == ip:
            return {"ip": ip, "banner": device["banner"]}
    return {"ip": ip, "banner": "No banner retrieved"}

def check_rtsp(ip, port):
    devices = _load_network()
    for device in devices:
        if device["ip"] == ip and port in device["open_ports"]:
            return {"ip": ip, "port": port, "status": "open", "stream": f"rtsp://{ip}:{port}/stream1"}
    return {"ip": ip, "port": port, "status": "closed", "stream": None}

def test_credentials(ip, username, password):
    default_creds = [("admin", "admin"), ("admin", "12345"), ("root", "root")]
    if (username, password) in default_creds:
        return {"ip": ip, "username": username, "status": "success", "access": "full"}
    return {"ip": ip, "username": username, "status": "failed", "access": None}