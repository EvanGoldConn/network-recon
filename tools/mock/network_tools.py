



import json
from config import MOCK_NETWORK_FILE
from core.vendors import get_rtsp_paths_for_vendor, get_http_paths_for_vendor

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
            return {
                "ip": ip, 
                "banners": {
                    80: device["banner"],
                    554: "",
                    8080: ""
                }
            }
    return {"ip": ip, "banners": {80:"", 554:"", 8080:""}}

def check_rtsp(ip, port=554, vendor="generic_nvr"):
    devices = _load_network()
    for device in devices:
        if device["ip"] == ip and port in device["open_ports"]:
            path = get_rtsp_paths_for_vendor(vendor)[0] #check against known paths in the core vendors dict
            return {"ip": ip, "port": port, "status": "open", "stream_url": f"rtsp://{ip}:{port}{path}"}
    return {"ip": ip, "port": port, "status": "closed", "stream_url": None}

def test_credentials(ip, username, password, vendor="generic_nvr"):
    default_creds = [("admin", "admin"), ("admin", "12345"), ("root", "root")]
    path = get_http_paths_for_vendor(vendor)[0]
    if (username, password) in default_creds: #Yay success!
        return {"ip": ip, "username": username, "password": password,
                "status": "success", "access_level": "admin", "endpoint": path}
    return {"ip": ip, "username": username, "password": password,
            "status": "failed", "access_level": None, "endpoint": path}