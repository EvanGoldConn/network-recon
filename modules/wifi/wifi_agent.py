"""
modules/wifi/wifi_agent.py
---------------------------
Stage 0: WiFi initial access via physically proximate cracking.

PURPOSE:
    Handles the case where the operator has no network access yet.
    Physical proximity to the target (within WiFi range) is the only
    prerequisite. This module gains the initial foothold that allows
    Stage 2 (Discovery) to run.

PREREQUISITES:
    - Linux environment (will not run on macOS natively)
    - Monitor-mode capable wireless adapter (see HARDWARE below)
    - Root/sudo privileges (raw packet capture requires it)
    - Tools installed: hcxdumptool, hcxtools, hashcat

HARDWARE:
    Monitor mode requires a chipset that supports it. Built-in MacBook
    WiFi does not. Recommended hardware:

    Alfa AWUS036ACM
        - Chipset: MediaTek MT7612U
        - USB 3.0, dual-band (2.4GHz + 5GHz)
        - Works with UTM/Linux VM via USB passthrough
        - Driver: mt76 (included in mainline Linux kernel)
        - Buy: ~$40 on Amazon

    Alfa AWUS036ACH (alternative)
        - Chipset: Realtek RTL8812AU
        - Requires out-of-tree driver (more setup)
        - Also solid, slightly cheaper

    SETUP FOR UTM (M1 Mac):
        1. Create UTM VM (Kali Linux recommended)
        2. In UTM settings: add USB device passthrough for the Alfa adapter
        3. In Kali: verify with `iwconfig` — adapter should appear
        4. Enable monitor mode: `sudo airmon-ng start wlan0`

WHAT THIS MODULE DOES:

    Phase 1 — Target identification:
        - Scan for nearby WiFi networks
        - Present list to operator for target selection
        - Identify security type (WPA2, WPA3, open)
        - Note: WPA3 is significantly harder; will flag and skip by default

    Phase 2 — Capture:
        Two methods, tried in order:

        PMKID Attack (preferred, no client needed):
            - hcxdumptool sends association requests to the AP
            - AP responds with PMKID in EAPOL frame
            - No connected client required — just proximity to the AP
            - Much faster than waiting for a handshake
            Command: hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1

        4-way Handshake (fallback):
            - Wait for or force a client to re-authenticate
            - Deauth attack forces reconnection: aireplay-ng --deauth
            - Capture the 4-way EAPOL handshake
            - Requires a client to be connected to the AP
            Command: airodump-ng -c [channel] --bssid [AP_MAC] -w capture wlan0mon

    Phase 3 — Offline cracking:
        - Convert capture to hashcat format via hcxtools
        - Run hashcat with wordlist (rockyou + rules, or targeted list)
        - GPU acceleration (if available) dramatically speeds this up
        - On CPU only: expect hours for complex passwords, seconds for defaults
        Commands:
            hcxpcapngtool -o hash.hc22000 capture.pcapng
            hashcat -m 22000 hash.hc22000 wordlist.txt -r rules/best64.rule

    Phase 4 — Network entry:
        - Connect to the network with the cracked passphrase
        - Verify connectivity, detect subnet
        - Populate ctx.wifi_ssid, ctx.wifi_passphrase, ctx.entry_method
        - Populate ctx.target_scope from detected subnet
        - Hand off to DiscoveryAgent

ETHICAL AND LEGAL NOTE:
    WPA cracking against a network you do not own or have explicit written
    permission to test is illegal in most jurisdictions. This module includes
    a mandatory scope acknowledgment prompt before execution. The operator
    must confirm they have authorization before any packet is transmitted.

LLM ROLE:
    Minimal. The WiFi module is mostly procedural — run tools, parse output,
    make decisions. LLM is used only for:
    - Parsing hcxdumptool/airodump output into structured data
    - Recommending wordlist/rule combinations based on target SSID heuristics
      (e.g., an SSID that looks like a router default suggests trying default
      router passwords first)

OUTPUT (written to ctx):
    - ctx.wifi_ssid: target network name
    - ctx.wifi_passphrase: cracked password (encrypted at rest in results/)
    - ctx.entry_method: "wifi_crack"
    - ctx.target_scope: auto-populated from detected subnet
    - ctx.audit_log: full chain of custody for the capture and crack
"""

from core.base_agent import BaseAgent, AgentRegistry
from core.engagement import EngagementContext
import platform
import os


@AgentRegistry.register
class WiFiAgent(BaseAgent):
    name = "WiFiAgent"
    stage = "wifi"
    description = "WiFi initial access via PMKID capture or handshake grab and offline crack."
    requires_root = True
    requires_network = False  # We're creating the network access, not using it
    requires_llm = False      # Mostly procedural

    def run(self, ctx: EngagementContext) -> EngagementContext:
        raise NotImplementedError("WiFiAgent.run() — implementation pending (requires Linux + monitor mode adapter)")

    def can_run(self, ctx: EngagementContext) -> tuple[bool, str]:
        if platform.system() != "Linux":
            return False, "WiFiAgent requires Linux. Run inside UTM/Kali VM with USB passthrough."
        if os.geteuid() != 0:
            return False, "WiFiAgent requires root. Run with sudo."
        # Check for required tools
        for tool in ["hcxdumptool", "hcxpcapngtool", "hashcat"]:
            if os.system(f"which {tool} > /dev/null 2>&1") != 0:
                return False, f"Required tool not found: {tool}. Install with: apt install {tool}"
        return True, ""
