# Agentic Network Recon & IoT/PoE Camera Exploitation Framework - NetRec

Autonomous LLM-powered security camera recon and exploitation pipeline. Built for authorized pen-testing on networks you own or have permission to test.

---

## ⚠️ Legal Notice

This tool is for networks you own or have **explicit written authorization** to test. Unauthorized use is illegal under the CFAA, UK Computer Misuse Act, and equivalent laws elsewhere.

---

## What it does

Runs a sequential agent pipeline against a target network. Each stage feeds into the shared `EngagementContext` object.

```
WiFiAgent → OSINTAgent → DiscoveryAgent → CameraAccessAgent → LateralMovementAgent → ReportingAgent
  (Kali)     (Shodan)      (nmap+banners)   (creds+RTSP)         (reuse+pivot)          (PDF report)
```

End result: a PDF pen-test report with discovered cameras, cracked credentials, captured frames, CVE mappings, and a full audit trail.

---

## Project structure

```
network-recon/
├── core/
│   ├── engagement.py          # EngagementContext — shared state object
│   ├── base_agent.py          # BaseAgent ABC + AgentRegistry
│   ├── pipeline.py            # PipelineRunner
│   ├── vendors.py             # Vendor fingerprints, credentials, CVEs, MAC OUI lookup
│   └── llm_defense.py         # Prompt injection defense utilities
│
├── agents/
│   ├── wifi_agent.py          # Stage 0: PMKID/EAPOL capture, PSK crack, network join
│   ├── osint_agent.py         # Stage 1: Shodan recon, public IP detection, CVE enrichment
│   ├── discovery_agent.py     # Stage 2: nmap scan, banner grab, vendor fingerprinting
│   ├── camera_access_agent.py # Stage 3: credential testing, RTSP, frame capture
│   ├── lateral_agent.py       # Stage 4: credential reuse, NVR pivot (stub)
│   └── reporting_agent.py     # Stage 5: PDF + Markdown report generation
│
├── tools/
│   ├── __init__.py            # Swaps real vs mock based on MODE in .env
│   ├── langchain_tools.py     # @tool wrappers for LangChain agents
│   ├── real/network_tools.py  # Live nmap, socket, HTTP, OpenCV operations
│   └── mock/network_tools.py  # Mock implementations (reads mock_network.json)
│
├── data/
│   ├── mock_network.json      # 6-device simulated network for testing
│   └── camera_creds.json      # Curated default credential list (SecLists + CVEs)
│
├── results/                   # Engagement output — gitignored
│   ├── artifacts/             # Captured frames (JPEG)
│   └── reports/               # Generated reports (MD + PDF)
│
├── config.py
├── main.py
└── .env
```

---

## Setup

```bash
# Python deps
pip install langchain langchain-ollama langchain-anthropic python-nmap \
            requests opencv-python python-dotenv pydantic \
            weasyprint markdown paramiko scp

# System deps (macOS)
brew install nmap pango hashcat

# Ollama (local LLM for discovery)
ollama pull qwen2.5:7b
```

`.env`:
```
MODE=mock
AGENT_MODEL=qwen2.5:7b
ACCESS_MODEL=claude-haiku-4-5
REPORTING_MODEL=claude-sonnet-4-5
ANTHROPIC_API_KEY=your_key
SHODAN_API_KEY=                         # optional, needed for OSINTAgent
HASHCAT_WORDLIST=/path/to/rockyou.txt   # needed for WiFiAgent
PI_SSH_KEY=~/.ssh/your_pi_key           # needed for WiFiAgent
VERBOSE=false
DEBUG=false
NO_REPORT=false
```

---

## Running it

```bash
# Mock mode (safe, no real network)
python main.py --mock
python main.py --mock --verbose
python main.py --mock --debug

# Real mode (needs sudo for ARP scan)
sudo python main.py
sudo python main.py --verbose

# Flags
--scope 192.168.1.0/24     # explicit scope
--stages discovery osint   # run specific stages in the order given
--engagement-id my-test    # custom engagement ID
--no-report                # skip report generation
--resume results/engagement-xyz.json

# External engagement targeting (OSINTAgent Phase 2, not yet implemented)
--org "Acme Corp"          # target org name for Shodan org: filter + ARIN lookup
--domain acmecorp.com      # target domain for cert transparency recon
--address "Newark NJ"      # physical location to geo-filter Shodan results

# Stealth / evasion (real mode only — no effect in mock)
--quiet                    # enable all stealth options at once
--slow-scan                # nmap T1 timing (15s inter-probe delay) — very slow
--fragment                 # fragment TCP probes into 8-byte chunks (-f), requires root
--decoys                   # send probes from 5 spoofed decoy IPs (-D RND:5), requires root
--spoof-source-port        # spoof nmap source port to 53 (DNS)
--randomize-hosts          # randomize host scan order
--spoof-mac                # spoof MAC address before scan, restore after, requires root
```

---

## WiFiAgent

Requires a Raspberry Pi with a monitor-mode capable adapter (Alfa AWUS036ACM confirmed working).
The Pi handles all wireless operations over SSH. The Mac handles cracking via Metal GPU.

```
Pi:  hcxdumptool scan → hcxdumptool capture → hcxpcapngtool convert
Mac: scp pull → hashcat crack → networksetup join → DiscoveryAgent handoff
```

Prerequisites:
- Pi reachable at `192.168.1.254` (WiFi) or `192.168.1.95` (ethernet)
- Key-based SSH auth configured (set `PI_SSH_KEY` in `.env`)
- `HASHCAT_WORDLIST` set in `.env`
- `paramiko` and `scp` installed in venv

Known limitations:
- PMKID capture requires AP to include PMKID in association frames — not all routers do
- Falls back to EAPOL handshake capture if no PMKID seen
- 5GHz scan uses `-F` flag (all available frequencies on adapter)
- iOS hotspot MAC randomization may prevent BPF filter from matching — workaround pending
- PSK crack only succeeds if passphrase is in the wordlist

---

## Key design decisions

**Scope enforcement in Python, not the LLM** — every network connection calls `ctx.enforce_scope(ip)` before firing. LLM output cannot expand scope.

**Prompt injection defense** — banner content is XML-wrapped before LLM ingestion (`<banner_data source="ip">...</banner_data>`) and checked against injection heuristics. A TODO marks where a secondary model guard would slot in.

**Three-tier credential strategy** — credential reuse from ctx first, vendor-specific defaults second, curated SecLists camera list third. Deduped per host.

**Mock/real swap** — `MODE=mock` in `.env` routes all network calls to mock implementations. Full pipeline runs against `mock_network.json` with no real traffic.

---

## Status

| Component | Status |
|-----------|--------|
| EngagementContext + framework | ✅ |
| OSINTAgent (Shodan, CVE enrichment, public IP) | ✅ |
| DiscoveryAgent (scan, banner, fingerprint, LLM fallback) | ✅ |
| CameraAccessAgent (creds, RTSP, frame capture) | ✅ |
| ReportingAgent (CVE mapping, LLM writing, PDF) | ✅ |
| Stealth/evasion flags (--quiet + granular) | ✅ |
| WiFiAgent (PMKID/EAPOL capture, crack, join) | ✅ |
| LateralMovementAgent | 🔧 stub |

---

## Known issues / TODO

- WiFiAgent: iOS hotspot BPF filter fails due to MAC randomization — need SSID-based filter fallback
- WiFiAgent: incomplete EAPOL handshakes can produce false positive crack results — deauth improvement needed
- LateralMovementAgent: not yet implemented
- OSINTAgent Phase 2 (ARIN, BGP/ASN, geo-filter): stubbed in ctx, not yet implemented

---

## Adding a vendor

Add an entry to `VENDOR_PROFILES` in `core/vendors.py` with `fingerprint`, `credentials`, `http_auth_paths`, `rtsp_paths`, `known_cves`. Nothing else needs to change.