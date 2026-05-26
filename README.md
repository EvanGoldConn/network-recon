# ~~LLM-Driven Network Recon & IoT Exploitation Framework~~
# CameraCrack3r
Autonomous LLM-powered security camera recon and exploitation pipeline. Built for authorized pen-testing on networks you own or have permission to test.

---

## ⚠️ Legal Notice

This tool is for networks you own or have **explicit written authorization** to test. Unauthorized use is illegal under the CFAA, UK Computer Misuse Act, and equivalent laws elsewhere. Don't be stupid with this.

---

## What it does

Runs a sequential agent pipeline against a target network. Each stage feeds into the next via a shared `EngagementContext` object.

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
│   ├── discovery_agent.py     # Stage 2: nmap scan, banner grab, vendor fingerprinting
│   ├── camera_access_agent.py # Stage 3: credential testing, RTSP, frame capture
│   ├── lateral_agent.py       # Stage 4: credential reuse, NVR pivot (stub)
│   ├── reporting_agent.py     # Stage 5: PDF + Markdown report generation
│   ├── wifi_agent.py          # Stage 0: WPA crack (Kali only, stub)
│   └── osint_agent.py         # Stage 1: Shodan recon (needs API key, stub)
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
            weasyprint markdown

# System deps (macOS)
brew install nmap pango

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
SHODAN_API_KEY=           # optional, needed for OSINTAgent
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
--stages discovery access  # run specific stages only
--engagement-id my-test    # custom engagement ID
--no-report                # skip report generation
--resume results/engagement-xyz.json
```

---

## Key design decisions

**Scope enforcement in Python, not the LLM** — every network connection calls `ctx.enforce_scope(ip)` before firing. LLM output can't expand scope. This matters because camera banners are attacker-controlled and could contain prompt injection attempts.

**Prompt injection defense** — banner content is XML-wrapped before LLM ingestion (`<banner_data source="ip">...</banner_data>`) and checked against injection heuristics. A TODO comment marks where a secondary model guard would slot in.

**Three-tier credential strategy** — credential reuse from ctx first, vendor-specific defaults second, curated SecLists camera list third. Deduped per host.

**Mock/real swap** — `MODE=mock` in `.env` routes all network calls to mock implementations. Full pipeline runs against `mock_network.json` with no real traffic.

---

## Status

| Component | Status |
|-----------|--------|
| EngagementContext + framework | ✅ |
| DiscoveryAgent (scan, banner, fingerprint, LLM fallback) | ✅ |
| CameraAccessAgent (creds, RTSP, frame capture) | ✅ |
| ReportingAgent (CVE mapping, LLM writing, PDF) | ✅ |
| LateralMovementAgent | 🔧 stub |
| WiFiAgent | 🔧 stub (Kali only) |
| OSINTAgent | 🔧 stub (needs Shodan key) |

---

## Adding a vendor

Add an entry to `VENDOR_PROFILES` in `core/vendors.py` with `fingerprint`, `credentials`, `http_auth_paths`, `rtsp_paths`, `known_cves`. Nothing else needs to change.