# network-recon — Build To-Do List

---

## Completed Work

### Session 1 — Prior Session (stage-3)
* [x] Built mock mode pipeline end-to-end (agents, tools, reporting)
* [x] Implemented `tools/mock/network_tools.py` — reads `mock_network.json`
* [x] Built `data/mock_network.json` — 6-device simulated network
* [x] Working `agents/discovery_agent.py` (pre-refactor, stage-3 only)
* [x] Working `agents/access_agent.py` (pre-refactor, stage-3 only)
* [x] Verified mock pipeline runs end-to-end in stage-3

### Session 2 — Architecture & Refactor
#### Environment
* [x] Created new project root at `/Volumes/UTM_DRIVE/network-recon/`
* [x] Created venv on external drive at `/Volumes/UTM_DRIVE/network-recon/venv/`
* [x] Verified all pip installs pointing to external drive (not local Mac)
* [x] Copied `tools/mock/network_tools.py` from stage-3
* [x] Copied `data/mock_network.json` from stage-3
* [x] Copied `.env` from stage-3 (API keys preserved)
* [x] Created GitHub private repo: `https://github.com/EvanGoldConn/network-recon`
* [x] Configured SSH key for GitHub authentication
* [x] Initial commit and push to GitHub

#### Framework (Layer 1 — core/)
* [x] Built `core/engagement.py` — `EngagementContext` dataclass
  * `HostRecord`, `CredentialRecord`, `ArtifactRecord`, `AuditEntry` data classes
  * Scope enforcement: `is_in_scope()` and `enforce_scope()` (hard Python exception, not LLM judgment)
  * Append-only mutation methods: `add_host()`, `add_credential()`, `add_artifact()`, `log()`
  * JSON serialization: `save()` and `load()` for engagement pause/resume
  * `summary()` method for pipeline output
* [x] Built `core/base_agent.py` — `BaseAgent` ABC + `AgentRegistry`
  * Abstract `run(ctx)` and default `can_run(ctx)` methods
  * `mitre_tactic` and `mitre_tactic_name` fields on every agent
  * `@AgentRegistry.register` decorator pattern for auto-discovery
  * `PIPELINE_ORDER` list defines canonical execution order
* [x] Built `core/pipeline.py` — `PipelineRunner`
  * Deterministic sequential execution
  * Graceful failure handling — logs error, continues to next agent
  * Verbose output with skip reasons from `can_run()`
* [x] Built `core/vendors.py` — vendor fingerprinting + credential database
  * Vendors: Hikvision, Dahua, Axis, Reolink, Amcrest, Hanwha, generic_nvr
  * Per-vendor: fingerprint strings, default credentials, HTTP auth paths, RTSP paths, known CVEs
  * Helper functions: `identify_vendor()`, `identify_device_type()`, `get_credentials_for_vendor()`, etc.
  * Credential sources: SecLists (danielmiessler/SecLists on GitHub)

#### Agents (Layer 2 — agents/)
* [x] Consolidated all agents into single `agents/` folder (removed `modules/` subfolder)
  * Rationale: `modules/` vs `agents/` distinction was arbitrary — all agents
    inherit from `BaseAgent` and behave identically. One folder is cleaner and
    more scalable.
* [x] Added MITRE ATT&CK tactic mapping to every agent
  * `mitre_tactic` and `mitre_tactic_name` fields on `BaseAgent`
  * Does not affect pipeline execution — purely for reporting layer
  * Aligns with industry standard used in all professional pen-test reports
* [x] Built `agents/wifi_agent.py` stub — Stage 0, TA0001 Initial Access
* [x] Built `agents/osint_agent.py` stub — Stage 1, TA0043 Reconnaissance
* [x] Built `agents/discovery_agent.py` stub — Stage 2, TA0007 Discovery
* [x] Built `agents/access_agent.py` stub — Stage 3, TA0006 Credential Access
* [x] Built `agents/lateral_agent.py` stub — Stage 4, TA0008 Lateral Movement
* [x] Built `agents/reporting_agent.py` stub — Stage 5, Reporting
* [x] Verified all 6 agents import cleanly and register correctly
* [x] Verified MITRE mapping prints correctly for all agents

#### Tools (Layer 3 — tools/)
* [x] Built `tools/__init__.py` — MODE switch (reads `.env`, imports real or mock)

#### CLI
* [x] Built `main.py` — CLI entry point
  * `--stages`, `--scope`, `--mock`, `--resume`, `--engagement-id` flags
  * Verified `python main.py --mock` runs correctly end-to-end
  * Pipeline skips/fails gracefully with correct messages per agent

#### Documentation
* [x] Built `README.md` — full architecture overview, directory structure, build status table
* [x] Built `HANDOFF.md` — complete session context for next session
* [x] Built `.env.template` — committed template without secrets
* [x] Built `.gitignore` — excludes `.env`, `venv/`, `results/`, `__pycache__/`

#### Design Decisions Made
* [x] `EngagementContext` as shared state (notebook pattern) — all agents read/write one object
* [x] Scope enforcement in Python tool layer, not LLM prompt — LLMs can be prompt-injected, Python code cannot
* [x] Append-only context — discovered hosts/credentials never removed, full history preserved
* [x] `AgentRegistry` decorator pattern — new agents self-register, pipeline runner never needs to change
* [x] Flat `agents/` folder — all agents equal, no arbitrary core vs module distinction
* [x] MITRE ATT&CK tactic fields on every agent — professional reporting standard
* [x] Lazy LLM initialization — each agent initializes its own LLM inside `run()`, not at startup
* [x] Mock vs real separation in `tools/` — one line in `.env` switches between them
* [x] `tools/__init__.py` as the swap point — agents never know which implementation they got
* [x] Banner content wrapped in XML tags before LLM ingestion (prompt injection defense) — planned
* [x] Separate `entry_method` field in ctx — report distinguishes wifi_crack vs given_access vs shodan_exposed
* [x] `exposed_services` stored as plain dicts (not dataclass) — Shodan returns varied structure

---

## Remaining Work

### Phase 1 — Tools Layer
Get the tools layer complete and consistent before touching agents.

* [ ] 1. Update `tools/mock/network_tools.py` — match new signatures
  * `grab_banner` returns `banners: {port: string}` dict instead of single string
  * Add `vendor` param to `check_rtsp` and `test_credentials` (mock can ignore it)
* [ ] 2. Build `tools/real/network_tools.py` — all 4 functions
  * `scan_network(network_range: str) -> list`
  * `grab_banner(ip: str) -> dict` — multi-port, returns all banners
  * `check_rtsp(ip: str, port: int = 554, vendor: str = "generic_nvr") -> dict`
  * `test_credentials(ip: str, username: str, password: str, vendor: str = "generic_nvr") -> dict`

---

### Phase 2 — Core Agents
Makes the pipeline runnable end-to-end.

* [ ] 3. Implement `agents/discovery_agent.py` `run()`
  * LangChain + Ollama (`qwen2.5:7b`)
  * Calls `scan_network` + `grab_banner`
  * Auto-detects subnet if `ctx.target_scope` is empty
  * Sanitizes banners before LLM ingestion (XML tag wrapping)
  * Writes `HostRecord` entries to `ctx`
* [ ] 4. Implement `agents/access_agent.py` `run()`
  * LangChain + Claude Haiku (`claude-haiku-4-5-20251001`)
  * Calls `check_rtsp` + `test_credentials`
  * Tries `ctx.credentials_found` first before vendor defaults (credential reuse)
  * Frame capture via opencv — saves JPEG to `results/` as proof of access
  * Writes `CredentialRecord` and `ArtifactRecord` entries to `ctx`
* [ ] 5. End-to-end mock test — `python main.py --mock`
* [ ] 6. End-to-end real test — `python main.py` against home network

---

### Phase 3 — Hardening
Security and reliability before expanding capability.

* [ ] 7. Input sanitization — wrap banner content in XML tags before passing to LLM
  * `<banner_data source="192.168.1.10">Hikvision-Webs</banner_data>`
  * Signals to LLM that content is data, not instructions
  * Defense against prompt injection via malicious camera banners
* [ ] 8. Scope enforcement test — write a test that verifies `enforce_scope()` raises
  `ScopeViolationError` for out-of-scope IPs and never makes a network connection
* [ ] 9. Results encryption — implement Fernet symmetric encryption on `results/` output
  * `cryptography` library already installed
  * Key derived from operator passphrase at report generation time
  * Credentials in plaintext output files are a secondary liability

---

### Phase 4 — Remaining Agents
Expand pipeline to full recon + reporting capability.

* [ ] 10. Implement `agents/osint_agent.py` `run()`
  * Shodan API integration (`shodan` library already installed)
  * Query for internet-exposed cameras/NVRs by IP range or org name
  * CVE lookup for identified device models
  * Feeds `ctx.exposed_services`
  * Requires `SHODAN_API_KEY` in `.env`
* [ ] 11. Implement `agents/reporting_agent.py` `run()`
  * LangChain + Claude Sonnet
  * Reads full `ctx` — hosts, credentials, artifacts, audit log
  * Auto-maps findings to MITRE ATT&CK using agent `mitre_tactic` fields
  * Output formats: Markdown (default), HTML, PDF, JSON
  * Sections: executive summary, attack chain narrative, technical findings,
    device inventory, credentials (encrypted), artifacts, audit trail
  * Writes to `results/<engagement_id>/`
* [ ] 12. Implement `agents/lateral_agent.py` `run()`
  * LangChain + Claude Sonnet
  * Credential reuse — tests every found credential against every other host
  * NVR exploitation — download config, enumerate all cameras
  * Router/gateway admin panel testing
  * SSH service testing on applicable hosts
  * Writes additional `CredentialRecord` and `ArtifactRecord` entries to `ctx`

---

### Phase 5 — WiFi Initial Access
Requires Alfa AWUS036ACM hardware + Kali Linux UTM VM.

* [ ] 13. Set up Kali Linux UTM VM with USB passthrough for Alfa adapter
  * UTM settings: add USB device passthrough for Alfa adapter
  * Verify in Kali: `iwconfig` shows adapter
  * Enable monitor mode: `sudo airmon-ng start wlan0`
  * Install tools: `apt install hcxdumptool hcxtools hashcat aircrack-ng`
* [ ] 14. Implement `agents/wifi_agent.py` `run()`
  * Phase 1: scan for nearby networks, present targets to operator
  * Phase 2: PMKID capture via hcxdumptool (preferred, no client needed)
  * Phase 2 fallback: 4-way handshake capture via airodump-ng + deauth
  * Phase 3: offline crack via hashcat (`-m 22000` for WPA2)
  * Phase 4: connect to network, detect subnet, populate `ctx`
  * Mandatory authorization acknowledgment prompt before any packet transmitted
  * Populates: `ctx.wifi_ssid`, `ctx.wifi_passphrase`, `ctx.entry_method`,
    `ctx.target_scope`

---

### Phase 6 — Full Chain Test

* [ ] 15. End-to-end test: WiFi crack → discovery → access → lateral → report
  * Run from Kali VM for Stage 0, switch to macOS for Stages 1-5
  * Verify full `EngagementContext` populated correctly through all stages
  * Verify report generates with complete ATT&CK mapping and artifacts

---

## Hardware

* [x] Alfa AWUS036ACM ordered (eBay — myneedlestore_intl, $47.99)
* [ ] Alfa AWUS036ACM arrived and confirmed working
  * Test: plug into Mac USB, then UTM VM USB passthrough
  * Verify: `system_profiler SPUSBDataType | grep -A 5 "AWUS\|MT7612\|MediaTek"`
  * Verify in Kali: `iwconfig` shows adapter in monitor mode
* [ ] Kali Linux UTM VM created and configured
* [ ] USB passthrough configured for Alfa adapter in UTM settings

---

## Future Extensions (Post Phase 6)

* [ ] Shodan Membership ($69/year) — needed for full results and CVE data
* [ ] RTSP stream path fuzzing — per-vendor path lists already in `vendors.py`,
  need automated fuzzer for unknown vendors
* [ ] CVE-specific exploit modules — Hikvision CVE-2021-36260 (RCE),
  Dahua CVE-2021-33044 (auth bypass) worth targeting specifically
* [ ] Async pipeline execution — Stage 0 and Stage 1 can run concurrently
  since they're independent. `asyncio` optimization for larger engagements.
* [ ] Broader attack chain integration — `EngagementContext` designed to be
  composable with other tools. SMB credential spray, AD enumeration, etc.
  can plug in as new agents via `@AgentRegistry.register`.
* [ ] Test runner with automated verdict tracking — run multiple iterations,
  track which devices were accessed, write structured JSON summary