"""
config.py
---------
Central configuration for the network-recon pipeline.



USAGE:
    from config import RESULTS_DIR, SCAN_PORTS, DEFAULT_TIMEOUT

ENVIRONMENT:
    Sensitive values (API keys, model selections) are read from .env via
    python-dotenv. Non-sensitive structural values (paths, timeouts) are
    defined directly here as constants.

    .env overrides are supported for model names so the operator can swap
    models without touching code.
"""

import os
from dotenv import load_dotenv

# Load .env file — must happen before any os.getenv() calls below.
# override=False means existing environment variables take precedence
# over .env values, which is correct behavior for CI/CD environments.
load_dotenv(override=False)


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# Base directory is always the project root, regardless of where the script
# is invoked from. Using __file__ here means this works whether you run
# `python main.py` from the project root or from a subdirectory.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

DATA_DIR    = os.path.join(BASE_DIR, "data")
RESULTS_DIR = os.path.join(BASE_DIR, "results")
DOCS_DIR    = os.path.join(BASE_DIR, "docs")

# Mock network definition — read by tools/mock/network_tools.py
MOCK_NETWORK_FILE = os.path.join(DATA_DIR, "mock_network.json")


# ---------------------------------------------------------------------------
# Pipeline mode
# ---------------------------------------------------------------------------

# "mock" uses tools/mock/network_tools.py (reads mock_network.json, no real I/O)
# "real" uses tools/real/network_tools.py (live nmap, socket, HTTP calls)
# Set via MODE= in .env or by passing --mock flag to main.py
MODE = os.getenv("MODE", "real").lower()




# ---------------------------------------------------------------------------
# Verbose mode
# ---------------------------------------------------------------------------


# Verbose mode prints detailed output from network_tools (banners, raw responses, etc.)
# Set to True for more information, False for clean pipeline output
VERBOSE = os.getenv("VERBOSE", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Debug mode
# ---------------------------------------------------------------------------


# Debug mode prints excessively detailed output
# Set to True for debugging, False for clean pipeline output
DEBUG = os.getenv("DEBUG", "false").lower() == "true"

# ---------------------------------------------------------------------------
# Report writing mode
# ---------------------------------------------------------------------------
NO_REPORT = os.getenv("NO_REPORT", "false").lower() == "true"

# ---------------------------------------------------------------------------
# LLM models
# ---------------------------------------------------------------------------

# Local Ollama model — used by DiscoveryAgent (fast, free, runs offline)
# qwen2.5:7b is a good default: strong reasoning, fits in 8GB VRAM
AGENT_MODEL = os.getenv("AGENT_MODEL", "qwen2.5:7b")

# Anthropic model — used by AccessAgent (better HTTP response reasoning)
ACCESS_MODEL = os.getenv("ACCESS_MODEL", "claude-haiku-4-5-20251001")

# Anthropic model — used by LateralMovementAgent and ReportingAgent
# Sonnet is used here because lateral movement and report generation require
# heavier reasoning than discovery or credential testing
REPORTING_MODEL = os.getenv("REPORTING_MODEL", "claude-sonnet-4-5")


# ---------------------------------------------------------------------------
# Network scanning
# ---------------------------------------------------------------------------

# Ports scanned against every live host during discovery.
# Covers: HTTP (80, 8080, 8000), HTTPS (443), RTSP (554, 8554),
# Dahua secondary (37777, 37778), generic NVR (9000)
SCAN_PORTS = [80, 443, 554, 8000, 8080, 8554, 9000, 37777, 37778]

# Timeout in seconds for all raw socket operations (banner grab, RTSP check).
# 3 seconds is enough for a LAN host — anything slower is likely filtered.
DEFAULT_TIMEOUT = 3

# Timeout in seconds for HTTP requests (credential testing).
# Slightly longer than socket timeout — HTTP auth can be slow on cheap hardware.
HTTP_TIMEOUT = 5

# Timeout in seconds for nmap operations per host.
# nmap has its own internal timing but we set a ceiling here.
NMAP_TIMEOUT = 30


# ---------------------------------------------------------------------------
# Results and artifacts
# ---------------------------------------------------------------------------

# Frame captures (JPEGs) and config dumps go here, under the engagement ID.
# Created at runtime by AccessAgent if it doesn't exist.
ARTIFACTS_DIR = os.path.join(RESULTS_DIR, "artifacts")

# Report output directory — ReportingAgent writes here.
REPORTS_DIR = os.path.join(RESULTS_DIR, "reports")


# ---------------------------------------------------------------------------
# API keys (never hardcode — always from .env)
# ---------------------------------------------------------------------------

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
SHODAN_API_KEY    = os.getenv("SHODAN_API_KEY", "")

# Results encryption key — used by ReportingAgent to encrypt credentials
# in output files. Generate with: from cryptography.fernet import Fernet;
# print(Fernet.generate_key().decode())
RESULTS_ENCRYPTION_KEY = os.getenv("RESULTS_ENCRYPTION_KEY", "")