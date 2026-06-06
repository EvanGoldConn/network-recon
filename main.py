"""
main.py
--------
CLI entry point for the recon pipeline.

USAGE:
    # Run full pipeline (auto-detect available stages)
    python main.py

    # Run specific stages only
    python main.py --stages discovery access

    # Start from existing engagement (resume)
    python main.py --resume results/engagement-abc123.json

    # Specify target scope explicitly
    python main.py --scope 192.168.1.0/24 --stages discovery access

    # Mock mode (safe testing without real network)
    python main.py --mock
"""


import os
import argparse
from dotenv import load_dotenv


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="PoE Camera Recon Tool — authorized pen-testing pipeline"
    )
    parser.add_argument(
        "--stages", nargs="+",
        help="Stages to run (wifi osint discovery access lateral reporting). Default: all available."
    )
    parser.add_argument(
        "--scope", nargs="+",
        help="Target network scope (e.g. 192.168.1.0/24). Auto-detected if not provided."
    )
    parser.add_argument(
        "--resume",
        help="Path to a saved EngagementContext JSON to resume."
    )
    parser.add_argument(
        "--mock", action="store_true",
        help="Force mock mode regardless of .env setting."
    )
    parser.add_argument(
        "--engagement-id",
        help="Custom engagement ID. Auto-generated if not provided."
    )
    parser.add_argument(
    "--verbose",
    action="store_true",
    default=False,
    help="Enable verbose output from network tools (banners, raw responses, etc.)"
    )
    parser.add_argument(
    "--debug",
    action="store_true",
    default=False,
    help="Enable debug output — raw banners, LLM prompts, internal state. Implies verbose."
    )
    parser.add_argument(
    "--no-report",
    action="store_true",
    default=False,
    help="Skip report generation."
)

    # --- Stealth / evasion flags ---
    # --quiet enables all sub-options at once (the preset).
    # Each sub-option can also be passed independently for surgical control.
    parser.add_argument(
        "--quiet",
        action="store_true",
        default=False,
        help=(
            "Enable all stealth/evasion options: slow scan timing, packet fragmentation, "
            "decoy IPs, DNS source port spoofing, randomized host order, MAC spoofing, "
            "and delayed banner grabs. Equivalent to passing all granular flags together."
        )
    )
    parser.add_argument(
        "--slow-scan",
        action="store_true",
        default=False,
        help="Drop nmap timing to T1 (sneaky) — 15s inter-probe delay. Slow but low-noise."
    )
    parser.add_argument(
        "--fragment",
        action="store_true",
        default=False,
        help="Fragment TCP probes into 8-byte chunks (-f). Defeats older IDS payload signatures. Requires root."
    )
    parser.add_argument(
        "--decoys",
        action="store_true",
        default=False,
        help="Send probes from 5 randomly spoofed decoy IPs alongside real IP (-D RND:5). Requires root."
    )
    parser.add_argument(
        "--spoof-source-port",
        action="store_true",
        default=False,
        help="Spoof nmap source port to 53 (DNS). Some firewalls whitelist DNS source ports."
    )
    parser.add_argument(
        "--randomize-hosts",
        action="store_true",
        default=False,
        help="Randomize host scan order. Sequential scanning is a common IDS trigger."
    )
    parser.add_argument(
        "--spoof-mac",
        action="store_true",
        default=False,
        help="Spoof MAC address of scanning interface before scan, restore after. Layer 2 only. Requires root."
    )

    # --- External engagement target (future: org-based recon) ---
    # These feed OSINTAgent Phase 2 — ARIN lookup, BGP/ASN resolution,
    # geolocation filtering. Currently stubbed in ctx, not yet implemented in OSINTAgent.
    parser.add_argument(
        "--org",
        help="Target organization name for Shodan org: filter and ARIN lookup. e.g. 'Acme Corp'"
    )
    parser.add_argument(
        "--domain",
        help="Target domain for certificate transparency and DNS recon. e.g. 'acmecorp.com'"
    )
    parser.add_argument(
        "--address",
        help="Target physical location to geo-filter Shodan results. e.g. 'Newark NJ'"
    )

    args = parser.parse_args()

    if args.mock:
        os.environ["MODE"] = "mock"
    if args.verbose:
        os.environ["VERBOSE"] = "true"
    if args.debug:
        os.environ["DEBUG"] = "true"
        os.environ["VERBOSE"] = "true"  # debug implies verbose
    if args.no_report:
        os.environ["NO_REPORT"] = "true"

    # --- Stealth flag wiring ---
    # --quiet fans out to all granular flags. Granular flags can also be set independently.
    # We write to os.environ so config.py picks them up when modules import it.
    if args.quiet:
        os.environ["QUIET"]             = "true"
        os.environ["SLOW_SCAN"]         = "true"
        os.environ["FRAGMENT_PACKETS"]  = "true"
        os.environ["USE_DECOYS"]        = "true"
        os.environ["SPOOF_SOURCE_PORT"] = "true"
        os.environ["RANDOMIZE_HOSTS"]   = "true"
        os.environ["SPOOF_MAC"]         = "true"
    # Granular flags: set individually if passed, regardless of --quiet
    if args.slow_scan:
        os.environ["SLOW_SCAN"]         = "true"
    if args.fragment:
        os.environ["FRAGMENT_PACKETS"]  = "true"
    if args.decoys:
        os.environ["USE_DECOYS"]        = "true"
    if args.spoof_source_port:
        os.environ["SPOOF_SOURCE_PORT"] = "true"
    if args.randomize_hosts:
        os.environ["RANDOMIZE_HOSTS"]   = "true"
    if args.spoof_mac:
        os.environ["SPOOF_MAC"]         = "true"

        
    # Import all agents to trigger @AgentRegistry.register decorators.
    # Order here doesn't matter — pipeline order is defined in AgentRegistry.PIPELINE_ORDER.
    from agents.wifi_agent import WiFiAgent
    from agents.osint_agent import OSINTAgent
    from agents.discovery_agent import DiscoveryAgent
    from agents.camera_access_agent import CameraAccessAgent
    from agents.lateral_agent import LateralMovementAgent
    from agents.reporting_agent import ReportingAgent

    from core.engagement import EngagementContext
    from core.pipeline import PipelineRunner

    # Load or create engagement context
    if args.resume:
        print(f"[Main] Resuming engagement from {args.resume}")
        ctx = EngagementContext.load(args.resume)
    else:
        if args.engagement_id: 
            ctx = EngagementContext(
                engagement_id=args.engagement_id,
                target_scope=args.scope or [],
                target_org=args.org or None,
                target_domain=args.domain or None,
                target_address=args.address or None,
            )
        else: #if no engagementID defined, it will just auto-generate one within the EngagementContext class
            ctx = EngagementContext(
                target_scope=args.scope or [],
                target_org=args.org or None,
                target_domain=args.domain or None,
                target_address=args.address or None,
            )

    print(f"\n[Main] Engagement ID: {ctx.engagement_id}")
    print(f"[Main] Mode: {os.getenv('MODE', 'real')}")
    print(f"[Main] Scope: {ctx.target_scope or 'auto-detect'}")
    if ctx.target_org:      print(f"[Main] Target org: {ctx.target_org}")
    if ctx.target_domain:   print(f"[Main] Target domain: {ctx.target_domain}")
    if ctx.target_address:  print(f"[Main] Target address: {ctx.target_address}")

    # Log active stealth settings to audit trail before any agent runs.
    # This ensures chain of custody includes evasion config for the report.
    ctx.log_stealth_config()

    # Build and run pipeline
    runner = PipelineRunner(ctx, verbose=True)

    try:
        if args.stages:
            for stage in args.stages:
                runner.add_stage(stage)
            ctx = runner.run()
        else:
            ctx = runner.run_all()
    except KeyboardInterrupt:
        print(f"\n[Main] Interrupted by operator -- shutting down cleanly")

    print(f"\n[Main] Pipeline complete.\n")
    print(ctx.summary())


if __name__ == "__main__":
    main()