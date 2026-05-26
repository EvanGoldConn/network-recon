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

    args = parser.parse_args()

    if args.mock:
        os.environ["MODE"] = "mock"
    if args.verbose:
        os.environ["VERBOSE"] = "true"
    if args.debug:
        os.environ["DEBUG"] = "true"
        os.environ["VERBOSE"] = "true"  # debug implies verbose

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
            )
        else: #if no engagementID defined, it will just auto-generate one within the EngagementContext class
            ctx = EngagementContext(
                target_scope=args.scope or [],
        )

    print(f"\n[Main] Engagement ID: {ctx.engagement_id}")
    print(f"[Main] Mode: {os.getenv('MODE', 'real')}")
    print(f"[Main] Scope: {ctx.target_scope or 'auto-detect'}")

    # Build and run pipeline
    runner = PipelineRunner(ctx, verbose=True)

    if args.stages:
        for stage in args.stages:
            runner.add_stage(stage)
        ctx = runner.run()
    else:
        ctx = runner.run_all()

    print(f"\n[Main] Pipeline complete.\n")
    print(ctx.summary())


if __name__ == "__main__":
    main()
