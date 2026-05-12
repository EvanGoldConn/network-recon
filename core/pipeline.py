"""
core/pipeline.py
----------------
The pipeline runner. Orchestrates agents in sequence, passing the
EngagementContext through each one.

WHY THIS IS SEPARATE FROM main.py:
    main.py is the CLI entry point — argument parsing, user interaction.
    pipeline.py is the execution engine — pure logic, no I/O.
    Keeping them separate means the pipeline can be imported and tested
    without spinning up a CLI, and the CLI can be swapped without touching
    the execution logic.

EXECUTION MODEL:
    Sequential by default. Each agent completes before the next starts.
    This is intentional — later agents depend on earlier agents' findings.

    Exception: OSINT (Stage 1) and WiFi (Stage 0) can run concurrently
    if both are requested, since they're independent. This is a future
    optimization; sequential is safer to start.

FAILURE HANDLING:
    If an agent raises an unhandled exception, the pipeline:
    1. Logs the failure to the audit trail
    2. Marks the stage as failed (not complete)
    3. Continues to the next agent
    This means a broken OSINT module doesn't prevent Discovery from running.
"""

import traceback
from typing import Optional
from core.engagement import EngagementContext
from core.base_agent import BaseAgent, AgentRegistry


class PipelineRunner:
    """
    Executes a sequence of agents against a shared EngagementContext.

    USAGE:
        runner = PipelineRunner(ctx)
        runner.add_stage("discovery")
        runner.add_stage("access")
        ctx = runner.run()

    OR run the full pipeline:
        runner = PipelineRunner(ctx)
        ctx = runner.run_all()
    """

    def __init__(self, ctx: EngagementContext, verbose: bool = True):
        self.ctx = ctx
        self.verbose = verbose
        self._stages: list[str] = []

    def add_stage(self, stage: str) -> "PipelineRunner":
        """Add a stage to the pipeline. Returns self for chaining."""
        self._stages.append(stage)
        return self

    def run(self) -> EngagementContext:
        """
        Execute the configured stages in order.

        Returns the EngagementContext after all stages have run.
        """
        agent_classes = AgentRegistry.get_pipeline(
            stages=self._stages if self._stages else None
        )

        if not agent_classes:
            print("[Pipeline] No agents registered or requested.")
            return self.ctx

        for agent_class in agent_classes:
            self._run_agent(agent_class)

        return self.ctx

    def run_all(self) -> EngagementContext:
        """Run all registered agents in pipeline order."""
        self._stages = []
        return self.run()

    def _run_agent(self, agent_class: type):
        """
        Instantiate and run a single agent.

        Handles prerequisite checks, execution, failure logging.
        """
        agent = agent_class()
        self.ctx.current_stage = agent.stage

        if self.verbose:
            print(f"\n[Pipeline] ── Starting {agent.name} (stage: {agent.stage}) ──")

        # Check prerequisites
        can_run, reason = agent.can_run(self.ctx)
        if not can_run:
            msg = f"Skipped {agent.name}: {reason}"
            if self.verbose:
                print(f"[Pipeline] ⚠  {msg}")
            self.ctx.log("Pipeline", f"Skipped stage: {agent.stage}", result=reason)
            return

        # Execute
        try:
            self.ctx = agent.run(self.ctx)
            if self.verbose:
                print(f"[Pipeline] ✓  {agent.name} complete")

        except Exception as e:
            tb = traceback.format_exc()
            error_msg = f"{agent.name} failed: {str(e)}"
            if self.verbose:
                print(f"[Pipeline] ✗  {error_msg}")
                print(tb)
            self.ctx.log("Pipeline", f"Stage failed: {agent.stage}", result=str(e))
