"""
core/base_agent.py
------------------
The abstract base class that every agent in the pipeline inherits from.

WHY A BASE CLASS:
    Without a shared interface, every agent is a snowflake. Adding a new
    agent means understanding how the existing ones work. With a base class,
    the contract is explicit: every agent takes an EngagementContext, runs,
    and returns an updated EngagementContext. That's it.

    This is what makes the pipeline composable. The pipeline runner doesn't
    need to know anything about what an agent does — just that it conforms
    to this interface.

INHERITANCE PATTERN:
    class MyNewAgent(BaseAgent):
        name = "MyNewAgent"
        stage = "my_stage"

        def run(self, ctx: EngagementContext) -> EngagementContext:
            # do work, append to ctx, return ctx
            ...

PLUGIN REGISTRATION:
    Agents register themselves via AgentRegistry.register().
    The pipeline runner discovers available agents from the registry.
    New agents don't require changes to the pipeline runner.
"""

from abc import ABC, abstractmethod
from typing import Optional
from core.engagement import EngagementContext


class BaseAgent(ABC):
    """
    Abstract base class for all pipeline agents.

    Every agent in the system — WiFi, OSINT, Discovery, Access,
    LateralMovement, Reporting — inherits from this class.
    """

    # --- Class-level identity (override in subclass) ---
    name: str = "UnnamedAgent"
    stage: str = "unknown"
    description: str = "No description provided."

    # --- MITRE ATT&CK mapping ---
    # Used by ReportingAgent to map findings to the ATT&CK framework.
    # Reference: https://attack.mitre.org/tactics/
    # Does not affect pipeline execution — purely for reporting.
    mitre_tactic: str = ""           # e.g. "TA0007"
    mitre_tactic_name: str = ""      # e.g. "Discovery"

    # Whether this agent requires elevated privileges (sudo/root)
    requires_root: bool = False

    # Whether this agent requires network access
    requires_network: bool = True

    # Whether this agent requires an LLM
    requires_llm: bool = True

    def __init__(self, config: Optional[dict] = None):
        """
        Args:
            config: Optional dict of agent-specific configuration.
                    Agents should define their expected keys in their
                    own __init__ with sensible defaults.
        """
        self.config = config or {}

    @abstractmethod
    def run(self, ctx: EngagementContext) -> EngagementContext:
        """
        Execute this agent's stage of the engagement.

        This is the only method the pipeline runner calls.

        Args:
            ctx: The shared EngagementContext. Read from it to understand
                 what prior agents found. Write to it with your findings.

        Returns:
            The same EngagementContext object, mutated with new findings.
            (Return the same object, not a copy — context is shared state.)

        Contract:
            - MUST call ctx.log() for every network action taken
            - MUST call ctx.enforce_scope() before every outbound connection
            - MUST call ctx.mark_stage_complete(self.stage) before returning
            - MUST NOT raise unhandled exceptions (catch and log instead)
            - MUST return ctx even if the stage fails or finds nothing
        """
        pass

    def can_run(self, ctx: EngagementContext) -> tuple[bool, str]:
        """
        Check whether this agent has what it needs to run.

        Override in subclasses to add prerequisite checks.
        The pipeline runner calls this before run() and skips the agent
        if it returns False.

        Returns:
            (True, "") if ready to run
            (False, "reason") if prerequisites not met
        """
        return True, ""

    def __repr__(self):
        return f"<{self.__class__.__name__} stage={self.stage}>"


class AgentRegistry:
    """
    Registry of all available agents.

    WHY A REGISTRY:
        Hard-coding agent order in main.py means every new agent requires
        editing the runner. A registry means agents self-register and the
        runner discovers them dynamically.

        This is the same pattern used by pytest (test discovery), Flask
        (route registration), and Django (app registry).

    USAGE:
        # Register an agent (done at class definition time)
        @AgentRegistry.register
        class MyAgent(BaseAgent):
            stage = "my_stage"
            ...

        # Get all registered agents in pipeline order
        agents = AgentRegistry.get_pipeline()
    """

    _registry: dict = {}

    # Canonical pipeline order. Agents not in this list run last.
    PIPELINE_ORDER = [
        "wifi",
        "osint",
        "discovery",
        "camera_access",
        "lateral",
        "reporting",
    ]

    @classmethod
    def register(cls, agent_class: type) -> type:
        """
        Decorator that registers an agent class.

        Usage:
            @AgentRegistry.register
            class MyAgent(BaseAgent):
                stage = "my_stage"
        """
        cls._registry[agent_class.stage] = agent_class
        return agent_class

    @classmethod
    def get(cls, stage: str) -> Optional[type]:
        """Get a registered agent class by stage name."""
        return cls._registry.get(stage)

    @classmethod
    def get_pipeline(cls, stages: Optional[list] = None) -> list:
        """
        Get agent classes in pipeline order.

        Args:
            stages: Optional list of stage names to include.
                    If None, returns all registered agents in order.

        Returns:
            List of agent classes in pipeline execution order.
        """
        if stages:
            requested = set(stages)
        else:
            requested = set(cls._registry.keys())

        ordered = []
        for stage in cls.PIPELINE_ORDER:
            if stage in requested and stage in cls._registry:
                ordered.append(cls._registry[stage])

        # Any registered agents not in PIPELINE_ORDER go at the end
        for stage, agent_class in cls._registry.items():
            if stage not in cls.PIPELINE_ORDER and stage in requested:
                ordered.append(agent_class)

        return ordered

    @classmethod
    def list_stages(cls) -> list:
        """List all registered stage names."""
        return list(cls._registry.keys())
