"""
TrigGuard Agent Integrations

Automatic tool protection for AI agent frameworks.

Supported frameworks:
- LangChain tools
- OpenAI function calling
- Generic callable tools

Usage:
    from trigguard.sdk import protect_tools, protect_tool

    # Protect all tools on an agent
    protect_tools(agent)

    # Protect a single tool
    protected = protect_tool(my_tool, surface="trigguard.data.export")

    # Auto-detect surface from function signature
    protected = protect_tool(transfer_funds)  # -> trigguard.spend.transfer
"""

from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable, Dict, List, Optional, Protocol, TypeVar, Union
import inspect
import logging
import re

from trigguard.sdk.decorators import requires_grant
from trigguard.registry import ExecutionSurfaceRegistry

logger = logging.getLogger(__name__)

F = TypeVar("F", bound=Callable[..., Any])


# Surface inference patterns
SURFACE_PATTERNS: Dict[str, str] = {
    # Spend patterns
    r"(transfer|send|pay|charge|withdraw|purchase)": "trigguard.spend.transfer",
    r"(refund|credit)": "trigguard.spend.refund",
    r"(subscribe|recurring)": "trigguard.spend.subscription",
    # Data patterns
    r"(export|download|extract|dump)": "trigguard.data.export",
    r"(delete|remove|drop|truncate|purge)": "trigguard.data.delete",
    r"(write|update|modify|change|set)": "trigguard.data.write",
    # Code patterns
    r"(exec|execute|run|eval).*(code|script|command|shell)": "trigguard.code.exec",
    r"(install|pip|npm|package)": "trigguard.code.install_package",
    # Network patterns
    r"(http|request|fetch|api|curl)": "trigguard.network.http_request",
    r"(email|mail|send.*message)": "trigguard.comms.email",
    # System patterns
    r"(file|read|open)": "trigguard.system.file_read",
    r"(process|spawn|fork|subprocess)": "trigguard.system.process_spawn",
    # Identity patterns
    r"(login|auth|authenticate|signin)": "trigguard.identity.authenticate",
    r"(impersonate|sudo|assume)": "trigguard.identity.impersonate",
    r"(invite|add.*user|create.*account)": "trigguard.identity.invite",
}


def infer_surface(func: Callable[..., Any]) -> Optional[str]:
    """
    Infer the execution surface from function name and signature.

    Args:
        func: The function to analyze

    Returns:
        Inferred surface ID or None if cannot determine
    """
    name = func.__name__.lower()
    doc = (func.__doc__ or "").lower()
    combined = f"{name} {doc}"

    for pattern, surface in SURFACE_PATTERNS.items():
        if re.search(pattern, combined):
            return surface

    return None


def protect_tool(
    func: F,
    surface: Optional[str] = None,
    verify_signature: bool = True,
) -> F:
    """
    Protect a single tool function with TrigGuard authorization.

    Args:
        func: The tool function to protect
        surface: Explicit surface ID (auto-inferred if not provided)
        verify_signature: Whether to verify grant signatures

    Returns:
        Protected function wrapper

    Example:
        @protect_tool(surface="trigguard.spend.transfer")
        def transfer_funds(amount: float):
            ...

        # Or with auto-inference
        protected = protect_tool(transfer_funds)
    """
    resolved_surface = surface or infer_surface(func)

    if not resolved_surface:
        raise ValueError(
            f"Cannot infer surface for {func.__name__}. "
            "Please specify surface explicitly."
        )

    # Use the existing decorator
    return requires_grant(
        surface=resolved_surface,
        verify_signature=verify_signature,
    )(func)


@dataclass
class ProtectionResult:
    """Result of protecting an agent's tools."""

    protected_count: int = 0
    skipped_count: int = 0
    protected_tools: List[str] = field(default_factory=list)
    skipped_tools: List[str] = field(default_factory=list)
    surface_mappings: Dict[str, str] = field(default_factory=dict)


class AgentProtocol(Protocol):
    """Protocol for agent-like objects with tools."""

    tools: List[Any]


def protect_tools(
    agent: Any,
    surfaces: Optional[Dict[str, str]] = None,
    skip_unknown: bool = True,
    verify_signature: bool = True,
) -> ProtectionResult:
    """
    Protect all tools on an agent with TrigGuard authorization.

    This function automatically wraps all callable tools on an agent
    with @requires_grant decorators, inferring surfaces where possible.

    Args:
        agent: Agent object with tools attribute
        surfaces: Explicit surface mappings {tool_name: surface_id}
        skip_unknown: Skip tools with unknown surfaces (vs raising)
        verify_signature: Whether to verify grant signatures

    Returns:
        ProtectionResult with details of what was protected

    Example:
        from langchain.agents import create_react_agent

        agent = create_react_agent(...)
        result = protect_tools(agent)
        print(f"Protected {result.protected_count} tools")

        # With explicit mappings
        protect_tools(agent, surfaces={
            "transfer_funds": "trigguard.spend.transfer",
            "export_data": "trigguard.data.export",
        })
    """
    surfaces = surfaces or {}
    result = ProtectionResult()

    # Get tools from agent
    tools = _extract_tools(agent)

    for tool in tools:
        tool_name = _get_tool_name(tool)
        tool_func = _get_tool_func(tool)

        if not tool_func:
            result.skipped_count += 1
            result.skipped_tools.append(tool_name)
            continue

        # Determine surface
        surface = surfaces.get(tool_name) or infer_surface(tool_func)

        if not surface:
            if skip_unknown:
                logger.warning(f"Skipping tool with unknown surface: {tool_name}")
                result.skipped_count += 1
                result.skipped_tools.append(tool_name)
                continue
            else:
                raise ValueError(
                    f"Cannot determine surface for tool: {tool_name}. "
                    "Provide explicit mapping in surfaces parameter."
                )

        # Protect the tool
        protected_func = requires_grant(
            surface=surface,
            verify_signature=verify_signature,
        )(tool_func)

        # Replace the tool's function
        _set_tool_func(tool, protected_func)

        result.protected_count += 1
        result.protected_tools.append(tool_name)
        result.surface_mappings[tool_name] = surface
        logger.info(f"Protected tool: {tool_name} -> {surface}")

    return result


def _extract_tools(agent: Any) -> List[Any]:
    """Extract tools from various agent types."""
    # Try common patterns
    if hasattr(agent, "tools"):
        return agent.tools
    if hasattr(agent, "get_tools"):
        return agent.get_tools()
    if hasattr(agent, "_tools"):
        return agent._tools

    # LangChain agent executor
    if hasattr(agent, "agent") and hasattr(agent.agent, "tools"):
        return agent.agent.tools

    raise TypeError(
        f"Cannot extract tools from {type(agent).__name__}. "
        "Expected object with 'tools' attribute."
    )


def _get_tool_name(tool: Any) -> str:
    """Get the name of a tool."""
    if hasattr(tool, "name"):
        return tool.name
    if hasattr(tool, "__name__"):
        return tool.__name__
    if callable(tool):
        return getattr(tool, "__name__", str(tool))
    return str(tool)


def _get_tool_func(tool: Any) -> Optional[Callable[..., Any]]:
    """Get the callable function from a tool."""
    if callable(tool):
        return tool
    if hasattr(tool, "func"):
        return tool.func
    if hasattr(tool, "_run"):
        return tool._run
    if hasattr(tool, "run"):
        return tool.run
    return None


def _set_tool_func(tool: Any, func: Callable[..., Any]) -> None:
    """Set the callable function on a tool."""
    if hasattr(tool, "func"):
        tool.func = func
    elif hasattr(tool, "_run"):
        tool._run = func
    elif hasattr(tool, "run"):
        tool.run = func
    # For plain callables, we can't replace in-place


# ============================================================================
# Framework-specific integrations
# ============================================================================


def protect_langchain_tools(
    tools: List[Any],
    surfaces: Optional[Dict[str, str]] = None,
) -> List[Any]:
    """
    Protect LangChain tools with TrigGuard authorization.

    Args:
        tools: List of LangChain Tool objects
        surfaces: Explicit surface mappings

    Returns:
        List of protected tools
    """
    surfaces = surfaces or {}
    protected = []

    for tool in tools:
        tool_name = tool.name if hasattr(tool, "name") else str(tool)
        surface = surfaces.get(tool_name) or infer_surface(tool.func)

        if surface:
            tool.func = requires_grant(surface=surface)(tool.func)
            logger.info(f"Protected LangChain tool: {tool_name} -> {surface}")

        protected.append(tool)

    return protected


def protect_openai_functions(
    functions: List[Dict[str, Any]],
    handlers: Dict[str, Callable[..., Any]],
    surfaces: Optional[Dict[str, str]] = None,
) -> Dict[str, Callable[..., Any]]:
    """
    Protect OpenAI function calling handlers with TrigGuard authorization.

    Args:
        functions: OpenAI function definitions
        handlers: Function name -> handler callable mapping
        surfaces: Explicit surface mappings

    Returns:
        Protected handlers dict
    """
    surfaces = surfaces or {}
    protected_handlers = {}

    for func_def in functions:
        func_name = func_def["name"]
        handler = handlers.get(func_name)

        if not handler:
            continue

        surface = surfaces.get(func_name) or infer_surface(handler)

        if surface:
            protected_handlers[func_name] = requires_grant(surface=surface)(handler)
            logger.info(f"Protected OpenAI function: {func_name} -> {surface}")
        else:
            protected_handlers[func_name] = handler

    return protected_handlers
