"""
TrigGuard Agent Framework Integration

Protects AI agent tool calls with TrigGuard authorization.

Usage:
    from trigguard.integrations.agent_guard import guarded_tool, AgentToolGuard

    # Wrap tools with TrigGuard protection
    @guarded_tool(surface="SPEND")
    def send_payment(amount: float, recipient: str):
        payment_api.send(amount, recipient)

    # Or wrap existing tools
    guard = AgentToolGuard()
    protected_tool = guard.wrap(original_tool, surface="SPEND")

Preferred approach for dangerous actions:
    # For CODE_EXEC, SPEND, DATA_EXPORT, use core.protected_actions
    from trigguard.core.protected_actions import protected_shell_command, protected_spend

    result = protected_shell_command(command=["git", "clone", url])
    result = protected_spend(amount=100, recipient="vendor",
                            transfer_callable=lambda: bank.transfer(100))
"""

from functools import wraps
from typing import Any, Callable, Dict, List, Optional, TypeVar, Union
from uuid import uuid4

from trigguard.sdk.gate import gate, guard, GateDeniedError, GateResult
from trigguard.protocol.decision_contracts import ExecutionSurface

F = TypeVar("F", bound=Callable[..., Any])


class AgentToolGuard:
    """
    Guard for AI agent tool invocations.

    Wraps agent tools to pass through TrigGuard before execution.
    Compatible with tool-calling patterns from LangChain, OpenAI, etc.
    """

    def __init__(
        self,
        default_surface: str = "tool_invocation",
        fail_silently: bool = False,
    ):
        """
        Initialize agent tool guard.

        Args:
            default_surface: Default surface for tool calls
            fail_silently: If True, return None on deny instead of raising
        """
        self.default_surface = default_surface
        self.fail_silently = fail_silently

    def wrap(
        self,
        tool: Callable,
        surface: Optional[str] = None,
        tool_name: Optional[str] = None,
    ) -> Callable:
        """
        Wrap a tool function with TrigGuard protection.

        Args:
            tool: The tool function to protect
            surface: Execution surface (default: tool_invocation)
            tool_name: Name for logging (default: function name)

        Returns:
            Protected tool function
        """
        surface = surface or self.default_surface
        name = tool_name or getattr(tool, "__name__", "unknown_tool")

        @wraps(tool)
        def protected_tool(*args, **kwargs):
            # Build request
            request = {
                "surface": surface,
                "action": name,
                "arguments": {
                    "args": args,
                    "kwargs": kwargs,
                },
                "context": {
                    "tool_name": name,
                    "invocation_id": str(uuid4()),
                },
            }

            # Check authorization
            decision = gate.check(request)

            if decision.permit:
                return tool(*args, **kwargs)
            elif self.fail_silently:
                return None
            else:
                raise GateDeniedError(decision)

        return protected_tool

    def wrap_tools(
        self,
        tools: Dict[str, Callable],
        surface_map: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Callable]:
        """
        Wrap multiple tools with TrigGuard protection.

        Args:
            tools: Dictionary of tool_name -> tool_function
            surface_map: Optional mapping of tool_name -> surface

        Returns:
            Dictionary of protected tools
        """
        surface_map = surface_map or {}
        return {
            name: self.wrap(
                tool,
                surface=surface_map.get(name, self.default_surface),
                tool_name=name,
            )
            for name, tool in tools.items()
        }


def guarded_tool(
    surface: str = "tool_invocation",
    raise_on_deny: bool = True,
) -> Callable[[F], F]:
    """
    Decorator for protecting agent tool functions.

    Args:
        surface: Execution surface
        raise_on_deny: If True, raise GateDeniedError on deny

    Returns:
        Decorated function

    Example:
        @guarded_tool(surface="SPEND")
        def send_payment(amount: float, recipient: str):
            payment_api.send(amount, recipient)

    Preferred for CODE_EXEC:
        # Use protected_shell_command from trigguard.core.protected_actions
        from trigguard.core.protected_actions import protected_shell_command
        result = protected_shell_command(command=["git", "status"])
    """
    return guard(surface=surface, raise_on_deny=raise_on_deny)


class LangChainToolGuard:
    """
    Integration for LangChain tools.

    Usage:
        from langchain.tools import Tool

        guard = LangChainToolGuard()

        protected_tool = guard.protect(
            original_tool,
            surface="CODE_EXEC"
        )
    """

    def __init__(self):
        self._guard = AgentToolGuard()

    def protect(
        self,
        tool: Any,
        surface: str = "tool_invocation",
    ) -> Any:
        """
        Protect a LangChain tool.

        Args:
            tool: LangChain Tool object
            surface: Execution surface

        Returns:
            Protected tool
        """
        # Wrap the underlying function
        if hasattr(tool, "func"):
            tool.func = self._guard.wrap(
                tool.func,
                surface=surface,
                tool_name=getattr(tool, "name", "langchain_tool"),
            )
        elif hasattr(tool, "_run"):
            original_run = tool._run
            tool._run = self._guard.wrap(
                original_run,
                surface=surface,
                tool_name=getattr(tool, "name", "langchain_tool"),
            )

        return tool


class OpenAIToolGuard:
    """
    Integration for OpenAI function calling.

    Usage:
        guard = OpenAIToolGuard()

        @guard.function(surface="SPEND")
        def transfer_money(amount: float, recipient: str):
            ...
    """

    def __init__(self):
        self._guard = AgentToolGuard()

    def function(
        self,
        surface: str = "tool_invocation",
    ) -> Callable[[F], F]:
        """Decorator for OpenAI function tools."""

        def decorator(func: F) -> F:
            return self._guard.wrap(func, surface=surface)

        return decorator

    def wrap_functions(
        self,
        functions: Dict[str, Callable],
        surface_map: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Callable]:
        """Wrap multiple functions for OpenAI tool use."""
        return self._guard.wrap_tools(functions, surface_map)


# Convenience export for common surfaces
AGENT_SURFACES = {
    "shell": "code_execution",
    "code": "code_execution",
    "file_write": "data_mutation",
    "file_read": "state_read",
    "api_call": "external_api",
    "payment": "spend",
    "email": "external_api",
    "database": "data_mutation",
}


def get_surface_for_tool(tool_name: str) -> str:
    """
    Get recommended surface for a tool name.

    Args:
        tool_name: Name of the tool

    Returns:
        Recommended execution surface
    """
    name_lower = tool_name.lower()

    for keyword, surface in AGENT_SURFACES.items():
        if keyword in name_lower:
            return surface

    return "tool_invocation"


__all__ = [
    "AgentToolGuard",
    "guarded_tool",
    "LangChainToolGuard",
    "OpenAIToolGuard",
    "AGENT_SURFACES",
    "get_surface_for_tool",
]
