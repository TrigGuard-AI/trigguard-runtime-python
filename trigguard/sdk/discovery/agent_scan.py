"""
TrigGuard Agent Scanner

Automatic tool discovery and surface inference for AI agent frameworks.

Supports:
- Generic Python classes with callable methods
- LangChain agents and tools
- OpenAI function calling
- Any object with a tools attribute

Usage:
    from trigguard.sdk.discovery import discover_tools, scan_agent

    class MyAgent:
        def transfer_funds(self, amount): pass
        def export_data(self): pass

    agent = MyAgent()

    # Simple discovery
    tools = discover_tools(agent)
    # [<bound method transfer_funds>, <bound method export_data>]

    # Full scan with surface inference
    result = scan_agent(agent)
    print(result.mappings)
    # {"transfer_funds": "trigguard.spend.transfer", ...}
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set
import inspect
import logging
import re

from trigguard.attestation import compute_surface_hash

logger = logging.getLogger(__name__)


# Patterns for surface inference (same as agent_integrations but more comprehensive)
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

# Methods to skip during discovery
SKIP_METHODS: Set[str] = {
    "__init__",
    "__new__",
    "__del__",
    "__repr__",
    "__str__",
    "__hash__",
    "__eq__",
    "__ne__",
    "__lt__",
    "__le__",
    "__gt__",
    "__ge__",
    "__getattr__",
    "__setattr__",
    "__delattr__",
    "__getattribute__",
    "__get__",
    "__set__",
    "__delete__",
    "__call__",
    "__len__",
    "__iter__",
    "__next__",
    "__contains__",
    "__enter__",
    "__exit__",
    "__await__",
    "__aiter__",
    "__anext__",
}


@dataclass
class ToolInfo:
    """Information about a discovered tool."""

    name: str
    func: Callable[..., Any]
    surface: Optional[str] = None
    code_hash: Optional[str] = None
    signature: Optional[str] = None
    docstring: Optional[str] = None

    @property
    def has_surface(self) -> bool:
        return self.surface is not None


@dataclass
class ScanResult:
    """Result of scanning an agent for tools."""

    tools: List[ToolInfo] = field(default_factory=list)
    unmapped: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def mappings(self) -> Dict[str, str]:
        """Tool name -> surface ID mapping."""
        return {t.name: t.surface for t in self.tools if t.surface}

    @property
    def tool_count(self) -> int:
        return len(self.tools)

    @property
    def mapped_count(self) -> int:
        return len([t for t in self.tools if t.surface])

    @property
    def unmapped_count(self) -> int:
        return len(self.unmapped)


def discover_tools(agent: Any) -> List[Callable[..., Any]]:
    """
    Discover callable tools on an agent.

    Scans the agent for callable methods that could be tools.
    Excludes private methods (starting with _) and magic methods.

    Args:
        agent: Agent object to scan

    Returns:
        List of callable methods
    """
    tools = []

    for name, member in inspect.getmembers(agent):
        # Skip private and magic methods
        if name.startswith("_"):
            continue

        # Skip non-callables
        if not callable(member):
            continue

        # Skip class methods and static methods that aren't tools
        if isinstance(member, type):
            continue

        tools.append(member)

    return tools


def infer_surface(func: Callable[..., Any]) -> Optional[str]:
    """
    Infer execution surface from function name and docstring.

    Args:
        func: Function to analyze

    Returns:
        Inferred surface ID or None
    """
    name = getattr(func, "__name__", str(func)).lower()
    doc = (getattr(func, "__doc__", "") or "").lower()
    combined = f"{name} {doc}"

    for pattern, surface in SURFACE_PATTERNS.items():
        if re.search(pattern, combined):
            return surface

    return None


def scan_agent(
    agent: Any,
    *,
    compute_hashes: bool = True,
    include_signatures: bool = True,
) -> ScanResult:
    """
    Perform full scan of an agent's tools.

    Discovers all tools, infers surfaces, and optionally computes
    code hashes for attestation.

    Args:
        agent: Agent to scan
        compute_hashes: Whether to compute code hashes
        include_signatures: Whether to include function signatures

    Returns:
        ScanResult with tool information
    """
    result = ScanResult()

    # Try different extraction methods
    tools = _extract_tools(agent)

    for tool in tools:
        name = _get_tool_name(tool)
        func = _get_tool_func(tool)

        if not func:
            result.errors.append(f"Could not get function for: {name}")
            continue

        # Create tool info
        info = ToolInfo(
            name=name,
            func=func,
            surface=infer_surface(func),
            docstring=func.__doc__,
        )

        # Compute code hash if requested
        if compute_hashes:
            try:
                info.code_hash = compute_surface_hash(func)
            except Exception as e:
                logger.warning(f"Could not compute hash for {name}: {e}")

        # Include signature if requested
        if include_signatures:
            try:
                info.signature = str(inspect.signature(func))
            except (ValueError, TypeError):
                pass

        if info.surface:
            result.tools.append(info)
        else:
            result.tools.append(info)
            result.unmapped.append(name)

    return result


def _extract_tools(agent: Any) -> List[Any]:
    """Extract tools from various agent types."""
    # Direct class methods
    if not hasattr(agent, "tools") and not hasattr(agent, "get_tools"):
        return discover_tools(agent)

    # Has tools attribute
    if hasattr(agent, "tools"):
        return agent.tools

    # Has get_tools method
    if hasattr(agent, "get_tools"):
        return agent.get_tools()

    # LangChain agent executor
    if hasattr(agent, "agent") and hasattr(agent.agent, "tools"):
        return agent.agent.tools

    return []


def _get_tool_name(tool: Any) -> str:
    """Get tool name from various formats."""
    if hasattr(tool, "name"):
        return tool.name
    if hasattr(tool, "__name__"):
        return tool.__name__
    return str(tool)


def _get_tool_func(tool: Any) -> Optional[Callable[..., Any]]:
    """Extract callable from tool wrapper."""
    if callable(tool):
        return tool
    if hasattr(tool, "func"):
        return tool.func
    if hasattr(tool, "_run"):
        return tool._run
    if hasattr(tool, "run"):
        return tool.run
    return None


def scan_and_report(agent: Any) -> str:
    """
    Scan agent and return human-readable report.

    Args:
        agent: Agent to scan

    Returns:
        Formatted report string
    """
    result = scan_agent(agent)

    lines = [
        f"TrigGuard Agent Scan Report",
        f"=" * 40,
        f"",
        f"Total tools: {result.tool_count}",
        f"Mapped to surfaces: {result.mapped_count}",
        f"Unmapped: {result.unmapped_count}",
        f"",
        f"Tool Mappings:",
        f"-" * 40,
    ]

    for tool in result.tools:
        status = "✓" if tool.surface else "?"
        surface = tool.surface or "UNKNOWN"
        lines.append(f"  {status} {tool.name} -> {surface}")
        if tool.code_hash:
            lines.append(f"      hash: {tool.code_hash[:20]}...")

    if result.unmapped:
        lines.append(f"")
        lines.append(f"Unmapped tools need explicit surface mapping:")
        for name in result.unmapped:
            lines.append(f"  - {name}")

    return "\n".join(lines)
