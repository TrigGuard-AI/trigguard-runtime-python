"""
TrigGuard Agent Discovery

Automatic tool scanning and surface inference for AI agents.

This module enables TrigGuard to automatically discover and protect
tools on any agent framework.

Usage:
    from trigguard.sdk.discovery import discover_tools, scan_agent

    # Discover all tools on an agent
    tools = discover_tools(agent)

    # Full scan with surface inference
    scan_result = scan_agent(agent)
    for tool, surface in scan_result.mappings.items():
        print(f"{tool} -> {surface}")
"""

from trigguard.sdk.discovery.agent_scan import (
    discover_tools,
    scan_agent,
    ScanResult,
    ToolInfo,
)

__all__ = [
    "discover_tools",
    "scan_agent",
    "ScanResult",
    "ToolInfo",
]
