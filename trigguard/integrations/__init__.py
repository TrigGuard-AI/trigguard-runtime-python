"""
TrigGuard Integrations

Pre-built integrations for common frameworks and patterns.

Available integrations:
- FastAPI middleware
- Agent tool guards (LangChain, OpenAI)
"""

from trigguard.integrations.agent_guard import (
    AgentToolGuard,
    guarded_tool,
    LangChainToolGuard,
    OpenAIToolGuard,
    AGENT_SURFACES,
    get_surface_for_tool,
)

try:
    from trigguard.integrations.fastapi_guard import (
        TrigGuardMiddleware,
        create_fastapi_dependency,
    )
except ImportError:
    # FastAPI/Starlette not installed
    TrigGuardMiddleware = None
    create_fastapi_dependency = None


__all__ = [
    # Agent integrations
    "AgentToolGuard",
    "guarded_tool",
    "LangChainToolGuard",
    "OpenAIToolGuard",
    "AGENT_SURFACES",
    "get_surface_for_tool",
    # FastAPI integration (optional)
    "TrigGuardMiddleware",
    "create_fastapi_dependency",
]
