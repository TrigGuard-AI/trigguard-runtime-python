"""
Context Builder

Assembles DetectionContext from raw requests.
This layer runs BEFORE detectors, enriching the request with
conversation history, tool calls, and other relevant context.

Keeps detectors simple and stateless.
"""

from typing import Any, Optional
from uuid import uuid4

from protocol.detection_event import (
    DetectionContext,
    DetectionRequest,
    Message,
    ToolCall,
)


class ContextBuilder:
    """
    Builds rich DetectionContext from DetectionRequest.
    
    Flow:
    1. Extract current prompt
    2. Parse conversation history
    3. Parse tool calls
    4. Assemble metadata
    5. Return DetectionContext
    
    Detectors then operate on DetectionContext, not raw input.
    """

    def __init__(self):
        pass

    def build(self, request: DetectionRequest) -> DetectionContext:
        """
        Build DetectionContext from a DetectionRequest.
        
        Args:
            request: The incoming detection request.
            
        Returns:
            DetectionContext ready for detector analysis.
        """
        # Parse conversation history from request
        conversation_history = self._parse_conversation_history(
            request.conversation_history
        )

        # Parse tool calls from request
        tool_calls = self._parse_tool_calls(request.tool_calls)

        return DetectionContext(
            request_id=request.request_id,
            current_prompt=request.prompt,
            system_prompt=request.system_prompt,
            conversation_history=conversation_history,
            tool_calls=tool_calls,
            user_id=request.user_id,
            session_id=request.session_id,
            metadata=request.metadata,
            timestamp=request.timestamp,
        )

    def _parse_conversation_history(
        self, history: list[dict[str, str]]
    ) -> list[Message]:
        """Parse raw conversation history into Message objects."""
        messages = []
        for item in history:
            if isinstance(item, dict):
                messages.append(
                    Message(
                        role=item.get("role", "user"),
                        content=item.get("content", ""),
                        metadata=item.get("metadata", {}),
                    )
                )
            elif isinstance(item, Message):
                messages.append(item)
        return messages

    def _parse_tool_calls(
        self, tool_calls: list[dict[str, Any]]
    ) -> list[ToolCall]:
        """Parse raw tool call data into ToolCall objects."""
        calls = []
        for item in tool_calls:
            if isinstance(item, dict):
                calls.append(
                    ToolCall(
                        tool_name=item.get("tool_name", item.get("name", "unknown")),
                        arguments=item.get("arguments", item.get("args", {})),
                        result=item.get("result"),
                        success=item.get("success", True),
                    )
                )
            elif isinstance(item, ToolCall):
                calls.append(item)
        return calls

    @staticmethod
    def from_simple_prompt(prompt: str, **kwargs) -> DetectionContext:
        """
        Convenience method for simple single-prompt requests.
        
        Args:
            prompt: The prompt to analyze.
            **kwargs: Additional context fields.
            
        Returns:
            DetectionContext for the prompt.
        """
        return DetectionContext(
            request_id=kwargs.get("request_id", uuid4()),
            current_prompt=prompt,
            system_prompt=kwargs.get("system_prompt"),
            user_id=kwargs.get("user_id"),
            session_id=kwargs.get("session_id"),
            metadata=kwargs.get("metadata", {}),
        )

    @staticmethod
    def from_conversation(
        current_prompt: str,
        history: list[dict[str, str]],
        system_prompt: Optional[str] = None,
        tool_calls: Optional[list[dict[str, Any]]] = None,
        **kwargs,
    ) -> DetectionContext:
        """
        Build context from a multi-turn conversation.
        
        Args:
            current_prompt: The current user prompt.
            history: List of previous messages.
            system_prompt: The system prompt (if any).
            tool_calls: List of tool invocations (if any).
            **kwargs: Additional context fields.
            
        Returns:
            DetectionContext for the conversation.
        """
        builder = ContextBuilder()
        
        request = DetectionRequest(
            prompt=current_prompt,
            system_prompt=system_prompt,
            conversation_history=history,
            tool_calls=tool_calls or [],
            user_id=kwargs.get("user_id"),
            session_id=kwargs.get("session_id"),
            metadata=kwargs.get("metadata", {}),
        )
        
        return builder.build(request)
