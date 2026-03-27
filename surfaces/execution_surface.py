"""
Execution Surface Classification

Classifies execution requests into risk-appropriate surfaces.
Surface classification determines default policy posture and required signals.
"""

from typing import Optional
import re

from protocol.decision_contracts import ExecutionRequest, ExecutionSurface


class SurfaceClassifier:
    """
    Classifies execution requests into execution surfaces.
    
    The execution surface determines:
    - Risk tier (1=highest, 3=lowest)
    - Whether actions are irreversible
    - Default policy posture
    - Required signals for authorization
    """

    # Action patterns mapped to surfaces
    ACTION_PATTERNS = {
        ExecutionSurface.SPEND: [
            r"pay|payment|transfer|charge|purchase|buy|withdraw|send_money",
            r"transaction|checkout|invoice|billing",
        ],
        ExecutionSurface.EXPORT: [
            r"export|download|send_email|upload|share|publish",
            r"write_file|save_external|output_file",
        ],
        ExecutionSurface.DELEGATION: [
            r"delegate|authorize|grant|assign_role|add_permission",
            r"create_user|invite|share_access",
        ],
        ExecutionSurface.IDENTITY_ASSERTION: [
            r"assert_identity|act_as|impersonate|on_behalf",
            r"sign|authenticate_as|claim_identity",
        ],
        ExecutionSurface.EXTERNAL_API: [
            r"external_api|http_request|fetch_url|webhook",
            r"call_service|remote_call|third_party",
        ],
        ExecutionSurface.CODE_EXECUTION: [
            r"exec|eval|run_code|execute|shell|command",
            r"compile|interpret|script",
        ],
        ExecutionSurface.DATA_MUTATION: [
            r"update|delete|insert|create|modify|write",
            r"db_query|mutate|set_value|store",
        ],
        ExecutionSurface.INTERNAL_API: [
            r"internal_api|service_call|rpc|grpc",
        ],
        ExecutionSurface.STATE_READ: [
            r"read|get|fetch|query|lookup|search",
            r"list|describe|status",
        ],
        ExecutionSurface.TOOL_INVOCATION: [
            r"tool_call|use_tool|invoke|function_call",
        ],
        ExecutionSurface.INFERENCE: [
            r"inference|predict|classify|embed|complete",
        ],
        ExecutionSurface.RETRIEVAL: [
            r"retrieve|rag|search_knowledge|vector_search",
        ],
        ExecutionSurface.GENERATION: [
            r"generate|compose|write_text|create_content",
        ],
    }

    def __init__(self):
        self._compiled_patterns: dict[ExecutionSurface, list[re.Pattern]] = {}
        for surface, patterns in self.ACTION_PATTERNS.items():
            self._compiled_patterns[surface] = [
                re.compile(p, re.IGNORECASE) for p in patterns
            ]

    def classify(self, request: ExecutionRequest) -> ExecutionSurface:
        """
        Classify an execution request into an execution surface.
        
        Args:
            request: The execution request to classify.
            
        Returns:
            The classified execution surface.
        """
        # If surface is already set and valid, use it
        if request.surface != ExecutionSurface.UNKNOWN:
            return request.surface

        # Classify based on action string
        if request.action:
            surface = self._classify_action(request.action)
            if surface != ExecutionSurface.UNKNOWN:
                return surface

        # Classify based on target
        if request.target:
            surface = self._classify_target(request.target)
            if surface != ExecutionSurface.UNKNOWN:
                return surface

        # Classify based on tool calls
        if request.tool_calls:
            surface = self._classify_tool_calls(request.tool_calls)
            if surface != ExecutionSurface.UNKNOWN:
                return surface

        # Default to UNKNOWN (fail closed will apply)
        return ExecutionSurface.UNKNOWN

    def _classify_action(self, action: str) -> ExecutionSurface:
        """Classify based on action string."""
        # Check patterns in order of risk (highest first)
        surface_order = [
            ExecutionSurface.SPEND,
            ExecutionSurface.DELEGATION,
            ExecutionSurface.IDENTITY_ASSERTION,
            ExecutionSurface.CODE_EXECUTION,
            ExecutionSurface.EXPORT,
            ExecutionSurface.DATA_MUTATION,
            ExecutionSurface.EXTERNAL_API,
            ExecutionSurface.INTERNAL_API,
            ExecutionSurface.TOOL_INVOCATION,
            ExecutionSurface.STATE_READ,
            ExecutionSurface.RETRIEVAL,
            ExecutionSurface.INFERENCE,
            ExecutionSurface.GENERATION,
        ]

        for surface in surface_order:
            patterns = self._compiled_patterns.get(surface, [])
            for pattern in patterns:
                if pattern.search(action):
                    return surface

        return ExecutionSurface.UNKNOWN

    def _classify_target(self, target: str) -> ExecutionSurface:
        """Classify based on target resource."""
        target_lower = target.lower()

        # Financial targets
        if any(t in target_lower for t in ["payment", "stripe", "paypal", "bank", "wallet"]):
            return ExecutionSurface.SPEND

        # External APIs
        if any(t in target_lower for t in ["http://", "https://", "api.", "webhook"]):
            return ExecutionSurface.EXTERNAL_API

        # Database targets
        if any(t in target_lower for t in ["database", "db.", "table:", "collection:"]):
            return ExecutionSurface.DATA_MUTATION

        return ExecutionSurface.UNKNOWN

    def _classify_tool_calls(self, tool_calls: list[dict]) -> ExecutionSurface:
        """Classify based on tool calls present."""
        if not tool_calls:
            return ExecutionSurface.UNKNOWN

        # Check tool names for high-risk patterns
        for call in tool_calls:
            tool_name = call.get("tool_name", call.get("name", "")).lower()
            
            if any(t in tool_name for t in ["exec", "shell", "eval", "run"]):
                return ExecutionSurface.CODE_EXECUTION
            if any(t in tool_name for t in ["pay", "transfer", "charge"]):
                return ExecutionSurface.SPEND
            if any(t in tool_name for t in ["email", "export", "download"]):
                return ExecutionSurface.EXPORT

        return ExecutionSurface.TOOL_INVOCATION

    @staticmethod
    def get_required_signals(surface: ExecutionSurface) -> list[str]:
        """
        Get the signals required for authorization on this surface.
        
        Irreversible surfaces require more thorough signal collection.
        """
        if surface.is_irreversible:
            return [
                "identity_verified",
                "rate_limit_checked", 
                "threat_scan_complete",
            ]
        elif surface.risk_tier == 2:
            return [
                "threat_scan_complete",
            ]
        else:
            return []

    @staticmethod
    def get_forbidden_signals(surface: ExecutionSurface) -> list[str]:
        """
        Get signals that immediately forbid execution on this surface.
        
        These are hard blocks - if detected, execution is denied.
        """
        if surface.is_irreversible:
            return [
                "prompt_override",
                "jailbreak_attempt",
                "role_escalation",
                "delegation_attempt",
            ]
        elif surface.risk_tier == 2:
            return [
                "prompt_override",
                "jailbreak_attempt",
            ]
        else:
            return [
                "jailbreak_attempt",
            ]
