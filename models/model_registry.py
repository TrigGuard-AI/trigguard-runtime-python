"""
Model Registry

Central registry for ML models used by the detection system.
Handles model discovery, versioning, and loading.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class ModelType(str, Enum):
    """Types of models in the registry."""

    CLASSIFIER = "classifier"
    EMBEDDINGS = "embeddings"
    RULES = "rules"


@dataclass
class ModelInfo:
    """Metadata about a registered model."""

    name: str
    version: str
    model_type: ModelType
    path: str
    description: str = ""
    metrics: Optional[dict[str, float]] = None


class ModelRegistry:
    """
    Central registry for all models.

    In production, this would:
    - Connect to S3/GCS for model storage
    - Handle model versioning
    - Support A/B testing
    - Track model performance
    """

    _instance: Optional["ModelRegistry"] = None

    # Singleton pattern for global access
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._models = {}
            cls._instance._loaded = {}
        return cls._instance

    def register(self, model: ModelInfo) -> None:
        """Register a model in the registry."""
        key = f"{model.name}:{model.version}"
        self._models[key] = model

    def get(self, name: str, version: str = "latest") -> Optional[ModelInfo]:
        """Get model info from the registry."""
        if version == "latest":
            # Find latest version
            candidates = [k for k in self._models if k.startswith(f"{name}:")]
            if not candidates:
                return None
            key = sorted(candidates)[-1]
        else:
            key = f"{name}:{version}"

        return self._models.get(key)

    def load(self, name: str, version: str = "latest") -> Any:
        """
        Load a model into memory.

        Returns the loaded model object.
        """
        model_info = self.get(name, version)
        if model_info is None:
            raise ValueError(f"Model not found: {name}:{version}")

        key = f"{name}:{version}"
        if key not in self._loaded:
            # Placeholder: actual loading logic
            self._loaded[key] = {"info": model_info, "model": None}

        return self._loaded[key]

    def list_models(self) -> list[ModelInfo]:
        """List all registered models."""
        return list(self._models.values())

    def unload(self, name: str, version: str = "latest") -> None:
        """Unload a model from memory."""
        key = f"{name}:{version}"
        if key in self._loaded:
            del self._loaded[key]
