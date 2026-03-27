"""
Policy Client

Fetches policy bundles from a remote policy registry.

The client does NOT make authorization decisions.
It only retrieves policy bundles for local kernel use.

Endpoints:
- /policy/latest - Get latest policy version
- /policy/{version} - Get specific policy version
- /policy/versions - List available versions
"""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Any
from enum import Enum

from trigguard.network.policy_bundle import PolicyBundle


class FetchStatus(str, Enum):
    """Result of fetch operation."""

    SUCCESS = "success"
    NOT_FOUND = "not_found"
    NETWORK_ERROR = "network_error"
    PARSE_ERROR = "parse_error"
    UNAUTHORIZED = "unauthorized"


@dataclass
class FetchResult:
    """Result of a policy fetch operation."""

    status: FetchStatus
    bundle: Optional[PolicyBundle]
    message: str
    metadata: dict = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

    @property
    def success(self) -> bool:
        return self.status == FetchStatus.SUCCESS


class PolicyClient:
    """
    Client for fetching policy bundles from a remote registry.

    In production, this would connect to an HTTPS endpoint.
    For testing/demo, it uses a simulated local registry.

    The client handles:
    - Fetching latest policy
    - Fetching specific versions
    - Listing available versions
    - Caching (optional)

    The client does NOT:
    - Verify bundles (that's PolicyVerifier's job)
    - Apply policies (that's UpdateManager's job)
    - Make decisions (that's DecisionEngine's job)
    """

    def __init__(
        self,
        registry_url: str = "https://policy.trigguard.ai",
        api_key: Optional[str] = None,
        timeout: int = 30,
        use_simulation: bool = True,
    ):
        """
        Initialize policy client.

        Args:
            registry_url: Base URL of policy registry
            api_key: API key for authentication
            timeout: Request timeout in seconds
            use_simulation: Use simulated registry for testing
        """
        self.registry_url = registry_url
        self.api_key = api_key
        self.timeout = timeout
        self.use_simulation = use_simulation

        # Simulated registry for testing
        self._simulated_registry: dict[str, PolicyBundle] = {}
        self._latest_version: Optional[str] = None

    def fetch_latest_policy(self) -> FetchResult:
        """
        Fetch the latest policy bundle.

        Returns:
            FetchResult with bundle if successful
        """
        if self.use_simulation:
            return self._simulated_fetch_latest()

        return self._http_fetch("/policy/latest")

    def fetch_policy(self, version: str) -> FetchResult:
        """
        Fetch a specific policy version.

        Args:
            version: Version string (e.g., "v1.0.0")

        Returns:
            FetchResult with bundle if successful
        """
        if self.use_simulation:
            return self._simulated_fetch_version(version)

        return self._http_fetch(f"/policy/{version}")

    def list_versions(self) -> list[str]:
        """
        List available policy versions.

        Returns:
            List of version strings
        """
        if self.use_simulation:
            return sorted(self._simulated_registry.keys(), reverse=True)

        result = self._http_fetch("/policy/versions")
        if result.success:
            return result.metadata.get("versions", [])
        return []

    def check_for_update(self, current_version: str) -> Optional[str]:
        """
        Check if a newer policy version is available.

        Args:
            current_version: Currently active version

        Returns:
            New version string if update available, None otherwise
        """
        result = self.fetch_latest_policy()
        if not result.success:
            return None

        latest = result.bundle.version
        if self._is_newer_version(latest, current_version):
            return latest
        return None

    # =========================================================================
    # Simulated Registry (for testing/demo)
    # =========================================================================

    def register_simulated_bundle(
        self,
        bundle: PolicyBundle,
        is_latest: bool = True,
    ) -> None:
        """
        Register a bundle in the simulated registry.

        For testing purposes.
        """
        self._simulated_registry[bundle.version] = bundle
        if is_latest:
            self._latest_version = bundle.version

    def clear_simulated_registry(self) -> None:
        """Clear the simulated registry."""
        self._simulated_registry.clear()
        self._latest_version = None

    def _simulated_fetch_latest(self) -> FetchResult:
        """Fetch from simulated registry."""
        if not self._latest_version:
            return FetchResult(
                status=FetchStatus.NOT_FOUND,
                bundle=None,
                message="No policies available",
            )

        bundle = self._simulated_registry.get(self._latest_version)
        if not bundle:
            return FetchResult(
                status=FetchStatus.NOT_FOUND,
                bundle=None,
                message=f"Latest version {self._latest_version} not found",
            )

        return FetchResult(
            status=FetchStatus.SUCCESS,
            bundle=bundle,
            message="Policy fetched successfully",
            metadata={"version": bundle.version},
        )

    def _simulated_fetch_version(self, version: str) -> FetchResult:
        """Fetch specific version from simulated registry."""
        bundle = self._simulated_registry.get(version)
        if not bundle:
            return FetchResult(
                status=FetchStatus.NOT_FOUND,
                bundle=None,
                message=f"Version {version} not found",
            )

        return FetchResult(
            status=FetchStatus.SUCCESS,
            bundle=bundle,
            message="Policy fetched successfully",
            metadata={"version": bundle.version},
        )

    # =========================================================================
    # HTTP Client (for production)
    # =========================================================================

    def _http_fetch(self, endpoint: str) -> FetchResult:
        """
        Fetch policy from HTTP endpoint.

        In production, this would use requests/httpx.
        """
        try:
            import urllib.request
            import urllib.error

            url = f"{self.registry_url}{endpoint}"
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"

            req = urllib.request.Request(url, headers=headers)

            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                data = json.loads(response.read().decode())

                if "bundle" in data:
                    bundle = PolicyBundle.from_dict(data["bundle"])
                    return FetchResult(
                        status=FetchStatus.SUCCESS,
                        bundle=bundle,
                        message="Policy fetched successfully",
                        metadata=data.get("metadata", {}),
                    )
                elif "versions" in data:
                    return FetchResult(
                        status=FetchStatus.SUCCESS,
                        bundle=None,
                        message="Versions fetched",
                        metadata={"versions": data["versions"]},
                    )
                else:
                    return FetchResult(
                        status=FetchStatus.PARSE_ERROR,
                        bundle=None,
                        message="Invalid response format",
                    )

        except urllib.error.HTTPError as e:
            if e.code == 404:
                return FetchResult(
                    status=FetchStatus.NOT_FOUND,
                    bundle=None,
                    message=f"Policy not found: {endpoint}",
                )
            elif e.code == 401 or e.code == 403:
                return FetchResult(
                    status=FetchStatus.UNAUTHORIZED,
                    bundle=None,
                    message="Unauthorized",
                )
            else:
                return FetchResult(
                    status=FetchStatus.NETWORK_ERROR,
                    bundle=None,
                    message=f"HTTP error: {e.code}",
                )
        except Exception as e:
            return FetchResult(
                status=FetchStatus.NETWORK_ERROR,
                bundle=None,
                message=f"Network error: {str(e)}",
            )

    # =========================================================================
    # Helpers
    # =========================================================================

    def _is_newer_version(self, candidate: str, current: str) -> bool:
        """Check if candidate version is newer than current."""

        def parse_version(v: str) -> tuple[int, ...]:
            if v.startswith("v"):
                v = v[1:]
            return tuple(int(x) for x in v.split("."))

        try:
            return parse_version(candidate) > parse_version(current)
        except ValueError:
            return False
