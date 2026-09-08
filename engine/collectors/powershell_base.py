"""Base class for PowerShell-based collectors."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collectors.powershell_client import PowerShellClient


class BasePowerShellCollector(ABC):
    """Abstract base class for PowerShell collectors.

    This base class is used for collectors that require PowerShell cmdlets
    from Exchange Online, Microsoft Teams, or Security & Compliance modules.

    Authentication uses client secret via MSAL to obtain access tokens,
    which are then passed to PowerShell cmdlets via the -AccessToken parameter.
    """

    @abstractmethod
    async def collect(self, client: "PowerShellClient") -> dict[str, Any]:
        """Collect data using PowerShell cmdlets.

        Args:
            client: The PowerShell client to use for data collection.

        Returns:
            Dictionary of collected data to be passed to OPA for evaluation.
        """
        pass


def powershell_records(value: Any) -> list[dict[str, Any]]:
    """Normalize the documented PowerShell zero/single/multiple result shapes."""
    if value is None:
        return []
    if isinstance(value, dict):
        return [powershell_object(value)]
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError("PowerShell response must be an object or list of objects")
    return [powershell_object(item) for item in value]


def powershell_object(value: Any) -> dict[str, Any]:
    """Preserve missing singleton evidence without inventing property values."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("PowerShell singleton response must be an object")
    if any(
        value.get(key) is not None for key in ("error", "collector_error")
    ) or value.get("errors"):
        raise ValueError("PowerShell response contains a collection error")
    return value
