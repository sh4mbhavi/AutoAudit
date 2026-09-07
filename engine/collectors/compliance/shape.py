"""Returned-object shape contract for the Security & Compliance collectors.

Microsoft's reference pages for Get-DlpCompliancePolicy and Get-LabelPolicy
document no return properties at all (fetched 2026-09-06), so the shapes this
codebase is willing to read are declared once, here, instead of being inferred
twice inside two collectors.

Two rules hold everywhere in this module:

1. No token vocabulary is invented. The only tokens named below are the ones the
   CIS Microsoft 365 Foundations procedures themselves name. Every other observed
   token is simply "not Enable" / "not PublishedSensitivityLabel"; it is reported
   and never classified.
2. An unrecognised element poisons its whole list. A helper returns None for the
   entire value rather than dropping the element it could not read, because a
   silently shortened list reads downstream as confident evidence of absence.
"""

from typing import Any

# Get-LabelPolicy location properties the CIS 3.3.1 audit asks the reviewer to
# look at. Only the property NAMES are ever projected into collector output:
# their contents are tenant principals, groups and site URLs.
LABEL_LOCATION_PROPERTIES: tuple[str, ...] = (
    "ExchangeLocation",
    "SharePointLocation",
    "OneDriveLocation",
    "ModernGroupLocation",
)

LABEL_LOCATION_SCOPES: dict[str, str] = {
    "ExchangeLocation": "exchange",
    "SharePointLocation": "sharepoint",
    "OneDriveLocation": "onedrive",
    "ModernGroupLocation": "moderngroup",
}

# CIS 3.3.1 audit step 3: "Ensure there is at least one ... PublishedSensitivityLabel".
PUBLISHED_SENSITIVITY_LABEL_TYPE = "PublishedSensitivityLabel"

# CIS 3.2.2 audit steps 4 and 5: Mode "Enable" and a TeamsLocation including All.
DLP_MODE_ENABLE = "Enable"
TEAMS_WORKLOAD_TOKEN = "Teams"
TEAMS_LOCATION_ALL = "All"


def location_names(value: Any) -> list[str] | None:
    """Read a PowerShell location list as names, or refuse to read it at all.

    Exactly four shapes are accepted: None (absent evidence), an empty list, a
    list whose every element is a string, and a list whose every element is an
    object carrying a string Name or DisplayName. Anything else -- including a
    bare string, and including a list with a single unrecognised element --
    returns None for the WHOLE list.
    """
    if not isinstance(value, list):
        return None
    if all(isinstance(item, str) for item in value):
        return [item.strip() for item in value]
    names: list[str] = []
    for item in value:
        if not isinstance(item, dict):
            return None
        name = item.get("Name")
        if not isinstance(name, str):
            name = item.get("DisplayName")
        if not isinstance(name, str):
            return None
        names.append(name.strip())
    return names


def workload_includes_teams(value: Any) -> bool | None:
    """Whether a DLP policy Workload names Teams, or None if it cannot be read.

    The CIS 3.2.2 audit filters on Workload matching Teams, and Workload is
    observed both as a comma-separated string and as a list of strings. Any
    other shape is unreadable rather than absent, so it returns None and the
    caller refuses the whole population.
    """
    if isinstance(value, str):
        return _includes_teams(value)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return any(_includes_teams(item) for item in value)
    return None


def mode_token(value: Any) -> str | None:
    """The Mode token exactly as reported, or None if it is not a string."""
    if isinstance(value, str):
        return value.strip()
    return None


def _includes_teams(value: str) -> bool:
    token = TEAMS_WORKLOAD_TOKEN.casefold()
    return any(token in part.strip().casefold() for part in value.split(","))
