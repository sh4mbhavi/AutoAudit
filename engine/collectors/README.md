# Data Collectors

This directory contains data collectors that fetch information from cloud APIs for compliance evaluation. Each collector gathers specific data that gets passed to OPA policies for assessment.

## How collectors work

A collector is a simple class with one job: call an API and return structured data. The data goes to OPA, which runs the actual compliance checks. Collectors don't make pass/fail decisions - they just gather facts.

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Collector  │────▶│  Raw Data   │────▶│  OPA Policy │
│  (fetch)    │     │  (dict)     │     │  (evaluate) │
└─────────────┘     └─────────────┘     └─────────────┘
```

## Writing a new collector

### 1. Create the collector class

Inherit from `BaseDataCollector` and implement the `collect` method.

**Pick the right client first.** Half of the registered collectors do not use
Graph at all: 24 of the 50 take a `PowerShellClient` and reach Exchange Online,
Teams or SharePoint through the PowerShell service, because the settings they
read have no Graph endpoint. The two are not interchangeable, and the worker
routes a collector by the client its `collect` method declares.

For a Graph collector:

```python
from typing import Any
from engine.collectors.base import BaseDataCollector
from engine.collectors.graph_client import GraphClient


class MyNewCollector(BaseDataCollector):
    """One-line description of what this collects."""

    async def collect(self, client: GraphClient) -> dict[str, Any]:
        # Fetch data from the API
        data = await client.get("/some/endpoint")

        # Return structured data for OPA
        return {
            "items": data.get("value", []),
            "count": len(data.get("value", [])),
        }
```

### 2. Place it in the right folder

Collectors are organized by service and domain:

```
collectors/
  entra/              # Microsoft Entra ID (Azure AD)
    roles/            # Role and admin management
    conditional_access/
  m365/               # Microsoft 365 services
    exchange/         # Exchange Online
    sharepoint/       # SharePoint Online
    teams/            # Microsoft Teams
```

### 3. Register it

Why do we need to register these?

You could dynamically import based on the string path, but that's fragile and has security implications. The registry provides:

- Explicit allowlist - Only registered collectors can be instantiated
- Single place to see all collectors - Easy to audit what's available
- Decoupling - The scan engine doesn't need to know the import paths, just the IDs
- Validation - get_collector() raises a clear error for unknown IDs

Add your collector to `registry.py`:

```python
from engine.collectors.entra.roles.my_new import MyNewCollector

DATA_COLLECTORS: dict[str, type[BaseDataCollector]] = {
    # ... existing collectors ...
    "entra.roles.my_new": MyNewCollector,
}
```

The ID follows the folder path: `entra.roles.my_new` maps to `entra/roles/my_new.py`.

### 4. Reference it in metadata.json

In the benchmark's `metadata.json`, set the `data_collector_id` for your control:

```json
{
  "control_id": "CIS-1.2.3",
  "data_collector_id": "entra.roles.my_new",
  ...
}
```

## Guidelines

**Keep collectors focused.** One collector per control, or per logical data set. If two controls need the same data, they can share a collector.

**Return raw data.** Don't make compliance decisions in collectors. Return the facts and let OPA policies interpret them. This keeps the logic testable and the collectors reusable.

**Handle pagination.** Use `client.get_all_pages()` for endpoints that return paged results. The Graph API often limits responses to 100 items.

**Use type hints.** The `collect` method should return `dict[str, Any]`. Document what keys the dict contains in the docstring.

**Async all the way.** Collectors are async. Use `await` for all API calls. This lets us run multiple collectors concurrently during scans.

## The two clients

`GraphClient` handles Microsoft Graph API authentication and requests. It is
used by the Entra and Intune collectors -- 26 of the 50 registered today.

The other 24 take a `PowerShellClient` and run a fixed, allow-listed cmdlet
through the PowerShell service, because Exchange Online, Teams and SharePoint
expose these settings only through PowerShell. Those collectors declare
`async def collect(self, client: PowerShellClient)` and call
`client.run_operation(...)` with an operation id, never a free-text command.

This page used to say `GraphClient` was "shared across all Microsoft
collectors", which was false for nearly half of them and sent every new
Exchange, Teams or SharePoint collector to the wrong client.

```python
# Basic GET request
data = await client.get("/users")

# GET with query parameters
data = await client.get("/users", params={"$filter": "accountEnabled eq true"})

# Paginated endpoint (fetches all pages)
all_users = await client.get_all_pages("/users")

# Beta endpoint
data = await client.get("/some/beta/endpoint", beta=True)
```

The client handles:
- OAuth token acquisition via MSAL
- Token caching and refresh
- Pagination with @odata.nextLink
- Both v1.0 and beta Graph endpoints
