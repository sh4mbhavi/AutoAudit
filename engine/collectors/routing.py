"""Which client a collector needs, decided in exactly one place.

Before Phase 9 this predicate was written three times -- as the automation gate
in ``worker.tasks.run_scan``, as the client choice in
``worker.tasks._evaluate_control_async``, and a third, differently spelled time in
``engine/scripts/test_collector.py``. Three copies of a routing rule is how a
collector ends up gated as PowerShell and then handed a GraphClient, so the rule
lives here and the call sites read it.

The rule itself is unchanged: Exchange, Compliance, Teams and SharePoint PnP
collectors run through the PowerShell service, except ``exchange.dns.*``, which
resolves DNS records and needs no tenant session at all.
"""

POWERSHELL_PREFIXES = ("exchange.", "compliance.", "teams.", "sharepoint.pnp.")
GRAPH_EXCEPTIONS = ("exchange.dns.",)


def uses_powershell(collector_id: str) -> bool:
    """True when this collector must be given a PowerShellClient."""
    if not isinstance(collector_id, str):
        return False
    return collector_id.startswith(POWERSHELL_PREFIXES) and not collector_id.startswith(
        GRAPH_EXCEPTIONS
    )
