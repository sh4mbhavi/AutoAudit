"""Mailboxes collector.

CIS Microsoft 365 Foundations Benchmark Controls:
    v6.0.0: 1.2.2

Connection Method: Exchange Online PowerShell (via Docker container)
Authentication: Client secret via MSAL -> access token passed to -AccessToken parameter
Required Cmdlets: Get-EXOMailbox, Get-User
Required Permissions: Exchange.ManageAsApp + Exchange role assignment
"""

from typing import Any

from collectors.powershell_base import BasePowerShellCollector
from collectors.powershell_client import PowerShellClient


class MailboxesDataCollector(BasePowerShellCollector):
    """Collects mailbox information for CIS compliance evaluation."""

    async def collect(self, client: PowerShellClient) -> dict[str, Any]:
        """Collect shared mailboxes and their associated user information."""

        mailboxes_raw = await client.run_operation(
            "exchange.mailbox.mailboxes.read", "exchange.mailbox.mailboxes"
        )

        mailboxes: list[dict[str, Any]]

        if mailboxes_raw is None:
            mailboxes = []
        elif isinstance(mailboxes_raw, dict):
            mailboxes = [mailboxes_raw]
        elif isinstance(mailboxes_raw, list):
            mailboxes = [
                mailbox for mailbox in mailboxes_raw if isinstance(mailbox, dict)
            ]
        else:
            mailboxes = []

        # Phase 9: one batched Exchange session instead of one whole pwsh
        # process, Connect-ExchangeOnline and Disconnect per shared mailbox. A
        # tenant with 200 shared mailboxes opened 200 extra sessions for this one
        # control. Results come back in request order, so the emitted evidence is
        # identical to the serial version for any given tenant response.
        named = [mailbox for mailbox in mailboxes if mailbox.get("UserPrincipalName")]
        accounts = await client.run_operations(
            [
                (
                    "exchange.mailbox.mailboxes.user",
                    "exchange.mailbox.mailboxes",
                    {"Identity": mailbox["UserPrincipalName"]},
                )
                for mailbox in named
            ]
        )
        # Aligned by POSITION, not by UPN: run_operations returns in request
        # order, and a UPN-keyed map would silently collapse two mailboxes that
        # report the same UserPrincipalName onto one lookup result. The serial
        # loop needed no uniqueness assumption and neither does this.
        by_index = {id(mailbox): account for mailbox, account in zip(named, accounts)}

        enriched_mailboxes = []

        for mailbox in mailboxes:
            user_account = by_index.get(id(mailbox))

            enriched_mailboxes.append(
                {
                    "display_name": mailbox.get("DisplayName"),
                    "user_principal_name": mailbox.get("UserPrincipalName"),
                    "external_directory_object_id": mailbox.get(
                        "ExternalDirectoryObjectId"
                    ),
                    "account_disabled": (
                        user_account.get("AccountDisabled")
                        if isinstance(user_account, dict)
                        else None
                    ),
                }
            )

        return {
            "shared_mailboxes": enriched_mailboxes,
            "total_shared_mailboxes": len(enriched_mailboxes),
        }
