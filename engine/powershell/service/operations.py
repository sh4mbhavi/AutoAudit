"""Fixed, read-only PowerShell operations shared by HTTP and local execution.

Adding an operation requires a reviewed code change. Request bodies never supply
module names, cmdlets, pipelines, script blocks, or parameter names outside this
registry. Fixed command sequences below are trusted source code, not user input.
"""

from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Any, Mapping


@dataclass(frozen=True)
class Operation:
    module: str
    command: str
    collectors: frozenset[str]
    parameters: Mapping[str, str]


def _operation(
    module: str, command: str, collector: str, identity: bool = False
) -> Operation:
    return Operation(
        module,
        command,
        frozenset({collector}),
        MappingProxyType({"Identity": "upn"} if identity else {}),
    )


OPERATIONS = MappingProxyType(
    {
        "exchange.authentication.dkim_signing_config.read": _operation(
            "ExchangeOnline",
            "Get-DkimSigningConfig",
            "exchange.authentication.dkim_signing_config",
            False,
        ),
        "exchange.mailbox.mailbox_audit.read": _operation(
            "ExchangeOnline",
            "Get-MailboxAuditBypassAssociation -ResultSize Unlimited -WarningAction SilentlyContinue | Where-Object { $_.AuditBypassEnabled -eq $true } | Select-Object Name, AuditBypassEnabled",
            "exchange.mailbox.mailbox_audit",
            False,
        ),
        "exchange.mailbox.mailbox_audit_actions.read": _operation(
            "ExchangeOnline",
            "Get-EXOMailbox -PropertySets Audit, Minimum -ResultSize Unlimited -WarningAction SilentlyContinue | Where-Object { $_.RecipientTypeDetails -eq 'UserMailbox' } | Select-Object UserPrincipalName, AuditEnabled, AuditAdmin, AuditDelegate, AuditOwner",
            "exchange.mailbox.mailbox_audit_actions",
            False,
        ),
        "exchange.mailbox.mailboxes.read": _operation(
            "ExchangeOnline",
            "Get-EXOMailbox -RecipientTypeDetails SharedMailbox -ResultSize Unlimited",
            "exchange.mailbox.mailboxes",
            False,
        ),
        "exchange.mailbox.mailboxes.user": _operation(
            "ExchangeOnline", "Get-User", "exchange.mailbox.mailboxes", True
        ),
        "exchange.mailbox.role_assignment_policy.read": _operation(
            "ExchangeOnline",
            "Get-RoleAssignmentPolicy",
            "exchange.mailbox.role_assignment_policy",
            False,
        ),
        "exchange.organization.admin_audit_log_config.read": _operation(
            "ExchangeOnline",
            "Get-AdminAuditLogConfig",
            "exchange.organization.admin_audit_log_config",
            False,
        ),
        "exchange.organization.organization_config.read": _operation(
            "ExchangeOnline",
            "Get-OrganizationConfig",
            "exchange.organization.organization_config",
            False,
        ),
        "exchange.organization.owa_mailbox_policy.read": _operation(
            "ExchangeOnline",
            "Get-OwaMailboxPolicy",
            "exchange.organization.owa_mailbox_policy",
            False,
        ),
        "exchange.organization.sharing_policy.read": _operation(
            "ExchangeOnline",
            "Get-SharingPolicy",
            "exchange.organization.sharing_policy",
            False,
        ),
        "exchange.organization.transport_config.read": _operation(
            "ExchangeOnline",
            "Get-TransportConfig",
            "exchange.organization.transport_config",
            False,
        ),
        "exchange.protection.anti_phish_policy.read": _operation(
            "ExchangeOnline",
            "Get-AntiPhishPolicy",
            "exchange.protection.anti_phish_policy",
            False,
        ),
        "exchange.protection.anti_phish_policy.rules": _operation(
            "ExchangeOnline",
            "Get-AntiPhishRule",
            "exchange.protection.anti_phish_policy",
            False,
        ),
        "exchange.protection.atp_policy_o365.read": _operation(
            "ExchangeOnline",
            "Get-AtpPolicyForO365",
            "exchange.protection.atp_policy_o365",
            False,
        ),
        "exchange.protection.hosted_connection_filter.read": _operation(
            "ExchangeOnline",
            "Get-HostedConnectionFilterPolicy",
            "exchange.protection.hosted_connection_filter",
            False,
        ),
        "exchange.protection.hosted_content_filter.read": _operation(
            "ExchangeOnline",
            "Get-HostedContentFilterPolicy",
            "exchange.protection.hosted_content_filter",
            False,
        ),
        "exchange.protection.hosted_outbound_spam_filter.read": _operation(
            "ExchangeOnline",
            "Get-HostedOutboundSpamFilterPolicy",
            "exchange.protection.hosted_outbound_spam_filter",
            False,
        ),
        "exchange.protection.malware_filter_policy.read": _operation(
            "ExchangeOnline",
            "Get-MalwareFilterPolicy",
            "exchange.protection.malware_filter_policy",
            False,
        ),
        "exchange.protection.safe_attachment_policy.read": _operation(
            "ExchangeOnline",
            "Get-SafeAttachmentPolicy",
            "exchange.protection.safe_attachment_policy",
            False,
        ),
        "exchange.protection.safe_links_policy.read": _operation(
            "ExchangeOnline",
            "Get-SafeLinksPolicy",
            "exchange.protection.safe_links_policy",
            False,
        ),
        "exchange.protection.teams_protection_policy.read": _operation(
            "ExchangeOnline",
            "Get-TeamsProtectionPolicy",
            "exchange.protection.teams_protection_policy",
            False,
        ),
        "exchange.transport.external_in_outlook.read": _operation(
            "ExchangeOnline",
            "Get-ExternalInOutlook",
            "exchange.transport.external_in_outlook",
            False,
        ),
        "exchange.transport.transport_rules.read": _operation(
            "ExchangeOnline",
            "Get-TransportRule",
            "exchange.transport.transport_rules",
            False,
        ),
        "exchange.transport.transport_rules.outbound_spam": _operation(
            "ExchangeOnline",
            "Get-HostedOutboundSpamFilterPolicy",
            "exchange.transport.transport_rules",
            False,
        ),
        # Compliance
        "compliance.dlp_compliance_policy.read": _operation(
            "Compliance",
            "Get-DlpCompliancePolicy | Select-Object Name, Guid, Mode, Enabled, Workload, TeamsLocation, TeamsLocationException",
            "compliance.dlp_compliance_policy",
            False,
        ),
        "compliance.label_policy.read": _operation(
            "Compliance",
            "Get-LabelPolicy -WarningAction Ignore | Select-Object Name, Guid, Type, Enabled, Mode, ExchangeLocation, SharePointLocation, OneDriveLocation, ModernGroupLocation",
            "compliance.label_policy",
            False,
        ),
        "sharepoint.pnp.tenant.read": _operation(
            "SharePointOnline", "Get-PnPTenant", "sharepoint.pnp.tenant", False
        ),
    }
)

# Intentionally excludes PowerShell interpolation and control characters. The one
# variable collector parameter is a mailbox UPN returned by Exchange.
_UPN = re.compile(
    r"[A-Za-z0-9_.+%-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?\.[A-Za-z]{2,63}"
)


def validate_operation(
    operation_id: str, collector_id: str, params: dict[str, Any]
) -> Operation:
    if type(operation_id) is not str or operation_id not in OPERATIONS:
        raise ValueError("Unknown PowerShell operation")
    operation = OPERATIONS[operation_id]
    if type(collector_id) is not str or collector_id not in operation.collectors:
        raise ValueError("Collector is not permitted to use this PowerShell operation")
    if type(params) is not dict or set(params) != set(operation.parameters):
        raise ValueError("Unexpected or missing PowerShell operation parameters")
    for key, kind in operation.parameters.items():
        value = params[key]
        if kind != "upn" or type(value) is not str or not _UPN.fullmatch(value):
            raise ValueError("Invalid PowerShell operation parameter")
    return operation


def operation_command(
    operation_id: str, collector_id: str, params: dict[str, Any]
) -> str:
    operation = validate_operation(operation_id, collector_id, params)
    # Names and types came from the registry; values passed the restrictive UPN
    # grammar. Single-quoted literals provide a second interpolation boundary.
    return operation.command + "".join(
        f" -{key} '{params[key]}'" for key in operation.parameters
    )
