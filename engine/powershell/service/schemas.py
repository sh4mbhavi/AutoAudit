"""Pydantic schemas for PowerShell service API."""

import re
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

if __package__:
    from .executor import validate_tenant_id
    from .operations import validate_batch, validate_operation
else:
    from executor import validate_tenant_id
    from operations import validate_batch, validate_operation

_GUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)
_CERT_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_SHAREPOINT_ADMIN_URL_RE = re.compile(
    r"^https://[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?-admin\.sharepoint\.com$",
    re.IGNORECASE,
)
_ONMICROSOFT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}\.onmicrosoft\.com$")


class ExecuteRequest(BaseModel):
    """Request to execute a PowerShell cmdlet."""

    model_config = ConfigDict(extra="forbid", strict=True)

    operation_id: str
    collector_id: str
    params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Parameters to pass to the cmdlet",
    )
    tenant_id: str = Field(description="Azure AD tenant ID (GUID or verified domain)")
    token: Optional[str] = Field(
        default=None,
        description="Access token for Exchange/Compliance/Teams",
    )
    graph_token: Optional[str] = Field(
        default=None,
        description="Graph API token (required for Teams module)",
    )
    client_id: Optional[str] = Field(
        default=None,
        description="App registration client ID (required for SharePointOnline)",
    )
    sharepoint_admin_url: Optional[str] = Field(
        default=None,
        description="SharePoint admin URL (required for SharePointOnline)",
    )
    certificate_alias: Optional[str] = Field(
        default=None,
        description="Certificate alias resolved by the service (required for SharePointOnline)",
    )
    compliance_certificate_alias: Optional[str] = Field(
        default=None,
        description="Certificate alias resolved by the service (required for Compliance)",
    )
    compliance_organization: Optional[str] = Field(
        default=None,
        description="Connect-IPPSSession -Organization primary .onmicrosoft.com domain (required for Compliance)",
    )

    @field_validator("tenant_id")
    @classmethod
    def check_tenant_id_format(cls, v: str) -> str:
        return validate_tenant_id(v)

    @field_validator("client_id")
    @classmethod
    def check_client_id_format(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        stripped = v.strip()
        if not _GUID_RE.match(stripped):
            raise ValueError(
                "Invalid client_id format. Must be a GUID "
                "(e.g. 12345678-1234-1234-1234-123456789abc)."
            )
        return stripped

    @field_validator("sharepoint_admin_url")
    @classmethod
    def check_sharepoint_admin_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        stripped = v.strip().rstrip("/")
        if not _SHAREPOINT_ADMIN_URL_RE.match(stripped):
            raise ValueError(
                "Invalid sharepoint_admin_url format. "
                "Must be https://<tenant>-admin.sharepoint.com."
            )
        return stripped

    @field_validator("certificate_alias")
    @classmethod
    def check_certificate_alias(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        stripped = v.strip()
        if not _CERT_ALIAS_RE.match(stripped):
            raise ValueError(
                "Invalid certificate_alias format. "
                "Must be an alias name (letters, digits, underscore, hyphen)."
            )
        return stripped

    @field_validator("compliance_certificate_alias")
    @classmethod
    def check_compliance_certificate_alias(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        stripped = v.strip()
        if not _CERT_ALIAS_RE.match(stripped):
            raise ValueError(
                "Invalid compliance_certificate_alias format. "
                "Must be an alias name (letters, digits, underscore, hyphen)."
            )
        return stripped

    @field_validator("compliance_organization")
    @classmethod
    def check_compliance_organization(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        stripped = v.strip()
        # The GUID branch is checked first so a tenant GUID always gets the
        # message that names the .onmicrosoft.com form it must be replaced with.
        if _GUID_RE.match(stripped):
            raise ValueError(
                "compliance_organization must be the tenant primary "
                ".onmicrosoft.com domain, not a tenant GUID."
            )
        if not _ONMICROSOFT_RE.match(stripped):
            raise ValueError(
                "Invalid compliance_organization format. "
                "Must be the tenant primary domain, e.g. contoso.onmicrosoft.com."
            )
        return stripped

    @property
    def module(self) -> str:
        return validate_operation(
            self.operation_id, self.collector_id, self.params
        ).module

    @model_validator(mode="after")
    def check_module_auth_fields(self) -> "ExecuteRequest":
        validate_operation(self.operation_id, self.collector_id, self.params)
        if self.module == "SharePointOnline":
            missing = [
                name
                for name, value in (
                    ("client_id", self.client_id),
                    ("sharepoint_admin_url", self.sharepoint_admin_url),
                    ("certificate_alias", self.certificate_alias),
                )
                if not value
            ]
            if missing:
                raise ValueError(
                    "SharePointOnline requires " + ", ".join(missing) + "."
                )
            if self.token:
                raise ValueError("SharePointOnline must not include token.")
            if self.graph_token:
                raise ValueError("SharePointOnline must not include graph_token.")
            if self.compliance_certificate_alias or self.compliance_organization:
                raise ValueError(
                    "Compliance authentication fields are only permitted for Compliance."
                )
            return self

        elif self.module == "Compliance":
            missing = [
                name
                for name, value in (
                    ("client_id", self.client_id),
                    (
                        "compliance_certificate_alias",
                        self.compliance_certificate_alias,
                    ),
                    ("compliance_organization", self.compliance_organization),
                )
                if not value
            ]
            if missing:
                raise ValueError("Compliance requires " + ", ".join(missing) + ".")
            if self.token:
                raise ValueError("Compliance must not include token.")
            if self.graph_token:
                raise ValueError("Compliance must not include graph_token.")
            if self.sharepoint_admin_url:
                raise ValueError("Compliance must not include sharepoint_admin_url.")
            if self.certificate_alias:
                raise ValueError(
                    "Compliance must not include certificate_alias; "
                    "use compliance_certificate_alias."
                )
            return self

        if any(
            value is not None
            for value in (
                self.client_id,
                self.sharepoint_admin_url,
                self.certificate_alias,
                self.compliance_certificate_alias,
                self.compliance_organization,
            )
        ):
            raise ValueError(
                "Certificate authentication fields are only permitted for SharePointOnline and Compliance"
            )
        if self.module != "Teams" and self.graph_token is not None:
            raise ValueError("graph_token is only permitted for Teams")
        if not self.token:
            raise ValueError("token is required")
        if self.module == "Teams" and not self.graph_token:
            raise ValueError("Teams module requires graph_token")
        return self


class ExecuteResponse(BaseModel):
    """Response from PowerShell cmdlet execution."""

    success: bool = Field(description="Whether execution succeeded")
    data: Any = Field(default=None, description="Cmdlet output as JSON")
    error: Optional[str] = Field(default=None, description="Error message if failed")


class HealthResponse(BaseModel):
    """Health check response."""

    status: str = "ok"


class BatchOperation(BaseModel):
    """One reviewed operation inside a batch."""

    model_config = ConfigDict(extra="forbid", strict=True)

    operation_id: str
    collector_id: str
    params: Dict[str, Any] = Field(default_factory=dict)


class ExecuteBatchRequest(BaseModel):
    """Several reviewed operations of ONE module, for one tenant, in one session.

    Deliberately a separate model rather than a list field on ExecuteRequest:
    the authentication fields are per session, not per operation, and modelling
    them once is what makes "one batch is one module and one tenant identity"
    checkable rather than conventional. Every module rule ExecuteRequest applies
    is applied here against the batch's single resolved module.
    """

    model_config = ConfigDict(extra="forbid", strict=True)

    operations: list[BatchOperation] = Field(min_length=1)
    tenant_id: str = Field(description="Azure AD tenant ID (GUID or verified domain)")
    token: Optional[str] = Field(default=None)
    graph_token: Optional[str] = Field(default=None)
    client_id: Optional[str] = Field(default=None)
    sharepoint_admin_url: Optional[str] = Field(default=None)
    certificate_alias: Optional[str] = Field(default=None)
    compliance_certificate_alias: Optional[str] = Field(default=None)
    compliance_organization: Optional[str] = Field(default=None)

    _check_tenant_id_format = field_validator("tenant_id")(
        ExecuteRequest.check_tenant_id_format.__func__
    )
    _check_client_id_format = field_validator("client_id")(
        ExecuteRequest.check_client_id_format.__func__
    )
    _check_sharepoint_admin_url = field_validator("sharepoint_admin_url")(
        ExecuteRequest.check_sharepoint_admin_url.__func__
    )
    _check_certificate_alias = field_validator("certificate_alias")(
        ExecuteRequest.check_certificate_alias.__func__
    )
    _check_compliance_certificate_alias = field_validator(
        "compliance_certificate_alias"
    )(ExecuteRequest.check_compliance_certificate_alias.__func__)
    _check_compliance_organization = field_validator("compliance_organization")(
        ExecuteRequest.check_compliance_organization.__func__
    )

    @property
    def module(self) -> str:
        module, _ = validate_batch(
            [operation.model_dump() for operation in self.operations]
        )
        return module

    @model_validator(mode="after")
    def check_module_auth_fields(self) -> "ExecuteBatchRequest":
        """Reuse ExecuteRequest's module rules verbatim against the batch module.

        The batch's first operation is used as the representative because
        validate_batch has already proved every operation resolves to the same
        module, and the module is the only thing those rules depend on.
        """
        module = self.module
        representative = self.operations[0]
        ExecuteRequest(
            operation_id=representative.operation_id,
            collector_id=representative.collector_id,
            params=representative.params,
            tenant_id=self.tenant_id,
            token=self.token,
            graph_token=self.graph_token,
            client_id=self.client_id,
            sharepoint_admin_url=self.sharepoint_admin_url,
            certificate_alias=self.certificate_alias,
            compliance_certificate_alias=self.compliance_certificate_alias,
            compliance_organization=self.compliance_organization,
        )
        assert module  # nosec B101 - resolved above; documents the invariant
        return self


class ExecuteBatchResponse(BaseModel):
    """Response from a batched execution."""

    success: bool = Field(description="Whether every operation in the batch succeeded")
    data: Optional[list] = Field(
        default=None, description="Cmdlet output per operation, in request order"
    )
    error: Optional[str] = Field(default=None, description="Error message if failed")
