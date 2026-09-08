"""Pydantic schemas for M365 connections."""

from datetime import datetime
import re
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator


def validate_sharepoint_binding(tenant_id, url, sharepoint_tenant_id, alias):
    """An optional connection binding must be complete and agree on tenant."""
    if not any(value is not None for value in (url, sharepoint_tenant_id, alias)):
        return
    if not all((url, sharepoint_tenant_id, alias)):
        raise ValueError(
            "SharePoint URL, tenant ID and certificate alias are required together"
        )
    if UUID(tenant_id) != UUID(sharepoint_tenant_id):
        raise ValueError("SharePoint tenant must match the selected M365 tenant")


class SharePointConfiguration(BaseModel):
    sharepoint_admin_url: str | None = None
    sharepoint_tenant_id: str | None = None
    sharepoint_certificate_alias: str | None = None

    @field_validator("sharepoint_admin_url")
    @classmethod
    def validate_admin_url(cls, value):
        if value is not None and not re.fullmatch(
            r"https://[a-z0-9][a-z0-9-]*-admin\.sharepoint\.com/?", value
        ):
            raise ValueError("Use an HTTPS SharePoint Online admin URL")
        return value.rstrip("/") if value else value

    @field_validator("sharepoint_tenant_id")
    @classmethod
    def validate_tenant(cls, value):
        return str(UUID(value)) if value is not None else None

    @field_validator("sharepoint_certificate_alias")
    @classmethod
    def validate_alias(cls, value):
        if value is not None and not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value
        ):
            raise ValueError("Use a configured certificate alias")
        return value


def validate_purview_binding(alias, organization):
    """The Purview certificate binding is all-or-nothing, like SharePoint's.

    It deliberately does NOT compare against ``tenant_id``: Connect-IPPSSession
    takes -Organization as the tenant primary .onmicrosoft.com domain, while
    ``tenant_id`` is commonly the tenant GUID. Comparing them would be a
    semantic lie, and it is the whole reason this column exists.
    """
    if alias is None and organization is None:
        return
    if not (alias and organization):
        raise ValueError(
            "Purview certificate alias and organization are required together"
        )


class PurviewConfiguration(BaseModel):
    compliance_certificate_alias: str | None = None
    compliance_organization: str | None = None

    @field_validator("compliance_certificate_alias")
    @classmethod
    def validate_compliance_alias(cls, value):
        if value is not None and not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", value
        ):
            raise ValueError("Use a configured certificate alias")
        return value

    @field_validator("compliance_organization")
    @classmethod
    def validate_compliance_organization(cls, value):
        if value is None:
            return None
        value = value.strip()
        if re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
            r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
            value,
        ):
            raise ValueError(
                "Purview organization must be the tenant primary "
                ".onmicrosoft.com domain, not a tenant GUID"
            )
        if not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9-]{0,62}\.onmicrosoft\.com",
            value,
            re.IGNORECASE,
        ):
            raise ValueError("Use the tenant primary .onmicrosoft.com domain")
        return value.lower()


class M365ConnectionBase(SharePointConfiguration, PurviewConfiguration):
    """Base schema for M365 connection."""

    name: str = Field(
        ...,
        min_length=1,
        max_length=255,
        description="Friendly name for this connection",
    )
    tenant_id: str = Field(
        ..., min_length=1, max_length=255, description="Azure AD tenant GUID"
    )
    client_id: str = Field(
        ..., min_length=1, max_length=255, description="App registration client ID"
    )


class M365ConnectionCreate(M365ConnectionBase):
    """Schema for creating an M365 connection."""

    client_secret: str = Field(
        ..., min_length=1, description="App registration client secret"
    )

    @model_validator(mode="after")
    def check_sharepoint_binding(self):
        validate_sharepoint_binding(
            self.tenant_id,
            self.sharepoint_admin_url,
            self.sharepoint_tenant_id,
            self.sharepoint_certificate_alias,
        )
        validate_purview_binding(
            self.compliance_certificate_alias,
            self.compliance_organization,
        )
        return self


class M365ConnectionUpdate(SharePointConfiguration, PurviewConfiguration):
    """Schema for updating an M365 connection."""

    name: str | None = Field(None, min_length=1, max_length=255)
    tenant_id: str | None = Field(None, min_length=1, max_length=255)
    client_id: str | None = Field(None, min_length=1, max_length=255)
    client_secret: str | None = Field(
        None, min_length=1, description="New client secret (if changing)"
    )
    is_active: bool | None = None


class M365ConnectionRead(M365ConnectionBase):
    """Schema for reading an M365 connection (without secret)."""

    id: int
    user_id: int
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class M365ConnectionTestResult(BaseModel):
    """Schema for connection test result."""

    success: bool
    message: str
    # Backwards-compatible display field (legacy)
    tenant_name: str | None = None

    # Preferred structured tenant details
    tenant_display_name: str | None = None
    default_domain: str | None = None
    verified_domains: list[str] | None = None
