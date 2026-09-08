"""Database models for the AutoAudit backend API."""

from app.models.user import User, Role
from app.models.auth_session import AuthSession
from app.models.oauth_account import OAuthAccount
from app.models.m365_connection import M365Connection
from app.models.azure_connection import AzureConnection
from app.models.gcp_connection import GCPConnection
from app.models.aws_connection import AWSConnection
from app.models.platform import Platform
from app.models.scan_result import ScanResult
from app.models.scan_dispatch import ScanDispatch
from app.models.manual_scan_result_detail import ManualScanResultDetail
from app.models.compliance import Scan
from app.models.evidence_validation import EvidenceValidation
from app.models.evidence_artifact import EvidenceArtifact
from app.models.evidence_audit_event import EvidenceAuditEvent
from app.models.manual_evidence import (
    ManualEvidenceRecord,
    ManualEvidenceRevision,
)
from app.models.contact import ContactSubmission, SubmissionNote, SubmissionHistory
from app.models.user_settings import UserSettings
from app.models.scan_result_factprint import ScanResultFactprint
from app.models.drift import (
    DriftBaseline,
    DriftRun,
    DriftEvent,
    DriftNotification,
)

__all__ = [
    "User",
    "AuthSession",
    "Role",
    "OAuthAccount",
    "M365Connection",
    "AzureConnection",
    "GCPConnection",
    "AWSConnection",
    "Platform",
    "ScanResult",
    "ScanDispatch",
    "ManualScanResultDetail",
    "Scan",
    "EvidenceValidation",
    "EvidenceArtifact",
    "EvidenceAuditEvent",
    "ManualEvidenceRecord",
    "ManualEvidenceRevision",
    "ContactSubmission",
    "SubmissionNote",
    "SubmissionHistory",
    "UserSettings",
    "ScanResultFactprint",
    "DriftBaseline",
    "DriftRun",
    "DriftEvent",
    "DriftNotification",
]
