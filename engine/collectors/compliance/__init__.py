"""Security & Compliance collectors.

These collectors run Security & Compliance PowerShell cmdlets inside the
PowerShell HTTP service, which connects with Connect-IPPSSession.

Authentication is certificate-based and app-only: the service holds the
certificate and passes -CertificateFilePath, -CertificatePassword, -AppID and
-Organization. Microsoft documents no app-only access-token form for
Connect-IPPSSession, and -CertificateThumbPrint is Windows-only, so no token is
acquired or transmitted for this module. -Organization is the tenant's primary
.onmicrosoft.com domain, never a tenant GUID.

Authorization needs both halves:
  * the application role Exchange.ManageAsApp, published by Microsoft Exchange
    Online Protection (resourceAppId 00000007-0000-0ff1-ce00-000000000000,
    app role id 455e5cd2-84e8-4751-8344-5672145dfa17); and
  * a directory role on the service principal -- Global Reader or Security
    Reader is sufficient for the read-only cmdlets used here.

Microsoft documentation fetched 2026-09-06.
"""
