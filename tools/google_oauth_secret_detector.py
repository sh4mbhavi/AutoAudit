"""Detect Google OAuth client secrets, including unquoted .example assignments.

The pinned detect-secrets 1.5.0 keyword detector requires quotes in .example
files. This provider-format detector closes that gap without network requests.
"""

import re

from detect_secrets.plugins.base import RegexBasedDetector


class GoogleOAuthClientSecretDetector(RegexBasedDetector):
    secret_type = (
        "Google OAuth Client Secret"  # pragma: allowlist secret - detector label
    )
    denylist = (re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{20,}\b"),)
