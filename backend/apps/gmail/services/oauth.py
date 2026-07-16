"""Gmail credentials helpers for tokens obtained during the main Google login."""

from __future__ import annotations

import logging

from django.conf import settings
from django.utils import timezone


logger = logging.getLogger(__name__)

SCOPES = [
    "https://www.googleapis.com/auth/gmail.modify",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]


def _make_credentials(email_account):
    """Build Google credentials from the tokens stored for an EmailAccount."""
    import google.oauth2.credentials as google_credentials

    return google_credentials.Credentials(
        token=email_account.access_token,
        refresh_token=email_account.refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GOOGLE_OAUTH_CLIENT_ID,
        client_secret=settings.GOOGLE_OAUTH_CLIENT_SECRET,
        scopes=SCOPES,
    )


def refresh_access_token(email_account) -> None:
    """Refresh and persist an expired Gmail access token."""
    import google.auth.transport.requests as google_requests

    credentials = _make_credentials(email_account)
    if not email_account.is_token_expired:
        return

    credentials.refresh(google_requests.Request())
    email_account.access_token = credentials.token
    if credentials.expiry:
        expiry = credentials.expiry
        if expiry.tzinfo is None:
            expiry = timezone.make_aware(expiry)
        email_account.token_expiry = expiry
    email_account.save(update_fields=["access_token", "token_expiry"])
    logger.info("Refreshed token for %s", email_account.email)


def build_gmail_service(email_account):
    """Return an authenticated Gmail API v1 resource."""
    from googleapiclient.discovery import build

    refresh_access_token(email_account)
    credentials = _make_credentials(email_account)
    return build("gmail", "v1", credentials=credentials, cache_discovery=False)
