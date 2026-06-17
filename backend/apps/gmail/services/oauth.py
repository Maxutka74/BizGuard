"""
apps/gmail/services/oauth.py

Google OAuth2 helpers:
  - build_authorization_url()   → redirect user to Google consent
  - exchange_code_for_tokens()  → get access + refresh token
  - refresh_access_token()      → silently refresh expired token
  - build_gmail_service()       → return authenticated googleapiclient resource
  - get_google_userinfo()       → fetch email + name from Google
"""
from __future__ import annotations

import logging
from typing import Optional

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "openid",
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/userinfo.profile",
]

_CLIENT_CONFIG = lambda: {  # noqa: E731
    "web": {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "redirect_uris": [settings.GOOGLE_REDIRECT_URI],
    }
}


def build_authorization_url(state: str) -> str:
    """Return the Google consent page URL to redirect the browser to."""
    import google_auth_oauthlib.flow as _flow

    flow = _flow.Flow.from_client_config(_CLIENT_CONFIG(), scopes=SCOPES)
    flow.redirect_uri = settings.GOOGLE_REDIRECT_URI
    url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
        state=state,
    )
    return url


def exchange_code_for_tokens(code: str) -> dict:
    """
    Exchange the OAuth2 authorization code for tokens.

    Returns:
        {
            "access_token": str,
            "refresh_token": str | None,
            "expiry": datetime | None,
        }
    """
    import google_auth_oauthlib.flow as _flow

    flow = _flow.Flow.from_client_config(_CLIENT_CONFIG(), scopes=SCOPES)
    flow.redirect_uri = settings.GOOGLE_REDIRECT_URI
    flow.fetch_token(code=code)
    creds = flow.credentials
    return {
        "access_token": creds.token,
        "refresh_token": creds.refresh_token,
        "expiry": creds.expiry,
    }


def _make_credentials(email_account):
    """Build a google.oauth2.credentials.Credentials from a stored EmailAccount."""
    import google.oauth2.credentials as _creds

    return _creds.Credentials(
        token=email_account.access_token,
        refresh_token=email_account.refresh_token,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=settings.GOOGLE_CLIENT_ID,
        client_secret=settings.GOOGLE_CLIENT_SECRET,
        scopes=SCOPES,
    )


def refresh_access_token(email_account) -> None:
    """Refresh the access token in-place and persist to DB if expired."""
    import google.auth.transport.requests as _req

    creds = _make_credentials(email_account)
    if email_account.is_token_expired:
        request = _req.Request()
        creds.refresh(request)
        email_account.access_token = creds.token
        if creds.expiry:
            expiry = creds.expiry
            if expiry.tzinfo is None:
                expiry = timezone.make_aware(expiry)
            email_account.token_expiry = expiry
        email_account.save(update_fields=["access_token", "token_expiry"])
        logger.info("Refreshed token for %s", email_account.email)


def build_gmail_service(email_account):
    """Return an authenticated Gmail API resource (v1)."""
    from googleapiclient.discovery import build

    refresh_access_token(email_account)
    creds = _make_credentials(email_account)
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def get_google_userinfo(access_token: str) -> Optional[dict]:
    """
    Fetch basic profile from Google.

    Returns:
        {"email": str, "name": str, "picture": str} or None on failure.
    """
    import requests

    try:
        resp = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as exc:
        logger.exception("Failed to fetch Google userinfo: %s", exc)
        return None
