import requests
import logging
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from .models import User

logger = logging.getLogger(__name__)

GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
PUBLIC_GOOGLE_SCOPES = ["openid", "email", "profile"]
GMAIL_SCOPES = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/gmail.modify",
]


class GoogleOAuthError(Exception):
    pass


def exchange_code_for_tokens(code: str, redirect_uri: str) -> dict:
    """Exchange OAuth authorization code for Google access/refresh tokens."""
    resp = requests.post(
        GOOGLE_TOKEN_URL,
        data={
            "code": code,
            "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
            "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
        timeout=10,
    )
    if resp.status_code != 200:
        raise GoogleOAuthError(
            f"Token exchange failed ({resp.status_code}): {resp.text}"
        )
    return resp.json()


def fetch_google_userinfo(access_token: str) -> dict:
    """Fetch Google profile data."""
    resp = requests.get(
        GOOGLE_USERINFO_URL,
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10,
    )
    if resp.status_code != 200:
        raise GoogleOAuthError(
            f"Userinfo fetch failed ({resp.status_code}): {resp.text}"
        )
    return resp.json()


def get_or_create_public_user_from_google(token_data: dict, userinfo: dict) -> User:
    """Create/update a user for the purchase site without connecting Gmail."""
    google_id = userinfo["sub"]
    email = userinfo["email"]
    expiry = None
    if token_data.get("expires_in"):
        expiry = timezone.now() + timedelta(seconds=int(token_data["expires_in"]))

    user = User.objects.filter(google_id=google_id).first()
    created = False
    if not user:
        user = User.objects.filter(email__iexact=email).first()
    if not user:
        user = User.objects.create(
            google_id=google_id,
            email=email,
            name=userinfo.get("name", ""),
            avatar_url=userinfo.get("picture"),
            gmail_connected=False,
        )
        created = True

    user.google_id = google_id
    user.email = email
    user.name = userinfo.get("name", user.name)
    user.avatar_url = userinfo.get("picture", user.avatar_url)
    user.google_access_token = token_data.get("access_token")
    if token_data.get("refresh_token"):
        user.google_refresh_token = token_data["refresh_token"]
    user.google_token_expiry = expiry
    user.save()

    logger.info("Public Google OAuth %s user: %s", "created" if created else "updated", user.email)
    return user
def get_or_create_user_from_google(token_data: dict, userinfo: dict, trigger_initial_scan: bool = True) -> User:
    google_id = userinfo["sub"]
    email = userinfo["email"]
    expiry = None
    if token_data.get("expires_in"):
        expiry = timezone.now() + timedelta(seconds=int(token_data["expires_in"]))

    user = User.objects.filter(google_id=google_id).first()
    created = False
    if not user:
        user = User.objects.filter(email__iexact=email).first()
    if not user:
        user = User.objects.create(
            google_id=google_id,
            email=email,
            name=userinfo.get("name", ""),
            avatar_url=userinfo.get("picture"),
            gmail_connected=True,
        )
        created = True

    # Update existing user data
    user.google_id = google_id
    user.email = email
    user.name = userinfo.get("name", user.name)
    user.avatar_url = userinfo.get("picture", user.avatar_url)
    user.google_access_token = token_data.get("access_token")
    if token_data.get("refresh_token"):
        user.google_refresh_token = token_data["refresh_token"]
    user.google_token_expiry = expiry
    user.gmail_connected = True
    user.save()

    logger.info("Google OAuth %s user: %s", "created" if created else "updated", user.email)

    # в”Ђв”Ђ HACKATHON FIX: Р°РІС‚Рѕ-СЃС‚РІРѕСЂСЋС”РјРѕ EmailAccount РѕРґСЂР°Р·Сѓ РїС–СЃР»СЏ Р»РѕРіС–РЅСѓ в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
    # РўРѕРєРµРЅРё РІР¶Рµ С” РЅР° User вЂ” РїСЂРѕСЃС‚Рѕ РєРѕРїС–СЋС”РјРѕ С—С… РІ EmailAccount С‰РѕР±
    # /api/gmail/emails/ С– /api/gmail/emails/stats/ РѕРґСЂР°Р·Сѓ РїСЂР°С†СЋРІР°Р»Рё.
    _sync_email_account(user, token_data, expiry, trigger_initial_scan=trigger_initial_scan)

    return user


def _sync_email_account(user: User, token_data: dict, expiry, trigger_initial_scan: bool = True) -> None:
    """Create or update EmailAccount from the fresh Google tokens."""
    try:
        from apps.gmail.models import EmailAccount

        access_token = token_data.get("access_token", "")
        refresh_token = token_data.get("refresh_token", "")

        account, created = EmailAccount.objects.update_or_create(
            user=user,
            defaults={
                "email": user.email,
                "access_token": access_token,
                # refresh_token РїСЂРёС…РѕРґРёС‚СЊ С‚С–Р»СЊРєРё РїСЂРё РїРµСЂС€РѕРјСѓ Р»РѕРіС–РЅС–;
                # РїСЂРё РїРѕРІС‚РѕСЂРЅРѕРјСѓ вЂ” Р·Р±РµСЂС–РіР°С”РјРѕ СЃС‚Р°СЂРёР№
                **({"refresh_token": refresh_token} if refresh_token else {}),
                "token_expiry": expiry,
                "granted_scopes": token_data.get("scope") or " ".join(GMAIL_SCOPES),
                "is_active": True,
            },
        )
        logger.info(
            "Google OAuth EmailAccount %s for %s",
            "created" if created else "updated",
            user.email,
        )
        if trigger_initial_scan:
            _trigger_initial_scan(account)
    except Exception as exc:
        # РќРµ Р»Р°РјР°С”РјРѕ Р»РѕРіС–РЅ СЏРєС‰Рѕ С‰РѕСЃСЊ РїС–С€Р»Рѕ РЅРµ С‚Р°Рє
        logger.warning("Could not sync EmailAccount after Google OAuth: %s", exc)


def _trigger_initial_scan(account) -> None:
    try:
        from apps.gmail.tasks import sync_gmail_account
        from apps.licenses.services import get_user_capabilities

        caps = get_user_capabilities(account.user)
        sync_gmail_account.delay(
            account.id,
            int(caps.get("maxMessagesPerRun") or 30),
            int(caps.get("recentLookbackDays") or 1),
            bool(caps.get("priorityAi")),
            True,
        )
        logger.info("Initial Gmail scan queued for %s", account.email)
    except Exception:
        logger.info("Celery unavailable; running initial Gmail scan inline for %s", account.email)
        try:
            from apps.gmail.services.sync import sync_account
            from apps.licenses.services import get_user_capabilities

            caps = get_user_capabilities(account.user)
            sync_account(
                account,
                max_results=int(caps.get("maxMessagesPerRun") or 30),
                recent_lookback_days=int(caps.get("recentLookbackDays") or 1),
                priority_ai=bool(caps.get("priorityAi")),
                backfill_to_limit=True,
            )
        except Exception as exc:
            logger.warning("Initial Gmail scan failed for %s: %s", account.email, exc)


