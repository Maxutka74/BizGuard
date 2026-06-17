import requests
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from .models import User

GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
GMAIL_SCOPES = [
    "openid",
    "email",
    "profile",
    "https://www.googleapis.com/auth/gmail.readonly",
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


def get_or_create_user_from_google(token_data: dict, userinfo: dict) -> User:
    google_id = userinfo["sub"]
    email = userinfo["email"]
    expiry = None
    if token_data.get("expires_in"):
        expiry = timezone.now() + timedelta(seconds=int(token_data["expires_in"]))

    user, created = User.objects.get_or_create(
        google_id=google_id,
        defaults={
            "email": email,
            "name": userinfo.get("name", ""),
            "avatar_url": userinfo.get("picture"),
            "gmail_connected": True,
        },
    )

    # Update existing user data
    user.email = email
    user.name = userinfo.get("name", user.name)
    user.avatar_url = userinfo.get("picture", user.avatar_url)
    user.google_access_token = token_data.get("access_token")
    if token_data.get("refresh_token"):
        user.google_refresh_token = token_data["refresh_token"]
    user.google_token_expiry = expiry
    user.gmail_connected = True
    user.save()

    print(
        f"[GOOGLE OAUTH] {'Created' if created else 'Updated'} user: "
        f"{user.email}"
    )

    # ── HACKATHON FIX: авто-створюємо EmailAccount одразу після логіну ───────
    # Токени вже є на User — просто копіюємо їх в EmailAccount щоб
    # /api/gmail/emails/ і /api/gmail/emails/stats/ одразу працювали.
    _sync_email_account(user, token_data, expiry)

    return user


def _sync_email_account(user: User, token_data: dict, expiry) -> None:
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
                # refresh_token приходить тільки при першому логіні;
                # при повторному — зберігаємо старий
                **({"refresh_token": refresh_token} if refresh_token else {}),
                "token_expiry": expiry,
                "is_active": True,
            },
        )
        print(
            f"[GOOGLE OAUTH] EmailAccount {'created' if created else 'updated'} "
            f"for {user.email}"
        )
    except Exception as exc:
        # Не ламаємо логін якщо щось пішло не так
        print(f"[GOOGLE OAUTH] WARNING: could not sync EmailAccount: {exc}")

