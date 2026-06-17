from __future__ import annotations

import logging
import secrets

from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response

from apps.gmail.models import EmailAccount, EmailMessage
from apps.gmail.serializers import (
    EmailDetailSerializer,
    EmailListSerializer,
    EmailAccountSerializer,
    ScanResponseSerializer,
    StatsSerializer,
)
from apps.gmail.services.oauth import (
    build_authorization_url,
    exchange_code_for_tokens,
    get_google_userinfo,
)
from apps.gmail.services.sync import sync_account

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Email list   GET /api/gmail/emails/
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def email_list(request: Request) -> Response:
    account = _get_account_or_404(request)
    qs = EmailMessage.objects.filter(account=account)

    search = request.query_params.get("search", "").strip()
    if search:
        from django.db.models import Q
        qs = qs.filter(
            Q(subject__icontains=search)
            | Q(sender__icontains=search)
            | Q(domain__icontains=search)
        )

    risk_level = request.query_params.get("risk_level", "").strip()
    if risk_level and risk_level != "All":
        qs = qs.filter(riskLevel=risk_level)

    ordering = request.query_params.get("ordering", "-date")
    allowed_orderings = {
        "date", "-date",
        "threatScore", "-threatScore",
        "riskLevel", "-riskLevel",
        "sender", "-sender",
        "subject", "-subject",
    }
    if ordering not in allowed_orderings:
        ordering = "-date"
    qs = qs.order_by(ordering)

    serializer = EmailListSerializer(qs, many=True)
    return Response({
        "emails": serializer.data,
        "total": qs.count(),
    })


# ─────────────────────────────────────────────────────────────────────────────
# Email stats   GET /api/gmail/emails/stats/
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def email_stats(request: Request) -> Response:
    account = _get_account_or_404(request)
    qs = EmailMessage.objects.filter(account=account)

    all_emails = list(qs.values("riskLevel"))
    total = len(all_emails)
    distribution = {"Critical": 0, "High": 0, "Medium": 0, "Safe": 0}
    for row in all_emails:
        lvl = row["riskLevel"]
        if lvl in distribution:
            distribution[lvl] += 1

    suspicious = total - distribution["Safe"]
    high = distribution["High"] + distribution["Critical"]
    critical = distribution["Critical"]

    data = {
        "total": total,
        "suspicious": suspicious,
        "high": high,
        "critical": critical,
        "distribution": distribution,
        "lastScannedAt": account.last_synced_at,
    }
    serializer = StatsSerializer(data)
    return Response(serializer.data)


# ─────────────────────────────────────────────────────────────────────────────
# Email detail   GET /api/gmail/emails/{id}/
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def email_detail(request: Request, email_id: str) -> Response:
    account = _get_account_or_404(request)
    message = get_object_or_404(EmailMessage, gmail_id=email_id, account=account)
    serializer = EmailDetailSerializer(message)
    return Response(serializer.data)


# ─────────────────────────────────────────────────────────────────────────────
# Rescan   POST /api/gmail/scan/
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def scan_emails(request: Request) -> Response:
    account = _get_account_or_404(request)
    max_results = int(request.data.get("max_results", 50))
    max_results = min(max(max_results, 1), 200)

    stats = sync_account(account, max_results=max_results)
    data = {
        **stats,
        "message": (
            f"Scan complete. {stats['created']} new, "
            f"{stats['updated']} updated, {stats['errors']} errors."
        ),
    }
    serializer = ScanResponseSerializer(data)
    return Response(serializer.data, status=status.HTTP_200_OK)


# ─────────────────────────────────────────────────────────────────────────────
# OAuth init   GET /api/gmail/auth/init/
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def oauth_init(request: Request) -> Response:
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state
    url = build_authorization_url(state=state)
    return Response({"authorization_url": url, "state": state})


# ─────────────────────────────────────────────────────────────────────────────
# OAuth callback   GET /api/gmail/auth/callback/
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def oauth_callback(request: Request) -> Response:
    code = request.query_params.get("code")
    state = request.query_params.get("state")
    error = request.query_params.get("error")

    if error:
        return Response({"detail": f"Google OAuth error: {error}"}, status=400)
    if not code:
        return Response({"detail": "Missing authorization code."}, status=400)

    session_state = request.session.get("oauth_state")
    if session_state and state != session_state:
        return Response({"detail": "Invalid OAuth state."}, status=400)

    try:
        tokens = exchange_code_for_tokens(code)
    except Exception as exc:
        logger.exception("Token exchange failed: %s", exc)
        return Response({"detail": "Failed to exchange authorization code."}, status=502)

    userinfo = get_google_userinfo(tokens["access_token"])
    if not userinfo or not userinfo.get("email"):
        return Response({"detail": "Could not retrieve Google account email."}, status=502)

    gmail_email = userinfo["email"]
    expiry = tokens.get("expiry")
    if expiry and expiry.tzinfo is None:
        from django.utils import timezone as tz
        expiry = tz.make_aware(expiry)

    account, created = EmailAccount.objects.update_or_create(
        user=request.user,
        defaults={
            "email": gmail_email,
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token", ""),
            "token_expiry": expiry,
            "is_active": True,
        },
    )

    _trigger_sync(account)

    serializer = EmailAccountSerializer(account)
    return Response(
        {"account": serializer.data, "created": created, "message": "Gmail account connected."},
        status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Disconnect   DELETE /api/gmail/auth/disconnect/
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def disconnect_account(request: Request) -> Response:
    try:
        account = EmailAccount.objects.get(user=request.user, is_active=True)
        account.is_active = False
        account.save(update_fields=["is_active"])
        return Response({"message": "Gmail account disconnected."})
    except EmailAccount.DoesNotExist:
        return Response({"detail": "No active Gmail account found."}, status=404)


# ─────────────────────────────────────────────────────────────────────────────
# Account status   GET /api/gmail/auth/status/
# ─────────────────────────────────────────────────────────────────────────────

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def account_status(request: Request) -> Response:
    try:
        account = EmailAccount.objects.get(user=request.user, is_active=True)
        return Response({
            "connected": True,
            "account": EmailAccountSerializer(account).data,
        })
    except EmailAccount.DoesNotExist:
        return Response({"connected": False})


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _get_account_or_404(request: Request) -> EmailAccount:
    """
    Return user's active EmailAccount.

    HACKATHON FIX: якщо EmailAccount не існує, пробуємо авто-створити
    його з токенів allauth SocialToken (якщо використовується allauth),
    або повертаємо 404 з зрозумілим повідомленням.
    """
    try:
        return EmailAccount.objects.get(user=request.user, is_active=True)
    except EmailAccount.DoesNotExist:
        pass

    # Спроба авто-створення з allauth SocialToken
    account = _try_create_account_from_allauth(request.user)
    if account:
        return account

    from rest_framework.exceptions import NotFound
    raise NotFound(
        "No Gmail account connected. "
        "Please connect via GET /api/gmail/auth/init/ or POST /api/gmail/scan/ "
        "after connecting via /api/accounts/google/."
    )


def _try_create_account_from_allauth(user) -> "EmailAccount | None":
    """
    Якщо юзер залогінився через allauth Google OAuth (accounts app),
    його access_token вже є в SocialToken. Беремо його і створюємо
    EmailAccount автоматично — без повторного OAuth flow.
    """
    try:
        from allauth.socialaccount.models import SocialToken, SocialApp
        token_qs = SocialToken.objects.filter(
            account__user=user,
            account__provider="google",
        ).select_related("account__user").first()

        if not token_qs:
            return None

        gmail_email = user.email
        if not gmail_email:
            return None

        account, _ = EmailAccount.objects.update_or_create(
            user=user,
            defaults={
                "email": gmail_email,
                "access_token": token_qs.token,
                "refresh_token": token_qs.token_secret or "",
                "token_expiry": token_qs.expires_at,
                "is_active": True,
            },
        )
        logger.info(
            "Auto-created EmailAccount for %s from allauth SocialToken", gmail_email
        )
        # Запускаємо початковий синк у фоні
        _trigger_sync(account)
        return account

    except Exception as exc:
        logger.debug("Could not auto-create EmailAccount from allauth: %s", exc)
        return None


def _trigger_sync(account: EmailAccount) -> None:
    try:
        from apps.gmail.tasks import sync_gmail_account
        sync_gmail_account.delay(account.id)
        logger.info("Celery sync task queued for %s", account.email)
    except Exception:
        logger.info("Running sync inline for %s", account.email)
        try:
            sync_account(account)
        except Exception as exc:
            logger.exception("Inline sync failed for %s: %s", account.email, exc)

