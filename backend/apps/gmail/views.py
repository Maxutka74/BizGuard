from __future__ import annotations

import logging

from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle

from apps.gmail.models import EmailAccount, EmailMessage, TrustedSenderRule
from apps.gmail.serializers import (
    EmailDetailSerializer,
    EmailListSerializer,
    EmailAccountSerializer,
    EmailProgressSerializer,
    EmailProgressItemSerializer,
    ScanResponseSerializer,
    ScanStatusSerializer,
    StatsSerializer,
    TrustedSenderRuleSerializer,
)
from apps.gmail.services.queue import enqueue_ai_queue
from apps.gmail.services.sync import sync_account
from apps.licenses.services import get_user_capabilities

logger = logging.getLogger(__name__)


class ScanRateThrottle(UserRateThrottle):
    scope = "scan"


# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
# Email list   GET /api/gmail/emails/
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

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

    if EmailMessage.objects.filter(account=account).exclude(analysis_status="done").exists():
        _trigger_ai_queue(account.id)

    serializer = EmailListSerializer(qs, many=True)
    return Response({
        "emails": serializer.data,
        "total": qs.count(),
    })


# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
# Email stats   GET /api/gmail/emails/stats/
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def email_stats(request: Request) -> Response:
    account = _get_account_or_404(request)
    data = _stats_payload(account)
    if data["pendingAi"]:
        _trigger_ai_queue(account.id)
    serializer = StatsSerializer(data)
    return Response(serializer.data)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def email_progress(request: Request) -> Response:
    account = _get_account_or_404(request)
    qs = (
        EmailMessage.objects.filter(account=account)
        .only(
            "gmail_id",
            "analysis_status",
            "analysisSource",
            "riskLevel",
            "threatScore",
            "spamActionStatus",
            "spamActionAt",
            "synced_at",
        )
        .order_by("-date")
    )
    stats_data = _stats_payload(account)
    if stats_data["pendingAi"]:
        _trigger_ai_queue(account.id)
    payload = {
        "emails": EmailProgressItemSerializer(qs, many=True).data,
        "stats": stats_data,
        "serverTime": timezone.now(),
        "hasPending": stats_data["pendingAi"] > 0,
    }
    serializer = EmailProgressSerializer(payload)
    return Response(serializer.data)


# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
# Email detail   GET /api/gmail/emails/{id}/
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def email_detail(request: Request, email_id: str) -> Response:
    account = _get_account_or_404(request)
    message = get_object_or_404(EmailMessage, gmail_id=email_id, account=account)
    serializer = EmailDetailSerializer(message)
    return Response(serializer.data)


# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
# Rescan   POST /api/gmail/scan/
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

@api_view(["POST"])
@permission_classes([IsAuthenticated])
@throttle_classes([ScanRateThrottle])
def scan_emails(request: Request) -> Response:
    account = _get_account_or_404(request)
    capabilities = get_user_capabilities(request.user)
    max_allowed = int(capabilities.get("maxMessagesPerRun") or 30)
    requested_max = int(request.data.get("max_results", max_allowed))
    max_results = min(max(requested_max, 1), max_allowed)
    recent_lookback_days = int(capabilities.get("recentLookbackDays") or 1)
    priority_ai = bool(capabilities.get("priorityAi"))

    try:
        from apps.gmail.tasks import sync_gmail_account

        async_result = sync_gmail_account.delay(
            account.id,
            max_results,
            recent_lookback_days,
            priority_ai,
            True,
        )
        data = {
            "fetched": 0,
            "processed": 0,
            "created": 0,
            "updated": 0,
            "errors": 0,
            "scan_id": async_result.id,
            "queued": True,
            "message": "Сканування поставлено в чергу. Листи оновлюватимуться під час аналізу.",
        }
        serializer = ScanResponseSerializer(data)
        return Response(serializer.data, status=status.HTTP_202_ACCEPTED)
    except Exception:
        logger.info("Celery unavailable; running scan inline for %s", account.email)

    stats = sync_account(
        account,
        max_results=max_results,
        recent_lookback_days=recent_lookback_days,
        priority_ai=priority_ai,
        backfill_to_limit=True,
    )
    data = {
        **stats,
        "queued": False,
        "message": (
            f"Сканування завершено. Нових: {stats['created']}, "
            f"оновлено: {stats['updated']}, помилок: {stats['errors']}."
        ),
    }
    serializer = ScanResponseSerializer(data)
    return Response(serializer.data, status=status.HTTP_200_OK)


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def scan_status(request: Request, scan_id: str) -> Response:
    try:
        from celery.result import AsyncResult

        result = AsyncResult(scan_id)
        info = result.info if isinstance(result.info, dict) else {}
        data = {
            "state": info.get("state") or result.state,
            "fetched": int(info.get("fetched", 0) or 0),
            "processed": int(info.get("processed", 0) or 0),
            "created": int(info.get("created", 0) or 0),
            "updated": int(info.get("updated", 0) or 0),
            "errors": int(info.get("errors", 0) or 0),
            "pending_ai": int(info.get("pending_ai", 0) or 0),
            "ready": result.ready(),
        }
        serializer = ScanStatusSerializer(data)
        return Response(serializer.data)
    except Exception as exc:
        logger.exception("Could not read scan status for %s: %s", scan_id, exc)
        return Response(
            {
                "state": "UNKNOWN",
                "fetched": 0,
                "processed": 0,
                "created": 0,
                "updated": 0,
                "errors": 0,
                "pending_ai": 0,
                "ready": True,
            }
        )


# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
@api_view(["GET", "POST"])
@permission_classes([IsAuthenticated])
def trusted_sender_rules(request: Request) -> Response:
    capability_error = _trusted_sender_capability_error(request)
    if capability_error:
        return capability_error

    if request.method == "GET":
        rules = TrustedSenderRule.objects.filter(user=request.user)
        return Response({"rules": TrustedSenderRuleSerializer(rules, many=True).data})

    rule_type = str(request.data.get("ruleType") or request.data.get("rule_type") or "").strip().lower()
    value = str(request.data.get("value") or "").strip().lower().removeprefix("@")
    if rule_type not in {TrustedSenderRule.RULE_TYPE_EMAIL, TrustedSenderRule.RULE_TYPE_DOMAIN}:
        return Response({"detail": "Тип правила має бути email або domain."}, status=400)
    if not value:
        return Response({"detail": "Вкажіть значення правила."}, status=400)
    if rule_type == TrustedSenderRule.RULE_TYPE_EMAIL and "@" not in value:
        return Response({"detail": "Правило email у списку дозволених має містити @."}, status=400)

    active_value = request.data.get("active", True)
    active = active_value if isinstance(active_value, bool) else str(active_value).lower() not in {"0", "false", "no"}
    rule, _ = TrustedSenderRule.objects.update_or_create(
        user=request.user,
        rule_type=rule_type,
        value=value,
        defaults={"active": active},
    )
    return Response(TrustedSenderRuleSerializer(rule).data, status=status.HTTP_201_CREATED)


@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def trusted_sender_rule_delete(request: Request, rule_id: int) -> Response:
    capability_error = _trusted_sender_capability_error(request)
    if capability_error:
        return capability_error
    rule = get_object_or_404(TrustedSenderRule, pk=rule_id, user=request.user)
    rule.delete()
    return Response(status=status.HTTP_204_NO_CONTENT)


@api_view(["DELETE"])
@permission_classes([IsAuthenticated])
def disconnect_account(request: Request) -> Response:
    try:
        account = EmailAccount.objects.get(user=request.user, is_active=True)
        account.is_active = False
        account.save(update_fields=["is_active"])
        return Response({"message": "Gmail-акаунт відключено."})
    except EmailAccount.DoesNotExist:
        return Response({"detail": "Активний Gmail-акаунт не знайдено."}, status=404)


# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
# Account status   GET /api/gmail/auth/status/
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ

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


# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ
# Helpers
# в”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђв”Ђ


def _stats_payload(account: EmailAccount) -> dict:
    qs = EmailMessage.objects.filter(account=account)
    analyzed_qs = qs.filter(analysis_status="done")
    all_emails = list(analyzed_qs.values("riskLevel"))
    distribution = {"Critical": 0, "High": 0, "Medium": 0, "Safe": 0}
    for row in all_emails:
        level = row["riskLevel"]
        if level in distribution:
            distribution[level] += 1

    analyzed = len(all_emails)
    pending_ai = qs.exclude(analysis_status="done").count()
    return {
        "total": qs.count(),
        "analyzed": analyzed,
        "pendingAi": pending_ai,
        "suspicious": analyzed - distribution["Safe"],
        "high": distribution["High"] + distribution["Critical"],
        "critical": distribution["Critical"],
        "distribution": distribution,
        "lastScannedAt": account.last_synced_at,
    }


def _trusted_sender_capability_error(request: Request) -> Response | None:
    capabilities = get_user_capabilities(request.user)
    if capabilities.get("trustedSenderAllowlist"):
        return None
    return Response(
        {"detail": "Список довірених відправників доступний лише на річному тарифі."},
        status=403,
    )


def _get_account_or_404(request: Request) -> EmailAccount:
    """Return the active Gmail account created during the main Google login."""
    try:
        return EmailAccount.objects.get(user=request.user, is_active=True)
    except EmailAccount.DoesNotExist:
        pass

    from rest_framework.exceptions import NotFound
    raise NotFound(
        {
            "detail": "Gmail-акаунт ще не підключено. Увійдіть через Google ще раз.",
            "code": "gmail_not_connected",
        }
    )


def _trigger_sync(account: EmailAccount) -> None:
    try:
        from apps.gmail.tasks import sync_gmail_account
        caps = get_user_capabilities(account.user)
        sync_gmail_account.delay(
            account.id,
            int(caps.get("maxMessagesPerRun") or 30),
            int(caps.get("recentLookbackDays") or 1),
            bool(caps.get("priorityAi")),
            True,
        )
        logger.info("Celery sync task queued for %s", account.email)
    except Exception:
        logger.info("Running sync inline for %s", account.email)
        try:
            caps = get_user_capabilities(account.user)
            sync_account(
                account,
                max_results=int(caps.get("maxMessagesPerRun") or 30),
                recent_lookback_days=int(caps.get("recentLookbackDays") or 1),
                priority_ai=bool(caps.get("priorityAi")),
                backfill_to_limit=True,
            )
        except Exception as exc:
            logger.exception("Inline sync failed for %s: %s", account.email, exc)


def _trigger_ai_queue(account_id: int) -> None:
    enqueue_ai_queue(account_id, debounce_seconds=3)


