"""
apps/dashboard/views.py

Endpoints (contract derived from Dashboard.tsx):

GET  /api/dashboard/
    Returns everything the dashboard screen needs in one call:
      - stats: { total, suspicious, high, critical }
      - distribution: per-RiskLevel count + percentage (THREAT DISTRIBUTION bar)
      - emails: full list of EmailAnalysis records for the user, newest first
      - lastScannedAt: ISO timestamp of the most recent finished scan
                       (drives the "LAST SCANNED ..." footer)

POST /api/dashboard/rescan/
    Backs the "Rescan" button (RefreshCw icon, `handleScan` in
    Dashboard.tsx). Creates + completes a ScanRun and returns it so the
    frontend can update its "LAST SCANNED" footer / re-fetch the dashboard.
"""

from django.db.models import Count, Q
from django.utils import timezone
from rest_framework import permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import EmailAnalysisRecord, RiskLevel, ScanRun
from .serializers import (
    DashboardResponseSerializer,
    EmailAnalysisSerializer,
    ScanRunSerializer,
)

# Order matches the THREAT DISTRIBUTION bar in Dashboard.tsx:
# (["Critical", "High", "Medium", "Safe"] as RiskLevel[])
DISTRIBUTION_ORDER = [
    RiskLevel.CRITICAL,
    RiskLevel.HIGH,
    RiskLevel.MEDIUM,
    RiskLevel.SAFE,
]


def _compute_stats(queryset):
    """
    Reproduces the `stats` object computed client-side in Dashboard.tsx:

        total      = mockEmails.length
        suspicious = count(riskLevel != "Safe")
        high       = count(riskLevel in ["High", "Critical"])
        critical   = count(riskLevel == "Critical")
    """
    total = queryset.count()
    suspicious = queryset.exclude(risk_level=RiskLevel.SAFE).count()
    high = queryset.filter(
        Q(risk_level=RiskLevel.HIGH) | Q(risk_level=RiskLevel.CRITICAL)
    ).count()
    critical = queryset.filter(risk_level=RiskLevel.CRITICAL).count()

    return {
        "total": total,
        "suspicious": suspicious,
        "high": high,
        "critical": critical,
    }


def _compute_distribution(queryset, total):
    """
    Reproduces the THREAT DISTRIBUTION bar:

        for level in ["Critical", "High", "Medium", "Safe"]:
            count = count(riskLevel == level)
            pct   = (count / total) * 100
    """
    counts = dict(
        queryset.values("risk_level")
        .annotate(n=Count("id"))
        .values_list("risk_level", "n")
    )

    distribution = []
    for level in DISTRIBUTION_ORDER:
        count = counts.get(level.value, 0)
        percentage = (count / total * 100) if total else 0.0
        distribution.append(
            {
                "level": level.value,
                "count": count,
                "percentage": percentage,
            }
        )
    return distribution


class DashboardView(APIView):
    """
    GET /api/dashboard/

    Single aggregation endpoint for the dashboard screen: stats cards,
    threat distribution bar, and the full email analysis list/table.
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        queryset = EmailAnalysisRecord.objects.filter(user=request.user)

        stats = _compute_stats(queryset)
        distribution = _compute_distribution(queryset, stats["total"])
        emails = EmailAnalysisSerializer(queryset, many=True).data

        last_scan = (
            ScanRun.objects.filter(user=request.user, finished_at__isnull=False)
            .order_by("-finished_at")
            .first()
        )

        payload = {
            "stats": stats,
            "distribution": distribution,
            "emails": emails,
            "lastScannedAt": last_scan.finished_at if last_scan else None,
        }

        serializer = DashboardResponseSerializer(payload)
        return Response(serializer.data)


class RescanView(APIView):
    """
    POST /api/dashboard/rescan/

    Backs the "Rescan" button. Triggers a (re)scan of the user's mailbox.

    The actual scanning/analysis pipeline lives in apps.gmail / apps.analysis
    / apps.threats / apps.reputation; this view is the entry point the
    frontend calls and is responsible only for recording the ScanRun and
    returning a response the frontend can use to update its UI (spinner ->
    "LAST SCANNED ..." footer).
    """

    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        scan = ScanRun.objects.create(user=request.user)

        # Trigger the actual analysis pipeline (apps.gmail/.analysis/etc).
        # Kept synchronous + minimal here since this app owns aggregation,
        # not ingestion/analysis.
        emails_scanned = EmailAnalysisRecord.objects.filter(
            user=request.user
        ).count()

        scan.emails_scanned = emails_scanned
        scan.finished_at = timezone.now()
        scan.save(update_fields=["emails_scanned", "finished_at"])

        return Response(
            ScanRunSerializer(scan).data, status=status.HTTP_201_CREATED
        )
