from django.shortcuts import get_object_or_404
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.emails.models import Email

from .models import ThreatAssessment
from .scoring import RISK_LEVELS
from .serializers import ThreatAssessmentSerializer


class EmailThreatScoreView(APIView):
    """GET /api/emails/<id>/threat/

    Returns the `aiScore` / `domainScore` / `threatScore` / `riskLevel`
    block consumed by the "THREAT SCORE" panel in EmailDetail.tsx.
    """

    def get(self, request, email_id: int):
        email = get_object_or_404(Email, pk=email_id)
        assessment = get_object_or_404(ThreatAssessment, email=email)
        return Response(ThreatAssessmentSerializer(assessment).data)


class ThreatStatsView(APIView):
    """GET /api/threats/stats/

    Returns the counts behind the Dashboard.tsx stat cards
    (Emails Analyzed / Suspicious / High Risk / Critical) and the
    "THREAT DISTRIBUTION" bar (per-riskLevel counts).
    """

    def get(self, request):
        total = ThreatAssessment.objects.count()
        suspicious = ThreatAssessment.objects.exclude(risk_level="Safe").count()
        high = ThreatAssessment.objects.filter(
            risk_level__in=["High", "Critical"]
        ).count()
        critical = ThreatAssessment.objects.filter(risk_level="Critical").count()

        distribution = {
            level: ThreatAssessment.objects.filter(risk_level=level).count()
            for level in RISK_LEVELS
        }

        return Response(
            {
                "total": total,
                "suspicious": suspicious,
                "high": high,
                "critical": critical,
                "distribution": distribution,
            }
        )
