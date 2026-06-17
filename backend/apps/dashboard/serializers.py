"""
apps/dashboard/serializers.py

Field names are deliberately camelCase to match the frontend
`EmailAnalysis` interface 1:1 (see mockData.ts), so the React code can
consume API responses with zero remapping.
"""

from rest_framework import serializers

from .models import EmailAnalysisRecord, ScanRun


class EmailAnalysisSerializer(serializers.ModelSerializer):
    """
    Serializes EmailAnalysisRecord -> exactly the `EmailAnalysis` shape
    used by Dashboard.tsx / EmailDetail.tsx.
    """

    id = serializers.CharField(read_only=True)
    senderName = serializers.CharField(source="sender_name")
    domainAge = serializers.CharField(source="domain_age")
    domainReputation = serializers.CharField(source="domain_reputation")
    lookalikeDomain = serializers.CharField(
        source="lookalike_domain", allow_null=True
    )
    credentialTheft = serializers.IntegerField(source="credential_theft")
    financialFraud = serializers.IntegerField(source="financial_fraud")
    authorityImpersonation = serializers.IntegerField(
        source="authority_impersonation"
    )
    aiSummary = serializers.CharField(source="ai_summary")
    aiScore = serializers.IntegerField(source="ai_score")
    domainScore = serializers.IntegerField(source="domain_score")
    threatScore = serializers.IntegerField(source="threat_score")
    riskLevel = serializers.CharField(source="risk_level")

    class Meta:
        model = EmailAnalysisRecord
        fields = [
            "id",
            "subject",
            "sender",
            "senderName",
            "domain",
            "date",
            "body",
            "domainAge",
            "domainReputation",
            "lookalikeDomain",
            "urgency",
            "fear",
            "credentialTheft",
            "financialFraud",
            "authorityImpersonation",
            "aiSummary",
            "aiScore",
            "domainScore",
            "threatScore",
            "riskLevel",
        ]


class DashboardStatsSerializer(serializers.Serializer):
    """Matches the 4 stats cards on the dashboard."""

    total = serializers.IntegerField()
    suspicious = serializers.IntegerField()
    high = serializers.IntegerField()
    critical = serializers.IntegerField()


class ThreatDistributionSerializer(serializers.Serializer):
    """
    Matches the THREAT DISTRIBUTION bar:
    one entry per RiskLevel with count + percentage of total.
    """

    level = serializers.CharField()
    count = serializers.IntegerField()
    percentage = serializers.FloatField()


class DashboardResponseSerializer(serializers.Serializer):
    """Top-level shape returned by GET /api/dashboard/."""

    stats = DashboardStatsSerializer()
    distribution = ThreatDistributionSerializer(many=True)
    emails = EmailAnalysisSerializer(many=True)
    lastScannedAt = serializers.DateTimeField(allow_null=True)


class ScanRunSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanRun
        fields = ["id", "started_at", "finished_at", "emails_scanned"]
