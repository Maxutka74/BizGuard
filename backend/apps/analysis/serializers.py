"""
Serializers for apps/analysis.

AnalyseEmailRequestSerializer  — validates POST /api/analysis/analyse/
AIAnalysisResultSerializer     — serializes stored results (camelCase for frontend)
"""

from rest_framework import serializers

from .models import EmailAnalysisResult


class AnalyseEmailRequestSerializer(serializers.Serializer):
    """
    Input payload for the analyse endpoint.
    The frontend triggers analysis by providing the raw email fields.
    """

    gmail_message_id = serializers.CharField(max_length=255)
    subject = serializers.CharField(max_length=998)  # RFC 2822 max
    sender = serializers.EmailField()
    body = serializers.CharField(allow_blank=True)
    # domain_score is computed by apps/reputation and passed in by the
    # orchestrating email endpoint so we can store the final threat_score here.
    domain_score = serializers.IntegerField(min_value=0, max_value=100, default=0)


class AIAnalysisResultSerializer(serializers.ModelSerializer):
    """
    Serialises EmailAnalysisResult using camelCase field names matching the
    frontend EmailAnalysis TypeScript interface.
    """

    credentialTheft = serializers.IntegerField(source="credential_theft")
    financialFraud = serializers.IntegerField(source="financial_fraud")
    authorityImpersonation = serializers.IntegerField(source="authority_impersonation")
    aiSummary = serializers.CharField(source="ai_summary")
    aiScore = serializers.IntegerField(source="ai_score")
    domainScore = serializers.IntegerField(source="domain_score")
    threatScore = serializers.IntegerField(source="threat_score")
    riskLevel = serializers.CharField(source="risk_level")

    class Meta:
        model = EmailAnalysisResult
        fields = [
            "gmail_message_id",
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
            "created_at",
            "updated_at",
        ]
        read_only_fields = fields
