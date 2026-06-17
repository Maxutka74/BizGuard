"""
apps/gmail/serializers.py

DRF serializers producing JSON that matches the frontend TypeScript
EmailAnalysis interface in mockData.ts exactly — including camelCase
field names (the model stores them in camelCase for zero-renaming).
"""
from rest_framework import serializers
from apps.gmail.models import EmailAccount, EmailMessage


class EmailListSerializer(serializers.ModelSerializer):
    """
    Used by GET /api/gmail/emails/
    Matches all fields displayed in the Dashboard email table:
      id, subject, sender, senderName, domain, date, riskLevel,
      domainReputation, threatScore
    """
    id = serializers.CharField(source="gmail_id")

    class Meta:
        model = EmailMessage
        fields = [
            "id",
            "subject",
            "sender",
            "senderName",
            "domain",
            "date",
            "riskLevel",
            "domainReputation",
            "threatScore",
            "aiScore",
            "domainScore",
        ]


class EmailDetailSerializer(serializers.ModelSerializer):
    """
    Used by GET /api/gmail/emails/{id}/
    Full EmailAnalysis shape consumed by EmailDetail.tsx.
    """
    id = serializers.CharField(source="gmail_id")
    # lookalikeDomain is nullable — DRF renders None as null (matches TS: string | null)

    class Meta:
        model = EmailMessage
        fields = [
            # Core
            "id",
            "subject",
            "sender",
            "senderName",
            "domain",
            "date",
            "body",
            # Domain analysis
            "domainAge",
            "domainReputation",
            "lookalikeDomain",
            # AI analysis
            "urgency",
            "fear",
            "credentialTheft",
            "financialFraud",
            "authorityImpersonation",
            "aiSummary",
            # Scores
            "aiScore",
            "domainScore",
            "threatScore",
            "riskLevel",
        ]


class StatsSerializer(serializers.Serializer):
    """
    Used by GET /api/gmail/emails/stats/
    Drives the 4 stat cards + threat distribution bar on Dashboard.
    """
    total = serializers.IntegerField()
    suspicious = serializers.IntegerField()
    high = serializers.IntegerField()
    critical = serializers.IntegerField()
    distribution = serializers.DictField(child=serializers.IntegerField())
    lastScannedAt = serializers.DateTimeField(allow_null=True)


class OAuthInitSerializer(serializers.Serializer):
    """POST /api/gmail/auth/init/ response."""
    authorization_url = serializers.URLField()
    state = serializers.CharField()


class OAuthCallbackSerializer(serializers.Serializer):
    """POST /api/gmail/auth/callback/ request body."""
    code = serializers.CharField()
    state = serializers.CharField()


class ScanResponseSerializer(serializers.Serializer):
    """POST /api/gmail/scan/ response."""
    fetched = serializers.IntegerField()
    created = serializers.IntegerField()
    updated = serializers.IntegerField()
    errors = serializers.IntegerField()
    message = serializers.CharField()


class EmailAccountSerializer(serializers.ModelSerializer):
    class Meta:
        model = EmailAccount
        fields = ["id", "email", "is_active", "connected_at", "last_synced_at"]
