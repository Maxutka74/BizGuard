"""
DRF serializers producing the camelCase JSON contract consumed by the frontend.
"""
from rest_framework import serializers

from apps.gmail.models import EmailAccount, EmailMessage, TrustedSenderRule
from apps.gmail.services.ai_providers import (
    final_summary_for_risk,
    sanitize_security_recommendations_for_risk,
)


class EmailListSerializer(serializers.ModelSerializer):
    id = serializers.CharField(source="gmail_id")
    analysisSource = serializers.SerializerMethodField()

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
            "analysis_status",
            "analysisSource",
            "spamActionStatus",
            "spamActionAt",
        ]

    def get_analysisSource(self, obj):
        return _public_analysis_source(obj)


class EmailDetailSerializer(serializers.ModelSerializer):
    id = serializers.CharField(source="gmail_id")
    analysisSource = serializers.SerializerMethodField()
    analysisNotice = serializers.SerializerMethodField()
    aiSummary = serializers.SerializerMethodField()
    recommendations = serializers.SerializerMethodField()

    class Meta:
        model = EmailMessage
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
            "verdict",
            "recommendations",
            "aiScore",
            "domainScore",
            "threatScore",
            "riskLevel",
            "securitySignals",
            "attachmentScore",
            "attachmentScanSummary",
            "scannedAttachments",
            "urlScanSummary",
            "urlScore",
            "scannedUrls",
            "hasPhishingUrl",
            "hasMaliciousUrl",
            "analysis_status",
            "analysisSource",
            "analysisNotice",
            "spamActionStatus",
            "spamActionAt",
            "spamActionError",
        ]

    def get_analysisSource(self, obj):
        return _public_analysis_source(obj)

    def get_analysisNotice(self, obj):
        if obj.analysis_status == "done":
            return ""
        if obj.analysisSource == "Waiting for reputation":
            return "Очікується перевірка URL/вкладень, інші листи продовжують аналізуватись."
        if obj.analysis_status in {"pending_ai", "processing"}:
            return "AI аналіз ще виконується. Попередні доменні, URL та локальні сигнали вже враховані."
        if obj.analysis_status == "failed":
            return "AI аналіз тимчасово недоступний. Лист очікує повторної перевірки."
        return "Аналіз ще не завершено. Частина локальних перевірок може бути попередньою."

    def get_aiSummary(self, obj):
        if obj.analysis_status != "done":
            return ""
        return final_summary_for_risk(obj.aiSummary, obj.riskLevel)

    def get_recommendations(self, obj):
        if obj.analysis_status != "done":
            return []
        recommendations = obj.recommendations if isinstance(obj.recommendations, list) else []
        return sanitize_security_recommendations_for_risk(
            recommendations,
            obj.riskLevel,
            {
                "scanned_urls": obj.scannedUrls or [],
                "scanned_attachments": obj.scannedAttachments or [],
            },
        )



class EmailProgressItemSerializer(serializers.ModelSerializer):
    id = serializers.CharField(source="gmail_id")
    analysisSource = serializers.SerializerMethodField()
    syncedAt = serializers.DateTimeField(source="synced_at")

    class Meta:
        model = EmailMessage
        fields = [
            "id",
            "analysis_status",
            "analysisSource",
            "riskLevel",
            "threatScore",
            "spamActionStatus",
            "spamActionAt",
            "syncedAt",
        ]

    def get_analysisSource(self, obj):
        return _public_analysis_source(obj)
def _public_analysis_source(obj):
    if obj.analysis_status == "done":
        if obj.analysisSource == "AI unavailable":
            return "AI unavailable"
        return "AI analyzer"
    if obj.analysis_status == "failed":
        return "AI unavailable"
    if obj.analysisSource == "Waiting for reputation":
        return "Waiting for reputation"
    return "AI pending"


class StatsSerializer(serializers.Serializer):
    total = serializers.IntegerField()
    analyzed = serializers.IntegerField()
    pendingAi = serializers.IntegerField()
    suspicious = serializers.IntegerField()
    high = serializers.IntegerField()
    critical = serializers.IntegerField()
    distribution = serializers.DictField(child=serializers.IntegerField())
    lastScannedAt = serializers.DateTimeField(allow_null=True)



class EmailProgressSerializer(serializers.Serializer):
    emails = serializers.ListField(child=serializers.DictField())
    stats = StatsSerializer()
    serverTime = serializers.DateTimeField()
    hasPending = serializers.BooleanField()
class OAuthInitSerializer(serializers.Serializer):
    authorization_url = serializers.URLField()
    state = serializers.CharField()


class OAuthCallbackSerializer(serializers.Serializer):
    code = serializers.CharField()
    state = serializers.CharField()


class ScanResponseSerializer(serializers.Serializer):
    fetched = serializers.IntegerField()
    processed = serializers.IntegerField()
    created = serializers.IntegerField()
    updated = serializers.IntegerField()
    errors = serializers.IntegerField()
    pending_ai = serializers.IntegerField(required=False)
    message = serializers.CharField(required=False)
    scan_id = serializers.CharField(required=False)
    queued = serializers.BooleanField(required=False)


class ScanStatusSerializer(serializers.Serializer):
    state = serializers.CharField()
    fetched = serializers.IntegerField()
    processed = serializers.IntegerField()
    created = serializers.IntegerField()
    updated = serializers.IntegerField()
    errors = serializers.IntegerField()
    pending_ai = serializers.IntegerField()
    ready = serializers.BooleanField()


class EmailAccountSerializer(serializers.ModelSerializer):
    reconnectRequired = serializers.SerializerMethodField()
    gmailModifyEnabled = serializers.SerializerMethodField()

    class Meta:
        model = EmailAccount
        fields = [
            "id",
            "email",
            "is_active",
            "last_synced_at",
            "connected_at",
            "gmailModifyEnabled",
            "reconnectRequired",
        ]

    def get_reconnectRequired(self, obj):
        return not obj.has_gmail_modify_scope

    def get_gmailModifyEnabled(self, obj):
        return obj.has_gmail_modify_scope


class TrustedSenderRuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = TrustedSenderRule
        fields = ["id", "rule_type", "value", "active", "created_at"]





