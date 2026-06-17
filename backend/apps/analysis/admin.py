from django.contrib import admin

from .models import EmailAnalysisResult


@admin.register(EmailAnalysisResult)
class EmailAnalysisResultAdmin(admin.ModelAdmin):
    list_display = (
        "gmail_message_id",
        "risk_level",
        "threat_score",
        "ai_score",
        "domain_score",
        "created_at",
    )
    list_filter = ("risk_level",)
    search_fields = ("gmail_message_id",)
    readonly_fields = (
        "gmail_message_id",
        "urgency",
        "fear",
        "credential_theft",
        "financial_fraud",
        "authority_impersonation",
        "ai_summary",
        "ai_score",
        "domain_score",
        "threat_score",
        "risk_level",
        "created_at",
        "updated_at",
    )
    ordering = ("-created_at",)
