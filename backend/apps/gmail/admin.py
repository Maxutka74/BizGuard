from django.contrib import admin
from apps.gmail.models import EmailAccount, EmailMessage


# @admin.register(EmailAccount)
# class EmailAccountAdmin(admin.ModelAdmin):
#     list_display = ["email", "user", "is_active", "connected_at", "last_synced_at"]
#     list_filter = ["is_active"]
#     search_fields = ["email", "user__email"]
#     readonly_fields = ["connected_at", "last_synced_at"]
#
#
# @admin.register(EmailMessage)
# class EmailMessageAdmin(admin.ModelAdmin):
#     list_display = [
#         "gmail_id", "subject", "sender", "domain",
#         "riskLevel", "threatScore", "date", "analysis_done",
#     ]
#     list_filter = ["riskLevel", "domainReputation", "analysis_done"]
#     search_fields = ["subject", "sender", "domain", "gmail_id"]
#     readonly_fields = ["synced_at", "gmail_id"]
#     ordering = ["-date"]
#
#     fieldsets = [
#         ("Email", {
#             "fields": ["account", "gmail_id", "subject", "sender", "senderName",
#                        "domain", "date", "body"],
#         }),
#         ("Domain Analysis", {
#             "fields": ["domainAge", "domainReputation", "lookalikeDomain", "domainScore"],
#         }),
#         ("AI Analysis", {
#             "fields": ["urgency", "fear", "credentialTheft", "financialFraud",
#                        "authorityImpersonation", "aiSummary", "aiScore"],
#         }),
#         ("Risk Assessment", {
#             "fields": ["threatScore", "riskLevel", "analysis_done"],
#         }),
#         ("Meta", {
#             "fields": ["synced_at"],
#         }),
#     ]
