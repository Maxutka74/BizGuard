from django.contrib import admin

from .models import EmailAnalysisRecord, ScanRun


# @admin.register(EmailAnalysisRecord)
# class EmailAnalysisRecordAdmin(admin.ModelAdmin):
#     list_display = (
#         "subject",
#         "sender",
#         "domain",
#         "user",
#         "risk_level",
#         "domain_reputation",
#         "date",
#     )
#     list_filter = ("risk_level", "domain_reputation")
#     search_fields = ("subject", "sender", "domain", "sender_name")
#     date_hierarchy = "date"
#
#
# @admin.register(ScanRun)
# class ScanRunAdmin(admin.ModelAdmin):
#     list_display = ("id", "user", "started_at", "finished_at", "emails_scanned")
#     list_filter = ("user",)
