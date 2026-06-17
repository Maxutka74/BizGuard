from django.contrib import admin
from django.utils.html import format_html

from .models import DomainReputation


@admin.register(DomainReputation)
class DomainReputationAdmin(admin.ModelAdmin):
    list_display = (
        "domain",
        "reputation_badge",
        "domain_score",
        "domain_age",
        "lookalike_domain",
        "fetched_at",
        "is_stale_display",
    )
    list_filter = ("reputation",)
    search_fields = ("domain", "lookalike_domain")
    readonly_fields = (
        "fetched_at",
        "vt_malicious",
        "vt_suspicious",
        "vt_harmless",
        "vt_undetected",
        "vt_total_votes_malicious",
        "vt_total_votes_harmless",
        "vt_reputation",
        "vt_creation_date",
    )
    ordering = ("-fetched_at",)

    fieldsets = (
        (
            "Frontend Contract",
            {
                "fields": (
                    "domain",
                    "reputation",
                    "domain_score",
                    "domain_age",
                    "lookalike_domain",
                )
            },
        ),
        (
            "VirusTotal Raw Data",
            {
                "classes": ("collapse",),
                "fields": (
                    "vt_malicious",
                    "vt_suspicious",
                    "vt_harmless",
                    "vt_undetected",
                    "vt_total_votes_malicious",
                    "vt_total_votes_harmless",
                    "vt_reputation",
                    "vt_creation_date",
                ),
            },
        ),
        (
            "Cache Metadata",
            {"fields": ("fetched_at", "error")},
        ),
    )

    def reputation_badge(self, obj: DomainReputation) -> str:
        colors = {
            "Trusted": "#22c55e",
            "Suspicious": "#eab308",
            "Malicious": "#ef4444",
        }
        color = colors.get(obj.reputation, "#888")
        return format_html(
            '<span style="color:{};font-weight:700">{}</span>', color, obj.reputation
        )

    reputation_badge.short_description = "Reputation"

    def is_stale_display(self, obj: DomainReputation) -> str:
        return "⚠ Stale" if obj.is_stale() else "✓ Fresh"

    is_stale_display.short_description = "Cache Status"
