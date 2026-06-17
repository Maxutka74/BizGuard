from django.contrib import admin
from .models import Email, Attachment


class AttachmentInline(admin.TabularInline):
    model = Attachment
    extra = 0
    readonly_fields = ["filename", "mime_type", "size_bytes", "attachment_id"]


@admin.register(Email)
class EmailAdmin(admin.ModelAdmin):
    list_display = [
        "sender_email", "sender_domain", "subject", "received_at",
        "is_read", "is_flagged", "risk_score", "attachment_count",
    ]
    list_filter = ["is_flagged", "is_read", "sender_domain", "received_at"]
    search_fields = ["sender_email", "sender_name", "subject", "message_id"]
    readonly_fields = [
        "message_id", "thread_id", "raw_headers", "created_at", "updated_at",
        "body_html",  # Never edit HTML directly
    ]
    inlines = [AttachmentInline]
    ordering = ["-received_at"]


@admin.register(Attachment)
class AttachmentAdmin(admin.ModelAdmin):
    list_display = ["filename", "mime_type", "size_bytes", "email"]
    search_fields = ["filename", "email__sender_email"]
