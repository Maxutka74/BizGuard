from django.db import models
from django.utils import timezone


class Email(models.Model):
    """
    Normalized email record.
    Raw email is parsed on ingestion; frontend consumes clean fields only.
    """

    # --- Identity ---
    message_id = models.CharField(max_length=512, unique=True, db_index=True)
    thread_id = models.CharField(max_length=256, blank=True, db_index=True)

    # --- Sender (parsed) ---
    sender_name = models.CharField(max_length=256, blank=True)
    sender_email = models.EmailField(max_length=320, db_index=True)
    sender_domain = models.CharField(max_length=253, blank=True, db_index=True)

    # --- Recipients ---
    recipients_to = models.JSONField(default=list)    # [{"name": "", "email": ""}]
    recipients_cc = models.JSONField(default=list)
    recipients_bcc = models.JSONField(default=list)

    # --- Content ---
    subject = models.TextField(blank=True)
    body_plain = models.TextField(blank=True)         # stripped plain text
    body_html = models.TextField(blank=True)          # original HTML (stored, never sent raw to frontend)
    snippet = models.CharField(max_length=512, blank=True)  # first ~200 chars of body_plain

    # --- Dates ---
    sent_at = models.DateTimeField(null=True, blank=True)
    received_at = models.DateTimeField(default=timezone.now, db_index=True)

    # --- Attachments ---
    has_attachments = models.BooleanField(default=False)
    attachment_count = models.PositiveSmallIntegerField(default=0)

    # --- Metadata ---
    raw_headers = models.JSONField(default=dict)      # full header dict for analysis
    is_read = models.BooleanField(default=False)
    labels = models.JSONField(default=list)           # e.g. ["INBOX", "IMPORTANT"]

    # --- Risk signals (set by analysis app, read by frontend) ---
    risk_score = models.FloatField(null=True, blank=True)
    is_flagged = models.BooleanField(default=False)
    flag_reason = models.CharField(max_length=512, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-received_at"]
        indexes = [
            models.Index(fields=["sender_domain", "received_at"]),
            models.Index(fields=["is_flagged", "received_at"]),
        ]

    def __str__(self):
        return f"[{self.sender_email}] {self.subject[:60]}"


class Attachment(models.Model):
    email = models.ForeignKey(Email, on_delete=models.CASCADE, related_name="attachments")
    filename = models.CharField(max_length=512)
    mime_type = models.CharField(max_length=256, blank=True)
    size_bytes = models.PositiveIntegerField(default=0)
    attachment_id = models.CharField(max_length=256, blank=True)  # provider-side ID

    def __str__(self):
        return f"{self.filename} ({self.email_id})"
