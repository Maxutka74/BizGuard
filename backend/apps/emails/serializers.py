"""
Serializers for the emails app.

Three shapes are served to the frontend:
  1. EmailListSerializer   — inbox/list view (lightweight, no body)
  2. EmailDetailSerializer — detail screen (full body, attachments, risk)
  3. EmailIngestSerializer — internal: validate raw Gmail message before parsing
"""

from rest_framework import serializers
from .models import Email, Attachment
from .parsers import strip_html


# ---------------------------------------------------------------------------
# Attachment
# ---------------------------------------------------------------------------

class AttachmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Attachment
        fields = ["id", "filename", "mime_type", "size_bytes"]


# ---------------------------------------------------------------------------
# List view — shown in inbox/email list screen
# ---------------------------------------------------------------------------

class EmailListSerializer(serializers.ModelSerializer):
    """
    Lightweight shape for list screens.
    Frontend fields observed: sender_name, sender_email, subject, snippet,
    received_at (formatted), is_read, is_flagged, has_attachments, risk_score.
    """
    sender = serializers.SerializerMethodField()
    received_at_formatted = serializers.SerializerMethodField()

    class Meta:
        model = Email
        fields = [
            "id",
            "message_id",
            "sender",
            "subject",
            "snippet",
            "received_at",
            "received_at_formatted",
            "is_read",
            "is_flagged",
            "has_attachments",
            "attachment_count",
            "risk_score",
            "labels",
        ]

    def get_sender(self, obj: Email) -> dict:
        return {
            "name": obj.sender_name,
            "email": obj.sender_email,
            "domain": obj.sender_domain,
        }

    def get_received_at_formatted(self, obj: Email) -> str:
        """Human-readable date for the list row (e.g. 'Jun 12, 2:45 PM')."""
        if not obj.received_at:
            return ""
        return obj.received_at.strftime("%-d %b, %-I:%M %p")


# ---------------------------------------------------------------------------
# Detail view — shown on the email detail screen
# ---------------------------------------------------------------------------

class EmailDetailSerializer(serializers.ModelSerializer):
    """
    Full email detail.
    Frontend needs: sender (name + email + domain), recipients, subject,
    body (clean text), sent_at (formatted), attachments, risk metadata.
    HTML body is intentionally NOT exposed — frontend receives clean text only.
    """
    sender = serializers.SerializerMethodField()
    recipients_to = serializers.SerializerMethodField()
    recipients_cc = serializers.SerializerMethodField()
    sent_at_formatted = serializers.SerializerMethodField()
    received_at_formatted = serializers.SerializerMethodField()
    attachments = AttachmentSerializer(many=True, read_only=True)
    body = serializers.SerializerMethodField()
    risk = serializers.SerializerMethodField()

    class Meta:
        model = Email
        fields = [
            "id",
            "message_id",
            "thread_id",
            "sender",
            "recipients_to",
            "recipients_cc",
            "subject",
            "body",                   # clean plain text
            "snippet",
            "sent_at",
            "sent_at_formatted",
            "received_at",
            "received_at_formatted",
            "is_read",
            "is_flagged",
            "flag_reason",
            "has_attachments",
            "attachment_count",
            "attachments",
            "labels",
            "risk",
        ]

    def get_sender(self, obj: Email) -> dict:
        return {
            "name": obj.sender_name or obj.sender_email,
            "email": obj.sender_email,
            "domain": obj.sender_domain,
            "initials": _get_initials(obj.sender_name or obj.sender_email),
        }

    def get_recipients_to(self, obj: Email) -> list:
        return obj.recipients_to or []

    def get_recipients_cc(self, obj: Email) -> list:
        return obj.recipients_cc or []

    def get_body(self, obj: Email) -> dict:
        """
        Return both plain text and a safe HTML version.
        Frontend can choose which to render.
        - plain: stripped, safe for <pre> or whitespace-preserved div
        - html:  re-sanitized HTML (tags allowed: p, br, b, i, ul, ol, li, a)
          Frontend should render via dangerouslySetInnerHTML only if html is present.
        """
        plain = obj.body_plain or strip_html(obj.body_html)
        return {
            "plain": plain,
            "has_html": bool(obj.body_html),
        }

    def get_sent_at_formatted(self, obj: Email) -> str:
        if not obj.sent_at:
            return ""
        return obj.sent_at.strftime("%B %-d, %Y at %-I:%M %p")

    def get_received_at_formatted(self, obj: Email) -> str:
        if not obj.received_at:
            return ""
        return obj.received_at.strftime("%B %-d, %Y at %-I:%M %p")

    def get_risk(self, obj: Email) -> dict:
        return {
            "score": obj.risk_score,
            "is_flagged": obj.is_flagged,
            "reason": obj.flag_reason,
            "level": _risk_level(obj.risk_score),
        }


# ---------------------------------------------------------------------------
# Ingest serializer (internal — used by Gmail sync service)
# ---------------------------------------------------------------------------

class GmailMessageIngestSerializer(serializers.Serializer):
    """
    Validates the raw Gmail API message dict before handing it to parsers.py.
    """
    id = serializers.CharField(max_length=512)
    threadId = serializers.CharField(max_length=256, required=False, default="")
    labelIds = serializers.ListField(child=serializers.CharField(), required=False, default=list)
    payload = serializers.DictField()

    def validate_payload(self, value: dict) -> dict:
        if "headers" not in value:
            raise serializers.ValidationError("payload must contain 'headers'.")
        return value


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_initials(name: str) -> str:
    """'John Doe' → 'JD', 'john@example.com' → 'J'"""
    parts = name.strip().split()
    if len(parts) >= 2:
        return (parts[0][0] + parts[-1][0]).upper()
    if parts:
        return parts[0][0].upper()
    return "?"


def _risk_level(score: float | None) -> str:
    """Map numeric risk score to frontend label."""
    if score is None:
        return "unknown"
    if score >= 0.75:
        return "high"
    if score >= 0.40:
        return "medium"
    return "low"
