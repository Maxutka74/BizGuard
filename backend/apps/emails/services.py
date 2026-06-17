"""
EmailNormalizationService

Orchestrates:
  - Upsert Email from parsed dict (idempotent by message_id)
  - Upsert Attachments
  - Post-parse normalization hooks (domain extraction guard, snippet trim)
"""

import logging
from typing import Any
from django.db import transaction

from .models import Email, Attachment

logger = logging.getLogger(__name__)


class EmailNormalizationService:

    @staticmethod
    @transaction.atomic
    def upsert(parsed: dict[str, Any]) -> Email:
        """
        Insert or update an Email record from a parsed email dict.
        Idempotent: keyed on message_id.
        """
        message_id = parsed.get("message_id", "")
        if not message_id:
            raise ValueError("message_id is required for upsert.")

        # Normalize domain just in case parsers.py is bypassed
        sender_email = parsed.get("sender_email", "")
        if not parsed.get("sender_domain") and "@" in sender_email:
            parsed["sender_domain"] = sender_email.split("@", 1)[1].lower()

        # Trim snippet to model max_length
        snippet = parsed.get("snippet", "")
        if len(snippet) > 512:
            parsed["snippet"] = snippet[:509] + "…"

        email, created = Email.objects.update_or_create(
            message_id=message_id,
            defaults={
                "thread_id": parsed.get("thread_id", ""),
                "sender_name": parsed.get("sender_name", ""),
                "sender_email": parsed.get("sender_email", ""),
                "sender_domain": parsed.get("sender_domain", ""),
                "recipients_to": parsed.get("recipients_to", []),
                "recipients_cc": parsed.get("recipients_cc", []),
                "recipients_bcc": parsed.get("recipients_bcc", []),
                "subject": parsed.get("subject", ""),
                "body_plain": parsed.get("body_plain", ""),
                "body_html": parsed.get("body_html", ""),
                "snippet": parsed.get("snippet", ""),
                "sent_at": parsed.get("sent_at"),
                "has_attachments": parsed.get("has_attachments", False),
                "attachment_count": parsed.get("attachment_count", 0),
                "raw_headers": parsed.get("raw_headers", {}),
                "labels": parsed.get("labels", []),
            },
        )

        action = "created" if created else "updated"
        logger.debug("Email %s: message_id=%s id=%s", action, message_id, email.id)
        return email

    @staticmethod
    @transaction.atomic
    def upsert_attachments(email: Email, att_data: list[dict]) -> None:
        """
        Replace attachment records for an email with the freshly parsed set.
        Uses attachment_id as the dedup key.
        """
        existing_ids = set(
            email.attachments.values_list("attachment_id", flat=True)
        )
        new_records = []
        for att in att_data:
            if att.get("attachment_id") not in existing_ids:
                new_records.append(
                    Attachment(
                        email=email,
                        filename=att.get("filename", ""),
                        mime_type=att.get("mime_type", ""),
                        size_bytes=att.get("size_bytes", 0),
                        attachment_id=att.get("attachment_id", ""),
                    )
                )

        if new_records:
            Attachment.objects.bulk_create(new_records)
            logger.debug("Created %d attachments for email id=%s", len(new_records), email.id)

    @staticmethod
    def get_normalized_detail(email_id: int) -> Email:
        """
        Fetch email with attachments pre-fetched (avoids N+1 on detail view).
        """
        return (
            Email.objects
            .prefetch_related("attachments")
            .get(pk=email_id)
        )
