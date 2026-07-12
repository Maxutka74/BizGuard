"""
Email parsing and normalization layer.

Responsibilities:
  - Parse raw email dicts (from Gmail API or IMAP) into clean model fields
  - Strip HTML → plain text
  - Extract sender domain
  - Build frontend-ready normalized representation
"""

import re
import html
import logging
from datetime import datetime, timezone
from email.utils import parseaddr, parsedate_to_datetime
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HTML → plain text
# ---------------------------------------------------------------------------

# Tags whose content we want to completely drop (scripts, styles, etc.)
_DROP_TAG_RE = re.compile(
    r"<(script|style|head)[^>]*>.*?</\1>",
    re.DOTALL | re.IGNORECASE,
)
# Block-level tags that should become newlines
_BLOCK_TAG_RE = re.compile(
    r"</?(?:p|div|br|li|tr|blockquote|h[1-6])[^>]*>",
    re.IGNORECASE,
)
# Any remaining HTML tag
_TAG_RE = re.compile(r"<[^>]+>")
# Collapse excessive whitespace / blank lines
_WHITESPACE_RE = re.compile(r"[ \t]+")
_NEWLINES_RE = re.compile(r"\n{3,}")


def strip_html(raw_html: str) -> str:
    """
    Convert HTML email body to readable plain text.
    Preserves paragraph structure via newlines.
    """
    if not raw_html:
        return ""

    text = raw_html
    # Remove script/style blocks entirely
    text = _DROP_TAG_RE.sub("", text)
    # Block tags → newline
    text = _BLOCK_TAG_RE.sub("\n", text)
    # Remove all remaining tags
    text = _TAG_RE.sub("", text)
    # Decode HTML entities (&amp; &nbsp; etc.)
    text = html.unescape(text)
    # Normalize horizontal whitespace
    text = _WHITESPACE_RE.sub(" ", text)
    # Collapse 3+ blank lines to 2
    text = _NEWLINES_RE.sub("\n\n", text)

    return text.strip()


# ---------------------------------------------------------------------------
# Sender parsing
# ---------------------------------------------------------------------------

def parse_address(raw: str) -> dict[str, str]:
    """
    Parse 'Name <email@domain.com>' → {"name": "Name", "email": "email@domain.com"}
    """
    name, email_addr = parseaddr(raw or "")
    return {
        "name": name.strip(),
        "email": email_addr.strip().lower(),
    }


def parse_address_list(raw: str) -> list[dict[str, str]]:
    """
    Parse comma-separated address list into [{name, email}, …].
    """
    if not raw:
        return []
    results = []
    for part in raw.split(","):
        parsed = parse_address(part.strip())
        if parsed["email"]:
            results.append(parsed)
    return results


def extract_domain(email_addr: str) -> str:
    """
    'user@example.com' → 'example.com'
    Returns empty string if the address is malformed.
    """
    if not email_addr or "@" not in email_addr:
        return ""
    return email_addr.split("@", 1)[1].lower().strip()


# ---------------------------------------------------------------------------
# Date parsing
# ---------------------------------------------------------------------------

def parse_email_date(raw_date: str) -> datetime | None:
    """
    Parse RFC 2822 date header → aware datetime (UTC).
    Returns None on failure instead of raising.
    """
    if not raw_date:
        return None
    try:
        dt = parsedate_to_datetime(raw_date)
        # Ensure UTC-aware
        return dt.astimezone(timezone.utc)
    except Exception:
        logger.debug("Could not parse email date: %r", raw_date)
        return None


# ---------------------------------------------------------------------------
# Snippet generation
# ---------------------------------------------------------------------------

def make_snippet(plain_text: str, max_length: int = 200) -> str:
    """
    First `max_length` characters of plain text, stripped of leading/trailing whitespace.
    """
    text = plain_text.strip()
    if len(text) <= max_length:
        return text
    return text[:max_length].rstrip() + "…"


# ---------------------------------------------------------------------------
# Gmail API payload → normalized dict
# ---------------------------------------------------------------------------

def _extract_headers(payload: dict) -> dict[str, str]:
    """Flatten Gmail's header list into a plain dict (last value wins)."""
    result: dict[str, str] = {}
    for h in payload.get("headers", []):
        result[h["name"].lower()] = h["value"]
    return result


def _get_body_parts(payload: dict, plain_parts: list, html_parts: list) -> None:
    """Recursively collect text/plain and text/html parts from Gmail payload."""
    mime = payload.get("mimeType", "")
    body = payload.get("body", {})

    if mime == "text/plain":
        data = body.get("data", "")
        if data:
            import base64
            plain_parts.append(base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace"))

    elif mime == "text/html":
        data = body.get("data", "")
        if data:
            import base64
            html_parts.append(base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace"))

    for part in payload.get("parts", []):
        _get_body_parts(part, plain_parts, html_parts)


def parse_gmail_message(raw_message: dict[str, Any]) -> dict[str, Any]:
    """
    Transform a raw Gmail API message object into a normalized dict
    that maps 1-to-1 with the Email model fields.

    Args:
        raw_message: Full Gmail API message resource (format=full).

    Returns:
        Dict ready to be passed to EmailNormalizer.from_parsed() or
        used directly to create/update an Email instance.
    """
    payload = raw_message.get("payload", {})
    headers = _extract_headers(payload)

    # --- Sender ---
    sender_parsed = parse_address(headers.get("from", ""))

    # --- Recipients ---
    to_list = parse_address_list(headers.get("to", ""))
    cc_list = parse_address_list(headers.get("cc", ""))
    bcc_list = parse_address_list(headers.get("bcc", ""))

    # --- Body ---
    plain_parts: list[str] = []
    html_parts: list[str] = []
    _get_body_parts(payload, plain_parts, html_parts)

    raw_html = "\n".join(html_parts)
    body_plain = "\n".join(plain_parts) if plain_parts else strip_html(raw_html)

    # --- Attachments ---
    def _count_attachments(p: dict) -> int:
        count = 0
        if p.get("filename") and p.get("body", {}).get("attachmentId"):
            count += 1
        for sub in p.get("parts", []):
            count += _count_attachments(sub)
        return count

    attachment_count = _count_attachments(payload)

    # --- Dates ---
    sent_at = parse_email_date(headers.get("date", ""))

    return {
        "message_id": raw_message.get("id", ""),
        "thread_id": raw_message.get("threadId", ""),
        "sender_name": sender_parsed["name"],
        "sender_email": sender_parsed["email"],
        "sender_domain": extract_domain(sender_parsed["email"]),
        "recipients_to": to_list,
        "recipients_cc": cc_list,
        "recipients_bcc": bcc_list,
        "subject": headers.get("subject", ""),
        "body_plain": body_plain,
        "body_html": raw_html,
        "snippet": make_snippet(body_plain),
        "sent_at": sent_at,
        "has_attachments": attachment_count > 0,
        "attachment_count": attachment_count,
        "raw_headers": headers,
        "labels": raw_message.get("labelIds", []),
    }


def parse_attachments_from_gmail(raw_message: dict[str, Any], email_id: int) -> list[dict]:
    """
    Extract attachment metadata from a Gmail message payload.
    Returns list of dicts suitable for bulk-creating Attachment records.
    """
    results = []

    def _walk(part: dict) -> None:
        filename = part.get("filename", "")
        body = part.get("body", {})
        attachment_id = body.get("attachmentId", "")
        if filename and attachment_id:
            results.append({
                "email_id": email_id,
                "filename": filename,
                "mime_type": part.get("mimeType", ""),
                "size_bytes": body.get("size", 0),
                "attachment_id": attachment_id,
            })
        for sub in part.get("parts", []):
            _walk(sub)

    _walk(raw_message.get("payload", {}))
    return results
