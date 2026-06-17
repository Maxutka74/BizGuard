"""
apps/gmail/services/gmail_fetcher.py

Fetches the last N emails from Gmail API and returns normalized dicts
ready to be saved as EmailMessage instances.

The normalization produces exactly the fields the frontend expects:
  id, subject, sender, senderName, domain, date, body
  (analysis fields are populated separately by analysis.py)
"""
from __future__ import annotations

import base64
import email as email_lib
import logging
import re
from datetime import datetime, timezone as dt_timezone
from typing import Iterator

from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)

# How many messages to fetch per sync (frontend says "last 50")
DEFAULT_MAX_RESULTS = 50


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def fetch_inbox_messages(service, max_results: int = DEFAULT_MAX_RESULTS) -> list[dict]:
    """
    Fetch up to `max_results` messages from INBOX (excluding SPAM/TRASH).

    Returns:
        List of normalized dicts with keys matching EmailMessage fields.
    """
    message_ids = _list_message_ids(service, max_results)
    results = []
    for msg_id in message_ids:
        try:
            raw = _get_message(service, msg_id)
            normalized = _normalize(raw)
            results.append(normalized)
        except HttpError as exc:
            logger.warning("Skipping message %s — API error: %s", msg_id, exc)
        except Exception as exc:
            logger.exception("Unexpected error normalizing message %s: %s", msg_id, exc)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Private helpers
# ─────────────────────────────────────────────────────────────────────────────

def _list_message_ids(service, max_results: int) -> list[str]:
    """Return a flat list of Gmail message IDs from INBOX."""
    ids = []
    page_token = None
    while len(ids) < max_results:
        batch_size = min(max_results - len(ids), 100)
        kwargs = {
            "userId": "me",
            "labelIds": ["INBOX"],
            "maxResults": batch_size,
        }
        if page_token:
            kwargs["pageToken"] = page_token
        try:
            resp = service.users().messages().list(**kwargs).execute()
        except HttpError as exc:
            logger.error("Gmail list error: %s", exc)
            break

        for m in resp.get("messages", []):
            ids.append(m["id"])

        page_token = resp.get("nextPageToken")
        if not page_token:
            break

    return ids[:max_results]


def _get_message(service, msg_id: str) -> dict:
    """Fetch a single message in 'full' format."""
    return (
        service.users()
        .messages()
        .get(userId="me", id=msg_id, format="full")
        .execute()
    )


def _normalize(raw: dict) -> dict:
    """
    Convert a raw Gmail API message dict into the shape expected by
    EmailMessage model (and therefore the frontend).
    """
    headers = {
        h["name"].lower(): h["value"]
        for h in raw.get("payload", {}).get("headers", [])
    }

    gmail_id = raw["id"]
    subject = headers.get("subject", "(no subject)")
    from_header = headers.get("from", "")
    sender, sender_name = _parse_from(from_header)
    domain = _extract_domain(sender)
    date = _parse_date(headers.get("date", ""), raw.get("internalDate"))
    body = _extract_body(raw.get("payload", {})) or raw.get("snippet", "")

    return {
        "gmail_id": gmail_id,
        "subject": subject,
        "sender": sender,
        "senderName": sender_name,
        "domain": domain,
        "date": date,
        "body": body,
        # Analysis fields are left at defaults; filled by analysis service
        "domainAge": "",
        "domainReputation": "Trusted",
        "lookalikeDomain": None,
        "urgency": 0,
        "fear": 0,
        "credentialTheft": 0,
        "financialFraud": 0,
        "authorityImpersonation": 0,
        "aiSummary": "",
        "aiScore": 0,
        "domainScore": 0,
        "threatScore": 0,
        "riskLevel": "Safe",
        "analysis_done": False,
    }


def _parse_from(from_header: str) -> tuple[str, str]:
    """
    Parse 'From' header into (email_address, display_name).

    Examples:
      "PayPal Security <security@paypa1.com>" → ("security@paypa1.com", "PayPal Security")
      "user@example.com"                       → ("user@example.com", "")
    """
    match = re.match(r'^"?([^"<]+?)"?\s*<([^>]+)>', from_header.strip())
    if match:
        name = match.group(1).strip()
        email_addr = match.group(2).strip()
        return email_addr, name

    # bare email
    addr = from_header.strip()
    return addr, ""


def _extract_domain(email_addr: str) -> str:
    """Extract domain from email address. e.g. 'user@paypa1.com' → 'paypa1.com'."""
    if "@" in email_addr:
        return email_addr.split("@", 1)[1].lower().strip()
    return email_addr.lower().strip()


def _parse_date(date_str: str, internal_date_ms: str | None) -> datetime:
    """
    Parse email date. Falls back to internalDate (epoch ms from Gmail API).
    Returns an aware UTC datetime.
    """
    if date_str:
        try:
            parsed = email_lib.utils.parsedate_to_datetime(date_str)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt_timezone.utc)
            return parsed
        except Exception:
            pass

    if internal_date_ms:
        try:
            ts = int(internal_date_ms) / 1000
            return datetime.fromtimestamp(ts, tz=dt_timezone.utc)
        except Exception:
            pass

    return datetime.now(tz=dt_timezone.utc)


def _extract_body(payload: dict, _depth: int = 0) -> str:
    """
    Recursively extract plain-text body from MIME payload.
    Prefers text/plain; falls back to text/html (stripped).
    """
    if _depth > 10:
        return ""

    mime_type = payload.get("mimeType", "")

    # Leaf node with data
    if "body" in payload and payload["body"].get("data"):
        text = _decode_b64(payload["body"]["data"])
        if mime_type == "text/plain":
            return text
        if mime_type == "text/html":
            return _strip_html(text)
        return text

    # Multipart — recurse parts
    parts = payload.get("parts", [])
    plain = ""
    html = ""
    for part in parts:
        result = _extract_body(part, _depth + 1)
        if part.get("mimeType") == "text/plain" and result:
            plain = result
        elif part.get("mimeType", "").startswith("text/html") and result:
            html = result
        elif result and not plain:
            plain = result

    return plain or html


def _decode_b64(data: str) -> str:
    """Decode URL-safe base64 encoded string."""
    try:
        padded = data + "=" * (4 - len(data) % 4)
        return base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace")
    except Exception:
        return ""


def _strip_html(html: str) -> str:
    """Very light HTML → plain text (no external deps)."""
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()
