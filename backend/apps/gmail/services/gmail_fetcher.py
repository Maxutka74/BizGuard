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
import hashlib
import html as html_lib
import logging
import re
from datetime import datetime, timezone as dt_timezone
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)

# How many recent messages to fetch per sync before sequential AI analysis starts.
DEFAULT_MAX_RESULTS = 30


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def fetch_inbox_messages(
    service,
    max_results: int = DEFAULT_MAX_RESULTS,
    newer_than_days: int | None = None,
    backfill_to_limit: bool = False,
    known_message_ids: set[str] | None = None,
    stop_at_known: bool = False,
) -> list[dict]:
    """
    Fetch up to `max_results` messages from INBOX (excluding SPAM/TRASH).

    Returns:
        List of normalized dicts with keys matching EmailMessage fields.
    """
    known_message_ids = known_message_ids or set()
    message_ids = _select_new_message_ids(
        _list_message_ids(service, max_results, newer_than_days=newer_than_days),
        known_message_ids=known_message_ids,
        stop_at_known=stop_at_known,
    )
    if backfill_to_limit and newer_than_days and len(message_ids) < max_results and not (stop_at_known and known_message_ids):
        all_recent_ids = _list_message_ids(service, max_results, newer_than_days=None)
        seen_ids = set(message_ids)
        for msg_id in all_recent_ids:
            if msg_id in known_message_ids and stop_at_known:
                break
            if msg_id in known_message_ids:
                continue
            if msg_id in seen_ids:
                continue
            message_ids.append(msg_id)
            seen_ids.add(msg_id)
            if len(message_ids) >= max_results:
                break

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


def _select_new_message_ids(
    message_ids: list[str],
    *,
    known_message_ids: set[str],
    stop_at_known: bool,
) -> list[str]:
    if not known_message_ids:
        return message_ids
    selected: list[str] = []
    for msg_id in message_ids:
        if msg_id in known_message_ids:
            if stop_at_known:
                break
            continue
        selected.append(msg_id)
    return selected


# ─────────────────────────────────────────────────────────────────────────────
# Private helpers
# ─────────────────────────────────────────────────────────────────────────────

def _list_message_ids(service, max_results: int, newer_than_days: int | None = None) -> list[str]:
    """Return a flat list of Gmail message IDs from INBOX."""
    ids = []
    page_token = None
    while len(ids) < max_results:
        batch_size = min(max_results - len(ids), 100)
        kwargs = {
            "userId": "me",
            "labelIds": ["INBOX"],
            "maxResults": batch_size,
            "fields": "nextPageToken,messages/id",
        }
        if newer_than_days:
            kwargs["q"] = f"newer_than:{max(1, int(newer_than_days))}d"
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
        .get(
            userId="me",
            id=msg_id,
            format="full",
            fields="id,internalDate,snippet,payload(headers,body,mimeType,filename,parts,partId)",
        )
        .execute()
    )


def _normalize(raw: dict) -> dict:
    """
    Convert a raw Gmail API message dict into the shape expected by
    EmailMessage model (and therefore the frontend).
    """
    raw_headers = raw.get("payload", {}).get("headers", [])
    headers = {
        h["name"].lower(): h["value"]
        for h in raw_headers
    }
    # Only Gmail's own authentication result can support a trusted-sender
    # decision; a sender can include a forged header with the same name.
    gmail_authentication_results = next((
        h.get("value", "") for h in raw_headers
        if h.get("name", "").lower() == "authentication-results"
        and h.get("value", "").strip().lower().startswith("mx.google.com;")
    ), "")
    received_headers = [
        h["value"]
        for h in raw.get("payload", {}).get("headers", [])
        if h.get("name", "").lower() == "received"
    ]

    gmail_id = raw["id"]
    subject = headers.get("subject", "(no subject)")
    from_header = headers.get("from", "")
    sender, sender_name = _parse_from(from_header)
    domain = _extract_domain(sender)
    date = _parse_date(headers.get("date", ""), raw.get("internalDate"))
    body = clean_email_text(_extract_body(raw.get("payload", {})) or raw.get("snippet", ""))
    attachments = _extract_attachments(raw.get("payload", {}))
    content_hash = _content_hash(subject, sender, body, attachments)

    return {
        "gmail_id": gmail_id,
        "subject": subject,
        "sender": sender,
        "senderName": sender_name,
        "domain": domain,
        "date": date,
        "body": body,
        "replyTo": headers.get("reply-to", ""),
        "returnPath": headers.get("return-path", ""),
        "messageId": headers.get("message-id", ""),
        "authenticationResults": gmail_authentication_results,
        "receivedHeaders": received_headers,
        "dkimSignature": headers.get("dkim-signature", ""),
        "contentHash": content_hash,
        "securitySignals": {},
        "headerScore": 0,
        "linkScore": 0,
        "attachmentScore": _count_attachments(raw.get("payload", {})),
        "attachments": attachments,
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
        "analysis_status": "pending",
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

    if html and _looks_like_css_dump(plain):
        return html
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
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html or "")
    text = re.sub(r"(?is)<!--.*?-->", " ", text)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</(p|div|tr|li|h[1-6]|table|section|article)>", "\n", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = html_lib.unescape(text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def clean_email_text(text: str) -> str:
    """Normalize Gmail body text so raw HTML/URL dumps stay readable in the UI."""
    if not text:
        return ""

    cleaned = html_lib.unescape(str(text).replace("\r\n", "\n").replace("\r", "\n"))
    cleaned = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", cleaned)
    if re.search(r"</?[a-z][^>]*>", cleaned, re.I):
        cleaned = _strip_html(cleaned)

    cleaned = html_lib.unescape(cleaned)
    cleaned = _remove_css_noise(cleaned)
    cleaned = re.sub(r"<(https?://[^>\s]+)>", r"\1", cleaned)
    cleaned = re.sub(r"(https?://[^\s<>]+)\s*/>", r"\1", cleaned)
    cleaned = re.sub(r"<(www\.[^>\s]+)>", r"\1", cleaned)
    cleaned = re.sub(r"[ \t]+", " ", cleaned)
    cleaned = re.sub(r"\n[ \t]+", "\n", cleaned)
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)

    lines = []
    seen_tracking = set()
    for line in cleaned.split("\n"):
        line = line.strip()
        if not line:
            if lines and lines[-1]:
                lines.append("")
            continue
        if re.fullmatch(r"https?://\S+", line):
            key = re.sub(
                r"[?&](utm_[^=&]+|profileToken|token|signature|sig|hash|id)=[^&\s]+",
                "",
                line,
                flags=re.I,
            )
            if key in seen_tracking:
                continue
            seen_tracking.add(key)
        lines.append(line)

    return "\n".join(lines).strip()


def _looks_like_css_dump(text: str) -> bool:
    sample = (text or "")[:2500].lower()
    if not sample:
        return False
    css_markers = ("@import", "@media", "font-family", "font-size", "text-decoration", "!important", "line-height")
    marker_hits = sum(1 for marker in css_markers if marker in sample)
    css_density = sample.count("{") + sample.count("}") + sample.count(";")
    return marker_hits >= 2 or css_density > 35


def _remove_css_noise(text: str) -> str:
    cleaned = text or ""
    cleaned = re.sub(r"(?is)@import\s+url\([^)]+\)\s*;?", " ", cleaned)
    cleaned = re.sub(r"(?is)/\*.*?\*/", " ", cleaned)
    cleaned = re.sub(r"(?is)@media[^{]+\{.*?\}\s*\}", " ", cleaned)
    cleaned = re.sub(r"(?is)@font-face\s*\{.*?\}", " ", cleaned)
    cleaned = re.sub(r"(?is)(?:^|\n)\s*[\w.#:\-\s,\[\]=\"']{1,120}\{[^{}]{0,700}\}", "\n", cleaned)

    lines = []
    for raw_line in cleaned.split("\n"):
        line = raw_line.strip()
        if not line:
            lines.append("")
            continue
        lower = line.lower()
        if lower.startswith(("@import", "@media", "@font-face")):
            continue
        if re.search(r"\b(font-size|font-family|line-height|text-decoration|background|border-collapse|mso-|webkit-)", lower):
            continue
        if line.count(";") >= 3 and re.search(r"\b(color|margin|padding|width|height|display)\s*:", lower):
            continue
        lines.append(line)
    return "\n".join(lines)


def _content_hash(subject: str, sender: str, body: str, attachments: list[dict] | None = None) -> str:
    attachment_fingerprint = "|".join(
        f"{att.get('filename','')}:{att.get('mime_type','')}:{att.get('size_bytes',0)}:{att.get('attachment_id','')}"
        for att in attachments or []
    )
    payload = "\n".join([subject or "", sender or "", body or "", attachment_fingerprint])
    return hashlib.sha256(payload.encode("utf-8", errors="ignore")).hexdigest()


def _count_attachments(payload: dict) -> int:
    count = 0
    filename = payload.get("filename")
    if filename:
        count += 1
    for part in payload.get("parts", []) or []:
        count += _count_attachments(part)
    return count


def _extract_attachments(payload: dict, part_id: str = "") -> list[dict]:
    attachments = []
    filename = payload.get("filename") or ""
    body = payload.get("body") or {}
    attachment_id = body.get("attachmentId") or ""
    if filename and attachment_id:
        attachments.append(
            {
                "filename": filename,
                "mime_type": payload.get("mimeType", ""),
                "size_bytes": body.get("size", 0) or 0,
                "attachment_id": attachment_id,
                "part_id": part_id,
            }
        )
    for index, part in enumerate(payload.get("parts", []) or []):
        child_part_id = f"{part_id}.{index}" if part_id else str(index)
        attachments.extend(_extract_attachments(part, child_part_id))
    return attachments

