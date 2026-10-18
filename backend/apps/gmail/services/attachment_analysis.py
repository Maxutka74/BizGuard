from __future__ import annotations

import base64
import hashlib
import io
import logging
import re
import time
from typing import Any

import requests
from django.conf import settings
from django.utils import timezone

from apps.reputation.models import AttachmentReputation
from apps.reputation.virustotal import REQUEST_TIMEOUT, VT_BASE

logger = logging.getLogger(__name__)

MAX_AI_ATTACHMENT_TEXT = 12_000
MAX_VT_UPLOAD_BYTES = 32 * 1024 * 1024
_VT_FILE_DISABLED_UNTIL = 0.0

SUSPICIOUS_FILENAME_WORDS = {
    "delivery",
    "parcel",
    "package",
    "posilka",
    "novaposhta",
    "address",
    "payment",
    "invoice",
    "verify",
    "update",
    "scam",
    "доставка",
    "посилка",
    "адрес",
    "оплата",
    "рахунок",
    "підтверд",
    "онов",
}

URGENT_ATTACHMENT_CONTEXT_RE = re.compile(
    r"(до\s+кінця\s+дня|терміново|негайно|уточн\w+\s+адрес|повернення\s+відправнику|"
    r"before\s+end\s+of\s+day|urgent|address\s+update|return\s+to\s+sender)",
    re.IGNORECASE | re.UNICODE,
)

UKRAINIAN_URGENT_ATTACHMENT_CONTEXT_RE = re.compile(
    r"(\u0434\u043e\s+\u043a\u0456\u043d\u0446\u044f\s+\u0434\u043d\u044f|"
    r"\u0442\u0435\u0440\u043c\u0456\u043d\u043e\u0432\u043e|\u043d\u0435\u0433\u0430\u0439\u043d\u043e|"
    r"\u0443\u0442\u043e\u0447\u043d\w*\s+\u0430\u0434\u0440\u0435\u0441|"
    r"\u043f\u043e\u0442\u0440\u0435\u0431\u0443\u0454\s+\u0443\u0442\u043e\u0447\u043d\u0435\u043d\u043d\u044f|"
    r"\u043f\u043e\u0432\u0435\u0440\u043d\u0435\u043d\w*\s+\u0432\u0456\u0434\u043f\u0440\u0430\u0432\u043d\u0438\u043a)",
    re.IGNORECASE | re.UNICODE,
)

DANGEROUS_FILE_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".hta", ".iso", ".zip", ".rar", ".7z"
}


def scan_email_attachments(service, gmail_id: str, attachments: list[dict], email_text: str) -> dict[str, Any]:
    if not attachments:
        return empty_attachment_scan_summary()

    scanned = []
    extracted_chunks = []
    for attachment in attachments:
        result = scan_attachment(service, gmail_id, attachment, email_text)
        scanned.append(result)
        if result.get("extracted_text_preview"):
            extracted_chunks.append(result["extracted_text_preview"])
        if result.get("qr_payloads"):
            extracted_chunks.extend([f"QR code content: {payload}" for payload in result["qr_payloads"]])

    score = max((item.get("score", 0) for item in scanned), default=0)
    has_malicious = any(item.get("is_malicious") for item in scanned)
    has_suspicious = any(item.get("is_suspicious") for item in scanned)
    summary = _build_attachment_summary(scanned)
    return {
        "attachment_score": score,
        "has_malicious_attachment": has_malicious,
        "has_suspicious_attachment": has_suspicious,
        "scanned_attachments": scanned,
        "attachment_summary": summary,
        "attachment_text": "\n\n".join(extracted_chunks)[:MAX_AI_ATTACHMENT_TEXT],
    }


def empty_attachment_scan_summary() -> dict[str, Any]:
    return {
        "attachment_score": 0,
        "has_malicious_attachment": False,
        "has_suspicious_attachment": False,
        "scanned_attachments": [],
        "attachment_summary": "No attachments found.",
        "attachment_text": "",
    }


def scan_attachment(service, gmail_id: str, attachment: dict, email_text: str) -> dict[str, Any]:
    filename = attachment.get("filename", "")
    mime_type = attachment.get("mime_type", "")
    size_bytes = int(attachment.get("size_bytes") or 0)
    findings = _local_attachment_findings(filename, mime_type, email_text)

    file_bytes = _fetch_attachment_bytes(service, gmail_id, attachment.get("attachment_id", ""))
    file_hash = hashlib.sha256(file_bytes).hexdigest() if file_bytes else _metadata_hash(attachment)
    extracted_text = _extract_pdf_text(file_bytes) if _looks_like_pdf(filename, mime_type) and file_bytes else ""
    if _looks_like_pdf(filename, mime_type) and file_bytes and not extracted_text:
        findings.append("pdf_text_empty_or_unavailable")
    findings.extend(_text_findings(extracted_text))
    qr_payloads = _extract_qr_payloads(file_bytes, filename, mime_type) if file_bytes else []
    findings.extend(_qr_findings(qr_payloads))
    text_preview = _join_attachment_preview(extracted_text, qr_payloads)

    cached = AttachmentReputation.objects.filter(file_hash=file_hash).first()
    if cached and not cached.is_stale():
        serialized = _serialize_attachment(cached, attachment, findings)
        if qr_payloads:
            serialized["qr_payloads"] = qr_payloads
            serialized["extracted_text_preview"] = _join_attachment_preview(
                serialized.get("extracted_text_preview", ""),
                qr_payloads,
            )
            local_score, local_verdict = _score_local_attachment(filename, mime_type, findings)
            if local_score > int(serialized.get("score") or 0):
                serialized["score"] = local_score
                serialized["verdict"] = local_verdict
                serialized["is_malicious"] = local_verdict == AttachmentReputation.VERDICT_MALICIOUS
                serialized["is_suspicious"] = local_verdict in {
                    AttachmentReputation.VERDICT_MALICIOUS,
                    AttachmentReputation.VERDICT_SUSPICIOUS,
                }
        return serialized

    vt = _fetch_or_submit_file(file_hash, file_bytes, filename) if file_bytes else _vt_unavailable_result("Attachment bytes unavailable.")
    local_score, local_verdict = _score_local_attachment(filename, mime_type, findings)
    vt_score = vt["score"]
    score = max(local_score, vt_score)
    verdict = _pick_verdict(score, vt["verdict"], local_verdict)
    is_malicious = verdict == AttachmentReputation.VERDICT_MALICIOUS
    is_suspicious = verdict in {AttachmentReputation.VERDICT_MALICIOUS, AttachmentReputation.VERDICT_SUSPICIOUS}

    obj, _ = AttachmentReputation.objects.update_or_create(
        file_hash=file_hash,
        defaults={
            "filename": filename,
            "mime_type": mime_type,
            "size_bytes": size_bytes,
            "verdict": verdict,
            "score": score,
            "is_malicious": is_malicious,
            "is_suspicious": is_suspicious,
            "extracted_text_preview": text_preview[:MAX_AI_ATTACHMENT_TEXT],
            "local_findings": sorted(set(findings)),
            "raw_stats": vt.get("stats", {}),
            "raw_results": vt.get("results", {}),
            "fetched_at": timezone.now(),
            "error": vt.get("error", ""),
        },
    )
    return _serialize_attachment(obj, attachment, findings)


def _fetch_attachment_bytes(service, gmail_id: str, attachment_id: str) -> bytes:
    if not attachment_id:
        return b""
    try:
        response = (
            service.users()
            .messages()
            .attachments()
            .get(userId="me", messageId=gmail_id, id=attachment_id)
            .execute()
        )
    except Exception as exc:
        logger.warning("Could not fetch Gmail attachment %s/%s: %s", gmail_id, attachment_id, exc)
        return b""
    data = response.get("data", "")
    if not data:
        return b""
    padded = data + "=" * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(padded)


def _extract_pdf_text(file_bytes: bytes) -> str:
    try:
        from pypdf import PdfReader
    except Exception:
        return ""
    try:
        reader = PdfReader(io.BytesIO(file_bytes))
        chunks = []
        for page in reader.pages[:8]:
            chunks.append(page.extract_text() or "")
        return "\n".join(chunks).strip()[:MAX_AI_ATTACHMENT_TEXT]
    except Exception as exc:
        logger.warning("PDF text extraction failed: %s", exc)
        return ""


def _extract_qr_payloads(file_bytes: bytes, filename: str, mime_type: str) -> list[str]:
    if not file_bytes:
        return []
    payloads: list[str] = []
    if _looks_like_image(filename, mime_type):
        payloads.extend(_decode_qr_from_image_bytes(file_bytes))
    if _looks_like_pdf(filename, mime_type):
        payloads.extend(_decode_qr_from_pdf_bytes(file_bytes))
    seen = set()
    unique = []
    for payload in payloads:
        payload = str(payload or "").strip()
        if payload and payload not in seen:
            seen.add(payload)
            unique.append(payload[:1200])
    return unique[:10]


def _decode_qr_from_image_bytes(file_bytes: bytes) -> list[str]:
    # Prefer OpenCV because it does not require the system zbar library.
    try:
        import cv2  # type: ignore
        import numpy as np  # type: ignore

        image = cv2.imdecode(np.frombuffer(file_bytes, np.uint8), cv2.IMREAD_COLOR)
        if image is None:
            return []
        detector = cv2.QRCodeDetector()
        ok, decoded, _, _ = detector.detectAndDecodeMulti(image)
        if ok and decoded:
            return [item for item in decoded if item]
        single, _, _ = detector.detectAndDecode(image)
        return [single] if single else []
    except Exception:
        pass

    try:
        from PIL import Image  # type: ignore
        from pyzbar.pyzbar import decode  # type: ignore

        image = Image.open(io.BytesIO(file_bytes))
        return [item.data.decode("utf-8", errors="replace") for item in decode(image)]
    except Exception:
        return []


def _decode_qr_from_pdf_bytes(file_bytes: bytes) -> list[str]:
    try:
        import fitz  # type: ignore
    except Exception:
        return []

    payloads: list[str] = []
    try:
        document = fitz.open(stream=file_bytes, filetype="pdf")
        for index in range(min(3, document.page_count)):
            page = document.load_page(index)
            pix = page.get_pixmap(matrix=fitz.Matrix(2, 2), alpha=False)
            payloads.extend(_decode_qr_from_image_bytes(pix.tobytes("png")))
        document.close()
    except Exception as exc:
        logger.debug("PDF QR extraction failed: %s", exc)
    return payloads


def _qr_findings(qr_payloads: list[str]) -> list[str]:
    findings = []
    if not qr_payloads:
        return findings
    findings.append("qr_code_detected")
    joined = "\n".join(qr_payloads)
    if re.search(r"https?://|www\.", joined, re.I):
        findings.append("qr_contains_url")
    if re.search(r"(login|signin|sign-in|password|verify|payment|wallet|kyc|account|парол|увій|оплат|рахунок)", joined, re.I | re.U):
        findings.append("qr_contains_sensitive_url")
    return findings


def _join_attachment_preview(extracted_text: str, qr_payloads: list[str]) -> str:
    chunks = [extracted_text.strip()] if extracted_text else []
    chunks.extend([f"QR code content: {payload}" for payload in qr_payloads])
    return "\n\n".join(chunks)[:MAX_AI_ATTACHMENT_TEXT]


def _fetch_or_submit_file(file_hash: str, file_bytes: bytes, filename: str) -> dict[str, Any]:
    global _VT_FILE_DISABLED_UNTIL
    api_key = getattr(settings, "VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return _vt_unavailable_result("VirusTotal API key is not configured.")
    if time.time() < _VT_FILE_DISABLED_UNTIL:
        return _vt_unavailable_result("VirusTotal file scan temporarily rate-limited.")
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        response = requests.get(f"{VT_BASE}/files/{file_hash}", headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        return _vt_unavailable_result(f"VirusTotal file lookup network error: {exc}")

    if response.status_code == 404:
        if len(file_bytes) > MAX_VT_UPLOAD_BYTES:
            return _vt_unavailable_result("File is too large for VirusTotal upload.")
        return _submit_file(file_bytes, filename, headers)
    if response.status_code == 429:
        _disable_vt_files()
        return _vt_unavailable_result("VirusTotal file rate limit hit.")
    if response.status_code == 401:
        return _vt_unavailable_result("VirusTotal API key is invalid.")
    if not response.ok:
        return _vt_unavailable_result(f"VirusTotal file lookup HTTP {response.status_code}.")

    attrs = response.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    results = attrs.get("last_analysis_results", {}) or {}
    score, verdict = _score_vt_stats(stats)
    return {"score": score, "verdict": verdict, "stats": stats, "results": _compact_vt_results(results), "error": ""}


def _submit_file(file_bytes: bytes, filename: str, headers: dict[str, str]) -> dict[str, Any]:
    try:
        response = requests.post(
            f"{VT_BASE}/files",
            headers=headers,
            files={"file": (filename or "attachment.bin", file_bytes)},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        return _vt_unavailable_result(f"VirusTotal file submit network error: {exc}")
    if response.status_code in {200, 201, 202}:
        return {
            "score": 25,
            "verdict": AttachmentReputation.VERDICT_PENDING,
            "stats": {},
            "results": {},
            "error": "VirusTotal file scan submitted; result is pending.",
        }
    if response.status_code == 429:
        _disable_vt_files()
        return _vt_unavailable_result("VirusTotal file upload rate limit hit.")
    return _vt_unavailable_result(f"VirusTotal file submit HTTP {response.status_code}.")


def _local_attachment_findings(filename: str, mime_type: str, email_text: str) -> list[str]:
    lower_name = (filename or "").lower()
    lower_mime = (mime_type or "").lower()
    findings = []
    if lower_name:
        findings.append("has_attachment")
    if any(lower_name.endswith(ext) for ext in DANGEROUS_FILE_EXTENSIONS):
        findings.append("dangerous_file_extension")
    if _looks_like_pdf(lower_name, lower_mime):
        findings.append("pdf_attachment")
    if any(word in lower_name for word in SUSPICIOUS_FILENAME_WORDS):
        findings.append("suspicious_filename")
    if URGENT_ATTACHMENT_CONTEXT_RE.search(email_text or "") or UKRAINIAN_URGENT_ATTACHMENT_CONTEXT_RE.search(email_text or ""):
        findings.append("urgent_attachment_context")
    if "pdf_attachment" in findings and "suspicious_filename" in findings and "urgent_attachment_context" in findings:
        findings.append("high_risk_delivery_pdf")
    return findings


def _text_findings(text: str) -> list[str]:
    findings = []
    lowered = (text or "").lower()
    if re.search(r"https?://|www\.", lowered):
        findings.append("pdf_contains_links")
    if "qr" in lowered or "scan" in lowered or "відскан" in lowered:
        findings.append("pdf_mentions_qr")
    if re.search(r"(login|password|verify|payment|address|парол|увій|оплат|адрес|підтверд)", lowered, re.I | re.U):
        findings.append("pdf_contains_credential_or_payment_language")
    return findings


def _score_local_attachment(filename: str, mime_type: str, findings: list[str]) -> tuple[int, str]:
    score = 0
    weights = {
        "has_attachment": 5,
        "dangerous_file_extension": 85,
        "pdf_attachment": 10,
        "suspicious_filename": 25,
        "urgent_attachment_context": 25,
        "high_risk_delivery_pdf": 70,
        "pdf_contains_links": 35,
        "pdf_mentions_qr": 45,
        "qr_code_detected": 20,
        "qr_contains_url": 45,
        "qr_contains_sensitive_url": 65,
        "pdf_contains_credential_or_payment_language": 45,
        "pdf_text_empty_or_unavailable": 10,
    }
    for finding in set(findings):
        score = max(score, weights.get(finding, 0))
    if "suspicious_filename" in findings and "urgent_attachment_context" in findings:
        score = max(score, 55)
    if "dangerous_file_extension" in findings:
        score = max(score, 85)
    if score >= 70:
        return score, AttachmentReputation.VERDICT_MALICIOUS
    if score >= 35:
        return score, AttachmentReputation.VERDICT_SUSPICIOUS
    return score, AttachmentReputation.VERDICT_CLEAN


def _score_vt_stats(stats: dict[str, int]) -> tuple[int, str]:
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    if malicious >= 2:
        return 95, AttachmentReputation.VERDICT_MALICIOUS
    if malicious == 1:
        return 80, AttachmentReputation.VERDICT_MALICIOUS
    if suspicious >= 1:
        return 55, AttachmentReputation.VERDICT_SUSPICIOUS
    return 0, AttachmentReputation.VERDICT_CLEAN


def _pick_verdict(score: int, vt_verdict: str, local_verdict: str) -> str:
    if vt_verdict == AttachmentReputation.VERDICT_MALICIOUS or local_verdict == AttachmentReputation.VERDICT_MALICIOUS:
        return AttachmentReputation.VERDICT_MALICIOUS
    if score >= 35 or vt_verdict == AttachmentReputation.VERDICT_SUSPICIOUS or local_verdict == AttachmentReputation.VERDICT_SUSPICIOUS:
        return AttachmentReputation.VERDICT_SUSPICIOUS
    if vt_verdict == AttachmentReputation.VERDICT_PENDING:
        return AttachmentReputation.VERDICT_PENDING
    if vt_verdict == AttachmentReputation.VERDICT_ERROR:
        return AttachmentReputation.VERDICT_ERROR if score == 0 else local_verdict
    return AttachmentReputation.VERDICT_CLEAN


def _compact_vt_results(results: dict[str, Any]) -> dict[str, Any]:
    compact = {}
    for engine, result in results.items():
        category = str(result.get("category", "")).lower()
        if category in {"malicious", "suspicious"}:
            compact[engine] = {"category": result.get("category"), "result": result.get("result")}
    return compact


def _serialize_attachment(rep: AttachmentReputation, attachment: dict, findings: list[str]) -> dict[str, Any]:
    qr_payloads = _extract_qr_payloads_from_preview(rep.extracted_text_preview)
    return {
        "filename": attachment.get("filename") or rep.filename,
        "mime_type": attachment.get("mime_type") or rep.mime_type,
        "size_bytes": attachment.get("size_bytes") or rep.size_bytes,
        "verdict": rep.verdict,
        "score": rep.score,
        "is_malicious": rep.is_malicious,
        "is_suspicious": rep.is_suspicious,
        "local_findings": sorted(set([*findings, *list(rep.local_findings or [])])),
        "extracted_text_preview": rep.extracted_text_preview,
        "qr_payloads": qr_payloads,
        "stats": rep.raw_stats,
        "detections": rep.raw_results,
        "fetched_at": rep.fetched_at.isoformat(),
        "error": rep.error,
    }


def _build_attachment_summary(scanned: list[dict[str, Any]]) -> str:
    if not scanned:
        return "No attachments found."
    malicious = [item for item in scanned if item.get("is_malicious")]
    suspicious = [item for item in scanned if item.get("is_suspicious")]
    pending = [item for item in scanned if item.get("verdict") == AttachmentReputation.VERDICT_PENDING]
    if malicious:
        names = ", ".join(item.get("filename", "attachment") for item in malicious[:3])
        return f"Attachment analysis found high-risk or malicious files: {names}."
    if suspicious:
        names = ", ".join(item.get("filename", "attachment") for item in suspicious[:3])
        return f"Attachment analysis found suspicious files: {names}."
    if pending:
        return f"VirusTotal file scan is pending for {len(pending)} attachment(s)."
    return f"Attachment analysis found no malicious indicators in {len(scanned)} attachment(s)."


def _looks_like_pdf(filename: str, mime_type: str) -> bool:
    return (filename or "").lower().endswith(".pdf") or (mime_type or "").lower() == "application/pdf"


def _looks_like_image(filename: str, mime_type: str) -> bool:
    lower_name = (filename or "").lower()
    lower_mime = (mime_type or "").lower()
    return lower_mime.startswith("image/") or lower_name.endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".tiff"))


def _extract_qr_payloads_from_preview(preview: str) -> list[str]:
    payloads = []
    for match in re.finditer(r"QR code content:\s*(.+)", preview or ""):
        payloads.append(match.group(1).strip())
    return payloads[:10]


def _metadata_hash(attachment: dict) -> str:
    raw = "|".join(
        [
            attachment.get("filename", ""),
            attachment.get("mime_type", ""),
            str(attachment.get("size_bytes", 0)),
            attachment.get("attachment_id", ""),
        ]
    )
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def _vt_unavailable_result(error: str) -> dict[str, Any]:
    return {
        "score": 0,
        "verdict": AttachmentReputation.VERDICT_ERROR,
        "stats": {},
        "results": {},
        "error": error,
    }


def _disable_vt_files() -> None:
    global _VT_FILE_DISABLED_UNTIL
    now = time.time()
    if now < _VT_FILE_DISABLED_UNTIL:
        return
    seconds = int(getattr(settings, "VIRUSTOTAL_DISABLE_ON_RATE_LIMIT_SECONDS", 900))
    _VT_FILE_DISABLED_UNTIL = now + seconds
    logger.warning("VirusTotal file lookups rate-limited; pausing live file scans for %ss.", seconds)
