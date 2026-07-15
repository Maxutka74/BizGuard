from __future__ import annotations

import logging
import re
import time
from email.utils import parseaddr
from urllib.parse import urlparse
from django.conf import settings
from django.utils import timezone

from apps.gmail.models import EmailAccount, EmailMessage, TrustedSenderRule
from apps.gmail.services.gmail_fetcher import fetch_inbox_messages
from apps.gmail.services.queue import enqueue_ai_queue
from apps.gmail.services.oauth import build_gmail_service

from apps.gmail.services.ai_analysis import (
    extract_link_domains,
    compute_ai_score,
)

from apps.gmail.services.ai_providers import (
    AIAnalysisTimedOut,
    ANALYSIS_SOURCE_DONE,
    analyze_email_with_providers,
    completed_local_fallback_result,
    deterministic_fallback_result,
    email_context_for_analysis,
    _clamp_contextual_false_positive,
    final_summary_for_risk,
    final_verdict_for_risk,
    sanitize_security_recommendations_for_risk,
    emergency_phishing_boost,
)
from apps.gmail.services.attachment_analysis import empty_attachment_scan_summary, scan_email_attachments
from apps.gmail.services.domain_analysis import analyze_domain
from apps.gmail.services.security_checks import analyze_security_signals
from apps.reputation.url_service import empty_url_scan_summary, extract_meaningful_urls, scan_urls_in_text
from apps.threats.scoring import compute_threat_result

logger = logging.getLogger(__name__)
ANALYSIS_VERSION = 6

TRUSTED_BRAND_GROUPS = [
    {"leetcode.com"},
    {"figma.com"},
    {"railway.app", "railway.com"},
    {"grammarly.com"},
    {"coingecko.com"},
    {"quizlet.com"},
    {"adidas.com"},
]


TRUSTED_NEWSLETTER_EXTERNAL_HOSTS = {
    "coingecko.com": {
        "coingecko.app.link",
        "bit.ly",
        "us-as.gr-cdn.com",
    },
}

EXPLICIT_CREDENTIAL_OR_THREAT_RE = re.compile(
    r"(password|login|sign[\s-]?in|enter\s+(?:your\s+)?(?:password|code)|2fa|mfa|sms\s+code|"
    r"payment\s+(?:card|data|details)|billing\s+details|bank\s+card|"
    r"account\s+(?:will\s+be\s+)?(?:blocked|suspended|terminated|deleted)|"
    r"парол|увійд|вхід|введіть.{0,40}(?:парол|код)|sms|2fa|mfa|"
    r"платіжн.{0,30}(?:дан|карт)|банківськ.{0,30}карт|"
    r"(?:акаунт|обліковий\s+запис|доступ).{0,80}(?:заблок|видален|призупин))",
    re.IGNORECASE | re.UNICODE,
)

NEWSLETTER_CONTEXT_RE = re.compile(
    r"(newsletter|unsubscribe|email_marketing_click|utm_campaign|read the full|research|publication|"
    r"weekly digest|market|bitcoin|crypto|price|chart|download our app|social|"
    r"розсилка|відписат|дослідження|ринок|ціна|графік)",
    re.IGNORECASE | re.UNICODE,
)
HIGH_RISK_INTENT_RE = re.compile(
    r"(login|sign[\s-]?in|password|verify|verification|account|bonus|reward|prize|payment|invoice|"
    r"deadline|today|urgent|suspend|blocked|confirm|credential|wallet|kyc|"
    r"увій|парол|підтверд|вериф|акаунт|обліков|бонус|виграш|оплат|рахунок|термін|до кінця дня|заблок)",
    re.IGNORECASE | re.UNICODE,
)


class AIPendingReputation(Exception):
    """Raised when URL or attachment reputation is still pending after AI work."""


# =========================================================
# MAIN SYNC ENTRY
# =========================================================

def sync_account(
    email_account: EmailAccount,
    max_results: int = 30,
    progress_callback=None,
    recent_lookback_days: int | None = None,
    priority_ai: bool = False,
    backfill_to_limit: bool = False,
) -> dict:
    logger.info("SYNC START: %s", email_account.email)
    stats = {"fetched": 0, "processed": 0, "created": 0, "updated": 0, "errors": 0, "pending_ai": 0}

    try:
        service = build_gmail_service(email_account)
        known_message_ids = set(
            EmailMessage.objects.filter(account=email_account).values_list("gmail_id", flat=True)
        )
        messages = fetch_inbox_messages(
            service,
            max_results=max_results,
            newer_than_days=recent_lookback_days,
            backfill_to_limit=backfill_to_limit,
            known_message_ids=known_message_ids,
            stop_at_known=True,
        )
        stats["fetched"] = len(messages)
        _emit_progress(progress_callback, stats)
    except Exception as exc:
        logger.exception("Gmail fetch failed: %s", exc)
        return stats

    for msg in messages:
        try:
            _process_message(email_account, msg, stats, service)
        except Exception as exc:
            logger.exception(
                "Processing failed for msg %s",
                msg.get("gmail_id"),
                exc
            )
            stats["errors"] += 1
        finally:
            stats["processed"] += 1
            _emit_progress(progress_callback, stats)

    email_account.last_synced_at = timezone.now()
    email_account.save(update_fields=["last_synced_at"])

    pending_existing = EmailMessage.objects.filter(account=email_account).exclude(analysis_status="done").count()
    stats["pending_ai"] = max(stats["pending_ai"], pending_existing)
    if pending_existing:
        _enqueue_ai_queue(email_account.id, priority_ai=priority_ai)

    logger.info("SYNC DONE: %s -> %s", email_account.email, stats)
    return stats


def _emit_progress(progress_callback, stats: dict) -> None:
    if not progress_callback:
        return
    try:
        progress_callback(dict(stats))
    except Exception:
        logger.debug("Could not emit sync progress", exc_info=True)


# =========================================================
# MESSAGE PROCESSOR
# =========================================================

def _process_message(
    email_account: EmailAccount,
    msg: dict,
    stats: dict,
    service=None,
) -> None:
    gmail_id = msg.get("gmail_id")
    if not gmail_id:
        return

    existing = EmailMessage.objects.filter(gmail_id=gmail_id).first()
    incoming_hash = msg.get("contentHash", "")
    if existing and existing.analysis_done and existing.analysis_status == "done" and existing.verdict:
        same_content = not incoming_hash or not existing.contentHash or existing.contentHash == incoming_hash
        if same_content:
            if incoming_hash and not existing.contentHash:
                existing.contentHash = incoming_hash
                existing.save(update_fields=["contentHash", "synced_at"])
            stats["updated"] += 1
            return

    body = msg.get("body", "")
    subject = msg.get("subject", "")
    sender = msg.get("sender", "")
    sender_domain = (msg.get("domain") or "").lower()

    security_result = analyze_security_signals(msg)
    msg["securitySignals"] = security_result["signals"]
    msg["headerScore"] = security_result["headerScore"]
    msg["linkScore"] = security_result["linkScore"]
    msg["attachmentScore"] = security_result["attachmentScore"]

    # =====================================================
    # 1. DOMAIN ANALYSIS
    # =====================================================
    try:
        domain_result = analyze_domain(sender_domain, allow_vt=True)
    except Exception:
        logger.exception("Domain analysis failed for %s", sender_domain)
        domain_result = {
            "domainAge": None,
            "domainReputation": "Suspicious",
            "lookalikeDomain": None,
            "domainScore": 30,
        }

    # IMPORTANT FIX: prevent NOT NULL crash
    if domain_result.get("domainAge") is None:
        domain_result["domainAge"] = "Unknown"

    # =====================================================
    # 2. LIGHTWEIGHT FIRST PASS
    # =====================================================
    attachment_scan_agg = empty_attachment_scan_summary()
    url_scan_agg = empty_url_scan_summary()

    # =====================================================
    # 3. PRELIMINARY SIGNALS ONLY
    # =====================================================
    combined_attachment_score = max(
        security_result["attachmentScore"],
        attachment_scan_agg.get("attachment_score", 0),
    )
    ai_done = False
    ai_result = deterministic_fallback_result(subject, sender, body, sender_domain, url_scan_agg)
    threat_score = 0
    risk_level = "Safe"
    stats["pending_ai"] += 1

    # =====================================================
    # 4. SAVE TO DB
    # =====================================================
    fields = {
        **msg,

        "domainAge": domain_result.get("domainAge", 0),
        "domainReputation": domain_result.get("domainReputation"),
        "lookalikeDomain": domain_result.get("lookalikeDomain"),
        "domainScore": domain_result.get("domainScore", 0),

        "urgency": ai_result.get("urgency", 0),
        "fear": ai_result.get("fear", 0),
        "credentialTheft": ai_result.get("credential_theft", 0),
        "financialFraud": ai_result.get("financial_fraud", 0),
        "authorityImpersonation": ai_result.get("authority_impersonation", 0),

        "aiSummary": ai_result.get("ai_summary", ""),
        "verdict": ai_result.get("verdict", ""),
        "recommendations": ai_result.get("recommendations", []),
        "aiScore": ai_result.get("ai_score", 0),
        "securitySignals": security_result["signals"],
        "headerScore": security_result["headerScore"],
        "linkScore": security_result["linkScore"],
        "attachmentScore": combined_attachment_score,
        "attachmentScanSummary": attachment_scan_agg.get("attachment_summary", ""),
        "scannedAttachments": attachment_scan_agg.get("scanned_attachments", []),
        "urlScanSummary": url_scan_agg.get("url_summary", ""),
        "urlScore": url_scan_agg.get("url_score", 0),
        "scannedUrls": url_scan_agg.get("scanned_urls", []),
        "hasPhishingUrl": url_scan_agg.get("any_phishing", False),
        "hasMaliciousUrl": url_scan_agg.get("any_malicious", False),

        "threatScore": threat_score,
        "riskLevel": risk_level,

        "analysis_done": ai_done,
        "analysis_status": ai_result.get("_analysis_status", "done"),
        "analysisSource": ai_result.get("_analysis_source", ""),
        "analysisVersion": ANALYSIS_VERSION,
        "account": email_account,
    }

    obj, created = EmailMessage.objects.update_or_create(
        gmail_id=gmail_id,
        defaults=fields,
    )

    stats["created" if created else "updated"] += 1


def _enqueue_ai_queue(account_id: int, priority_ai: bool = False) -> None:
    try:
        from apps.gmail.tasks import process_ai_queue

        process_ai_queue.apply_async(
            args=[account_id],
            kwargs={"max_batch": 60 if priority_ai else 30},
            queue="ai",
            priority=9 if priority_ai else 5,
        )
    except Exception as exc:
        logger.debug("Could not enqueue AI queue for account %s: %s", account_id, exc)


def _needs_deep_analysis_before_vt(
    msg: dict,
    security_result: dict,
    domain_result: dict,
    attachment_scan_agg: dict,
) -> bool:
    text = f"{msg.get('subject', '')}\n{msg.get('body', '')}"
    email_context = email_context_for_analysis(msg.get("subject", ""), msg.get("body", ""), None)
    benign_context = email_context in {"receipt_or_invoice", "meeting_invite", "newsletter_or_info", "course_promo", "survey"}
    if HIGH_RISK_INTENT_RE.search(text) and not _is_trusted_newsletter_context(msg, msg.get("domain", "")):
        return True
    if security_result["headerScore"] > 0:
        return True
    if security_result["linkScore"] >= 25 and not benign_context and not _is_trusted_newsletter_context(msg, msg.get("domain", "")):
        return True
    if security_result.get("attachmentScore", 0) >= (75 if benign_context else 30):
        return True
    if domain_result.get("domainReputation") != "Trusted" or domain_result.get("domainScore", 0) >= 30:
        return True
    if attachment_scan_agg.get("attachment_score", 0) >= (75 if benign_context else 1):
        return True
    return False


def _has_attachment_or_qr_evidence(attachment_scan_agg: dict) -> bool:
    scanned = attachment_scan_agg.get("scanned_attachments") or []
    if scanned:
        return True
    text = attachment_scan_agg.get("attachment_text", "") or ""
    return "QR code content:" in text


def _run_detailed_evidence_scan(
    email_account: EmailAccount,
    service,
    gmail_id: str,
    attachments: list[dict],
    subject: str,
    body: str,
    include_tracking: bool,
    max_urls: int | None = None,
    max_attachments: int | None = None,
) -> tuple[dict, dict]:
    limited_attachments = attachments
    if max_attachments is not None:
        limited_attachments = attachments[: max(0, int(max_attachments))]

    try:
        attachment_scan_agg = scan_email_attachments(
            service=service or build_gmail_service(email_account),
            gmail_id=gmail_id,
            attachments=limited_attachments,
            email_text=f"{subject}\n{body}",
        )
    except Exception:
        logger.exception("Attachment scan failed for %s", gmail_id)
        attachment_scan_agg = empty_attachment_scan_summary()

    scan_text = "\n\n".join([body, attachment_scan_agg.get("attachment_text", "")])
    try:
        url_scan_agg = scan_urls_in_text(
            scan_text,
            max_urls=max_urls if include_tracking else min(max_urls or 3, 3),
            include_tracking=include_tracking,
            vt_enrichment=True,
        )
    except Exception:
        logger.exception("URL scan failed for %s", gmail_id)
        url_scan_agg = empty_url_scan_summary()
    url_scan_agg["attachment_summary"] = attachment_scan_agg.get("attachment_summary", "")
    url_scan_agg["scanned_attachments"] = attachment_scan_agg.get("scanned_attachments", [])
    return attachment_scan_agg, url_scan_agg


def _security_capabilities(email_account: EmailAccount) -> dict:
    try:
        from apps.licenses.services import get_user_capabilities

        return get_user_capabilities(email_account.user)
    except Exception:
        logger.debug("Could not load license capabilities for %s", email_account.email, exc_info=True)
        return {
            "maxUrlsPerEmail": 3,
            "maxAttachmentsPerEmail": 1,
        }


def _deep_scan_limits(email_account: EmailAccount) -> tuple[int, int]:
    caps = _security_capabilities(email_account)
    max_urls = max(1, int(caps.get("maxUrlsPerEmail") or 3))
    max_attachments = max(0, int(caps.get("maxAttachmentsPerEmail") or 1))
    return max_urls, max_attachments


def _fast_safe_analysis(
    msg: dict,
    subject: str,
    sender_domain: str,
    security_result: dict,
    domain_result: dict,
    attachment_scan_agg: dict,
    url_scan_agg: dict,
) -> dict | None:
    if not _is_strict_safe_fast_path(msg, subject, sender_domain, security_result, domain_result, attachment_scan_agg, url_scan_agg):
        return None


    email_context = email_context_for_analysis(subject, msg.get("body", ""), url_scan_agg)
    threat = compute_threat_result(
        ai_score=8,
        domain_score=domain_result.get("domainScore", 0),
        link_domain_scores=None,
        url_score=url_scan_agg.get("url_score", 0),
        attachment_score=attachment_scan_agg.get("attachment_score", 0),
        any_phishing_url=False,
        any_malicious_url=False,
        email_context=email_context,
        explicit_security_intent=email_context == "security_action",
    )
    return {
        "urgency": 0,
        "fear": 0,
        "credential_theft": 0,
        "financial_fraud": 0,
        "authority_impersonation": 0,
        "ai_summary": "Лист пройшов швидку перевірку без ознак фішингу, підміни відправника або небезпечних вкладень.",
        "verdict": "Безпечний лист",
        "recommendations": [
            "Перед відкриттям посилань перевірте, що домен у браузері відповідає очікуваному сервісу.",
            "Не вводьте паролі або платіжні дані, якщо сторінка після переходу виглядає незвично.",
            "Якщо лист просить термінову дію або дані акаунта, перевірте запит через офіційний сайт.",
        ],
        "ai_score": threat.ai_score,
        "threatScore": threat.threat_score,
        "riskLevel": threat.risk_level,
        "_analysis_status": "done",
        "_analysis_source": "Fast security rules",
    }


def _is_strict_safe_fast_path(
    msg: dict,
    subject: str,
    sender_domain: str,
    security_result: dict,
    domain_result: dict,
    attachment_scan_agg: dict,
    url_scan_agg: dict,
) -> bool:
    body = msg.get("body", "")
    text = f"{subject}\n{body}"
    if HIGH_RISK_INTENT_RE.search(text) and not _is_trusted_newsletter_context(msg, sender_domain):
        return False
    if msg.get("attachments"):
        return False
    if attachment_scan_agg.get("attachment_score", 0) > 0:
        return False
    if security_result["headerScore"] > 0:
        return False
    if "shortened_url" in security_result["signals"].get("linkFindings", []) and not _is_trusted_newsletter_context(msg, sender_domain):
        return False
    if domain_result.get("domainReputation") == "Malicious" or domain_result.get("domainScore", 0) >= 25:
        return False
    if url_scan_agg.get("any_phishing") or url_scan_agg.get("any_malicious") or url_scan_agg.get("url_score", 0) >= 30:
        return False

    link_hosts = _hosts_from_message_and_scan(msg, url_scan_agg)
    if not link_hosts:
        return True

    sender_root = _root_domain(sender_domain)
    allowed_group = next((group for group in TRUSTED_BRAND_GROUPS if sender_root in group), None)
    if allowed_group:
        return all(
            _root_domain(host) in allowed_group or _is_allowed_newsletter_external_host(sender_root, host)
            for host in link_hosts
        )
    if domain_result.get("domainReputation") == "Trusted" and domain_result.get("domainScore", 0) <= 10:
        return all(
            _root_domain(host) == sender_root or _is_allowed_newsletter_external_host(sender_root, host)
            for host in link_hosts
        )
    return False



def _is_allowed_newsletter_external_host(sender_root: str, host: str) -> bool:
    allowed_hosts = TRUSTED_NEWSLETTER_EXTERNAL_HOSTS.get(sender_root, set())
    normalized = (host or "").lower().strip(".")
    return any(normalized == allowed or normalized.endswith(f".{allowed}") for allowed in allowed_hosts)


def _is_trusted_newsletter_context(msg: dict, sender_domain: str) -> bool:
    sender_root = _root_domain(sender_domain)
    if sender_root not in TRUSTED_NEWSLETTER_EXTERNAL_HOSTS:
        return False
    text = f"{msg.get('subject', '')}\n{msg.get('body', '')}"
    if EXPLICIT_CREDENTIAL_OR_THREAT_RE.search(text):
        return False
    if not NEWSLETTER_CONTEXT_RE.search(text):
        return False
    link_hosts = _hosts_from_message_and_scan(msg, {})
    return all(
        _root_domain(host) == sender_root or _is_allowed_newsletter_external_host(sender_root, host)
        for host in link_hosts
    )

def _hosts_from_message_and_scan(msg: dict, url_scan_agg: dict) -> set[str]:
    hosts = _hosts_from_scanned_urls(url_scan_agg)
    for host in extract_link_domains(msg.get("body", "") or "") or []:
        if host:
            hosts.add(str(host).lower())
    return hosts


def _hosts_from_scanned_urls(url_scan_agg: dict) -> set[str]:
    hosts = set()
    for item in url_scan_agg.get("scanned_urls") or []:
        try:
            host = urlparse(item.get("url") or "").hostname or ""
        except ValueError:
            host = ""
        if host:
            hosts.add(host.lower())
    return hosts


def _root_domain(host: str) -> str:
    parts = (host or "").lower().strip(".").split(".")
    if len(parts) < 2:
        return host.lower()
    return ".".join(parts[-2:])


def _url_scan_agg_from_message(message: EmailMessage) -> dict:
    scanned_urls = message.scannedUrls or []
    if not scanned_urls:
        try:
            body_urls, _ = extract_meaningful_urls(message.body or "", include_tracking=False, max_urls=5)
        except Exception:
            body_urls = []
        scanned_urls = [
            {
                "url": url,
                "verdict": "Unknown",
                "score": 0,
                "confidence": "none",
                "is_phishing": False,
                "is_malicious": False,
            }
            for url in body_urls
        ]
    return {
        "url_score": message.urlScore,
        "any_phishing": message.hasPhishingUrl,
        "any_malicious": message.hasMaliciousUrl,
        "malicious_urls": [
            item.get("url")
            for item in scanned_urls
            if item.get("is_malicious") and item.get("confidence") != "low"
        ],
        "phishing_urls": [
            item.get("url")
            for item in scanned_urls
            if item.get("is_phishing") and item.get("confidence") != "low"
        ],
        "scanned_urls": scanned_urls,
        "url_summary": message.urlScanSummary or ("URL found in email body." if scanned_urls else ""),
        "total_urls": len(scanned_urls),
        "attachment_summary": message.attachmentScanSummary,
        "scanned_attachments": message.scannedAttachments or [],
    }

def _has_pending_reputation(message: EmailMessage) -> bool:
    return any(item.get("verdict") == "Pending" for item in (message.scannedUrls or [])) or any(
        item.get("verdict") == "Pending" for item in (message.scannedAttachments or [])
    )


def _has_complete_detailed_evidence(message: EmailMessage, max_urls: int | None = None) -> bool:
    if not _has_detailed_evidence(message):
        return False
    expected_urls, _ = extract_meaningful_urls(
        _message_scan_text(message),
        max_urls=max_urls,
        include_tracking=True,
    )
    if expected_urls and len(message.scannedUrls or []) < len(expected_urls):
        return False
    if (message.attachments or []) and not (message.scannedAttachments or []):
        return False
    return True


def _final_verdict_for_risk(risk_level: str) -> str:
    return final_verdict_for_risk(risk_level)


def _summary_conflicts_with_risk(summary: str) -> bool:
    lowered = (summary or "").lower()
    safe_markers = (
        "safe",
        "legitimate",
        "no phishing",
        "безпеч",
        "легітим",
        "ознак фішингу не виявлено",
        "не виявлено ознак фішингу",
    )
    return any(marker in lowered for marker in safe_markers)


def _final_summary_for_risk(summary: str, risk_level: str) -> str:
    summary = (summary or "").strip()
    if risk_level == "Safe":
        return summary
    if summary and not _summary_conflicts_with_risk(summary):
        return summary
    return (
        "Фінальна оцінка врахувала підозрілі сигнали домену, URL, вкладень "
        "або вмісту листа. Не виконуйте дії з листа без перевірки через офіційний канал."
    )


def _final_summary_for_risk(summary: str, risk_level: str) -> str:
    return final_summary_for_risk(summary, risk_level)


def analyze_saved_email_message(
    message: EmailMessage,
    time_budget_seconds: float | None = None,
    deadline: float | None = None,
    allow_pending_reputation: bool = False,
) -> bool:
    deadline = _analysis_deadline(time_budget_seconds=time_budget_seconds, deadline=deadline)
    _check_analysis_deadline(deadline)
    max_urls, max_attachments = _deep_scan_limits(message.account)
    scan_text = _message_scan_text(message)
    url_scan_agg = _url_scan_agg_from_message(message)

    _check_analysis_deadline(deadline)
    ai_result = analyze_email_with_providers(
        subject=message.subject,
        sender=message.sender,
        body=scan_text,
        domain=(message.domain or "").lower(),
        url_scan_agg=url_scan_agg,
        deadline=deadline,
    )
    _check_analysis_deadline(deadline)
    if ai_result.get("_analysis_status") != "done":
        return False
    deep_required = _should_run_detailed_after_ai(message, ai_result)
    if deep_required and not _has_complete_detailed_evidence(message, max_urls=max_urls):
        _check_analysis_deadline(deadline)
        attachment_scan_agg, detailed_url_scan_agg = _run_detailed_evidence_scan(
            email_account=message.account,
            service=None,
            gmail_id=message.gmail_id,
            attachments=message.attachments or [],
            subject=message.subject,
            body=message.body,
            include_tracking=True,
            max_urls=max_urls,
            max_attachments=max_attachments,
        )
        _check_analysis_deadline(deadline)
        _apply_detailed_evidence(message, attachment_scan_agg, detailed_url_scan_agg)
        scan_text = _message_scan_text(message)
        url_scan_agg = _url_scan_agg_from_message(message)
        _check_analysis_deadline(deadline)
        ai_result = analyze_email_with_providers(
            subject=message.subject,
            sender=message.sender,
            body=scan_text,
            domain=(message.domain or "").lower(),
            url_scan_agg=url_scan_agg,
            deadline=deadline,
        )
        _check_analysis_deadline(deadline)
        if ai_result.get("_analysis_status") != "done":
            return False

    _check_analysis_deadline(deadline)
    if _has_pending_reputation(message) and not allow_pending_reputation:
        raise AIPendingReputation("URL or attachment reputation is still pending.")

    return _complete_message_analysis(
        message,
        ai_result,
        ANALYSIS_SOURCE_DONE,
        allow_link_domain_vt=deep_required or _has_detailed_evidence(message),
        deadline=deadline,
    )


def finalize_saved_email_with_local_fallback(
    message: EmailMessage,
    reason: str = "",
    *,
    allow_pending_reputation: bool = False,
    run_missing_deep_scan: bool = True,
) -> bool:
    max_urls, max_attachments = _deep_scan_limits(message.account)
    scan_text = _message_scan_text(message)
    url_scan_agg = _url_scan_agg_from_message(message)
    ai_result = completed_local_fallback_result(
        subject=message.subject,
        sender=message.sender,
        body=scan_text,
        domain=(message.domain or "").lower(),
        url_scan_agg=url_scan_agg,
    )
    deep_required = _should_run_detailed_after_ai(message, ai_result)
    if run_missing_deep_scan and deep_required and not _has_complete_detailed_evidence(message, max_urls=max_urls):
        attachment_scan_agg, detailed_url_scan_agg = _run_detailed_evidence_scan(
            email_account=message.account,
            service=None,
            gmail_id=message.gmail_id,
            attachments=message.attachments or [],
            subject=message.subject,
            body=message.body,
            include_tracking=True,
            max_urls=max_urls,
            max_attachments=max_attachments,
        )
        _apply_detailed_evidence(message, attachment_scan_agg, detailed_url_scan_agg)
        if _has_pending_reputation(message) and not allow_pending_reputation:
            return False
        scan_text = _message_scan_text(message)
        ai_result = completed_local_fallback_result(
            subject=message.subject,
            sender=message.sender,
            body=scan_text,
            domain=(message.domain or "").lower(),
            url_scan_agg=_url_scan_agg_from_message(message),
        )
    if reason:
        logger.warning("Completing message %s with local fallback: %s", message.gmail_id, reason)
    if _has_pending_reputation(message) and not allow_pending_reputation:
        return False
    return _complete_message_analysis(
        message,
        ai_result,
        "AI unavailable",
        allow_link_domain_vt=run_missing_deep_scan and (deep_required or _has_detailed_evidence(message)),
    )


def _complete_message_analysis(
    message: EmailMessage,
    ai_result: dict,
    source: str,
    allow_link_domain_vt: bool = False,
    deadline: float | None = None,
) -> bool:
    link_domain_scores = []
    if allow_link_domain_vt:
        try:
            link_domains = [
                d.lower()
                for d in set(extract_link_domains(message.body) or [])
                if d and _root_domain(d) != _root_domain(message.domain or "")
            ]
            for domain in link_domains:
                _check_analysis_deadline(deadline)
                try:
                    link_domain_scores.append(analyze_domain(domain, allow_vt=True).get("domainScore", 0))
                except Exception:
                    link_domain_scores.append(30)
        except Exception:
            logger.debug("Could not compute link domain scores for %s", message.gmail_id, exc_info=True)

    # Emergency/local phishing guard: do not let a low AI score or clean URL reputation
    # mark explicit credential-extortion emails as safe.
    ai_result = emergency_phishing_boost(
        text=f"{message.subject}\n{message.sender}\n{message.body}",
        score=dict(ai_result),
        sender=message.sender,
        sender_domain=message.domain,
    )
    ai_result = _clamp_contextual_false_positive(
        ai_result,
        f"{message.subject}\n{message.body}",
        _url_scan_agg_from_message(message),
    )
    ai_result["ai_score"] = compute_ai_score(
        urgency=ai_result.get("urgency", 0),
        fear=ai_result.get("fear", 0),
        credential_theft=ai_result.get("credential_theft", 0),
        financial_fraud=ai_result.get("financial_fraud", 0),
        authority_impersonation=ai_result.get("authority_impersonation", 0),
    )
    url_context = _url_scan_agg_from_message(message)
    email_context = email_context_for_analysis(message.subject, message.body, url_context)
    threat = compute_threat_result(
        ai_score=ai_result.get("ai_score", 0),
        domain_score=message.domainScore,
        link_domain_scores=link_domain_scores or None,
        credential_theft=ai_result.get("credential_theft", 0),
        urgency=ai_result.get("urgency", 0),
        authority_impersonation=ai_result.get("authority_impersonation", 0),
        fear=ai_result.get("fear", 0),
        financial_fraud=ai_result.get("financial_fraud", 0),
        url_score=max(message.linkScore, message.urlScore),
        any_phishing_url=message.hasPhishingUrl,
        any_malicious_url=message.hasMaliciousUrl,
        attachment_score=message.attachmentScore,
        any_suspicious_attachment=any(item.get("is_suspicious") for item in (message.scannedAttachments or [])),
        any_malicious_attachment=any(item.get("is_malicious") for item in (message.scannedAttachments or [])),
        email_context=email_context,
        explicit_security_intent=email_context == "security_action",
    )

    final_verdict = _final_verdict_for_risk(threat.risk_level)
    message.urgency = ai_result.get("urgency", 0)
    message.fear = ai_result.get("fear", 0)
    message.credentialTheft = ai_result.get("credential_theft", 0)
    message.financialFraud = ai_result.get("financial_fraud", 0)
    message.authorityImpersonation = ai_result.get("authority_impersonation", 0)
    message.aiSummary = _final_summary_for_risk(ai_result.get("ai_summary", ""), threat.risk_level)
    message.verdict = final_verdict
    message.recommendations = sanitize_security_recommendations_for_risk(
        ai_result.get("recommendations", []),
        threat.risk_level,
        url_context,
        email_context,
    )
    message.aiScore = ai_result.get("ai_score", 0)
    message.threatScore = threat.threat_score
    message.riskLevel = threat.risk_level
    message.analysis_done = True
    message.analysis_status = "done"
    message.analysisSource = source
    message.analysisVersion = ANALYSIS_VERSION
    message.save(
        update_fields=[
            "urgency",
            "fear",
            "credentialTheft",
            "financialFraud",
            "authorityImpersonation",
            "aiSummary",
            "verdict",
            "recommendations",
            "aiScore",
            "threatScore",
            "riskLevel",
            "analysis_done",
            "analysis_status",
            "analysisSource",
            "analysisVersion",
            "synced_at",
        ]
    )
    _apply_auto_spam_action(message)
    return True


def _analysis_deadline(time_budget_seconds: float | None = None, deadline: float | None = None) -> float | None:
    if deadline is not None:
        return deadline
    if time_budget_seconds is None:
        time_budget_seconds = getattr(settings, "AI_MESSAGE_TIME_BUDGET_SECONDS", 30)
    if float(time_budget_seconds) <= 0:
        return None
    return time.monotonic() + float(time_budget_seconds)


def _check_analysis_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise AIAnalysisTimedOut("Email analysis exceeded the per-email time budget.")


def _apply_auto_spam_action(message: EmailMessage) -> None:
    caps = _security_capabilities(message.account)
    if not caps.get("autoSpamCritical"):
        return
    if message.riskLevel != "Critical":
        return
    if message.spamActionStatus == "moved":
        return

    now = timezone.now()
    if caps.get("trustedSenderAllowlist") and _message_sender_is_allowlisted(message):
        message.spamActionStatus = "skipped"
        message.spamActionAt = now
        message.spamActionError = "Trusted sender/domain allowlist."
        message.save(update_fields=["spamActionStatus", "spamActionAt", "spamActionError", "synced_at"])
        return

    try:
        from apps.gmail.services.spam_actions import move_message_to_spam

        move_message_to_spam(message.account, message.gmail_id)
        message.spamActionStatus = "moved"
        message.spamActionAt = now
        message.spamActionError = ""
    except Exception as exc:
        message.spamActionStatus = "failed"
        message.spamActionAt = now
        message.spamActionError = str(exc)[:1000]

    message.save(update_fields=["spamActionStatus", "spamActionAt", "spamActionError", "synced_at"])


def _message_sender_is_allowlisted(message: EmailMessage) -> bool:
    sender_email = (parseaddr(message.sender or "")[1] or message.sender or "").strip().lower()
    sender_domain = (message.domain or "").strip().lower()
    if not sender_domain and "@" in sender_email:
        sender_domain = sender_email.split("@")[-1].strip().lower()
    rules = TrustedSenderRule.objects.filter(user=message.account.user, active=True)

    for rule in rules:
        value = (rule.value or "").lower().strip()
        if not value:
            continue
        if rule.rule_type == TrustedSenderRule.RULE_TYPE_EMAIL and sender_email == value:
            return True
        if rule.rule_type == TrustedSenderRule.RULE_TYPE_DOMAIN:
            if sender_domain == value or sender_domain.endswith(f".{value}"):
                return True
    return False


def _should_run_detailed_after_ai(message: EmailMessage, ai_result: dict) -> bool:
    url_context = _url_scan_agg_from_message(message)
    email_context = email_context_for_analysis(message.subject, message.body, url_context)
    benign_context = email_context in {"receipt_or_invoice", "meeting_invite", "newsletter_or_info", "course_promo", "survey"}

    if message.domainReputation != "Trusted" or message.domainScore >= 30:
        return True
    if message.headerScore > 0:
        return True
    if benign_context:
        if message.hasPhishingUrl or message.hasMaliciousUrl or message.linkScore >= 70 or message.attachmentScore >= 75:
            return True
    elif message.linkScore >= 25 or message.attachmentScore >= 30:
        return True
    if ai_result.get("credential_theft", 0) >= 40 or ai_result.get("financial_fraud", 0) >= 40:
        return True
    if not benign_context and ai_result.get("ai_score", 0) >= 31:
        return True
    if ai_result.get("urgency", 0) >= 60 and ai_result.get("authority_impersonation", 0) >= 40:
        return True
    return False


def _has_detailed_evidence(message: EmailMessage) -> bool:
    return bool(
        message.scannedUrls
        or message.scannedAttachments
        or message.urlScore > 0
        or message.attachmentScore > 0
        or message.hasPhishingUrl
        or message.hasMaliciousUrl
    )


def _apply_detailed_evidence(message: EmailMessage, attachment_scan_agg: dict, url_scan_agg: dict) -> None:
    message.attachmentScore = max(message.attachmentScore, attachment_scan_agg.get("attachment_score", 0))
    message.attachmentScanSummary = attachment_scan_agg.get("attachment_summary", "")
    message.scannedAttachments = attachment_scan_agg.get("scanned_attachments", [])
    message.urlScore = url_scan_agg.get("url_score", 0)
    message.scannedUrls = url_scan_agg.get("scanned_urls", [])
    message.urlScanSummary = url_scan_agg.get("url_summary", "")
    message.hasPhishingUrl = url_scan_agg.get("any_phishing", False)
    message.hasMaliciousUrl = url_scan_agg.get("any_malicious", False)
    message.save(
        update_fields=[
            "attachmentScore",
            "attachmentScanSummary",
            "scannedAttachments",
            "urlScore",
            "scannedUrls",
            "urlScanSummary",
            "hasPhishingUrl",
            "hasMaliciousUrl",
            "synced_at",
        ]
    )


def _message_scan_text(message: EmailMessage) -> str:
    attachment_text = "\n\n".join(
        str(item.get("extracted_text_preview", ""))[:1000]
        for item in (message.scannedAttachments or [])
        if item.get("extracted_text_preview")
    )
    return "\n\n".join(part for part in [message.body, attachment_text] if part)

