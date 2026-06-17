from __future__ import annotations

import logging
from django.utils import timezone

from apps.gmail.models import EmailAccount, EmailMessage
from apps.gmail.services.gmail_fetcher import fetch_inbox_messages
from apps.gmail.services.oauth import build_gmail_service

from apps.gmail.services.ai_analysis import (
    analyse_email,
    _heuristic_fallback,
    compute_ai_score,
    emergency_phishing_boost,
    extract_link_domains,
)

from apps.gmail.services.domain_analysis import analyze_domain
from apps.threats.scoring import compute_threat_result

logger = logging.getLogger(__name__)


# =========================================================
# MAIN SYNC ENTRY
# =========================================================

def sync_account(email_account: EmailAccount, max_results: int = 50) -> dict:
    logger.info("SYNC START: %s", email_account.email)
    stats = {"fetched": 0, "created": 0, "updated": 0, "errors": 0}

    try:
        service = build_gmail_service(email_account)
        messages = fetch_inbox_messages(service, max_results=max_results)
        stats["fetched"] = len(messages)
    except Exception as exc:
        logger.exception("Gmail fetch failed: %s", exc)
        return stats

    for msg in messages:
        try:
            _process_message(email_account, msg, stats)
        except Exception as exc:
            logger.exception(
                "Processing failed for msg %s",
                msg.get("gmail_id"),
                exc
            )
            stats["errors"] += 1

    email_account.last_synced_at = timezone.now()
    email_account.save(update_fields=["last_synced_at"])

    logger.info("SYNC DONE: %s -> %s", email_account.email, stats)
    return stats


# =========================================================
# MESSAGE PROCESSOR
# =========================================================

def _process_message(email_account: EmailAccount, msg: dict, stats: dict) -> None:
    gmail_id = msg.get("gmail_id")
    if not gmail_id:
        return

    existing = EmailMessage.objects.filter(gmail_id=gmail_id).first()
    if existing and existing.analysis_done:
        stats["updated"] += 1
        return

    body = msg.get("body", "")
    subject = msg.get("subject", "")
    sender = msg.get("sender", "")
    sender_domain = (msg.get("domain") or "").lower()

    # =====================================================
    # 1. DOMAIN ANALYSIS
    # =====================================================
    try:
        domain_result = analyze_domain(sender_domain)
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
        domain_result["domainAge"] = 0

    # =====================================================
    # 2. AI ANALYSIS (NO url_scan anymore)
    # =====================================================
    try:
        ai_result = analyse_email(
            subject=subject,
            sender=sender,
            body=body,
            domain=sender_domain,
        )
    except Exception:
        logger.exception("AI analysis failed for %s", sender_domain)
        ai_result = _heuristic_fallback(subject, sender, body, sender_domain)

        ai_result = emergency_phishing_boost(
            text=f"{subject} {sender} {body}",
            score=ai_result,
            sender=sender,
            sender_domain=sender_domain,
        )

        ai_result["ai_score"] = compute_ai_score(
            ai_result.get("urgency", 0),
            ai_result.get("fear", 0),
            ai_result.get("credential_theft", 0),
            ai_result.get("financial_fraud", 0),
            ai_result.get("authority_impersonation", 0),
        )

    # =====================================================
    # 3. LINK DOMAINS
    # =====================================================
    link_domain_scores = []
    try:
        raw_links = extract_link_domains(body) or []
        link_domains = [
            d.lower()
            for d in set(raw_links)
            if d and d.lower() != sender_domain
        ]

        for ld in link_domains:
            try:
                ld_result = analyze_domain(ld)
                link_domain_scores.append(ld_result.get("domainScore", 0))
            except Exception:
                link_domain_scores.append(30)

    except Exception:
        logger.exception("Link domain extraction failed for %s", gmail_id)

    # =====================================================
    # 4. THREAT SCORE
    # =====================================================
    try:
        threat = compute_threat_result(
            ai_score=ai_result.get("ai_score", 0),
            domain_score=domain_result.get("domainScore", 0),
            link_domain_scores=link_domain_scores or None,
            credential_theft=ai_result.get("credential_theft", 0),
            urgency=ai_result.get("urgency", 0),
            authority_impersonation=ai_result.get("authority_impersonation", 0),
            fear=ai_result.get("fear", 0),
            url_score=0,
            any_phishing_url=False,
            any_malicious_url=False,
        )

        threat_score = threat.threat_score
        risk_level = threat.risk_level

    except Exception:
        logger.exception("Threat computation failed for %s", gmail_id)

        fallback_ai = ai_result.get("ai_score", 0)
        fallback_domain = domain_result.get("domainScore", 0)

        threat_score = max(fallback_ai, fallback_domain)

        if threat_score >= 81:
            risk_level = "Critical"
        elif threat_score >= 61:
            risk_level = "High"
        elif threat_score >= 31:
            risk_level = "Medium"
        else:
            risk_level = "Safe"

    # =====================================================
    # 5. AI SUMMARY
    # =====================================================
    ai_summary = ai_result.get("ai_summary", "")

    # =====================================================
    # 6. SAVE TO DB
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

        "aiSummary": ai_summary,
        "aiScore": ai_result.get("ai_score", 0),

        "threatScore": threat_score,
        "riskLevel": risk_level,

        "analysis_done": True,
        "account": email_account,
    }

    obj, created = EmailMessage.objects.update_or_create(
        gmail_id=gmail_id,
        defaults=fields,
    )

    stats["created" if created else "updated"] += 1