"""Validate AI phishing claims against the message and independent security signals."""

from __future__ import annotations

import re
from urllib.parse import urlparse


SCORE_KEYS = (
    "urgency",
    "fear",
    "credential_theft",
    "financial_fraud",
    "authority_impersonation",
)

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_ACTION = (
    r"(?:enter|provide|submit|send|share|type|input|"
    r"введ\w*|надішл\w*|повідом\w*|вкаж\w*|"
    r"введите|предостав\w*|отправ\w*|сообщ\w*|укаж\w*)"
)
_SECRET = (
    r"(?:password|passcode|verification\s+code|confirmation\s+code|"
    r"sms[ -]?code|2fa|mfa|otp|парол\w*|"
    r"код\s+(?:підтвердження|подтверждения|доступу|доступа|з\s+sms))"
)
_CARD = r"(?:card\s+(?:number|details)|cvv|bank\s+details|payment\s+details|картк\w*|банківськ\w*\s+дан\w*|платіжн\w*\s+дан\w*|платежн\w*\s+дан\w*)"
_CREDENTIAL_REQUEST_RE = re.compile(rf"{_ACTION}.{{0,90}}{_SECRET}", re.I | re.U)
_PAYMENT_DATA_RE = re.compile(rf"{_ACTION}.{{0,90}}{_CARD}", re.I | re.U)
_PAYMENT_REQUEST_RE = re.compile(
    r"\b(?:pay|transfer|wire|send\s+money|оплатіть|сплатіть|перекажіть|"
    r"оплатите|переведите|перечислите)\b",
    re.I | re.U,
)
_LOGIN_REQUEST_RE = re.compile(
    r"\b(?:log[ -]?in|sign[ -]?in|login|увійд\w*|увійти|ввійти|"
    r"войдите|войти|авторизуйтесь)\b",
    re.I | re.U,
)
_URGENCY_RE = re.compile(
    r"\b(?:immediately|urgent(?:ly)?|within\s+\d+\s+(?:minutes?|hours?|days?)|"
    r"негайно|терміново|протягом\s+\d+\s+(?:хвилин|годин|днів)|"
    r"срочно|немедленно|в\s+течение\s+\d+\s+(?:минут|часов|дней))\b",
    re.I | re.U,
)
_THREAT_RE = re.compile(
    r"(?:account|access|profile|акаунт|обліков\w*\s+запис|доступ|"
    r"аккаунт|учетн\w*\s+запис).{0,90}"
    r"(?:block\w*|suspend\w*|delet\w*|terminat\w*|заблок\w*|"
    r"видал\w*|призупин\w*|удал\w*|приостанов\w*)|"
    r"(?:block\w*|suspend\w*|заблок\w*).{0,90}"
    r"(?:account|access|акаунт|доступ|аккаунт)",
    re.I | re.U,
)
_NEGATION_RE = re.compile(r"(?:\bnot\b|\bnever\b|don't|do\s+not|\bне\b|ніколи|никогда)", re.I | re.U)


def _root_domain(value: str) -> str:
    parts = [part for part in (value or "").lower().strip(".").split(".") if part]
    # Do not mistake every *.co.uk or *.com.au host for the same sender.
    if len(parts) >= 3 and len(parts[-1]) == 2 and parts[-2] in {
        "ac", "co", "com", "edu", "gov", "net", "org",
    }:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else (parts[0] if parts else "")


def _has_affirmative_match(pattern: re.Pattern, text: str) -> bool:
    for match in pattern.finditer(text):
        # Safety advice such as "do not enter your password" is not a request.
        preceding = text[max(0, match.start() - 18):match.start()]
        if not _NEGATION_RE.search(preceding):
            return True
    return False


def _technical_signals(message) -> dict:
    findings = message.securitySignals or {}
    header_findings = set(findings.get("headerFindings") or [])
    link_findings = set(findings.get("linkFindings") or [])
    auth = (message.authenticationResults or "").lower()
    sender_root = _root_domain(message.domain)
    body_urls = set(_URL_RE.findall(message.body or ""))
    urls = set(body_urls)
    urls.update(str(item.get("url") or "") for item in (message.scannedUrls or []))
    link_roots = {
        _root_domain(urlparse(url).hostname or "")
        for url in urls if urlparse(url).hostname
    }
    aligned_links = bool(sender_root) and all(root == sender_root for root in link_roots)
    url_mismatch = bool(sender_root and link_roots and not aligned_links)
    malicious_url = bool(message.hasMaliciousUrl or any(
        item.get("is_malicious") for item in (message.scannedUrls or [])
    ))
    phishing_url = bool(message.hasPhishingUrl or any(
        item.get("is_phishing") for item in (message.scannedUrls or [])
    ))
    malicious_attachment = any(
        item.get("is_malicious") or int(item.get("score") or 0) >= 75
        for item in (message.scannedAttachments or [])
    )
    form_conflict = any(
        item.get("form_resolution") == "conflicting_reputation"
        for item in (message.scannedUrls or [])
    )
    authenticated = (
        auth.strip().startswith("mx.google.com;")
        and "dmarc=pass" in auth
        and ("dkim=pass" in auth or "spf=pass" in auth)
        and "dmarc=fail" not in auth
    )
    clean_scanned_urls = {
        str(item.get("url") or "")
        for item in (message.scannedUrls or [])
        if str(item.get("verdict") or "").lower() in {"clean", "safe"}
    }
    clean_urls = (
        body_urls.issubset(clean_scanned_urls)
        and all(
            str(item.get("verdict") or "").lower() in {"clean", "safe"}
            for item in (message.scannedUrls or [])
        )
    )
    clean_external = (
        message.domainReputation == "Trusted"
        and int(message.domainScore or 0) <= 20
        and int(message.headerScore or 0) == 0
        and int(message.linkScore or 0) == 0
        and int(message.urlScore or 0) <= 10
        and int(message.attachmentScore or 0) < 30
        and clean_urls
        and len(message.scannedAttachments or []) >= len(message.attachments or [])
        and not (malicious_url or phishing_url or malicious_attachment)
    )
    trusted_delivery = (
        authenticated
        and message.domainReputation == "Trusted"
        and clean_external
        and aligned_links
        and clean_urls
        and not header_findings
        and not link_findings
        and not (message.attachments or [])
    )
    return {
        "authenticated": authenticated,
        "aligned_links": aligned_links,
        "clean_external": clean_external,
        "trusted_delivery": trusted_delivery,
        "malicious_url": malicious_url,
        "phishing_url": phishing_url,
        "malicious_attachment": malicious_attachment,
        "form_conflict": form_conflict,
        "url_mismatch": url_mismatch or "link_domain_mismatch" in link_findings,
        "impersonation": bool(
            message.lookalikeDomain
            or header_findings.intersection({
                "auth_failure", "reply_to_domain_mismatch", "return_path_domain_mismatch",
                "punycode_sender_domain",
            })
            or "punycode_link_domain" in link_findings
        ),
        "header_findings": sorted(header_findings),
        "link_findings": sorted(link_findings),
    }


def technical_context_for_ai(message) -> dict:
    signals = _technical_signals(message)
    return {
        "authenticated_sender": signals["authenticated"],
        "sender_and_link_domains_aligned": signals["aligned_links"],
        "domain_reputation": message.domainReputation,
        "domain_risk_score": message.domainScore,
        "header_findings": signals["header_findings"],
        "link_findings": signals["link_findings"],
        "url_risk_score": message.urlScore,
        "attachment_risk_score": message.attachmentScore,
        "checked_urls": [
            {
                "url": item.get("url"),
                "verdict": item.get("verdict"),
                "score": item.get("score"),
                "provider": (item.get("stats") or {}).get("provider"),
                "form_resolution": item.get("form_resolution"),
                "resolved_url": item.get("resolved_url"),
                "destination_reputation": item.get("destination_reputation"),
            }
            for item in (message.scannedUrls or [])[:3]
        ],
    }


def _validated_quotes(result: dict, message) -> dict[str, str]:
    quotes = result.get("_evidence") or {}
    if not isinstance(quotes, dict):
        return {}
    source = " ".join(
        str(part or "") for part in (
            message.subject,
            message.sender,
            message.body,
            message.urlScanSummary,
            message.attachmentScanSummary,
            *(item.get("url") for item in (message.scannedUrls or [])),
            *(item.get("resolved_url") for item in (message.scannedUrls or [])),
            *(item.get("extracted_text_preview") for item in (message.scannedAttachments or [])),
        )
    )
    haystack = " ".join(source.casefold().split())
    validated = {}
    for key in SCORE_KEYS:
        quote = quotes.get(key)
        if isinstance(quote, str):
            compact = " ".join(quote.casefold().split())
            if 5 <= len(compact) <= 160 and compact in haystack:
                validated[key] = quote[:160]
    return validated


def calibrate_phishing_scores(result: dict, message, *, require_model_evidence: bool = False) -> dict:
    """Remove unsupported model scores; preserve concrete text and external threats."""
    calibrated = dict(result)
    attachment_text = "\n".join(
        str(item.get("extracted_text_preview") or "")[:2000]
        for item in (message.scannedAttachments or [])[:3]
    )
    text = f"{message.subject or ''}\n{message.body or ''}\n{attachment_text}"
    signals = _technical_signals(message)
    quotes = _validated_quotes(result, message)
    credential_request = _has_affirmative_match(_CREDENTIAL_REQUEST_RE, text)
    payment_data_request = _has_affirmative_match(_PAYMENT_DATA_RE, text)
    payment_request = _has_affirmative_match(_PAYMENT_REQUEST_RE, text)
    login_request = _has_affirmative_match(_LOGIN_REQUEST_RE, text)
    urgency = bool(_URGENCY_RE.search(text))
    fear = bool(_THREAT_RE.search(text))
    credential_risk = credential_request or (
        login_request and signals["url_mismatch"]
    )
    financial_risk = payment_data_request or (
        payment_request and not signals["trusted_delivery"] and not signals["clean_external"]
    )
    # A different destination is not impersonation on its own (newsletters
    # often use third-party links), but it matters when secrets are requested.
    impersonation = signals["impersonation"] or (
        signals["url_mismatch"] and credential_risk
    )
    supported = {
        "urgency": urgency,
        "fear": fear,
        "credential_theft": credential_risk,
        "financial_fraud": financial_risk,
        "authority_impersonation": impersonation,
    }
    independently_verified = {
        "urgency": urgency and (credential_risk or financial_risk or signals["url_mismatch"]),
        "fear": fear and (credential_risk or financial_risk or signals["url_mismatch"]),
        "credential_theft": credential_risk,
        "financial_fraud": financial_risk,
        "authority_impersonation": impersonation,
    }

    for key in SCORE_KEYS:
        value = max(0, min(100, int(calibrated.get(key) or 0)))
        if not supported[key]:
            value = min(value, 20)
        elif require_model_evidence and key not in quotes and not independently_verified[key]:
            value = min(value, 20)
        calibrated[key] = value

    # A genuine, aligned sender and clean independent checks are strong counter-
    # evidence to model guesses, unless the email asks for secrets or card details.
    if signals["trusted_delivery"] and not (credential_request or payment_data_request):
        for key in SCORE_KEYS:
            calibrated[key] = min(calibrated[key], 15)
    elif signals["clean_external"] and not (credential_risk or financial_risk):
        for key in SCORE_KEYS:
            calibrated[key] = min(calibrated[key], 25)

    # A URL reputation hit alone is not evidence that the text asks for a
    # password. Only an independent request in the email may raise this bar.
    if credential_request and signals["malicious_url"] and int(message.urlScore or 0) >= 80:
        calibrated["credential_theft"] = max(calibrated["credential_theft"], 85)
        if urgency:
            calibrated["urgency"] = max(calibrated["urgency"], 70)
    elif credential_request and signals["phishing_url"]:
        calibrated["credential_theft"] = max(calibrated["credential_theft"], 70)

    raw_assessment = calibrated.get("_assessment")
    assessment = raw_assessment
    if assessment not in {"benign", "review", "phishing"}:
        assessment = None
    content_phishing = credential_request or payment_data_request
    if assessment == "phishing" and not (
        content_phishing or financial_risk or signals["impersonation"]
        or signals["malicious_attachment"]
    ):
        assessment = "review" if (
            signals["malicious_url"] or signals["phishing_url"]
            or signals["form_conflict"]
        ) else "benign"
    elif assessment == "benign" and (
        signals["malicious_url"] or signals["phishing_url"]
        or signals["form_conflict"]
        or (content_phishing and signals["url_mismatch"])
    ):
        assessment = "review"

    calibrated["_assessment"] = assessment
    calibrated["_evidence"] = quotes
    calibrated["_evidence_signals"] = {
        "authenticated_sender": signals["authenticated"],
        "aligned_links": signals["aligned_links"],
        "clean_external": signals["clean_external"],
        "credential_request": credential_request,
        "payment_data_request": payment_data_request,
        "content_phishing": content_phishing,
        "model_assessment": assessment,
        "raw_model_assessment": raw_assessment,
        "url_threat": signals["malicious_url"] or signals["phishing_url"],
        "form_conflict": signals["form_conflict"],
        "attachment_threat": signals["malicious_attachment"],
    }
    return calibrated
