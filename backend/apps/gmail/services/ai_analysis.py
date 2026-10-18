from __future__ import annotations

import re
import logging
from typing import Dict, Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# =========================================================
# NORMALIZER
# =========================================================

def normalize_ai_result(data: Any) -> Dict[str, Any]:
    if data is None:
        return empty_ai_result()
    if hasattr(data, "__dict__"):
        data = data.__dict__
    return {
        "urgency":                data.get("urgency", 0),
        "fear":                   data.get("fear", 0),
        "credential_theft":       data.get("credential_theft", data.get("credentialTheft", 0)),
        "financial_fraud":        data.get("financial_fraud",  data.get("financialFraud", 0)),
        "authority_impersonation":data.get("authority_impersonation", data.get("authorityImpersonation", 0)),
        "ai_score":               data.get("ai_score", data.get("aiScore", 0)),
        "ai_summary":             data.get("ai_summary", data.get("aiSummary", "")),
        "verdict":                data.get("verdict", ""),
        "recommendations":         data.get("recommendations", []),
    }


def empty_ai_result() -> Dict[str, Any]:
    return {
        "urgency": 0, "fear": 0, "credential_theft": 0,
        "financial_fraud": 0, "authority_impersonation": 0,
        "ai_score": 0, "ai_summary": "No analysis available.",
        "verdict": "", "recommendations": [],
    }


# =========================================================
# LINK EXTRACTION
# =========================================================

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


def extract_link_domains(body: str) -> list[str]:
    domains = []
    for url in _URL_RE.findall(body or ""):
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if host:
            domains.append(host)
    return domains


# =========================================================
# TRUSTED-INFRA IMPERSONATION DETECTOR
# =========================================================

_FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "ukr.net", "meta.ua", "i.ua", "mail.ru", "yandex.ru",
}

_BRAND_PATTERNS = [
    r"privat\s*24", r"приват\s*24", r"privatbank", r"приватбанк",
    r"monobank", r"монобанк", r"oschadbank", r"ощадбанк",
    r"raiffeisen", r"укрсиббанк", r"пумб", r"abank",
    r"paypal", r"apple\s*pay", r"google\s*pay",
    r"microsoft", r"google\s+support", r"amazon",
    r"nova\s*poshta", r"нова\s*пошта", r"укрпошта",
    r"служба\s+безпеки", r"security\s+team", r"support\s+team",
    r"адміністрація", r"адміністратор",
]


def detect_sender_impersonation(sender: str, body: str, sender_domain: str) -> int:
    if sender_domain not in _FREE_EMAIL_PROVIDERS:
        return 0
    combined = (sender + " " + body).lower()
    hits = sum(1 for p in _BRAND_PATTERNS if re.search(p, combined, re.I | re.U))
    if hits >= 2: return 50
    if hits == 1: return 30
    return 0


# =========================================================
# EMERGENCY PHISHING RULE ENGINE
# =========================================================

_EMERGENCY_RULES: list[tuple] = [
    (re.compile(r"(qr[\s-]?code|scan\s+qr|відскануй|скануй\s+qr|qr[\s-]?код)", re.I | re.U),
     ["credential_theft", "urgency", "authority_impersonation"], 45),

    (re.compile(r"(sync\s+device|синхронізац|2fa\s+sync|підтверд.{0,10}(пристрій|device)|"
                r"2fa\s+верифікац|two[\s-]?factor\s+verif)", re.I | re.U),
     ["credential_theft", "authority_impersonation"], 45),

    (re.compile(r"(заблокують|буде\s+заблоковано|account\s+will\s+be\s+suspended|"
                r"ваш\s+(акаунт|рахунок|обліковий\s+запис).{0,30}(заблок|припин|призупин))",
                re.I | re.U),
     ["fear", "urgency"], 40),

    (re.compile(r"(\d+\s*(годин|hours?|год\.)\s*(на\s+підтвердж)?|"
                r"протягом\s+\d+\s*(год|хв|хвилин)|within\s+\d+\s*(hours?|minutes?))", re.I | re.U),
     ["urgency"], 35),

    (re.compile(r"(оновіть?\s+(налаштування|безпеку|пароль)|update\s+security\s+settings|"
                r"verify\s+your\s+identity|підтвердіть?\s+(особу|ідентичність))", re.I | re.U),
     ["credential_theft", "authority_impersonation"], 40),

    (re.compile(r"(privat24|приват24|privatbank|приватбанк|monobank|монобанк)", re.I | re.U),
     ["authority_impersonation"], 35),

    (re.compile(r"(введіть\s+логін|введіть.{0,40}парол|ввести\s+пароль|"
                r"введіть.{0,40}код\s+підтвердження|sms.{0,20}код|код.{0,20}sms|"
                r"enter\s+your\s+(password|login)|log\s+in\s+to\s+confirm|confirm\s+your\s+account)",
                re.I | re.U),
     ["credential_theft"], 30),
]



def _has_severe_credential_extortion(text: str) -> bool:
    """Detect explicit account-lock pressure plus credential/payment collection."""
    lowered = (text or "").lower()
    has_account_pressure = bool(re.search(
        r"(акаунт|account|доступ|обліковий\s+запис).{0,80}(заблок|видален|suspend|blocked|deleted|terminated)|"
        r"(заблок|видален|suspend|blocked|deleted|terminated).{0,80}(акаунт|account|доступ|обліковий\s+запис)",
        lowered,
        re.I | re.U,
    ))
    has_password = bool(re.search(r"(парол|password|login|sign[\s-]?in|увійд|вхід)", lowered, re.I | re.U))
    has_code = bool(re.search(r"(код\s+підтвердження|sms|2fa|mfa|одноразовий\s+код|verification\s+code)", lowered, re.I | re.U))
    has_payment = bool(re.search(r"(платіжн|банківськ|картк|card|payment|billing)", lowered, re.I | re.U))
    has_deadline = bool(re.search(r"(протягом\s+\d+\s*(хв|хвилин|год)|within\s+\d+\s*(minutes?|hours?)|негайно|терміново|immediately|urgent)", lowered, re.I | re.U))
    return has_account_pressure and has_deadline and has_password and (has_code or has_payment)

def emergency_phishing_boost(
    text: str,
    score: Dict[str, Any],
    sender: str = "",
    sender_domain: str = "",
) -> Dict[str, Any]:
    t = (text or "").lower()
    for pattern, fields, boost in _EMERGENCY_RULES:
        if pattern.search(t):
            for f in fields:
                score[f] = min(100, score.get(f, 0) + boost)
            logger.debug("Emergency rule matched → boost %s by %d", fields, boost)

    if _has_severe_credential_extortion(t):
        score["credential_theft"] = max(score.get("credential_theft", 0), 95)
        score["urgency"] = max(score.get("urgency", 0), 85)
        score["fear"] = max(score.get("fear", 0), 80)
        score["authority_impersonation"] = max(score.get("authority_impersonation", 0), 65)
        if re.search(r"(платіжн|банківськ|картк|card|payment|billing)", t, re.I | re.U):
            score["financial_fraud"] = max(score.get("financial_fraud", 0), 70)
        logger.debug("Emergency rule matched -> severe credential extortion floors applied")
    imp_boost = detect_sender_impersonation(sender, text, sender_domain)
    if imp_boost:
        score["authority_impersonation"] = min(100, score.get("authority_impersonation", 0) + imp_boost)
        score["credential_theft"] = min(100, score.get("credential_theft", 0) + imp_boost // 2)

    return score


# =========================================================
# AI SCORE COMPUTATION
# =========================================================

def compute_ai_score(urgency: int, fear: int, credential_theft: int,
                     financial_fraud: int, authority_impersonation: int) -> int:
    return min(100, round(
        credential_theft        * 0.30 +
        financial_fraud         * 0.25 +
        authority_impersonation * 0.20 +
        urgency                 * 0.15 +
        fear                    * 0.10
    ))


# =========================================================
# HEURISTIC FALLBACK (multilingual)
# =========================================================

_URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bwithin\s+\d+\s+hour",
    r"\bact\s+now\b", r"\bexpire[sd]?\b", r"\bdeadline\b",
    r"\btime[\s-]?sensitive\b", r"\bASAP\b", r"\btoday\s+only\b",
    r"терміново", r"срочно", r"негайно", r"немедленно",
    r"до кінця дня", r"протягом\s+\d", r"в течение\s+\d",
    r"діє до", r"залишилось\s+\d",
]
_FEAR_PATTERNS = [
    r"\bsuspended?\b", r"\blocked?\b", r"\bterminated?\b",
    r"\bunauthorized\b", r"\bsuspicious\s+activity\b", r"\bdeactivat",
    r"заблоковано", r"заблокирован", r"призупинено", r"приостановлен",
    r"видален", r"анульован", r"повернуться до", r"згорять",
    r"обмежено\s+доступ", r"втратите",
]
_CREDENTIAL_PATTERNS = [
    r"\bpassword\b", r"\bcredential\b", r"\blogin\b", r"\bsign[\s-]?in\b",
    r"\bverif[yied]+\b", r"\bauthenticat\b", r"\baccount\b",
    r"\bupdate\s+your\s+profile\b", r"\bconfirm\s+your\b", r"\bclick\s+here\b",
    r"qr[\s-]?code", r"scan\s+qr", r"відскануй", r"скануй",
    r"sync\s+device", r"синхронізац", r"2fa",
    r"пароль", r"увійти", r"войти", r"вхід",
    r"підтвердьте?\b", r"підтвердж", r"оновити\s+(статус\s+)?профіл",
]
_FINANCIAL_PATTERNS = [
    r"\$[\d,]+", r"\bwire\s+transfer\b", r"\binvoice\b", r"\bpayment\b",
    r"\bbilling\b", r"\brefund\b", r"\bbank\b", r"\btransfer\b",
    r"\bbonus(es)?\b", r"\breward\b", r"\bprize\b", r"\bwinn(er|ings)\b",
    r"бонус", r"кошти", r"средства", r"виграш",
    r"переказ", r"оплат", r"рахунок", r"нараховано",
]
_AUTHORITY_PATTERNS = [
    r"\bpaypal\b", r"\bmicrosoft\b", r"\bgoogle\b", r"\bapple\b",
    r"\bamazon\b", r"\bsupport\s+team\b", r"\bloyalty\s+program\b",
    r"privat24", r"приват24", r"privatbank", r"приватбанк",
    r"monobank", r"монобанк", r"oschadbank", r"ощадбанк",
    r"служба підтримки", r"служба поддержки", r"адміністрація",
    r"банк", r"податкова",
]


def _match_score(text: str, patterns: list[str]) -> int:
    text_lower = text.lower()
    hits = sum(1 for p in patterns if re.search(p, text_lower, re.IGNORECASE | re.UNICODE))
    return min(hits * 15, 95)


def _heuristic_fallback(subject: str, sender: str, body: str, domain: str) -> Dict[str, Any]:
    full_text = f"{subject} {sender} {body}"
    urgency        = _match_score(full_text, _URGENCY_PATTERNS)
    fear           = _match_score(full_text, _FEAR_PATTERNS)
    credential_theft = _match_score(full_text, _CREDENTIAL_PATTERNS)
    financial_fraud  = _match_score(full_text, _FINANCIAL_PATTERNS)
    authority_imp    = _match_score(full_text, _AUTHORITY_PATTERNS)

    link_domains = set(extract_link_domains(body))
    link_domains.discard((domain or "").lower())
    if link_domains and (credential_theft > 0 or financial_fraud > 0):
        credential_theft = min(100, credential_theft + 30)
        authority_imp    = min(100, authority_imp + 15)

    ai_score = compute_ai_score(urgency, fear, credential_theft, financial_fraud, authority_imp)
    ai_summary = _fallback_summary(
        domain=domain,
        ai_score=ai_score,
        link_domains=link_domains,
        credential_theft=credential_theft,
        financial_fraud=financial_fraud,
        authority_impersonation=authority_imp,
        urgency=urgency,
        fear=fear,
    )
    return {
        "urgency": urgency, "fear": fear,
        "credential_theft": credential_theft, "financial_fraud": financial_fraud,
        "authority_impersonation": authority_imp, "ai_score": ai_score,
        "ai_summary": ai_summary,
    }


def _fallback_summary(
    domain: str,
    ai_score: int,
    link_domains: set[str],
    credential_theft: int,
    financial_fraud: int,
    authority_impersonation: int,
    urgency: int,
    fear: int,
) -> str:
    domain_label = domain or "unknown"
    if ai_score < 20:
        return (
            "AI service is temporarily unavailable. The email was checked with local "
            f"security rules: sender domain {domain_label}, no strong phishing indicators detected."
        )

    findings = []
    if credential_theft >= 30:
        findings.append("credential request indicators")
    if financial_fraud >= 30:
        findings.append("financial fraud indicators")
    if authority_impersonation >= 30:
        findings.append("authority impersonation")
    if urgency >= 30:
        findings.append("urgency pressure")
    if fear >= 30:
        findings.append("fear tactics")
    if link_domains:
        findings.append(f"external link domains: {', '.join(sorted(link_domains))}")

    return (
        "AI service is temporarily unavailable. The email was checked with local "
        f"security rules for sender domain {domain_label}; detected "
        f"{'; '.join(findings) if findings else 'suspicious patterns'}."
    )
