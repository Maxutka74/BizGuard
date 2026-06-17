from __future__ import annotations

import os
import re
import time
import json
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)

DEFAULT_GEMINI_MODEL = "gemini-2.0-flash"
_GEMINI_DELAY = 4.0


# =========================================================
# RESULT MODEL
# =========================================================

@dataclass
class AIAnalysisResult:
    urgency: int
    fear: int
    credential_theft: int
    financial_fraud: int
    authority_impersonation: int
    ai_score: int
    ai_summary: str


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
    }


def empty_ai_result() -> Dict[str, Any]:
    return {
        "urgency": 0, "fear": 0, "credential_theft": 0,
        "financial_fraud": 0, "authority_impersonation": 0,
        "ai_score": 0, "ai_summary": "No analysis available.",
    }


# =========================================================
# LINK EXTRACTION
# =========================================================

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


def extract_link_domains(body: str) -> list[str]:
    domains = []
    for url in _URL_RE.findall(body or ""):
        m = re.match(r"https?://([^/]+)", url, re.IGNORECASE)
        if m:
            host = m.group(1).lower().split("@")[-1].split(":")[0]
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
                r"протягом\s+\d+\s*год|within\s+\d+\s*hours?)", re.I | re.U),
     ["urgency"], 35),

    (re.compile(r"(оновіть?\s+(налаштування|безпеку|пароль)|update\s+security\s+settings|"
                r"verify\s+your\s+identity|підтвердіть?\s+(особу|ідентичність))", re.I | re.U),
     ["credential_theft", "authority_impersonation"], 40),

    (re.compile(r"(privat24|приват24|privatbank|приватбанк|monobank|монобанк)", re.I | re.U),
     ["authority_impersonation"], 35),

    (re.compile(r"(введіть\s+логін|ввести\s+пароль|enter\s+your\s+(password|login)|"
                r"log\s+in\s+to\s+confirm|confirm\s+your\s+account)", re.I | re.U),
     ["credential_theft"], 30),
]


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

    imp_boost = detect_sender_impersonation(sender, text, sender_domain)
    if imp_boost:
        score["authority_impersonation"] = min(100, score.get("authority_impersonation", 0) + imp_boost)
        score["credential_theft"] = min(100, score.get("credential_theft", 0) + imp_boost // 2)

    return score


# =========================================================
# URL SCAN BOOST  ← NEW
# =========================================================

def url_scan_boost(score: Dict[str, Any], url_agg: dict) -> Dict[str, Any]:
    """
    Inject URL scan signals into AI dimension scores.
    Called AFTER emergency_phishing_boost, before final ai_score computation.

    url_agg is the dict returned by aggregate_url_scores().
    """
    url_score = url_agg.get("url_score", 0)
    any_phishing  = url_agg.get("any_phishing", False)
    any_malicious = url_agg.get("any_malicious", False)

    if any_malicious:
        # Definitive malicious URL → hard lift on credential_theft + authority
        score["credential_theft"]        = max(score.get("credential_theft", 0), 85)
        score["authority_impersonation"] = max(score.get("authority_impersonation", 0), 70)
        score["urgency"]                 = max(score.get("urgency", 0), 60)
        logger.debug("URL scan boost: malicious URL detected")

    elif any_phishing:
        score["credential_theft"]        = max(score.get("credential_theft", 0), 70)
        score["authority_impersonation"] = max(score.get("authority_impersonation", 0), 55)
        score["urgency"]                 = max(score.get("urgency", 0), 45)
        logger.debug("URL scan boost: phishing URL detected")

    elif url_score >= 50:
        # Suspicious URL
        score["credential_theft"] = max(score.get("credential_theft", 0), url_score - 10)
        logger.debug("URL scan boost: suspicious URL score=%d", url_score)

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
    return {
        "urgency": urgency, "fear": fear,
        "credential_theft": credential_theft, "financial_fraud": financial_fraud,
        "authority_impersonation": authority_imp, "ai_score": ai_score,
        "ai_summary": f"Heuristic analysis (Gemini unavailable). Domain: {domain or 'unknown'}.",
    }


# =========================================================
# GEMINI CALL  — STRICT PROMPT
# =========================================================

_SYSTEM_PROMPT = """You are an expert cybersecurity analyst specialising in phishing, BEC, and social-engineering email detection.

LANGUAGE: The email may be in ANY language (English, Ukrainian, Russian, Polish, etc.).
Analyse MEANING and INTENT — not keyword presence. A Ukrainian-language phishing email is as dangerous as an English one.

────────────────────────────────────────────────────────────
FIVE THREAT DIMENSIONS  (each 0-100)
────────────────────────────────────────────────────────────
urgency
  Pressure to act within a time limit. Deadlines, countdowns, "X hours", "today only".
  → 0 = no time pressure   |  100 = extreme artificial deadline

fear
  Threat of negative consequences if the reader does NOT act.
  Account blocking, service termination, legal action, loss of funds/bonuses.
  → 0 = no fear tactic  |  100 = severe explicit threat

credential_theft
  ANY attempt to collect login credentials, 2FA codes, or account access.
  Includes: QR-code scan (to "sync" or "verify"), device pairing,
  2FA sync, "log in to confirm", phishing links, fake portals.
  QR-code + 2FA/sync + deadline = TEXTBOOK phishing → score 85-100.
  → 0 = no credential request  |  100 = blatant credential harvesting

financial_fraud
  Monetary lure or fraud: bonuses, prizes, refunds, invoices, wire transfers.
  → 0 = no financial element  |  100 = clear financial fraud

authority_impersonation
  Pretending to be a bank, well-known brand, security team, government body,
  or official service. Especially HIGH (85-100) when sent from a FREE email
  provider (gmail.com, ukr.net, etc.) while claiming to be a bank or brand.
  → 0 = clearly the real sender  |  100 = definitive impersonation

────────────────────────────────────────────────────────────
STRICT SCORING RULES  (non-negotiable)
────────────────────────────────────────────────────────────
1. QR-code phishing (scan QR / sync device / 2FA verification):
   credential_theft ≥ 85, urgency ≥ 70, authority_impersonation ≥ 70

2. Free email provider (gmail / yahoo / ukr.net) impersonating a bank or brand:
   authority_impersonation ≥ 85

3. "Account will be blocked/suspended in X hours":
   fear ≥ 80, urgency ≥ 75

4. Any combination of (urgency ≥ 60) + (bank/brand impersonation) + (credential request):
   ALL three affected dimensions ≥ 70

5. Mismatched link domain (URL domain ≠ claimed sender brand):
   credential_theft ≥ 70, authority_impersonation ≥ 65

6. Legitimate transactional email from a verified corporate domain with no suspicious signals:
   ALL dimensions 0-15 max

────────────────────────────────────────────────────────────
SCALE REFERENCE
────────────────────────────────────────────────────────────
0-10   → No indicators, clearly legitimate
11-39  → Minor / ambiguous indicators
40-69  → Moderate — suspicious
70-89  → Strong — high threat
90-100 → Textbook / definitive malicious content

────────────────────────────────────────────────────────────
OUTPUT FORMAT  (strict JSON, no markdown, no code fences)
────────────────────────────────────────────────────────────
{
  "urgency": <int 0-100>,
  "fear": <int 0-100>,
  "credential_theft": <int 0-100>,
  "financial_fraud": <int 0-100>,
  "authority_impersonation": <int 0-100>,
  "ai_summary": "<2-4 sentences in the SAME LANGUAGE as the email body explaining the key threat indicators>"
}"""


def _gemini(subject: str, sender: str, body: str, domain: str,
            api_key: str, url_context: str = "") -> Dict[str, Any]:
    import requests as req

    model = os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
    url_api = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent?key={api_key}"
    )

    link_domains = extract_link_domains(body)
    links_note = ""
    if link_domains:
        links_note = (
            f"Links in email point to: {', '.join(sorted(set(link_domains)))}. "
            f"Sender domain is '{domain}'. Domain mismatch = strong phishing signal.\n"
        )

    # Inject URL scan results so Gemini has external verdict
    url_scan_note = ""
    if url_context:
        url_scan_note = f"\n[EXTERNAL URL SCAN RESULTS]\n{url_context}\n"

    user_prompt = (
        f"From: {sender}\nSubject: {subject}\n"
        f"Sender domain: {domain}\n"
        f"{links_note}"
        f"{url_scan_note}"
        f"\nBody:\n{body[:4000]}"
    )

    payload = {
        "contents": [
            {"role": "user", "parts": [{"text": _SYSTEM_PROMPT + "\n\n" + user_prompt}]}
        ],
        "generationConfig": {
            "temperature": 0.05,       # very low — deterministic judgements
            "maxOutputTokens": 512,
            "responseMimeType": "application/json",
        },
    }

    resp = req.post(url_api, json=payload, timeout=30)
    if resp.status_code == 429:
        logger.warning("Gemini 429, sleeping then retrying...")
        time.sleep(_GEMINI_DELAY * 3)
        resp = req.post(url_api, json=payload, timeout=30)

    resp.raise_for_status()
    raw = resp.json()

    try:
        parts   = raw["candidates"][0]["content"]["parts"]
        text    = "".join(p.get("text", "") for p in parts).strip()
    except (KeyError, IndexError) as exc:
        raise ValueError(f"Unexpected Gemini response: {raw}") from exc

    text = re.sub(r"^```(?:json)?", "", text).strip()
    text = re.sub(r"```$", "", text).strip()

    data = json.loads(text)
    time.sleep(_GEMINI_DELAY)
    return data


# =========================================================
# MAIN ENTRY POINT
# =========================================================

def analyse_email(
    subject: str,
    sender: str,
    body: str,
    domain: str,
    url_scan_agg: Optional[dict] = None,   # ← NEW: from url_scan.aggregate_url_scores()
) -> Dict[str, Any]:
    """
    Main analysis pipeline:
      1. Try Gemini (with URL scan context injected into prompt)
      2. Heuristic fallback if Gemini fails
      3. Emergency rule boosts (always)
      4. URL scan dimension boost (always, if url_scan_agg provided)
      5. Recompute ai_score
    """
    api_key = os.environ.get("GEMINI_API_KEY")

    # Build URL context string for Gemini prompt
    url_context = ""
    if url_scan_agg:
        parts = []
        if url_scan_agg.get("any_malicious"):
            parts.append(f"MALICIOUS URLs found: {', '.join(url_scan_agg.get('malicious_urls', []))}")
        if url_scan_agg.get("any_phishing") and not url_scan_agg.get("any_malicious"):
            parts.append(f"PHISHING URLs found: {', '.join(url_scan_agg.get('phishing_urls', []))}")
        if url_scan_agg.get("url_score", 0) >= 40:
            parts.append(f"Highest URL risk score: {url_scan_agg['url_score']}/100")
        if url_scan_agg.get("url_summary"):
            parts.append(url_scan_agg["url_summary"])
        url_context = "\n".join(parts)

    raw_result = None
    if api_key:
        try:
            raw_result = _gemini(subject, sender, body, domain, api_key, url_context=url_context)
        except Exception as exc:
            logger.warning("Gemini failed → heuristic fallback: %s", exc)

    result = normalize_ai_result(raw_result) if raw_result is not None else _heuristic_fallback(subject, sender, body, domain)

    # Emergency rule engine — always
    result = emergency_phishing_boost(
        text=f"{subject} {sender} {body}",
        score=result,
        sender=sender,
        sender_domain=domain,
    )

    # URL scan dimension boost — always if data available
    if url_scan_agg:
        result = url_scan_boost(result, url_scan_agg)

    # Recompute ai_score from final boosted dimensions
    result["ai_score"] = compute_ai_score(
        urgency=result["urgency"],
        fear=result["fear"],
        credential_theft=result["credential_theft"],
        financial_fraud=result["financial_fraud"],
        authority_impersonation=result["authority_impersonation"],
    )

    return result
