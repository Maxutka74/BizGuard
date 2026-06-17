from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_GEMINI_MODEL = "gemini-2.0-flash"
_GEMINI_DELAY = 4.0  # Free tier: 15 RPM -> 1 запит кожні 4 секунди


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AIAnalysisResult:
    urgency: int
    fear: int
    credential_theft: int
    financial_fraud: int
    authority_impersonation: int
    ai_summary: str
    ai_score: int


# ---------------------------------------------------------------------------
# Prompt (multilingual, incl. Ukrainian)
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """You are a cybersecurity AI that analyses emails for phishing, scam, \
and social-engineering threats.

CRITICAL: The email may be written in ANY language - English, Ukrainian, Russian, \
Polish, etc. Analyse the MEANING and INTENT of the text, not specific English \
keywords. A phishing email written in Ukrainian is exactly as dangerous as one \
written in English and MUST receive an equivalent score.

Evaluate the email on five threat dimensions, each scored 0-100:

- urgency: language that pressures the reader to act fast or within a short
  deadline (examples in any language: "act now", "today only", "until the end
  of the day", "сьогодні", "до кінця дня", "терміново", "негайно").

- fear: warnings of negative consequences if the reader does NOT act (account
  suspension, loss of access, loss of money/bonuses, legal action - e.g.
  "ваш рахунок буде заблоковано", "бонуси повернуться до фонду").

- credential_theft: ANY request to log in, "confirm", "update", "verify" an
  account / profile / personal data via a link, especially when the link
  points to a domain unrelated to the claimed sender (e.g. "увійдіть у ваш
  особистий кабінет", "оновити статус профілю", "підтвердьте дані"). Polite
  or friendly wording does NOT reduce the score.

- financial_fraud: mentions of money, bonuses, rewards, refunds, prizes,
  loyalty-programme winnings, invoices, transfers used as bait
  (e.g. "бонусні кошти нараховано", "ваш виграш", "повернення коштів").

- authority_impersonation: the email claims to be from a bank, well-known
  company, government body, "support team", "loyalty programme",
  "administration", HR/IT department, etc. (e.g. "Служба підтримки",
  "Адміністрація сайту").

IMPORTANT PATTERN: A message that (1) congratulates the user / offers a
bonus, reward, refund or gift, AND (2) asks them to click a link to
"confirm", "activate", "update" or "log in" to receive it, is a CLASSIC
PHISHING PATTERN regardless of how friendly the tone is. Score such emails
HIGH on credential_theft, financial_fraud, urgency and
authority_impersonation (typically 60-90+), NOT low.

Also pay close attention to any URLs in the email body: if a URL's domain
does NOT match the organisation the sender claims to represent, this is a
STRONG credential_theft and authority_impersonation signal (60-90+).

Scoring guide:
  0-10   -> No indicators / clearly legitimate
  11-39  -> Minor indicators, likely safe
  40-69  -> Moderate indicators, suspicious
  70-89  -> Strong indicators, high threat
  90-100 -> Definitive malicious content / textbook phishing

Also provide a concise "ai_summary" (2-4 sentences) WRITTEN IN THE SAME
LANGUAGE AS THE EMAIL BODY, explaining the key threat indicators found
(including any suspicious link/domain), or confirming the email is
legitimate.

Respond ONLY with valid JSON (no markdown, no code fences, no extra text):
{
  "urgency": <int 0-100>,
  "fear": <int 0-100>,
  "credential_theft": <int 0-100>,
  "financial_fraud": <int 0-100>,
  "authority_impersonation": <int 0-100>,
  "ai_summary": "<string, same language as the email body>"
}"""

_USER_PROMPT_TEMPLATE = """Analyse the following email:

From: {sender}
Subject: {subject}
Sender domain: {domain}
{links_note}
Body:
{body}"""

# ---------------------------------------------------------------------------
# Link extraction (also used by the heuristic fallback)
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


def extract_link_domains(body: str) -> list[str]:
    """Return a list of lowercase domains found in URLs within the body."""
    domains = []
    for url in _URL_RE.findall(body or ""):
        m = re.match(r"https?://([^/]+)", url, re.IGNORECASE)
        if not m:
            continue
        host = m.group(1).lower().split("@")[-1].split(":")[0]
        domains.append(host)
    return domains


# ---------------------------------------------------------------------------
# Score helpers
# ---------------------------------------------------------------------------

def _compute_ai_score(
        urgency: int,
        fear: int,
        credential_theft: int,
        financial_fraud: int,
        authority_impersonation: int,
) -> int:
    """
    Weighted aggregate of the five threat dimensions:
      credential_theft        30%
      financial_fraud         25%
      authority_impersonation 20%
      urgency                 15%
      fear                    10%
    """
    score = (
            credential_theft * 0.30
            + financial_fraud * 0.25
            + authority_impersonation * 0.20
            + urgency * 0.15
            + fear * 0.10
    )
    return min(100, round(score))


def compute_threat_score(ai_score: int, domain_score: int) -> int:
    """Final threat score: AI Score (70%) + Domain Score (30%)."""
    return max(0, min(100, round(ai_score * 0.70 + domain_score * 0.30)))


def score_to_risk_level(threat_score: int) -> str:
    """
    Map numeric threat score to RiskLevel string matching frontend enum.
    Thresholds per spec: 0-30 Safe, 31-60 Medium, 61-80 High, 81-100 Critical.
    """
    if threat_score >= 81:
        return "Critical"
    if threat_score >= 61:
        return "High"
    if threat_score >= 31:
        return "Medium"
    return "Safe"


def _clamp(value: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, value))


# ---------------------------------------------------------------------------
# Core analysis function
# ---------------------------------------------------------------------------

def analyse_email(
        subject: str,
        sender: str,
        body: str,
        *,
        domain: str = "",
        fallback_on_error: bool = True,
) -> AIAnalysisResult:
    """
    Call Gemini to analyse a single email. Falls back to a multilingual
    heuristic analyser (NOT a neutral zero-result) if Gemini is unavailable
    or fails, so the UI never shows "Safe / 0%" for an email that simply
    couldn't be analysed by Gemini.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        logger.warning("GEMINI_API_KEY is not set - using heuristic analysis only.")
        return _analyse_heuristic(subject, sender, body, domain)

    try:
        return _analyse_with_gemini(subject, sender, body, domain, api_key)
    except Exception:
        logger.exception(
            "Gemini analysis failed for sender=%s domain=%s subject=%r. "
            "Falling back to heuristic analysis.",
            sender, domain, subject,
        )
        if not fallback_on_error:
            raise
        return _analyse_heuristic(subject, sender, body, domain)


def _analyse_with_gemini(
        subject: str, sender: str, body: str, domain: str, api_key: str,
) -> AIAnalysisResult:
    import requests

    model_name = os.environ.get("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model_name}:generateContent?key={api_key}"
    )

    link_domains = extract_link_domains(body)
    links_note = ""
    if link_domains:
        links_note = (
                "Links found in the email body point to these domains: "
                + ", ".join(sorted(set(link_domains)))
                + f". The sender's email domain is '{domain}'. Compare them.\n"
        )

    prompt = _USER_PROMPT_TEMPLATE.format(
        sender=sender,
        subject=subject,
        domain=domain,
        links_note=links_note,
        body=body[:4000],
    )

    payload = {
        "contents": [
            {"role": "user", "parts": [{"text": _SYSTEM_PROMPT + "\n\n" + prompt}]}
        ],
        "generationConfig": {
            "temperature": 0.1,
            "maxOutputTokens": 512,
            "responseMimeType": "application/json",
        },
    }

    resp = requests.post(url, json=payload, timeout=30)

    if resp.status_code == 429:
        logger.warning("Gemini 429, sleeping %ss then retrying...", _GEMINI_DELAY * 3)
        time.sleep(_GEMINI_DELAY * 3)
        resp = requests.post(url, json=payload, timeout=30)

    if not resp.ok:
        logger.error(
            "Gemini API error %s for model=%s: %s",
            resp.status_code, model_name, resp.text[:1000],
        )
    resp.raise_for_status()
    raw_data = resp.json()

    try:
        candidates = raw_data["candidates"]
        if not candidates:
            raise ValueError(f"Gemini returned no candidates: {raw_data}")
        parts = candidates[0]["content"]["parts"]
        raw_text = "".join(p.get("text", "") for p in parts).strip()
    except (KeyError, IndexError) as exc:
        raise ValueError(f"Unexpected Gemini response shape: {raw_data}") from exc

    if not raw_text:
        raise ValueError(f"Gemini returned empty text. Full response: {raw_data}")

    raw_text = re.sub(r"^```(?:json)?", "", raw_text).strip()
    raw_text = re.sub(r"```$", "", raw_text).strip()

    try:
        data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Could not parse Gemini JSON: {raw_text!r}") from exc

    urgency = _clamp(int(data.get("urgency", 0)))
    fear = _clamp(int(data.get("fear", 0)))
    credential_theft = _clamp(int(data.get("credential_theft", 0)))
    financial_fraud = _clamp(int(data.get("financial_fraud", 0)))
    authority_impersonation = _clamp(int(data.get("authority_impersonation", 0)))
    ai_summary = str(data.get("ai_summary", "")).strip() or "Аналіз недоступний."

    ai_score = _compute_ai_score(
        urgency=urgency,
        fear=fear,
        credential_theft=credential_theft,
        financial_fraud=financial_fraud,
        authority_impersonation=authority_impersonation,
    )

    # Throttle після успішного запиту
    time.sleep(_GEMINI_DELAY)

    return AIAnalysisResult(
        urgency=urgency,
        fear=fear,
        credential_theft=credential_theft,
        financial_fraud=financial_fraud,
        authority_impersonation=authority_impersonation,
        ai_summary=ai_summary,
        ai_score=ai_score,
    )


# ---------------------------------------------------------------------------
# Heuristic fallback (multilingual: English + Ukrainian/Russian)
# ---------------------------------------------------------------------------

_URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bwithin\s+\d+\s+hour",
    r"\bact\s+now\b", r"\bexpire[sd]?\b", r"\bdeadline\b",
    r"\btime[\s-]?sensitive\b", r"\bASAP\b", r"\btoday\s+only\b",
    r"терміново", r"срочно", r"негайно", r"немедленно",
    r"до кінця дня", r"до конца дня", r"протягом\s+\d", r"в течение\s+\d",
    r"діє до", r"действует до", r"встигніть", r"успейте",
    r"залишилось\s+\d", r"осталось\s+\d",
]
_FEAR_PATTERNS = [
    r"\bsuspended?\b", r"\blocked?\b", r"\bterminated?\b",
    r"\bunauthorized\b", r"\bsuspicious\s+activity\b",
    r"\bfailure\s+to\b", r"\bpenalt[yies]+\b", r"\bpermanent(ly)?\b",
    r"\bdeactivat",
    r"заблоковано", r"заблокирован", r"призупинено", r"приостановлен",
    r"видален", r"анульован", r"аннулирован",
    r"повернуться до", r"вернутся в", r"згорять", r"сгорят",
    r"обмежено\s+доступ", r"ограничен\s+доступ", r"втратите", r"потеряете",
]
_CREDENTIAL_PATTERNS = [
    r"\bpassword\b", r"\bcredential\b", r"\blogin\b", r"\bsign[\s-]?in\b",
    r"\bverif[yied]+\b", r"\bauthenticat\b", r"\baccount\b",
    r"\bupdate\s+your\s+profile\b", r"\bconfirm\s+your\b",
    r"\bclick\s+here\b", r"\bpersonal\s+(account|dashboard|cabinet)\b",
    r"пароль", r"увійти", r"войти", r"вхід", r"вход",
    r"особист(ий|ому)\s+кабінет", r"личн(ый|ом)\s+кабинет",
    r"особистий рахунок", r"личный счет",
    r"оновити\s+(статус\s+)?профіл", r"обновить\s+(статус\s+)?профил",
    r"підтвердьте?\b", r"подтвердите?\b", r"підтвердж", r"подтвержд",
    r"оновлення\s+(статусу|облікового запису)", r"обновление\s+(статуса|аккаунта)",
    r"особистому кабінеті", r"личном кабинете",
]
_FINANCIAL_PATTERNS = [
    r"\$[\d,]+", r"\bwire\s+transfer\b", r"\binvoice\b",
    r"\bpayment\b", r"\bbilling\b", r"\brefund\b",
    r"\bbank\b", r"\btransfer\b", r"\bbonus(es)?\b", r"\breward\b",
    r"\bprize\b", r"\bwinn(er|ings)\b", r"\bcashback\b",
    r"бонус", r"кошти", r"средства", r"виграш", r"выигрыш",
    r"переказ", r"перевод", r"оплат", r"рахунок", r"счет",
    r"повернення\s+коштів", r"возврат\s+средств", r"приз", r"знижк", r"скидк",
    r"нараховано", r"начислен",
]
_AUTHORITY_PATTERNS = [
    r"\bpaypal\b", r"\bmicrosoft\b", r"\bgoogle\b", r"\bapple\b",
    r"\bamazon\b", r"\bfedex\b", r"\bups\b", r"\bits\s+department\b",
    r"\bceo\b", r"\bmanagement\b", r"\bhr\s+department\b",
    r"\bdocusign\b", r"\birs\b", r"\bfbi\b", r"\bsupport\s+team\b",
    r"\bloyalty\s+program\b",
    r"служба підтримки", r"служба поддержки", r"підтримки клієнтів",
    r"поддержки клиентов", r"адміністрація", r"администрация",
    r"програма лояльності", r"программа лояльности",
    r"банк", r"податкова", r"налоговая",
]


def _match_score(text: str, patterns: list[str]) -> int:
    text_lower = text.lower()
    hits = sum(1 for p in patterns if re.search(p, text_lower, re.IGNORECASE | re.UNICODE))
    return min(hits * 15, 95)


def _analyse_heuristic(subject: str, sender: str, body: str, domain: str) -> AIAnalysisResult:
    full_text = f"{subject} {sender} {body}"
    urgency = _match_score(full_text, _URGENCY_PATTERNS)
    fear = _match_score(full_text, _FEAR_PATTERNS)
    credential_theft = _match_score(full_text, _CREDENTIAL_PATTERNS)
    financial_fraud = _match_score(full_text, _FINANCIAL_PATTERNS)
    authority_imp = _match_score(full_text, _AUTHORITY_PATTERNS)

    link_domains = set(extract_link_domains(body))
    link_domains.discard((domain or "").lower())
    if link_domains and (credential_theft > 0 or financial_fraud > 0):
        credential_theft = min(100, credential_theft + 30)
        authority_imp = min(100, authority_imp + 15)
        if urgency == 0:
            urgency = max(urgency, 15)

    is_ukrainian = bool(re.search(r"[а-яіїєґА-ЯІЇЄҐ]", body or ""))
    ai_summary = _generate_heuristic_summary(
        domain, urgency, fear, credential_theft, financial_fraud, authority_imp,
        link_domains, is_ukrainian,
    )

    ai_score = _compute_ai_score(
        urgency=urgency,
        fear=fear,
        credential_theft=credential_theft,
        financial_fraud=financial_fraud,
        authority_impersonation=authority_imp,
    )

    return AIAnalysisResult(
        urgency=urgency,
        fear=fear,
        credential_theft=credential_theft,
        financial_fraud=financial_fraud,
        authority_impersonation=authority_imp,
        ai_summary=ai_summary,
        ai_score=ai_score,
    )


def _generate_heuristic_summary(
        domain, urgency, fear, credential, financial, authority, link_domains, is_ukrainian,
) -> str:
    max_score = max(urgency, fear, credential, financial, authority)
    domain = domain or "невідомого джерела"

    if is_ukrainian:
        if max_score < 10:
            return "Ознак фішингу не виявлено. Лист виглядає легітимним."
        parts = []
        if credential >= 30:
            parts.append("викрадення облікових даних")
        if financial >= 30:
            parts.append("фінансове шахрайство")
        if authority >= 30:
            parts.append("імітацію офіційного джерела")
        tactics = []
        if urgency >= 30:
            tactics.append("тиск через терміновість")
        if fear >= 30:
            tactics.append("залякування втратою доступу/коштів")

        threat_str = " та ".join(parts) if parts else "фішингову атаку"
        tactic_str = f" із застосуванням {' і '.join(tactics)}" if tactics else ""
        link_str = ""
        if link_domains:
            link_str = (
                f" Лист містить посилання на домен(и) {', '.join(sorted(link_domains))}, "
                f"що відрізняється від домену відправника '{domain}' - "
                f"це є типовою ознакою фішингу."
            )
        return (
            f"Виявлено можливу {threat_str} з боку відправника з домену '{domain}'"
            f"{tactic_str}.{link_str} "
            f"Не переходьте за посиланнями та не вводьте особисті дані до перевірки."
        )

    if max_score < 10:
        return "No phishing indicators detected. Email appears to be legitimate."
    parts = []
    if credential >= 30:
        parts.append("credential harvesting")
    if financial >= 30:
        parts.append("financial fraud")
    if authority >= 30:
        parts.append("authority impersonation")
    tactics = []
    if urgency >= 30:
        tactics.append("urgency tactics")
    if fear >= 30:
        tactics.append("fear tactics")
    threat_str = " and ".join(parts) if parts else "phishing"
    tactic_str = f" using {' and '.join(tactics)}" if tactics else ""
    link_str = ""
    if link_domains:
        link_str = (
            f" The email contains link(s) to {', '.join(sorted(link_domains))}, "
            f"which does not match the sender domain '{domain}' - a classic "
            f"phishing indicator."
        )
    return (
        f"Potential {threat_str} attempt from domain '{domain}'{tactic_str}."
        f"{link_str} Exercise caution before clicking any links or providing "
        f"information."
    )

