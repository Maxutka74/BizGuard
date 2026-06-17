from __future__ import annotations

import logging
from typing import Optional, Dict, Any

from apps.reputation.virustotal import fetch_domain_reputation

logger = logging.getLogger(__name__)


# =========================================================
# DOMAIN ANALYSIS (SINGLE SOURCE OF TRUTH)
# =========================================================

def analyze_domain(domain: str) -> Dict[str, Any]:
    """
    Main domain risk analyzer.

    Pipeline:
    1. VirusTotal intelligence
    2. Lookalike detection (inside VT module)
    3. Reputation classification
    4. Domain scoring
    """

    domain = (domain or "").lower().strip()

    if not domain:
        return _fallback_domain_result()

    # -----------------------------------------------------
    # 1. Fetch external intelligence (VirusTotal)
    # -----------------------------------------------------
    try:
        vt = fetch_domain_reputation(domain)
    except Exception as exc:
        logger.warning("VirusTotal failed for %s: %s", domain, exc)
        return _fallback_domain_result()

    # -----------------------------------------------------
    # 2. Extract signals
    # -----------------------------------------------------
    age_days: Optional[int] = vt.get("_vt", {}).get("creation_date")
    lookalike: Optional[str] = vt.get("lookalikeDomain")

    # VirusTotal already gives initial reputation
    base_reputation = vt.get("domainReputation", "Suspicious")

    # -----------------------------------------------------
    # 3. Final classification
    # -----------------------------------------------------
    reputation = classify_reputation(domain, age_days, lookalike, base_reputation)

    # -----------------------------------------------------
    # 4. Score computation
    # -----------------------------------------------------
    score = compute_domain_score(age_days, reputation, lookalike)

    return {
        "domain": domain,
        "domainAge": vt.get("domainAge"),
        "domainReputation": reputation,
        "lookalikeDomain": lookalike,
        "domainScore": score,
    }


# =========================================================
# FALLBACK (NEVER TRUST = NEVER ZERO RISK)
# =========================================================

def _fallback_domain_result() -> Dict[str, Any]:
    return {
        "domainAge": None,
        "domainReputation": "Suspicious",
        "lookalikeDomain": None,
        "domainScore": 30,
    }


# =========================================================
# REPUTATION CLASSIFIER
# =========================================================

TRUSTED_INFRA = {
    "gmail.com",
    "google.com",
    "microsoft.com",
    "outlook.com",
    "yahoo.com",
    "apple.com",
}


def classify_reputation(
    domain: str,
    age_days: Optional[int],
    lookalike: Optional[str],
    base_reputation: str,
) -> str:

    root = domain.lower()

    # -----------------------------------------------------
    # 1. Lookalike ALWAYS overrides trust
    # -----------------------------------------------------
    if lookalike:
        return "Suspicious"

    # -----------------------------------------------------
    # 2. Trusted infrastructure = neutral, not safe
    # -----------------------------------------------------
    if root in TRUSTED_INFRA:
        return "Neutral"

    # -----------------------------------------------------
    # 3. Base VT signal
    # -----------------------------------------------------
    if base_reputation == "Malicious":
        return "Malicious"

    if base_reputation == "Suspicious":
        return "Suspicious"

    # -----------------------------------------------------
    # 4. Age-based risk (important: phishing infra can age)
    # -----------------------------------------------------
    if age_days is not None:
        if age_days < 3:
            return "Malicious"
        if age_days < 14:
            return "Suspicious"
        if age_days < 90:
            return "Suspicious"

    # -----------------------------------------------------
    # 5. Default
    # -----------------------------------------------------
    return "Suspicious"


# =========================================================
# DOMAIN SCORE ENGINE
# =========================================================

def compute_domain_score(
    age_days: Optional[int],
    reputation: str,
    lookalike: Optional[str],
) -> int:
    """
    0–100 domain risk score
    """

    score = 0

    # -----------------------------------------------------
    # Reputation weight
    # -----------------------------------------------------
    if reputation == "Malicious":
        score += 60
    elif reputation == "Suspicious":
        score += 35
    elif reputation == "Neutral":
        score += 10  # IMPORTANT: not zero trust

    # -----------------------------------------------------
    # Age risk (phishing infra can be mid-aged)
    # -----------------------------------------------------
    if age_days is not None:
        if age_days < 3:
            score += 35
        elif age_days < 14:
            score += 25
        elif age_days < 90:
            score += 15

    # -----------------------------------------------------
    # Lookalike / typosquat penalty
    # -----------------------------------------------------
    if lookalike:
        score += 30

    return min(100, score)