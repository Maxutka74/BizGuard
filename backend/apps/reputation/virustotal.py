"""
VirusTotal v3 API client and response normalizer for BizGuard's reputation app.

Maps raw VT data → the exact shape the frontend EmailDetail component expects:
  - domainReputation: "Trusted" | "Suspicious" | "Malicious"
  - domainScore:      0-100  (used in Threat Score card, weight 30 %)
  - domainAge:        human-readable string  e.g. "4 days", "6 years"
  - lookalikeDomain:  str | null
"""

from __future__ import annotations

import difflib
import logging
import re
from datetime import datetime, timezone
from typing import Optional

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

VT_BASE = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 10  # seconds

# ----- Well-known legitimate brands for lookalike detection ----------------
BRAND_DOMAINS: list[str] = [
    "paypal.com",
    "microsoft.com",
    "google.com",
    "apple.com",
    "amazon.com",
    "aws.amazon.com",
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "linkedin.com",
    "dropbox.com",
    "docusign.com",
    "adobe.com",
    "netflix.com",
    "chase.com",
    "wellsfargo.com",
    "bankofamerica.com",
    "irs.gov",
    "fedex.com",
    "dhl.com",
    "ups.com",
    "outlook.com",
    "office365.com",
    "github.com",
    "gitlab.com",
    "stripe.com",
    "shopify.com",
    "zoom.us",
    "slack.com",
]

LOOKALIKE_THRESHOLD = 0.82  # SequenceMatcher ratio


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _domain_age_human(creation_ts: Optional[int]) -> str:
    """Convert a Unix epoch to a human-readable age string."""
    if not creation_ts:
        return "Unknown"
    try:
        created = datetime.fromtimestamp(creation_ts, tz=timezone.utc)
        delta = datetime.now(tz=timezone.utc) - created
        days = delta.days
        if days < 1:
            return "Less than 1 day"
        if days == 1:
            return "1 day"
        if days < 30:
            return f"{days} days"
        months = days // 30
        if months < 12:
            return f"{months} month{'s' if months > 1 else ''}"
        years = months // 12
        return f"{years} year{'s' if years > 1 else ''}"
    except (OSError, OverflowError, ValueError):
        return "Unknown"


def _detect_lookalike(domain: str) -> Optional[str]:
    """
    Return the brand domain this domain most closely resembles, or None.
    Uses SequenceMatcher on the base domain (strips www / subdomains).
    Also catches digit-substitution typosquats like 'paypa1' → 'paypal'.
    """
    # Strip leading 'www.' and extract the registrable part
    base = re.sub(r"^www\.", "", domain.lower())
    # Remove TLD for comparison (compare SLD only)
    sld = re.sub(r"\.[^.]+$", "", base)  # e.g. "paypa1-support" from "paypa1-support.com"

    best_brand: Optional[str] = None
    best_ratio = 0.0

    for brand in BRAND_DOMAINS:
        brand_sld = re.sub(r"\.[^.]+$", "", brand)  # e.g. "paypal"
        ratio = difflib.SequenceMatcher(None, sld, brand_sld).ratio()
        if ratio > best_ratio:
            best_ratio = ratio
            best_brand = brand

    if best_ratio >= LOOKALIKE_THRESHOLD and best_brand and base != best_brand:
        return best_brand
    return None


def _compute_domain_score(
    malicious: int,
    suspicious: int,
    harmless: int,
    undetected: int,
    vt_reputation: int,
    community_malicious: int,
    community_harmless: int,
    lookalike: Optional[str],
    domain_age_days: Optional[int],
) -> int:
    """
    Compute a 0-100 domain risk score mirroring what the frontend displays
    as `domainScore` (weight 30 % in the final threat score).

    Scoring rationale:
      - Engine detections carry the most weight (malicious > suspicious)
      - Community votes and VT reputation add signal
      - Very new domains (< 30 days) get a base penalty
      - Lookalike detection adds a significant penalty
    """
    score = 0.0
    total_engines = malicious + suspicious + harmless + undetected
    if total_engines > 0:
        detection_ratio = (malicious + 0.5 * suspicious) / total_engines
        score += detection_ratio * 60  # up to 60 pts from engine detections

    # VT community reputation is often negative for bad domains
    if vt_reputation < 0:
        score += min(abs(vt_reputation) * 0.5, 15)  # up to 15 pts

    total_votes = community_malicious + community_harmless
    if total_votes > 0:
        vote_ratio = community_malicious / total_votes
        score += vote_ratio * 15  # up to 15 pts

    # Penalty for very new domains (common in phishing)
    if domain_age_days is not None:
        if domain_age_days < 7:
            score += 20
        elif domain_age_days < 30:
            score += 12
        elif domain_age_days < 90:
            score += 5

    # Lookalike / typosquat penalty
    if lookalike:
        score += 15

    return min(round(score), 100)


def _reputation_label(score: int, malicious: int) -> str:
    """Map numeric score → frontend reputation string."""
    if malicious >= 3 or score >= 70:
        return "Malicious"
    if malicious >= 1 or score >= 35:
        return "Suspicious"
    return "Trusted"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class VirusTotalError(Exception):
    """Raised when the VT API returns an unexpected error."""


def fetch_domain_reputation(domain: str) -> dict:
    """
    Query VirusTotal for *domain* and return a dict matching the frontend
    EmailAnalysis shape for the reputation section:

    {
        "domain":            str,
        "domainAge":         str,   # human-readable
        "domainReputation":  "Trusted" | "Suspicious" | "Malicious",
        "domainScore":       int,   # 0-100
        "lookalikeDomain":   str | null,

        # Extra fields stored in the model (not rendered directly by frontend)
        "_vt": {
            "malicious":       int,
            "suspicious":      int,
            "harmless":        int,
            "undetected":      int,
            "vt_reputation":   int,
            "community_malicious": int,
            "community_harmless":  int,
            "creation_date":   int | null,   # Unix epoch
        }
    }

    Raises VirusTotalError on API errors (caller should handle gracefully).
    """
    api_key = getattr(settings, "VIRUSTOTAL_API_KEY", "")
    if not api_key:
        raise VirusTotalError("VIRUSTOTAL_API_KEY is not configured in settings.")

    url = f"{VT_BASE}/domains/{domain}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise VirusTotalError(f"Network error contacting VirusTotal: {exc}") from exc

    if response.status_code == 404:
        raise VirusTotalError(f"Domain '{domain}' not found in VirusTotal.")
    if response.status_code == 401:
        raise VirusTotalError("VirusTotal API key is invalid or quota exceeded.")
    if response.status_code == 429:
        raise VirusTotalError("VirusTotal rate limit hit. Retry later.")
    if not response.ok:
        raise VirusTotalError(
            f"VirusTotal returned HTTP {response.status_code}: {response.text[:200]}"
        )

    data = response.json()
    attrs = data.get("data", {}).get("attributes", {})

    # ----- Extract raw stats ------------------------------------------------
    last_analysis_stats: dict = attrs.get("last_analysis_stats", {})
    malicious: int = last_analysis_stats.get("malicious", 0)
    suspicious: int = last_analysis_stats.get("suspicious", 0)
    harmless: int = last_analysis_stats.get("harmless", 0)
    undetected: int = last_analysis_stats.get("undetected", 0)

    total_votes: dict = attrs.get("total_votes", {})
    community_malicious: int = total_votes.get("malicious", 0)
    community_harmless: int = total_votes.get("harmless", 0)

    vt_reputation: int = attrs.get("reputation", 0)
    creation_date: Optional[int] = attrs.get("creation_date")  # Unix epoch or None

    # ----- Derived fields ---------------------------------------------------
    domain_age_days: Optional[int] = None
    if creation_date:
        try:
            created = datetime.fromtimestamp(creation_date, tz=timezone.utc)
            domain_age_days = (datetime.now(tz=timezone.utc) - created).days
        except (OSError, OverflowError, ValueError):
            domain_age_days = None

    lookalike = _detect_lookalike(domain)

    domain_score = _compute_domain_score(
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        vt_reputation=vt_reputation,
        community_malicious=community_malicious,
        community_harmless=community_harmless,
        lookalike=lookalike,
        domain_age_days=domain_age_days,
    )

    reputation = _reputation_label(domain_score, malicious)
    domain_age_str = _domain_age_human(creation_date)

    return {
        "domain": domain,
        "domainAge": domain_age_str,
        "domainReputation": reputation,
        "domainScore": domain_score,
        "lookalikeDomain": lookalike,
        "_vt": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "vt_reputation": vt_reputation,
            "community_malicious": community_malicious,
            "community_harmless": community_harmless,
            "creation_date": creation_date,
        },
    }
