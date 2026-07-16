"""
Service layer for domain reputation lookups.

The Gmail analysis pipeline should import
`get_domain_reputation` from here rather than calling VirusTotal directly.
The service implements cache-first logic backed by the DomainReputation model.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from django.conf import settings
from django.utils import timezone

from .models import DomainReputation
from .virustotal import VirusTotalError, fetch_domain_reputation

logger = logging.getLogger(__name__)
_VT_DOMAIN_DISABLED_UNTIL = 0.0


def get_domain_reputation(domain: str, force_refresh: bool = False, allow_live_vt: bool = False) -> dict:
    """
    Return reputation data for *domain*, hitting the DB cache first.

    Cache TTL:
      - Malicious / Suspicious: 24 hours
      - Trusted / clean:         7 days

    Returns a dict compatible with the frontend EmailAnalysis shape:
    {
        "domain":           str,
        "domainAge":        str,
        "domainReputation": "Trusted" | "Suspicious" | "Malicious",
        "domainScore":      int,
        "lookalikeDomain":  str | null,
        "cached":           bool,
        "error":            str | null,
    }
    """
    domain = domain.lower().strip().lstrip("www.").rstrip(".")

    # --- Cache hit ---------------------------------------------------------
    cached: Optional[DomainReputation] = None
    try:
        cached = DomainReputation.objects.get(domain=domain)
    except DomainReputation.DoesNotExist:
        pass

    if cached and not force_refresh and not cached.is_stale():
        logger.debug("Cache hit for domain %s", domain)
        return _serialize(cached, from_cache=True)

    if not allow_live_vt:
        if cached:
            result = _serialize(cached, from_cache=True)
            result["error"] = "Live VirusTotal domain enrichment was skipped."
            return result
        return _local_domain_fallback(domain)

    if time.time() < _VT_DOMAIN_DISABLED_UNTIL:
        if cached:
            result = _serialize(cached, from_cache=True)
            result["error"] = "VirusTotal domain scan temporarily rate-limited."
            return result
        return _error_fallback(domain, "VirusTotal domain scan temporarily rate-limited.")

    # --- Live VirusTotal lookup --------------------------------------------
    logger.info("Fetching VirusTotal data for domain: %s", domain)
    try:
        vt_data = fetch_domain_reputation(domain)
    except VirusTotalError as exc:
        if _is_rate_limit_error(exc):
            _disable_vt_domains()
        else:
            logger.warning("VirusTotal error for %s: %s", domain, exc)
        if cached:
            # Return stale cache rather than a hard failure
            result = _serialize(cached, from_cache=True)
            result["error"] = str(exc)
            return result
        # No cache at all — return a neutral fallback
        return _error_fallback(domain, str(exc))

    # --- Persist to cache --------------------------------------------------
    vt_raw = vt_data.pop("_vt")
    creation_ts = vt_raw.get("creation_date")
    creation_dt = None
    if creation_ts:
        from datetime import datetime, timezone as _tz
        try:
            creation_dt = datetime.fromtimestamp(creation_ts, tz=_tz.utc)
        except (OSError, OverflowError, ValueError):
            creation_dt = None

    obj, _ = DomainReputation.objects.update_or_create(
        domain=domain,
        defaults={
            "reputation": vt_data["domainReputation"],
            "domain_score": vt_data["domainScore"],
            "domain_age": vt_data["domainAge"],
            "lookalike_domain": vt_data["lookalikeDomain"],
            "vt_malicious": vt_raw["malicious"],
            "vt_suspicious": vt_raw["suspicious"],
            "vt_harmless": vt_raw["harmless"],
            "vt_undetected": vt_raw["undetected"],
            "vt_total_votes_malicious": vt_raw["community_malicious"],
            "vt_total_votes_harmless": vt_raw["community_harmless"],
            "vt_reputation": vt_raw["vt_reputation"],
            "vt_creation_date": creation_dt,
            "fetched_at": timezone.now(),
            "error": "",
        },
    )
    return _serialize(obj, from_cache=False)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _serialize(obj: DomainReputation, from_cache: bool) -> dict:
    return {
        "domain": obj.domain,
        "domainAge": obj.domain_age,
        "domainReputation": obj.reputation,
        "domainScore": obj.domain_score,
        "lookalikeDomain": obj.lookalike_domain,
        "cached": from_cache,
        "error": obj.error or None,
    }


def _error_fallback(domain: str, error_msg: str) -> dict:
    """Return a safe neutral result when VT is unavailable and no cache exists."""
    return {
        "domain": domain,
        "domainAge": "Unknown",
        "domainReputation": "Suspicious",
        "domainScore": 50,
        "lookalikeDomain": None,
        "cached": False,
        "error": error_msg,
    }


def _local_domain_fallback(domain: str) -> dict:
    trusted_infra = {
        "gmail.com",
        "google.com",
        "microsoft.com",
        "outlook.com",
        "yahoo.com",
        "apple.com",
        "icloud.com",
    }
    if domain in trusted_infra:
        return {
            "domain": domain,
            "domainAge": "Known infrastructure",
            "domainReputation": "Trusted",
            "domainScore": 10,
            "lookalikeDomain": None,
            "cached": False,
            "error": "Live VirusTotal domain enrichment was skipped.",
        }
    return {
        "domain": domain,
        "domainAge": "Unknown",
        "domainReputation": "Suspicious",
        "domainScore": 30,
        "lookalikeDomain": None,
        "cached": False,
        "error": "Live VirusTotal domain enrichment was skipped.",
    }


def _is_rate_limit_error(exc: Exception) -> bool:
    return "rate limit" in str(exc).lower() or "429" in str(exc)


def _disable_vt_domains() -> None:
    global _VT_DOMAIN_DISABLED_UNTIL
    now = time.time()
    if now < _VT_DOMAIN_DISABLED_UNTIL:
        return
    seconds = int(getattr(settings, "VIRUSTOTAL_DISABLE_ON_RATE_LIMIT_SECONDS", 900))
    _VT_DOMAIN_DISABLED_UNTIL = now + seconds
    logger.warning("VirusTotal domain lookups rate-limited; pausing live domain scans for %ss.", seconds)
