from __future__ import annotations

import base64
import hashlib
import logging
import re
import time
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
from django.conf import settings
from django.utils import timezone

from apps.reputation.models import UrlReputation
from apps.reputation.virustotal import REQUEST_TIMEOUT, VT_BASE, VirusTotalError

logger = logging.getLogger(__name__)

URL_RE = re.compile(r"https?://[^\s<>'\")\]]+", re.IGNORECASE)
_VT_URL_DISABLED_UNTIL = 0.0
_WEB_RISK_URL_DISABLED_UNTIL = 0.0
WEB_RISK_LOOKUP_URL = "https://webrisk.googleapis.com/v1/uris:search"
WEB_RISK_THREAT_TYPES = ("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE")
TRUSTED_URL_HOSTS = {
    "facebook.com",
    "www.facebook.com",
    "instagram.com",
    "www.instagram.com",
    "linkedin.com",
    "www.linkedin.com",
    "x.com",
    "www.x.com",
    "twitter.com",
    "www.twitter.com",
    "grammarly.com",
    "www.grammarly.com",
    "app.grammarly.com",
    "support.grammarly.com",
}
TRACKING_HOST_PARTS = {
    "email-links.",
    "customer.io",
    "click.",
    "track.",
    "tracking.",
    "mailchimp.com",
    "sendgrid.net",
}
TRACKING_PATH_PARTS = {
    "unsubscribe",
    "preferences",
    "mail_profile_preferences",
    "email_marketing_click",
    "redirect",
    "/click/",
    "/track/",
    "/photos/",
    "/images/",
    "/assets/",
}
MEDIA_PATH_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".avif")
SHORTENER_HOSTS = {
    "goo.gl",
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "ow.ly",
    "shorturl.at",
    "rebrand.ly",
    "cutt.ly",
}
STRIP_QUERY_KEYS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_content",
    "utm_term",
    "profiletoken",
    "token",
    "signature",
    "sig",
    "hash",
    "customer_id",
    "message_id",
}
TRAILING_PUNCTUATION = ".,;:!?)】]}>\"'"


def scan_urls_in_text(
    text: str,
    max_urls: int | None = 3,
    include_tracking: bool = False,
    vt_enrichment: bool = False,
) -> dict[str, Any]:
    urls, skipped_tracking = extract_meaningful_urls(text, max_urls=max_urls, include_tracking=include_tracking)
    if not urls:
        summary = empty_url_scan_summary()
        summary["skipped_tracking_urls_count"] = skipped_tracking
        if skipped_tracking:
            summary["url_summary"] = f"No meaningful URLs selected for reputation checks; skipped {skipped_tracking} tracking/preference link(s)."
        return summary

    scanned = []
    selected_urls = urls if max_urls is None else urls[:max_urls]
    for url in selected_urls:
        try:
            rep = get_url_reputation(url, use_vt_enrichment=vt_enrichment)
            scanned.append(_serialize_reputation(rep))
        except Exception as exc:
            logger.warning("URL reputation failed for %s: %s", url, exc)
            scanned.append(
                {
                    "url": url,
                    "verdict": "Error",
                    "score": 0,
                    "confidence": "error",
                    "is_phishing": False,
                    "is_malicious": False,
                    "error": str(exc),
                }
            )

    highest_score = max((item.get("score", 0) for item in scanned), default=0)
    malicious_urls = [item["url"] for item in scanned if item.get("is_malicious") and item.get("confidence") != "low"]
    phishing_urls = [item["url"] for item in scanned if item.get("is_phishing") and item.get("confidence") != "low"]
    summary = _build_summary(scanned, len(urls), max_urls or len(urls), skipped_tracking)
    return {
        "url_score": highest_score,
        "any_phishing": bool(phishing_urls),
        "any_malicious": bool(malicious_urls),
        "malicious_urls": malicious_urls,
        "phishing_urls": phishing_urls,
        "scanned_urls": scanned,
        "url_summary": summary,
        "total_urls": len(urls),
        "skipped_tracking_urls_count": skipped_tracking,
    }


def empty_url_scan_summary() -> dict[str, Any]:
    return {
        "url_score": 0,
        "any_phishing": False,
        "any_malicious": False,
        "malicious_urls": [],
        "phishing_urls": [],
        "scanned_urls": [],
        "url_summary": "No URLs found in the email body.",
        "total_urls": 0,
        "skipped_tracking_urls_count": 0,
    }


def extract_urls(text: str) -> list[str]:
    seen = set()
    urls = []
    for match in URL_RE.findall(text or ""):
        normalized = normalize_url(match)
        if normalized and normalized not in seen:
            seen.add(normalized)
            urls.append(normalized)
    return urls


def extract_meaningful_urls(text: str, max_urls: int | None = 3, include_tracking: bool = False) -> tuple[list[str], int]:
    all_urls = extract_urls(text)
    meaningful = []
    skipped_tracking = 0
    for url in all_urls:
        if not include_tracking and _is_tracking_or_preference_url(url):
            skipped_tracking += 1
            continue
        meaningful.append(url)
        if max_urls is not None and len(meaningful) >= max_urls:
            break
    return meaningful, skipped_tracking + max(0, len(all_urls) - skipped_tracking - len(meaningful))


def normalize_url(url: str) -> str:
    cleaned = (url or "").strip().rstrip(TRAILING_PUNCTUATION)
    try:
        parts = urlsplit(cleaned)
    except ValueError:
        return cleaned
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        return cleaned
    host = parts.netloc.lower()
    path = parts.path or "/"
    query = _clean_query(parts.query)
    return urlunsplit((parts.scheme.lower(), host, path, query, ""))


def _clean_query(query: str) -> str:
    if not query:
        return ""
    kept = []
    for key, value in parse_qsl(query, keep_blank_values=True):
        lower_key = key.lower()
        if lower_key.startswith("utm_") or lower_key in STRIP_QUERY_KEYS:
            continue
        if any(token in lower_key for token in ("token", "signature", "tracking", "campaign")):
            continue
        kept.append((key, value))
    return urlencode(kept, doseq=True)


def _is_tracking_or_preference_url(url: str) -> bool:
    try:
        parts = urlsplit(url)
    except ValueError:
        return True
    host = parts.netloc.lower()
    path = parts.path.lower()
    query = parts.query.lower()
    if path.endswith(MEDIA_PATH_EXTENSIONS):
        return True
    if any(part in host for part in TRACKING_HOST_PARTS):
        return True
    if any(part in path for part in TRACKING_PATH_PARTS):
        return True
    if "unsubscribe" in query or "preferences" in query or "profiletoken" in query:
        return True
    return False


def get_url_reputation(url: str, use_vt_enrichment: bool = False) -> UrlReputation:
    normalized = normalize_url(url)
    url_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    cached = UrlReputation.objects.filter(url_hash=url_hash).first()
    if cached and not cached.is_stale():
        _normalize_cached_confidence(cached)
        return cached

    if not use_vt_enrichment:
        return _store_error(cached, normalized, url_hash, "VirusTotal URL enrichment was skipped.", confidence="skipped")

    web_risk_key = getattr(settings, "GOOGLE_WEB_RISK_API_KEY", "")
    if web_risk_key and time.time() >= _WEB_RISK_URL_DISABLED_UNTIL:
        try:
            result = fetch_web_risk_reputation(normalized)
            return _store_url_result(cached, normalized, url_hash, result)
        except VirusTotalError as exc:
            if _is_rate_limit_error(exc):
                _disable_web_risk_urls()
            logger.warning("Google Web Risk URL lookup failed for %s: %s", normalized, exc)

    if not getattr(settings, "VIRUSTOTAL_API_KEY", ""):
        return _store_url_result(cached, normalized, url_hash, _local_url_reputation(normalized, "No live URL provider configured."))
    if time.time() < _VT_URL_DISABLED_UNTIL:
        if cached:
            return cached
        return _store_url_result(cached, normalized, url_hash, _local_url_reputation(normalized, "VirusTotal URL scan temporarily rate-limited."))
    try:
        result = fetch_url_reputation(normalized)
    except VirusTotalError as exc:
        if _is_rate_limit_error(exc):
            _disable_vt_urls()
            if cached:
                return cached
        return _store_url_result(cached, normalized, url_hash, _local_url_reputation(normalized, str(exc)))
    return _store_url_result(cached, normalized, url_hash, result)

def _store_url_result(
    cached: UrlReputation | None,
    normalized: str,
    url_hash: str,
    result: dict[str, Any],
) -> UrlReputation:
    defaults = {
        "vt_url_id": result.get("vt_url_id", virustotal_url_id(normalized)),
        "verdict": result["verdict"],
        "score": result["score"],
        "is_phishing": result["is_phishing"],
        "is_malicious": result["is_malicious"],
        "vt_malicious": result["stats"].get("malicious", 0),
        "vt_suspicious": result["stats"].get("suspicious", 0),
        "vt_harmless": result["stats"].get("harmless", 0),
        "vt_undetected": result["stats"].get("undetected", 0),
        "raw_stats": {**result["stats"], "confidence": result.get("confidence", ""), "provider": result.get("provider", "")},
        "raw_results": result["results"],
        "fetched_at": timezone.now(),
        "error": result.get("error", ""),
    }
    obj, _ = UrlReputation.objects.update_or_create(
        url_hash=url_hash,
        defaults={"normalized_url": normalized, **defaults},
    )
    return obj


def fetch_url_reputation(normalized_url: str) -> dict[str, Any]:
    api_key = getattr(settings, "VIRUSTOTAL_API_KEY", "")
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    vt_id = virustotal_url_id(normalized_url)
    report_url = f"{VT_BASE}/urls/{vt_id}"

    try:
        response = requests.get(report_url, headers=headers, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise VirusTotalError(f"Network error contacting VirusTotal: {exc}") from exc

    if response.status_code == 404:
        _submit_url(normalized_url, headers)
        return {
            "vt_url_id": vt_id,
            "verdict": UrlReputation.VERDICT_PENDING,
            "score": 5,
            "confidence": "pending",
            "is_phishing": False,
            "is_malicious": False,
            "stats": {},
            "results": {},
        }
    if response.status_code == 401:
        raise VirusTotalError("VirusTotal API key is invalid.")
    if response.status_code == 429:
        raise VirusTotalError("VirusTotal rate limit hit. Retry later.")
    if not response.ok:
        raise VirusTotalError(f"VirusTotal URL lookup returned HTTP {response.status_code}: {response.text[:200]}")

    attrs = response.json().get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {}) or {}
    results = attrs.get("last_analysis_results", {}) or {}
    score, verdict, is_phishing, is_malicious, confidence = _score_url(normalized_url, stats, results)
    return {
        "vt_url_id": vt_id,
        "verdict": verdict,
        "score": score,
        "confidence": confidence,
        "is_phishing": is_phishing,
        "is_malicious": is_malicious,
        "stats": stats,
        "results": _compact_results(results),
        "provider": "virustotal",
        "error": "",
    }


def fetch_web_risk_reputation(normalized_url: str) -> dict[str, Any]:
    api_key = getattr(settings, "GOOGLE_WEB_RISK_API_KEY", "")
    params: list[tuple[str, str]] = [("key", api_key), ("uri", normalized_url)]
    params.extend(("threatTypes", threat_type) for threat_type in WEB_RISK_THREAT_TYPES)

    try:
        response = requests.get(WEB_RISK_LOOKUP_URL, params=params, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        raise VirusTotalError(f"Network error contacting Google Web Risk: {exc}") from exc

    if response.status_code == 429:
        raise VirusTotalError("Google Web Risk rate limit hit. Retry later.")
    if response.status_code in {401, 403}:
        raise VirusTotalError("Google Web Risk API key is invalid or not allowed.")
    if not response.ok:
        raise VirusTotalError(f"Google Web Risk lookup returned HTTP {response.status_code}: {response.text[:200]}")

    threat = response.json().get("threat") or {}
    threat_types = threat.get("threatTypes") or []
    if not threat_types:
        return {
            "vt_url_id": virustotal_url_id(normalized_url),
            "verdict": UrlReputation.VERDICT_CLEAN,
            "score": 0,
            "confidence": "google_clean",
            "is_phishing": False,
            "is_malicious": False,
            "stats": {"malicious": 0, "suspicious": 0, "provider": "google_web_risk"},
            "results": {},
            "provider": "google_web_risk",
            "error": "",
        }

    threat_type_set = {str(item).upper() for item in threat_types}
    phishing = "SOCIAL_ENGINEERING" in threat_type_set
    malicious = bool(threat_type_set.intersection({"MALWARE", "UNWANTED_SOFTWARE", "SOCIAL_ENGINEERING"}))
    score = 90 if phishing or "MALWARE" in threat_type_set else 70
    return {
        "vt_url_id": virustotal_url_id(normalized_url),
        "verdict": UrlReputation.VERDICT_MALICIOUS if malicious else UrlReputation.VERDICT_SUSPICIOUS,
        "score": score,
        "confidence": "google_match",
        "is_phishing": phishing,
        "is_malicious": malicious,
        "stats": {
            "malicious": 1 if malicious else 0,
            "suspicious": 0 if malicious else 1,
            "provider": "google_web_risk",
        },
        "results": {"Google Web Risk": {"category": ",".join(threat_type_set), "result": "threat_match"}},
        "provider": "google_web_risk",
        "error": "",
    }


def virustotal_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")


def _submit_url(normalized_url: str, headers: dict[str, str]) -> None:
    try:
        response = requests.post(
            f"{VT_BASE}/urls",
            headers=headers,
            data={"url": normalized_url},
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        raise VirusTotalError(f"Network error submitting URL to VirusTotal: {exc}") from exc
    if response.status_code in {200, 201, 202, 409}:
        return
    if response.status_code == 429:
        raise VirusTotalError("VirusTotal rate limit hit while submitting URL.")
    raise VirusTotalError(f"VirusTotal URL submit returned HTTP {response.status_code}: {response.text[:200]}")


def _score_url(normalized_url: str, stats: dict[str, int], results: dict[str, Any]) -> tuple[int, str, bool, bool, str]:
    malicious = int(stats.get("malicious", 0) or 0)
    suspicious = int(stats.get("suspicious", 0) or 0)
    phishing_hits = 0
    for result in results.values():
        category = str(result.get("category", "")).lower()
        result_text = str(result.get("result", "")).lower()
        if category == "phishing" or "phishing" in result_text:
            phishing_hits += 1

    host = urlsplit(normalized_url).netloc.lower()
    trusted_host = host in TRUSTED_URL_HOSTS

    if malicious >= 2:
        return 85, UrlReputation.VERDICT_MALICIOUS, phishing_hits > 0, True, "high"
    if malicious == 1:
        if trusted_host and not phishing_hits:
            return 25, UrlReputation.VERDICT_SUSPICIOUS, False, False, "low"
        return 45, UrlReputation.VERDICT_SUSPICIOUS, phishing_hits > 0, False, "medium"
    if phishing_hits >= 2:
        return 80, UrlReputation.VERDICT_MALICIOUS, True, True, "high"
    if phishing_hits == 1:
        return 45, UrlReputation.VERDICT_SUSPICIOUS, True, False, "medium"
    if suspicious >= 2:
        return 45, UrlReputation.VERDICT_SUSPICIOUS, False, False, "medium"
    if suspicious == 1:
        return 20, UrlReputation.VERDICT_SUSPICIOUS, False, False, "low"
    if host in SHORTENER_HOSTS:
        return 15, UrlReputation.VERDICT_SUSPICIOUS, False, False, "unknown_redirect"
    return 0, UrlReputation.VERDICT_CLEAN, False, False, "none"


def _compact_results(results: dict[str, Any]) -> dict[str, Any]:
    compact = {}
    for engine, result in results.items():
        category = str(result.get("category", "")).lower()
        result_text = str(result.get("result", "")).lower()
        if category in {"malicious", "suspicious", "phishing"} or "phishing" in result_text:
            compact[engine] = {
                "category": result.get("category"),
                "result": result.get("result"),
            }
    return compact


def _store_error(cached: UrlReputation | None, normalized: str, url_hash: str, error: str, confidence: str = "error") -> UrlReputation:
    obj = cached
    if not obj:
        obj, _ = UrlReputation.objects.get_or_create(
            url_hash=url_hash,
            defaults={
                "normalized_url": normalized,
                "vt_url_id": virustotal_url_id(normalized),
            },
        )
    obj.normalized_url = normalized
    obj.vt_url_id = obj.vt_url_id or virustotal_url_id(normalized)
    obj.verdict = UrlReputation.VERDICT_ERROR
    obj.score = 0
    obj.raw_stats = {**(obj.raw_stats or {}), "confidence": confidence}
    obj.error = error
    obj.fetched_at = timezone.now()
    obj.save()
    return obj


def _normalize_cached_confidence(rep: UrlReputation) -> None:
    host = urlsplit(rep.normalized_url).netloc.lower()
    if host not in TRUSTED_URL_HOSTS:
        return
    if rep.vt_malicious != 1 or rep.is_phishing:
        return
    raw_stats = rep.raw_stats or {}
    if raw_stats.get("confidence") == "low":
        return
    rep.verdict = UrlReputation.VERDICT_SUSPICIOUS
    rep.score = min(rep.score, 25)
    rep.is_malicious = False
    rep.raw_stats = {**raw_stats, "confidence": "low"}
    rep.save(update_fields=["verdict", "score", "is_malicious", "raw_stats"])


def _is_rate_limit_error(exc: Exception) -> bool:
    return "rate limit" in str(exc).lower() or "429" in str(exc)


def _disable_vt_urls() -> None:
    global _VT_URL_DISABLED_UNTIL
    now = time.time()
    if now < _VT_URL_DISABLED_UNTIL:
        return
    seconds = int(getattr(settings, "VIRUSTOTAL_DISABLE_ON_RATE_LIMIT_SECONDS", 900))
    _VT_URL_DISABLED_UNTIL = now + seconds
    logger.warning("VirusTotal URL lookups rate-limited; pausing live URL scans for %ss.", seconds)


def _disable_web_risk_urls() -> None:
    global _WEB_RISK_URL_DISABLED_UNTIL
    now = time.time()
    if now < _WEB_RISK_URL_DISABLED_UNTIL:
        return
    seconds = int(getattr(settings, "GOOGLE_WEB_RISK_DISABLE_ON_RATE_LIMIT_SECONDS", 900))
    _WEB_RISK_URL_DISABLED_UNTIL = now + seconds
    logger.warning("Google Web Risk URL lookups rate-limited; pausing live URL scans for %ss.", seconds)


def _local_url_reputation(normalized_url: str, error: str = "") -> dict[str, Any]:
    host = urlsplit(normalized_url).netloc.lower()
    path = f"{urlsplit(normalized_url).path} {urlsplit(normalized_url).query}".lower()
    suspicious = host in SHORTENER_HOSTS or bool(
        re.search(r"(login|signin|sign-in|password|reset|wallet|payment|invoice|kyc|verify|confirm)", path)
    )
    score = 25 if suspicious else 0
    verdict = UrlReputation.VERDICT_SUSPICIOUS if suspicious else UrlReputation.VERDICT_CLEAN
    return {
        "vt_url_id": virustotal_url_id(normalized_url),
        "verdict": verdict,
        "score": score,
        "confidence": "local",
        "is_phishing": False,
        "is_malicious": False,
        "stats": {"provider": "local_heuristic"},
        "results": {},
        "provider": "local_heuristic",
        "error": error,
    }


def _serialize_reputation(rep: UrlReputation) -> dict[str, Any]:
    return {
        "url": rep.normalized_url,
        "verdict": rep.verdict,
        "score": rep.score,
        "confidence": (rep.raw_stats or {}).get("confidence", ""),
        "is_phishing": rep.is_phishing,
        "is_malicious": rep.is_malicious,
        "stats": rep.raw_stats,
        "detections": rep.raw_results,
        "fetched_at": rep.fetched_at.isoformat(),
        "error": rep.error,
    }


def _build_summary(scanned: list[dict[str, Any]], total_urls: int, max_urls: int, skipped_tracking: int = 0) -> str:
    if not scanned:
        return "No URLs found in the email body."
    malicious = [item for item in scanned if item.get("is_malicious")]
    phishing = [item for item in scanned if item.get("is_phishing")]
    suspicious = [item for item in scanned if item.get("verdict") == UrlReputation.VERDICT_SUSPICIOUS]
    pending = [item for item in scanned if item.get("verdict") == UrlReputation.VERDICT_PENDING]
    suffix = ""
    if total_urls > max_urls:
        suffix = f" Checked first {max_urls} of {total_urls} URLs."
    if skipped_tracking:
        suffix += f" Skipped {skipped_tracking} tracking/preference link(s)."
    if malicious:
        return f"URL reputation providers detected malicious indicators in {len(malicious)} link(s).{suffix}"
    if phishing:
        return f"URL reputation providers detected phishing indicators in {len(phishing)} link(s).{suffix}"
    if suspicious:
        return f"URL reputation providers marked {len(suspicious)} link(s) as suspicious.{suffix}"
    if pending:
        return f"URL reputation scan is pending for {len(pending)} new link(s).{suffix}"
    return f"URL reputation providers did not detect malicious indicators in {len(scanned)} checked link(s).{suffix}"
