from __future__ import annotations

import re
from urllib.parse import urlparse


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "click",
    "work",
    "quest",
    "country",
    "stream",
}

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".js",
    ".vbs",
    ".bat",
    ".cmd",
    ".ps1",
    ".hta",
    ".iso",
    ".zip",
    ".rar",
    ".7z",
}

SUSPICIOUS_ATTACHMENT_WORDS = {
    "delivery", "parcel", "package", "address", "payment", "verify", "update", "scam",
    "доставка", "посилка", "адрес", "оплата", "підтверд", "онов",
}

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


def analyze_security_signals(message: dict) -> dict:
    sender_domain = (message.get("domain") or "").lower()
    sender_root = _root_domain(sender_domain)
    body = message.get("body") or ""
    reply_to = message.get("replyTo") or ""
    return_path = message.get("returnPath") or ""
    auth_results = (message.get("authenticationResults") or "").lower()

    link_domains = sorted(set(_extract_link_domains(body)))
    external_link_domains = [
        d for d in link_domains
        if d and _root_domain(d) != sender_root
    ]

    header_findings = []
    link_findings = []
    attachment_findings = []

    reply_domain = _domain_from_address(reply_to)
    if reply_domain and sender_root and _root_domain(reply_domain) != sender_root:
        header_findings.append("reply_to_domain_mismatch")

    return_path_domain = _domain_from_address(return_path)
    if return_path_domain and sender_root and _root_domain(return_path_domain) != sender_root:
        header_findings.append("return_path_domain_mismatch")

    if "spf=fail" in auth_results or "dkim=fail" in auth_results or "dmarc=fail" in auth_results:
        header_findings.append("auth_failure")
    elif auth_results and not any(token in auth_results for token in ("spf=pass", "dkim=pass", "dmarc=pass")):
        header_findings.append("auth_not_passed")

    if sender_domain.startswith("xn--") or any(part.startswith("xn--") for part in sender_domain.split(".")):
        header_findings.append("punycode_sender_domain")

    if external_link_domains:
        link_findings.append("link_domain_mismatch")

    if any(domain in SHORTENER_DOMAINS for domain in link_domains):
        link_findings.append("shortened_url")

    if any(_tld(domain) in SUSPICIOUS_TLDS for domain in [sender_domain, *link_domains] if domain):
        link_findings.append("suspicious_tld")

    if any(domain.startswith("xn--") or any(part.startswith("xn--") for part in domain.split(".")) for domain in link_domains):
        link_findings.append("punycode_link_domain")

    attachment_count = int(message.get("attachmentScore") or 0)
    attachments = message.get("attachments") or []
    if attachment_count:
        attachment_findings.append("has_attachments")

    filenames = [att.get("filename", "") for att in attachments if att.get("filename")]
    filenames.extend(_extract_filenames(body))
    for filename in filenames:
        lower_filename = filename.lower()
        if lower_filename.endswith(".pdf"):
            attachment_findings.append("pdf_attachment")
        if any(word in lower_filename for word in SUSPICIOUS_ATTACHMENT_WORDS):
            attachment_findings.append("suspicious_attachment_name")
        if any(lower_filename.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            attachment_findings.append("dangerous_attachment_reference")

    if "suspicious_attachment_name" in attachment_findings and re.search(
        r"(до\s+кінця\s+дня|уточн\w+\s+адрес|повернення\s+відправнику|urgent|address)",
        body,
        re.I | re.U,
    ):
        attachment_findings.append("urgent_suspicious_attachment")

    for filename in _extract_filenames(body):
        if any(filename.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            attachment_findings.append("dangerous_attachment_reference")
            break

    header_score = _score_findings(header_findings, {
        "reply_to_domain_mismatch": 20,
        "return_path_domain_mismatch": 20,
        "auth_failure": 35,
        "auth_not_passed": 10,
        "punycode_sender_domain": 35,
    })
    link_score = _score_findings(link_findings, {
        "link_domain_mismatch": 30,
        "shortened_url": 25,
        "suspicious_tld": 20,
        "punycode_link_domain": 35,
    })
    attachment_score = min(100, attachment_count * 10 + _score_findings(attachment_findings, {
        "has_attachments": 5,
        "pdf_attachment": 10,
        "suspicious_attachment_name": 30,
        "urgent_suspicious_attachment": 55,
        "dangerous_attachment_reference": 45,
    }))

    return {
        "signals": {
            "senderDomain": sender_domain,
            "replyToDomain": reply_domain,
            "returnPathDomain": return_path_domain,
            "linkDomains": link_domains,
            "externalLinkDomains": external_link_domains,
            "headerFindings": sorted(set(header_findings)),
            "linkFindings": sorted(set(link_findings)),
            "attachmentFindings": sorted(set(attachment_findings)),
        },
        "headerScore": header_score,
        "linkScore": link_score,
        "attachmentScore": attachment_score,
    }


def _extract_link_domains(body: str) -> list[str]:
    domains = []
    for url in URL_RE.findall(body or ""):
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if host:
            domains.append(host)
    return domains


def _domain_from_address(value: str) -> str:
    match = re.search(r"@([^>\s]+)", value or "")
    if match:
        return match.group(1).strip().lower()
    return ""


def _tld(domain: str) -> str:
    parts = domain.rsplit(".", 1)
    return parts[1].lower() if len(parts) == 2 else ""


def _root_domain(domain: str) -> str:
    parts = (domain or "").lower().strip(".").split(".")
    if len(parts) < 2:
        return domain.lower()
    return ".".join(parts[-2:])


def _extract_filenames(text: str) -> list[str]:
    return re.findall(r"[\w.-]+\.(?:exe|scr|js|vbs|bat|cmd|ps1|hta|iso|zip|rar|7z|pdf)", text or "", re.I)


def _score_findings(findings: list[str], weights: dict[str, int]) -> int:
    return min(100, sum(weights.get(finding, 0) for finding in set(findings)))
