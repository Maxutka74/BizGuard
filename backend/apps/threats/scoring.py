from dataclasses import dataclass
from typing import List, Optional


RISK_LEVELS = ("Safe", "Medium", "High", "Critical")


@dataclass
class ThreatResult:
    ai_score: int
    domain_score: int
    url_score: int
    threat_score: int
    risk_level: str


def clamp(v: int) -> int:
    return max(0, min(100, int(v)))


def risk_level(score: int) -> str:
    if score >= 81:
        return "Critical"
    if score >= 61:
        return "High"
    if score >= 31:
        return "Medium"
    return "Safe"


def compute_threat_result(
    ai_score: int,
    domain_score: int,
    link_domain_scores: Optional[List[int]] = None,
    credential_theft: int = 0,
    urgency: int = 0,
    authority_impersonation: int = 0,
    fear: int = 0,
    financial_fraud: int = 0,
    url_score: int = 0,
    any_phishing_url: bool = False,
    any_malicious_url: bool = False,
    attachment_score: int = 0,
    any_suspicious_attachment: bool = False,
    any_malicious_attachment: bool = False,
) -> ThreatResult:
    """
    Combine AI, domain, URL and attachment evidence.

    VirusTotal is evidence, not an automatic final verdict. A URL signal can
    lift a message into Medium/High, but Critical requires strong AI intent,
    strong VT/file evidence, or multiple severe signals together.
    """
    ai_score = clamp(ai_score)
    domain_score = clamp(domain_score)
    url_score = clamp(url_score)
    attachment_score = clamp(attachment_score)
    credential_theft = clamp(credential_theft)
    urgency = clamp(urgency)
    authority_impersonation = clamp(authority_impersonation)
    fear = clamp(fear)
    financial_fraud = clamp(financial_fraud)

    if link_domain_scores:
        domain_score = max([domain_score] + [clamp(x) for x in link_domain_scores])

    if max(url_score, attachment_score) > 0:
        threat_score = clamp(round(
            ai_score * 0.60 +
            domain_score * 0.18 +
            url_score * 0.10 +
            attachment_score * 0.12
        ))
    else:
        threat_score = clamp(round(ai_score * 0.75 + domain_score * 0.25))

    if any_malicious_url:
        threat_score = max(threat_score, 70)
    elif any_phishing_url:
        threat_score = max(threat_score, 55)

    if any_malicious_attachment or attachment_score >= 75:
        threat_score = max(threat_score, 65)
    elif any_suspicious_attachment or attachment_score >= 45:
        threat_score = max(threat_score, 40)

    if credential_theft >= 70 and (urgency >= 50 or authority_impersonation >= 60):
        threat_score = max(threat_score, 68)
    if credential_theft >= 85:
        threat_score = max(threat_score, 72)
    if authority_impersonation >= 80 and fear >= 60:
        threat_score = max(threat_score, 68)
    if credential_theft >= 60 and urgency >= 60 and authority_impersonation >= 60:
        threat_score = max(threat_score, 72)
    if credential_theft >= 90 and urgency >= 75 and fear >= 70 and (financial_fraud >= 60 or authority_impersonation >= 60):
        threat_score = max(threat_score, 82)

    strong_url = any_malicious_url and url_score >= 80
    strong_ai = credential_theft >= 85 and (urgency >= 70 or authority_impersonation >= 75)
    strong_file = any_malicious_attachment and attachment_score >= 80
    if strong_file or (strong_url and strong_ai):
        threat_score = max(threat_score, 82)

    threat_score = clamp(threat_score)
    return ThreatResult(
        ai_score=ai_score,
        domain_score=domain_score,
        url_score=url_score,
        threat_score=threat_score,
        risk_level=risk_level(threat_score),
    )
