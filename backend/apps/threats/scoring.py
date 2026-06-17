from dataclasses import dataclass
from typing import List, Optional


RISK_LEVELS = ("Safe", "Medium", "High", "Critical")


@dataclass
class ThreatResult:
    ai_score: int
    domain_score: int
    url_score: int          # NEW: highest URL scan score (0-100)
    threat_score: int
    risk_level: str


def clamp(v: int) -> int:
    return max(0, min(100, int(v)))


def risk_level(score: int) -> str:
    if score >= 81: return "Critical"
    if score >= 61: return "High"
    if score >= 31: return "Medium"
    return "Safe"


def compute_threat_result(
    ai_score: int,
    domain_score: int,
    link_domain_scores: Optional[List[int]] = None,
    # Raw AI dimensions (for safety floors)
    credential_theft: int = 0,
    urgency: int = 0,
    authority_impersonation: int = 0,
    fear: int = 0,
    # NEW: URL scan signal
    url_score: int = 0,
    any_phishing_url: bool = False,
    any_malicious_url: bool = False,
) -> ThreatResult:
    """
    Final threat score computation.

    Formula (base):
        threat_score = ai_score × 0.60
                     + domain_score × 0.25
                     + url_score × 0.15

    If no URL scan available (url_score==0), weights shift:
        threat_score = ai_score × 0.70 + domain_score × 0.30

    Safety floors prevent obvious phishing from scoring "Safe" or "Medium".
    """

    ai_score    = clamp(ai_score)
    domain_score = clamp(domain_score)
    url_score   = clamp(url_score)

    credential_theft        = clamp(credential_theft)
    urgency                 = clamp(urgency)
    authority_impersonation = clamp(authority_impersonation)
    fear                    = clamp(fear)

    # Take max across all link domain scores
    if link_domain_scores:
        domain_score = max([domain_score] + [clamp(x) for x in link_domain_scores])

    # ── Base weighted formula ────────────────────────────────────────────────
    if url_score > 0:
        threat_score = clamp(round(
            ai_score     * 0.60 +
            domain_score * 0.25 +
            url_score    * 0.15
        ))
    else:
        threat_score = clamp(round(ai_score * 0.70 + domain_score * 0.30))

    # ── Hard URL floors ──────────────────────────────────────────────────────
    if any_malicious_url:
        threat_score = max(threat_score, 82)   # → Critical
    elif any_phishing_url:
        threat_score = max(threat_score, 65)   # → High

    # ── Safety floors from AI dimensions ────────────────────────────────────

    # QR/2FA/credential theft + urgency or impersonation
    if credential_theft >= 70 and (urgency >= 50 or authority_impersonation >= 60):
        threat_score = max(threat_score, 65)

    # Very high credential theft alone
    if credential_theft >= 85:
        threat_score = max(threat_score, 70)

    # Bank impersonation + fear
    if authority_impersonation >= 80 and fear >= 60:
        threat_score = max(threat_score, 65)

    # All three high-risk dims present
    if credential_theft >= 60 and urgency >= 60 and authority_impersonation >= 60:
        threat_score = max(threat_score, 72)

    threat_score = clamp(threat_score)

    return ThreatResult(
        ai_score=ai_score,
        domain_score=domain_score,
        url_score=url_score,
        threat_score=threat_score,
        risk_level=risk_level(threat_score),
    )
