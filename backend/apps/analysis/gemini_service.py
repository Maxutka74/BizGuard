from __future__ import annotations

from dataclasses import dataclass

from apps.gmail.services.ai_analysis import analyse_email as analyse_email_dict
from apps.gmail.services.ai_analysis import compute_ai_score
from apps.threats.scoring import risk_level

genai = None


@dataclass
class AIAnalysisResult:
    urgency: int
    fear: int
    credential_theft: int
    financial_fraud: int
    authority_impersonation: int
    ai_summary: str
    ai_score: int


def analyse_email(
    subject: str,
    sender: str,
    body: str,
    *,
    domain: str = "",
    fallback_on_error: bool = True,
) -> AIAnalysisResult:
    try:
        result = analyse_email_dict(subject=subject, sender=sender, body=body, domain=domain)
    except Exception:
        if not fallback_on_error:
            raise
        result = {
            "urgency": 0,
            "fear": 0,
            "credential_theft": 0,
            "financial_fraud": 0,
            "authority_impersonation": 0,
            "ai_summary": "AI analysis unavailable.",
            "ai_score": 0,
        }
    return AIAnalysisResult(
        urgency=int(result.get("urgency", 0)),
        fear=int(result.get("fear", 0)),
        credential_theft=int(result.get("credential_theft", 0)),
        financial_fraud=int(result.get("financial_fraud", 0)),
        authority_impersonation=int(result.get("authority_impersonation", 0)),
        ai_summary=str(result.get("ai_summary", "")),
        ai_score=int(result.get("ai_score", 0)),
    )


def _compute_ai_score(
    urgency: int,
    fear: int,
    credential_theft: int,
    financial_fraud: int,
    authority_impersonation: int,
) -> int:
    return compute_ai_score(
        urgency,
        fear,
        credential_theft,
        financial_fraud,
        authority_impersonation,
    )


def compute_threat_score(ai_score: int, domain_score: int) -> int:
    return max(0, min(100, round(ai_score * 0.70 + domain_score * 0.30)))


def score_to_risk_level(threat_score: int) -> str:
    return risk_level(threat_score)
