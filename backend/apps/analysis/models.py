"""
Models for apps/analysis.

EmailAnalysisResult caches the Gemini response so we do not re-call the API
for the same email on every page load. The email is identified by its Gmail
message ID (from apps/gmail).
"""

from django.db import models


class EmailAnalysisResult(models.Model):
    """
    Persisted AI analysis result for a single email.

    Field names use camelCase-friendly snake_case that maps 1-to-1 with the
    frontend EmailAnalysis interface fields returned from the API.
    """

    # Link to the Gmail message — we store just the message_id to stay
    # decoupled from the gmail app's internals.
    gmail_message_id = models.CharField(
        max_length=255,
        unique=True,
        db_index=True,
        help_text="Gmail API message ID used to look up cached results.",
    )

    # ---- AI threat-dimension scores (0-100, from Gemini) ----------------
    urgency = models.PositiveSmallIntegerField(default=0)
    fear = models.PositiveSmallIntegerField(default=0)
    credential_theft = models.PositiveSmallIntegerField(default=0)
    financial_fraud = models.PositiveSmallIntegerField(default=0)
    authority_impersonation = models.PositiveSmallIntegerField(default=0)

    # ---- Summary and composite scores -----------------------------------
    ai_summary = models.TextField(blank=True)
    ai_score = models.PositiveSmallIntegerField(
        default=0,
        help_text="Weighted composite of the five threat dimensions (0-100).",
    )
    # domain_score comes from apps/reputation and is stored here for convenience
    domain_score = models.PositiveSmallIntegerField(
        default=0,
        help_text="Score from domain reputation analysis (0-100).",
    )
    threat_score = models.PositiveSmallIntegerField(
        default=0,
        help_text="Final score: aiScore*0.70 + domainScore*0.30 (0-100).",
    )

    RISK_CHOICES = [
        ("Critical", "Critical"),
        ("High", "High"),
        ("Medium", "Medium"),
        ("Safe", "Safe"),
    ]
    risk_level = models.CharField(
        max_length=10,
        choices=RISK_CHOICES,
        default="Safe",
    )

    # ---- Audit ----------------------------------------------------------
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        verbose_name = "Email Analysis Result"
        verbose_name_plural = "Email Analysis Results"

    def __str__(self) -> str:
        return f"{self.gmail_message_id} [{self.risk_level}] score={self.threat_score}"

    def to_analysis_dict(self) -> dict:
        """
        Return a dict matching the AI-analysis portion of the frontend
        EmailAnalysis interface. Used by the email serializer to merge
        AI fields into the full email response.
        """
        return {
            "urgency": self.urgency,
            "fear": self.fear,
            "credentialTheft": self.credential_theft,
            "financialFraud": self.financial_fraud,
            "authorityImpersonation": self.authority_impersonation,
            "aiSummary": self.ai_summary,
            "aiScore": self.ai_score,
            "domainScore": self.domain_score,
            "threatScore": self.threat_score,
            "riskLevel": self.risk_level,
        }
