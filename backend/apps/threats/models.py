from django.conf import settings
from django.db import models

from .scoring import RISK_LEVELS, compute_threat_result


RISK_LEVEL_CHOICES = [(level, level) for level in RISK_LEVELS]


class ThreatAssessment(models.Model):
    """The final, combined threat assessment for a single email.

    This is the row that backs the right-hand "THREAT SCORE" panel and the
    `RiskBadge` in the dashboard table. It is intentionally a thin
    aggregation layer: the raw Gemini analysis lives in `apps.analysis`,
    and the raw domain reputation lookup lives in `apps.reputation`. This
    app's only job is to combine those two numbers into `threatScore` /
    `riskLevel` exactly as the frontend expects.
    """

    email = models.OneToOneField(
        "emails.Email",
        on_delete=models.CASCADE,
        related_name="threat_assessment",
    )

    # --- Inputs (copied in at compute time so this row is self-describing
    # and the API can be served without re-joining other apps) ---
    ai_score = models.PositiveSmallIntegerField(
        help_text="0-100 Gemini-derived risk score (apps.analysis).",
    )
    domain_score = models.PositiveSmallIntegerField(
        help_text="0-100 domain reputation risk score (apps.reputation).",
    )

    # --- Outputs (exactly what the frontend renders) ---
    threat_score = models.PositiveSmallIntegerField(
        help_text="round(aiScore * 0.7 + domainScore * 0.3), 0-100.",
    )
    risk_level = models.CharField(
        max_length=8,
        choices=RISK_LEVEL_CHOICES,
        help_text='One of "Critical" | "High" | "Medium" | "Safe".',
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-threat_score"]
        indexes = [
            models.Index(fields=["risk_level"]),
            models.Index(fields=["threat_score"]),
        ]

    def __str__(self) -> str:
        return f"{self.email_id}: {self.risk_level} ({self.threat_score})"

    @classmethod
    def compute_and_save(cls, email, ai_score: int, domain_score: int) -> "ThreatAssessment":
        """Combine Gemini + reputation scores for `email` and persist the
        result. Called from `apps.analysis` / `apps.reputation` (or the
        scan pipeline in `apps.dashboard`) once both inputs are available.
        """
        result = compute_threat_result(ai_score, domain_score)
        obj, _created = cls.objects.update_or_create(
            email=email,
            defaults={
                "ai_score": result.ai_score,
                "domain_score": result.domain_score,
                "threat_score": result.threat_score,
                "risk_level": result.risk_level,
            },
        )
        return obj
