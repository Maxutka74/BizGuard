from django.db import models
from django.utils import timezone


class DomainReputation(models.Model):
    """
    Cached VirusTotal domain reputation result.
    TTL = 24 hours for malicious/suspicious, 7 days for trusted/clean.
    """

    REPUTATION_TRUSTED = "Trusted"
    REPUTATION_SUSPICIOUS = "Suspicious"
    REPUTATION_MALICIOUS = "Malicious"

    REPUTATION_CHOICES = [
        (REPUTATION_TRUSTED, "Trusted"),
        (REPUTATION_SUSPICIOUS, "Suspicious"),
        (REPUTATION_MALICIOUS, "Malicious"),
    ]

    domain = models.CharField(max_length=253, unique=True, db_index=True)

    # Core frontend fields
    reputation = models.CharField(
        max_length=20, choices=REPUTATION_CHOICES, default=REPUTATION_SUSPICIOUS
    )
    domain_score = models.IntegerField(default=0, help_text="0-100 risk score used as domainScore")
    domain_age = models.CharField(max_length=64, blank=True, default="")
    lookalike_domain = models.CharField(
        max_length=253, blank=True, null=True, default=None,
        help_text="Detected lookalike / typosquat target domain, or null"
    )

    # Raw VirusTotal stats stored for audit / re-scoring
    vt_malicious = models.IntegerField(default=0)
    vt_suspicious = models.IntegerField(default=0)
    vt_harmless = models.IntegerField(default=0)
    vt_undetected = models.IntegerField(default=0)
    vt_total_votes_malicious = models.IntegerField(default=0)
    vt_total_votes_harmless = models.IntegerField(default=0)
    vt_reputation = models.IntegerField(
        default=0, help_text="VirusTotal community reputation score (can be negative)"
    )
    vt_creation_date = models.DateTimeField(null=True, blank=True)

    # Cache metadata
    fetched_at = models.DateTimeField(default=timezone.now)
    error = models.TextField(blank=True, default="")

    class Meta:
        verbose_name = "Domain Reputation"
        verbose_name_plural = "Domain Reputations"
        ordering = ["-fetched_at"]

    def __str__(self):
        return f"{self.domain} → {self.reputation} ({self.domain_score})"

    def is_stale(self) -> bool:
        """Cached data is stale if over 24 h old for risky domains, 7 days for trusted."""
        delta = timezone.now() - self.fetched_at
        if self.reputation in (self.REPUTATION_MALICIOUS, self.REPUTATION_SUSPICIOUS):
            return delta.total_seconds() > 86_400  # 24 h
        return delta.total_seconds() > 604_800  # 7 days
