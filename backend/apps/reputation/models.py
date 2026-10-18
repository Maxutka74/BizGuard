from django.conf import settings
from django.db import models
from django.utils import timezone


def _pending_recheck_seconds() -> int:
    return int(getattr(settings, "VIRUSTOTAL_PENDING_RECHECK_SECONDS", 60))


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


class UrlReputation(models.Model):
    """
    Cached VirusTotal URL reputation result.
    Stores full normalized URLs because phishing often hides behind benign domains.
    """

    VERDICT_CLEAN = "Clean"
    VERDICT_SUSPICIOUS = "Suspicious"
    VERDICT_MALICIOUS = "Malicious"
    VERDICT_PENDING = "Pending"
    VERDICT_ERROR = "Error"

    VERDICT_CHOICES = [
        (VERDICT_CLEAN, "Clean"),
        (VERDICT_SUSPICIOUS, "Suspicious"),
        (VERDICT_MALICIOUS, "Malicious"),
        (VERDICT_PENDING, "Pending"),
        (VERDICT_ERROR, "Error"),
    ]

    normalized_url = models.TextField()
    url_hash = models.CharField(max_length=64, unique=True, db_index=True)
    vt_url_id = models.TextField(blank=True, default="")
    verdict = models.CharField(max_length=20, choices=VERDICT_CHOICES, default=VERDICT_PENDING)
    score = models.IntegerField(default=0)
    is_phishing = models.BooleanField(default=False)
    is_malicious = models.BooleanField(default=False)
    vt_malicious = models.IntegerField(default=0)
    vt_suspicious = models.IntegerField(default=0)
    vt_harmless = models.IntegerField(default=0)
    vt_undetected = models.IntegerField(default=0)
    raw_stats = models.JSONField(default=dict, blank=True)
    raw_results = models.JSONField(default=dict, blank=True)
    fetched_at = models.DateTimeField(default=timezone.now)
    error = models.TextField(blank=True, default="")

    class Meta:
        verbose_name = "URL Reputation"
        verbose_name_plural = "URL Reputations"
        ordering = ["-fetched_at"]
        indexes = [
            models.Index(fields=["url_hash"], name="reputation__url_has_08139a_idx"),
            models.Index(fields=["verdict", "fetched_at"], name="reputation__verdict_4dbdbb_idx"),
        ]

    def __str__(self):
        return f"{self.normalized_url[:80]} -> {self.verdict} ({self.score})"

    def is_stale(self) -> bool:
        delta = timezone.now() - self.fetched_at
        if self.verdict == self.VERDICT_PENDING:
            return delta.total_seconds() > _pending_recheck_seconds()
        if self.verdict in (self.VERDICT_MALICIOUS, self.VERDICT_SUSPICIOUS, self.VERDICT_ERROR):
            return delta.total_seconds() > 86_400
        return delta.total_seconds() > 604_800


class AttachmentReputation(models.Model):
    VERDICT_CLEAN = "Clean"
    VERDICT_SUSPICIOUS = "Suspicious"
    VERDICT_MALICIOUS = "Malicious"
    VERDICT_PENDING = "Pending"
    VERDICT_ERROR = "Error"

    VERDICT_CHOICES = [
        (VERDICT_CLEAN, "Clean"),
        (VERDICT_SUSPICIOUS, "Suspicious"),
        (VERDICT_MALICIOUS, "Malicious"),
        (VERDICT_PENDING, "Pending"),
        (VERDICT_ERROR, "Error"),
    ]

    file_hash = models.CharField(max_length=64, unique=True)
    filename = models.CharField(max_length=512, blank=True, default="")
    mime_type = models.CharField(max_length=255, blank=True, default="")
    size_bytes = models.IntegerField(default=0)
    verdict = models.CharField(max_length=20, choices=VERDICT_CHOICES, default=VERDICT_PENDING)
    score = models.IntegerField(default=0)
    is_malicious = models.BooleanField(default=False)
    is_suspicious = models.BooleanField(default=False)
    extracted_text_preview = models.TextField(blank=True, default="")
    local_findings = models.JSONField(default=list, blank=True)
    raw_stats = models.JSONField(default=dict, blank=True)
    raw_results = models.JSONField(default=dict, blank=True)
    fetched_at = models.DateTimeField(default=timezone.now)
    error = models.TextField(blank=True, default="")

    class Meta:
        verbose_name = "Attachment Reputation"
        verbose_name_plural = "Attachment Reputations"
        ordering = ["-fetched_at"]
        indexes = [
            models.Index(fields=["verdict", "fetched_at"], name="reputation__verdict_5d9629_idx"),
        ]

    def __str__(self):
        return f"{self.filename or self.file_hash} -> {self.verdict} ({self.score})"

    def is_stale(self) -> bool:
        delta = timezone.now() - self.fetched_at
        if self.verdict == self.VERDICT_PENDING:
            return delta.total_seconds() > _pending_recheck_seconds()
        if self.verdict in (self.VERDICT_MALICIOUS, self.VERDICT_SUSPICIOUS, self.VERDICT_ERROR):
            return delta.total_seconds() > 86_400
        return delta.total_seconds() > 604_800
