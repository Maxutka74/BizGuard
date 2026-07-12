import uuid
from datetime import timedelta

from django.conf import settings
from django.db import models
from django.utils import timezone


class LicensePlan(models.TextChoices):
    FREE_1_DAY = "free_1_day", "Free 1 day"
    HALF_YEAR = "half_year", "6 months"
    YEAR = "year", "1 year"


PLAN_DURATION_DAYS = {
    LicensePlan.FREE_1_DAY: 1,
    LicensePlan.HALF_YEAR: 183,
    LicensePlan.YEAR: 365,
}


class LicenseKey(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    key_hash = models.CharField(max_length=64, unique=True, db_index=True)
    key_prefix = models.CharField(max_length=12, db_index=True)
    plan = models.CharField(max_length=32, choices=LicensePlan.choices)
    duration_days = models.PositiveIntegerField()
    active = models.BooleanField(default=True)
    max_activations = models.PositiveIntegerField(default=1)
    note = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.key_prefix}... ({self.get_plan_display()})"

    @property
    def activation_count(self) -> int:
        return self.activations.filter(revoked=False).count()

    @property
    def has_activation_capacity(self) -> bool:
        return self.activation_count < self.max_activations

    @property
    def remaining_activations(self) -> int:
        return max(0, self.max_activations - self.activation_count)

    def expires_at_from(self, activated_at=None):
        activated_at = activated_at or timezone.now()
        return activated_at + timedelta(days=self.duration_days)


class LicenseActivation(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="license_activations",
    )
    license_key = models.ForeignKey(
        LicenseKey,
        on_delete=models.PROTECT,
        related_name="activations",
    )
    activated_at = models.DateTimeField(default=timezone.now)
    last_confirmed_at = models.DateTimeField(null=True, blank=True)
    confirmation_due_at = models.DateTimeField(null=True, blank=True, db_index=True)
    expires_at = models.DateTimeField(db_index=True)
    revoked = models.BooleanField(default=False)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-expires_at"]
        indexes = [
            models.Index(fields=["user", "expires_at"]),
            models.Index(fields=["license_key", "activated_at"]),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "license_key"],
                name="unique_license_key_activation_per_user",
            )
        ]

    def __str__(self):
        return f"{self.user_id} - {self.license_key.key_prefix}..."

    @property
    def is_active(self) -> bool:
        return not self.revoked and self.expires_at > timezone.now()
