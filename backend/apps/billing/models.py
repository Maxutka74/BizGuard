import uuid

from django.conf import settings
from django.db import models
from django.utils import timezone

from apps.licenses.models import LicenseKey, LicensePlan


class PurchaseOrder(models.Model):
    class Provider(models.TextChoices):
        STRIPE = "stripe", "Stripe"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        PAID = "paid", "Paid"
        CANCELED = "canceled", "Canceled"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="purchase_orders",
    )
    plan = models.CharField(max_length=32, choices=LicensePlan.choices)
    provider = models.CharField(max_length=32, choices=Provider.choices, default=Provider.STRIPE)
    provider_session_id = models.CharField(max_length=255, unique=True, null=True, blank=True)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.PENDING, db_index=True)
    amount = models.PositiveIntegerField(default=0)
    base_amount = models.PositiveIntegerField(default=0)
    extra_seat_amount = models.PositiveIntegerField(default=0)
    unit_extra_seat_amount = models.PositiveIntegerField(default=0)
    activation_count = models.PositiveIntegerField(default=1)
    currency = models.CharField(max_length=8, default="uah")
    generated_license_key = models.ForeignKey(
        LicenseKey,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="purchase_orders",
    )
    # Recoverable only with BILLING_LICENSE_ENCRYPTION_SECRET. Never log this value.
    encrypted_license_key = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    paid_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "status"]),
            models.Index(fields=["provider_session_id"]),
        ]

    def mark_paid(self):
        self.status = self.Status.PAID
        self.paid_at = self.paid_at or timezone.now()
