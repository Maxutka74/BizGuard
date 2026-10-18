from django.contrib import admin

from .models import LicenseActivation, LicenseKey


@admin.register(LicenseKey)
class LicenseKeyAdmin(admin.ModelAdmin):
    list_display = (
        "key_prefix",
        "plan",
        "duration_days",
        "active",
        "max_activations",
        "activation_count",
        "remaining_activations",
        "created_at",
    )
    list_filter = ("plan", "active", "created_at")
    search_fields = ("key_prefix", "note")
    readonly_fields = ("id", "key_hash", "key_prefix", "created_at", "updated_at")


@admin.register(LicenseActivation)
class LicenseActivationAdmin(admin.ModelAdmin):
    list_display = (
        "user",
        "license_key",
        "activated_at",
        "last_confirmed_at",
        "confirmation_due_at",
        "expires_at",
        "revoked",
    )
    list_filter = ("revoked", "license_key__plan", "activated_at", "expires_at")
    search_fields = ("user__email", "license_key__key_prefix")
    readonly_fields = ("id", "created_at")
