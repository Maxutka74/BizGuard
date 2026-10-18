from django.urls import path

from .views import (
    ActivateLicenseView,
    ConfirmLicenseView,
    LicensePlansView,
    LicenseStatusView,
    ValidateLicenseKeyView,
)

urlpatterns = [
    path("validate-key", ValidateLicenseKeyView.as_view(), name="license-validate-key"),
    path("plans", LicensePlansView.as_view(), name="license-plans"),
    path("status", LicenseStatusView.as_view(), name="license-status"),
    path("activate", ActivateLicenseView.as_view(), name="license-activate"),
    path("confirm", ConfirmLicenseView.as_view(), name="license-confirm"),
]
