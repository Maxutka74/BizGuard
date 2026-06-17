from django.urls import path

from .views import BulkDomainReputationView, DomainReputationRawView, DomainReputationView

app_name = "reputation"

urlpatterns = [
    # Single domain lookup — primary endpoint used by email analysis
    path(
        "<str:domain>/",
        DomainReputationView.as_view(),
        name="domain-lookup",
    ),
    # Batch lookup — used by analysis pipeline (up to 50 domains at once)
    path(
        "bulk/",
        BulkDomainReputationView.as_view(),
        name="bulk-lookup",
    ),
    # Raw VT stats — debug / admin use only
    path(
        "<str:domain>/raw/",
        DomainReputationRawView.as_view(),
        name="domain-raw",
    ),
]
