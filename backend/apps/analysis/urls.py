"""
URL configuration for apps/analysis.

Mount in the root urls.py with:
    path("api/analysis/", include("apps.analysis.urls")),
"""

from django.urls import path

from .views import AnalyseEmailView, AnalysisDetailView, BatchAnalysisView

app_name = "analysis"

urlpatterns = [
    # Analyse (or retrieve cached result for) a single email
    path("analyse/", AnalyseEmailView.as_view(), name="analyse"),
    # Retrieve cached result by Gmail message ID
    path("<str:gmail_message_id>/", AnalysisDetailView.as_view(), name="detail"),
    # Bulk retrieval for Dashboard email list
    path("batch/", BatchAnalysisView.as_view(), name="batch"),
]
