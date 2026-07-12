from django.urls import path

from .views import EmailThreatScoreView, ThreatStatsView

app_name = "threats"

urlpatterns = [
    path("emails/<int:email_id>/threat/", EmailThreatScoreView.as_view(), name="email-threat"),
    path("threats/stats/", ThreatStatsView.as_view(), name="threat-stats"),
]
