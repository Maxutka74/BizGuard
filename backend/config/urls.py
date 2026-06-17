"""
BizGuard – root URL configuration.

API structure (matching frontend expectations):
  /api/accounts/   → accounts app  (auth, user profile)
  /api/gmail/      → gmail app     (email list, stats, detail, scan, oauth)
  /api/dashboard/  → dashboard app (aggregated dashboard view + rescan)
  /api/analysis/   → analysis app  (Gemini AI analysis cache)
  /api/reputation/ → reputation app (domain reputation lookups)
  /api/emails/     → emails app    (raw email store / ingest)
  /api/threats/    → threats app   (threat score aggregation)
  /admin/          → Django admin
"""
from django.contrib import admin
from django.urls import path, include
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView
print("🔥 ROOT URLCONF LOADED")
urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/accounts/", include("apps.accounts.urls")),
    path("api/gmail/", include("apps.gmail.urls")),
    path("api/dashboard/", include("apps.dashboard.urls")),
    path("api/analysis/", include("apps.analysis.urls")),
    path("api/reputation/", include("apps.reputation.urls")),
    path("api/emails/", include("apps.emails.urls")),
    path("api/threats/", include("apps.threats.urls")),
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
]
