"""
Root URL configuration for the BizGuard API.

The public application routes expose authentication, licensing, billing,
Gmail analysis and reputation services.
"""

from django.contrib import admin
from django.conf import settings
from django.urls import include, path
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/accounts/", include("apps.accounts.urls")),
    path("api/licenses/", include("apps.licenses.urls")),
    path("api/billing/", include("apps.billing.urls")),
    path("api/gmail/", include("apps.gmail.urls")),
    path("api/reputation/", include("apps.reputation.urls")),
]

if settings.API_DOCS_ENABLED:
    urlpatterns += [
        path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
        path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="swagger-ui"),
    ]


