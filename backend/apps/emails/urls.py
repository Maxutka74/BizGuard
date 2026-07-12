from django.urls import path, include
from rest_framework.routers import DefaultRouter

from .views import EmailViewSet, EmailIngestView

router = DefaultRouter()

# пустий префікс
router.register(r"", EmailViewSet, basename="email")

urlpatterns = [
    path("", include(router.urls)),
    path("ingest/", EmailIngestView.as_view(), name="email-ingest"),
]