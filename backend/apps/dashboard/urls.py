from django.urls import path

from .views import DashboardView, RescanView

app_name = "dashboard"

urlpatterns = [
    path("", DashboardView.as_view(), name="dashboard"),
    path("rescan/", RescanView.as_view(), name="rescan"),
]
