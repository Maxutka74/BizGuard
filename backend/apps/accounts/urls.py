from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import GoogleAuthURLView, GoogleAuthCallbackView, MeView, LogoutView

urlpatterns = [
    path("google/url", GoogleAuthURLView.as_view(), name="google-auth-url"),
    path("google/callback", GoogleAuthCallbackView.as_view(), name="google-auth-callback"),
    path("token/refresh", TokenRefreshView.as_view(), name="token-refresh"),
    path("me", MeView.as_view(), name="me"),
    path("logout", LogoutView.as_view(), name="logout"),
]
