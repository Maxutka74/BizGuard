from django.urls import path
from .views import (
    CookieTokenRefreshView,
    CsrfTokenView,
    GoogleAuthURLView,
    GoogleAuthCallbackView,
    GooglePublicAuthURLView,
    GooglePublicAuthCallbackView,
    GooglePublicAuthRedirectView,
    MeView,
    LogoutView,
)

urlpatterns = [
    path("google/url", GoogleAuthURLView.as_view(), name="google-auth-url"),
    path("google/public-url", GooglePublicAuthURLView.as_view(), name="google-public-auth-url"),
    path("google/callback", GoogleAuthCallbackView.as_view(), name="google-auth-callback"),
    path("google/public-callback", GooglePublicAuthCallbackView.as_view(), name="google-public-auth-callback"),
    path("google/public-redirect", GooglePublicAuthRedirectView.as_view(), name="google-public-auth-redirect"),
    path("token/refresh", CookieTokenRefreshView.as_view(), name="token-refresh"),
    path("csrf", CsrfTokenView.as_view(), name="csrf-token"),
    path("me", MeView.as_view(), name="me"),
    path("logout", LogoutView.as_view(), name="logout"),
]