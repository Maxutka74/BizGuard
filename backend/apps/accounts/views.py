from django.conf import settings
import logging
from urllib.parse import urlparse
from django.middleware.csrf import get_token
from django.shortcuts import redirect
from rest_framework import status
from rest_framework.authentication import CSRFCheck
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from .google_oauth import (
    GoogleOAuthError,
    exchange_code_for_tokens,
    fetch_google_userinfo,
    get_or_create_user_from_google,
    get_or_create_public_user_from_google,
    _trigger_initial_scan,
    GMAIL_SCOPES,
    PUBLIC_GOOGLE_SCOPES,
)
from .cookies import REFRESH_COOKIE, clear_auth_cookies, set_auth_cookies
from .serializers import UserSerializer, GoogleAuthCallbackSerializer, GooglePublicAuthCallbackSerializer

logger = logging.getLogger(__name__)


def _tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {"access": str(refresh.access_token), "refresh": str(refresh)}


def _csrf_failed_reason(request) -> str | None:
    check = CSRFCheck(lambda req: None)
    check.process_request(request)
    return check.process_view(request, None, (), {})


class GoogleAuthURLView(APIView):
    """
    GET /api/accounts/google/url
    Returns the Google OAuth consent URL for the "Continue with Google" button.
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "google_auth_url"

    def get(self, request):
        redirect_uri = request.query_params.get("redirect_uri", settings.GOOGLE_OAUTH_REDIRECT_URI)
        if not _is_allowed_redirect_uri(redirect_uri):
            return Response({"detail": "Недозволений Google OAuth redirect_uri."}, status=400)
        state = request.query_params.get("state", "")
        params = {
            "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(GMAIL_SCOPES),
            "access_type": "offline",
            "prompt": "select_account consent",
        }
        if state:
            params["state"] = state
        from urllib.parse import urlencode
        url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
        return Response({"url": url})


class GooglePublicAuthURLView(APIView):
    """GET /api/accounts/google/public-url for purchase site login without Gmail scope."""
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "google_auth_url"

    def get(self, request):
        redirect_uri = request.query_params.get("redirect_uri", settings.GOOGLE_PUBLIC_OAUTH_REDIRECT_URI)
        if not _is_allowed_redirect_uri(redirect_uri):
            return Response({"detail": "Недозволений Google OAuth redirect_uri."}, status=400)
        state = request.query_params.get("state", "")
        params = {
            "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(PUBLIC_GOOGLE_SCOPES),
            "access_type": "offline",
            "prompt": "select_account consent",
        }
        if state:
            params["state"] = state
        from urllib.parse import urlencode
        url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
        return Response({"url": url})



class GooglePublicAuthRedirectView(APIView):
    """Browser-facing Google OAuth redirect endpoint for the purchase site."""
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "google_callback"

    def get(self, request):
        frontend_url = settings.PURCHASE_SITE_URL.rstrip("/")
        error = request.query_params.get("error")
        state = request.query_params.get("state", "")
        if error:
            return redirect(f"{frontend_url}/?auth_error={error}&state={state}")

        code = request.query_params.get("code")
        if not code:
            return redirect(f"{frontend_url}/?auth_error=missing_code&state={state}")

        try:
            token_data = exchange_code_for_tokens(code, settings.GOOGLE_PUBLIC_OAUTH_REDIRECT_URI)
            userinfo = fetch_google_userinfo(token_data["access_token"])
            user = get_or_create_public_user_from_google(token_data, userinfo)
        except GoogleOAuthError:
            logger.exception("Public Google OAuth backend redirect failed")
            return redirect(f"{frontend_url}/?auth_error=google_oauth_failed&state={state}")
        except Exception:
            logger.exception("Public Google OAuth backend redirect failed")
            return redirect(f"{frontend_url}/?auth_error=google_callback_failed&state={state}")

        tokens = _tokens_for_user(user)
        response = redirect(f"{frontend_url}/?auth=success&state={state}")
        set_auth_cookies(response, tokens["access"], tokens["refresh"])
        get_token(request)
        return response

class GooglePublicAuthCallbackView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "google_callback"

    def post(self, request):
        serializer = GooglePublicAuthCallbackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        code = serializer.validated_data["code"]
        redirect_uri = serializer.validated_data.get("redirect_uri", settings.GOOGLE_PUBLIC_OAUTH_REDIRECT_URI)
        if not _is_allowed_redirect_uri(redirect_uri):
            return Response({"detail": "Недозволений Google OAuth redirect_uri."}, status=400)

        try:
            token_data = exchange_code_for_tokens(code, redirect_uri)
            userinfo = fetch_google_userinfo(token_data["access_token"])
            user = get_or_create_public_user_from_google(token_data, userinfo)
        except GoogleOAuthError as e:
            return Response({"detail": str(e), "code": "google_oauth_failed"}, status=400)
        except Exception:
            logger.exception("Public Google OAuth callback failed")
            return Response(
                {
                    "detail": "Не вдалося завершити вхід через Google. Спробуйте ще раз.",
                    "code": "google_callback_failed",
                },
                status=400,
            )

        tokens = _tokens_for_user(user)
        response = Response({"user": UserSerializer(user).data})
        set_auth_cookies(response, tokens["access"], tokens["refresh"])
        get_token(request)
        return response

class GoogleAuthCallbackView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "google_callback"

    def post(self, request):
        serializer = GoogleAuthCallbackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data["code"]
        redirect_uri = serializer.validated_data.get(
            "redirect_uri",
            settings.GOOGLE_OAUTH_REDIRECT_URI
        )
        if not _is_allowed_redirect_uri(redirect_uri):
            return Response({"detail": "Недозволений Google OAuth redirect_uri."}, status=400)

        try:
            token_data = exchange_code_for_tokens(code, redirect_uri)
            userinfo = fetch_google_userinfo(token_data["access_token"])
            user = get_or_create_user_from_google(token_data, userinfo, trigger_initial_scan=False)
        except GoogleOAuthError as e:
            return Response({"detail": str(e), "code": "google_oauth_failed"}, status=400)
        except Exception as e:
            logger.exception("Google OAuth callback failed")
            return Response(
                {
                    "detail": "Не вдалося завершити вхід через Google. Спробуйте ще раз.",
                    "code": "google_callback_failed",
                },
                status=400,
            )

        tokens = _tokens_for_user(user)
        response = Response({"user": UserSerializer(user).data})
        set_auth_cookies(response, tokens["access"], tokens["refresh"])
        get_token(request)
        return response


class CsrfTokenView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        return Response({"csrfToken": get_token(request)})


class CookieTokenRefreshView(APIView):
    permission_classes = [AllowAny]
    authentication_classes = []
    throttle_scope = "token_refresh"

    def post(self, request):
        refresh_token = request.COOKIES.get(REFRESH_COOKIE) or request.data.get("refresh")
        if not refresh_token:
            return Response({"detail": "Refresh token відсутній."}, status=status.HTTP_401_UNAUTHORIZED)

        if request.COOKIES.get(REFRESH_COOKIE):
            reason = _csrf_failed_reason(request)
            if reason:
                raise PermissionDenied({"detail": f"CSRF Failed: {reason}", "code": "csrf_failed"})

        serializer = TokenRefreshSerializer(data={"refresh": refresh_token})
        try:
            serializer.is_valid(raise_exception=True)
        except Exception:
            response = Response({"detail": "Refresh token invalid."}, status=status.HTTP_401_UNAUTHORIZED)
            clear_auth_cookies(response)
            return response

        access = serializer.validated_data["access"]
        new_refresh = serializer.validated_data.get("refresh", refresh_token)
        response = Response({"refreshed": True})
        set_auth_cookies(response, access, new_refresh)
        get_token(request)
        return response


class MeView(APIView):
    """
    GET /api/accounts/me
    Returns the currently authenticated user's profile.
    Used on app load to restore session / hydrate dashboard.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(UserSerializer(request.user).data)


class LogoutView(APIView):
    """
    POST /api/accounts/logout
    Body: { "refresh": "..." }
    Blacklists the refresh token. Frontend calls this on "Sign out".
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        refresh_token = request.COOKIES.get(REFRESH_COOKIE) or request.data.get("refresh")
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except Exception:
                pass
        response = Response(status=status.HTTP_205_RESET_CONTENT)
        clear_auth_cookies(response)
        return response


def _is_allowed_redirect_uri(redirect_uri: str) -> bool:
    allowed = {
        settings.GOOGLE_OAUTH_REDIRECT_URI,
        settings.GOOGLE_PUBLIC_OAUTH_REDIRECT_URI,
    }
    for origin in settings.CORS_ALLOWED_ORIGINS:
        allowed.add(origin.rstrip("/") + "/auth/callback")

    if redirect_uri in allowed:
        return True

    if settings.DEBUG:
        parsed = urlparse(redirect_uri)
        return parsed.scheme in {"http", "https"} and parsed.hostname in {"localhost", "127.0.0.1"}

    return False




