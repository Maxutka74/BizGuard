from django.conf import settings
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .google_oauth import (
    GoogleOAuthError,
    exchange_code_for_tokens,
    fetch_google_userinfo,
    get_or_create_user_from_google,
    GMAIL_SCOPES,
)
from .serializers import UserSerializer, GoogleAuthCallbackSerializer


def _tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {"access": str(refresh.access_token), "refresh": str(refresh)}


class GoogleAuthURLView(APIView):
    """
    GET /api/accounts/google/url
    Returns the Google OAuth consent URL for the "Continue with Google" button.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        redirect_uri = request.query_params.get("redirect_uri", settings.GOOGLE_OAUTH_REDIRECT_URI)
        params = {
            "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": " ".join(GMAIL_SCOPES),
            "access_type": "offline",
            "prompt": "consent",
        }
        from urllib.parse import urlencode
        url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
        return Response({"url": url})


class GoogleAuthCallbackView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = GoogleAuthCallbackSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data["code"]
        redirect_uri = serializer.validated_data.get(
            "redirect_uri",
            settings.GOOGLE_OAUTH_REDIRECT_URI
        )

        try:
            token_data = exchange_code_for_tokens(code, redirect_uri)
            userinfo = fetch_google_userinfo(token_data["access_token"])
            user = get_or_create_user_from_google(token_data, userinfo)
        except GoogleOAuthError as e:
            return Response({"detail": str(e)}, status=400)

        refresh = RefreshToken.for_user(user)

        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "user": UserSerializer(user).data
        })


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
        refresh_token = request.data.get("refresh")
        if refresh_token:
            try:
                token = RefreshToken(refresh_token)
                token.blacklist()
            except Exception:
                pass
        return Response(status=status.HTTP_205_RESET_CONTENT)
