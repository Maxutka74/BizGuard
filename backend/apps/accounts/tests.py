from unittest.mock import patch
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.cookies import ACCESS_COOKIE, REFRESH_COOKIE
from apps.accounts.models import User
from apps.accounts.google_oauth import get_or_create_user_from_google
from apps.gmail.models import EmailAccount
from apps.licenses.models import LicensePlan
from apps.licenses.services import create_license_key


class CookieAuthTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(email="cookie@example.com")
        self.client = APIClient()

    def test_refresh_cookie_sets_http_only_auth_cookies(self):
        refresh = RefreshToken.for_user(self.user)
        csrf_response = self.client.get("/api/accounts/csrf")
        csrf_token = csrf_response.data["csrfToken"]
        self.client.cookies[REFRESH_COOKIE] = str(refresh)

        response = self.client.post(
            "/api/accounts/token/refresh",
            {},
            format="json",
            HTTP_X_CSRFTOKEN=csrf_token,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(ACCESS_COOKIE, response.cookies)
        self.assertIn(REFRESH_COOKIE, response.cookies)
        self.assertTrue(response.cookies[ACCESS_COOKIE]["httponly"])
        self.assertTrue(response.cookies[REFRESH_COOKIE]["httponly"])
        self.assertNotIn("access", response.data)
        self.assertNotIn("refresh", response.data)

    def test_me_accepts_access_cookie_without_authorization_header(self):
        refresh = RefreshToken.for_user(self.user)
        self.client.cookies[ACCESS_COOKIE] = str(refresh.access_token)

        response = self.client.get("/api/accounts/me")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["email"], self.user.email)

    def test_google_auth_url_forces_account_selection_without_license_gate(self):
        response = self.client.get(
            "/api/accounts/google/url",
            {"redirect_uri": "http://localhost:5173/auth/callback"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("prompt=select_account+consent", response.data["url"])
        self.assertIn("gmail.modify", response.data["url"])

    def test_public_google_auth_url_uses_profile_scopes_only(self):
        response = self.client.get(
            "/api/accounts/google/public-url",
            {"redirect_uri": "http://localhost:5174/auth/callback"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("scope=openid+email+profile", response.data["url"])
        self.assertNotIn("gmail.modify", response.data["url"])
        self.assertIn("prompt=select_account+consent", response.data["url"])

    def test_public_google_auth_url_ignores_stale_auth_cookie(self):
        stale_user = User.objects.create(email="stale-cookie@example.com")
        refresh = RefreshToken.for_user(stale_user)
        stale_user.delete()
        self.client.cookies[ACCESS_COOKIE] = str(refresh.access_token)

        response = self.client.get(
            "/api/accounts/google/public-url",
            {"redirect_uri": "http://localhost:5174/auth/callback"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("scope=openid+email+profile", response.data["url"])

    def test_bizguard_google_auth_url_allows_email_first_login(self):
        response = self.client.get(
            "/api/accounts/google/url",
            {"redirect_uri": "http://localhost:5173/auth/callback"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("gmail.modify", response.data["url"])


class GoogleEmailFirstLoginTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_bizguard_google_login_creates_active_gmail_account(self):
        user = get_or_create_user_from_google(
            {
                "access_token": "gmail-access",
                "refresh_token": "gmail-refresh",
                "expires_in": 3600,
                "scope": "openid email profile https://www.googleapis.com/auth/gmail.modify",
            },
            {
                "sub": "google-email-first",
                "email": "protected@example.com",
                "name": "Protected User",
            },
            trigger_initial_scan=False,
        )

        account = EmailAccount.objects.get(user=user)
        self.assertTrue(account.is_active)
        self.assertEqual(account.email, user.email)
        self.assertEqual(account.refresh_token, "gmail-refresh")

        refresh = RefreshToken.for_user(user)
        self.client.cookies[ACCESS_COOKIE] = str(refresh.access_token)
        response = self.client.get("/api/accounts/me")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data["gmailConnected"])

    @patch("apps.accounts.views.get_or_create_user_from_google")
    @patch("apps.accounts.views.fetch_google_userinfo")
    @patch("apps.accounts.views.exchange_code_for_tokens")
    def test_google_callback_allows_login_without_license_gate(self, token_mock, userinfo_mock, get_user_mock):
        user = User.objects.create(email="email-first@example.com")
        token_mock.return_value = {"access_token": "google-access"}
        userinfo_mock.return_value = {"email": user.email}
        get_user_mock.return_value = user

        response = self.client.post(
            "/api/accounts/google/callback",
            {"code": "dummy", "redirect_uri": "http://localhost:5173/auth/callback"},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["user"]["email"], user.email)
        self.assertEqual(response.data["user"]["license"]["status"], "missing")
