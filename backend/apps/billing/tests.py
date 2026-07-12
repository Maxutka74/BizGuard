from unittest.mock import Mock, patch

from django.test import TestCase, override_settings
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User
from apps.licenses.models import LicenseKey


@override_settings(BILLING_FAKE_MODE=True, PURCHASE_SITE_URL="http://localhost:5174")
class BillingTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(email="buyer@example.com")
        self.client = APIClient()
        self.client.force_authenticate(self.user)

    def test_checkout_requires_authenticated_user(self):
        client = APIClient()
        response = client.post("/api/billing/checkout", {"plan": "half_year"}, format="json")
        self.assertEqual(response.status_code, 401)

    def test_billing_endpoints_do_not_require_active_license(self):
        client = APIClient()
        refresh = RefreshToken.for_user(self.user)
        auth = f"Bearer {refresh.access_token}"

        profile = client.get("/api/billing/profile", HTTP_AUTHORIZATION=auth)
        self.assertEqual(profile.status_code, 200)

        checkout = client.post(
            "/api/billing/checkout",
            {"plan": "half_year", "activationCount": 2},
            format="json",
            HTTP_AUTHORIZATION=auth,
        )
        self.assertEqual(checkout.status_code, 200)
        self.assertEqual(checkout.data["price"]["activationCount"], 2)

    def test_fake_checkout_creates_order_and_complete_generates_key_once(self):
        checkout = self.client.post(
            "/api/billing/checkout",
            {"plan": "half_year", "activationCount": 3},
            format="json",
        )
        self.assertEqual(checkout.status_code, 200)
        self.assertTrue(checkout.data["fakeMode"])
        self.assertTrue(checkout.data["sessionId"].startswith("direct_"))
        self.assertEqual(checkout.data["price"]["amount"], 59900)
        self.assertEqual(checkout.data["price"]["activationCount"], 3)

        complete = self.client.post("/api/billing/complete", {"sessionId": checkout.data["sessionId"]}, format="json")
        self.assertEqual(complete.status_code, 200)
        self.assertTrue(complete.data["plaintextKey"].startswith("BG-"))
        self.assertEqual(complete.data["order"]["activationCount"], 3)
        self.assertEqual(complete.data["order"]["generatedLicense"]["maxActivations"], 3)
        self.assertEqual(LicenseKey.objects.count(), 1)

        again = self.client.post("/api/billing/complete", {"sessionId": checkout.data["sessionId"]}, format="json")
        self.assertEqual(again.status_code, 200)
        self.assertIsNone(again.data["plaintextKey"])
        self.assertEqual(LicenseKey.objects.count(), 1)

    @override_settings(BILLING_FAKE_MODE=False, STRIPE_SECRET_KEY="")
    def test_free_plan_generates_key_without_stripe_key(self):
        checkout = self.client.post("/api/billing/checkout", {"plan": "free_1_day"}, format="json")
        self.assertEqual(checkout.status_code, 200)
        self.assertTrue(checkout.data["fakeMode"])
        self.assertTrue(checkout.data["sessionId"].startswith("direct_"))

        complete = self.client.post("/api/billing/complete", {"sessionId": checkout.data["sessionId"]}, format="json")
        self.assertEqual(complete.status_code, 200)
        self.assertTrue(complete.data["plaintextKey"].startswith("BG-"))
        self.assertEqual(complete.data["order"]["generatedLicense"]["maxActivations"], 1)

    def test_free_plan_rejects_multiple_activations(self):
        response = self.client.post(
            "/api/billing/checkout",
            {"plan": "free_1_day", "activationCount": 2},
            format="json",
        )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], "free_plan_single_activation_only")

    @override_settings(BILLING_FAKE_MODE=False, STRIPE_SECRET_KEY="sk_test_123", PURCHASE_SITE_URL="http://localhost:5174")
    @patch("apps.billing.services.requests.post")
    def test_stripe_checkout_created_for_paid_plan_when_fake_mode_off(self, post_mock):
        post_mock.return_value = Mock(
            status_code=200,
            json=lambda: {"id": "cs_test_123", "url": "https://checkout.stripe.test/session"},
        )

        response = self.client.post(
            "/api/billing/checkout",
            {"plan": "year", "activationCount": 5},
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data["fakeMode"])
        self.assertEqual(response.data["sessionId"], "cs_test_123")
        self.assertEqual(response.data["price"]["amount"], 121900)
        payload = post_mock.call_args.kwargs["data"]
        self.assertEqual(payload["line_items[0][price_data][currency]"], "uah")
        self.assertEqual(payload["line_items[0][price_data][unit_amount]"], "89900")
        self.assertEqual(payload["line_items[1][quantity]"], "4")
        self.assertEqual(payload["line_items[1][price_data][unit_amount]"], "8000")

    @override_settings(BILLING_FAKE_MODE=False, STRIPE_SECRET_KEY="sk_test_123", PURCHASE_SITE_URL="http://localhost:5174")
    @patch("apps.billing.services.requests.post")
    def test_half_year_business_price_formula(self, post_mock):
        post_mock.return_value = Mock(
            status_code=200,
            json=lambda: {"id": "cs_test_half", "url": "https://checkout.stripe.test/half"},
        )
        response = self.client.post(
            "/api/billing/checkout",
            {"plan": "half_year", "activationCount": 5},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["price"]["amount"], 69900)
        self.assertEqual(response.data["price"]["extraSeatAmount"], 20000)

    @override_settings(BILLING_FAKE_MODE=False, STRIPE_SECRET_KEY="sk_test_123", PURCHASE_SITE_URL="http://localhost:5174")
    @patch("apps.billing.services.requests.get")
    @patch("apps.billing.services.requests.post")
    def test_paid_stripe_session_generates_key_only_after_paid_status(self, post_mock, get_mock):
        post_mock.return_value = Mock(
            status_code=200,
            json=lambda: {"id": "cs_test_paid", "url": "https://checkout.stripe.test/paid"},
        )
        get_mock.return_value = Mock(status_code=200, json=lambda: {"payment_status": "paid"})

        checkout = self.client.post(
            "/api/billing/checkout",
            {"plan": "half_year", "activationCount": 4},
            format="json",
        )
        self.assertEqual(checkout.status_code, 200)
        self.assertFalse(checkout.data["fakeMode"])

        complete = self.client.post("/api/billing/complete", {"sessionId": "cs_test_paid"}, format="json")
        self.assertEqual(complete.status_code, 200)
        self.assertTrue(complete.data["plaintextKey"].startswith("BG-"))
        self.assertEqual(complete.data["order"]["generatedLicense"]["maxActivations"], 4)
        self.assertEqual(LicenseKey.objects.count(), 1)

    @override_settings(BILLING_FAKE_MODE=False, STRIPE_SECRET_KEY="sk_test_123", PURCHASE_SITE_URL="http://localhost:5174")
    @patch("apps.billing.services.requests.get")
    @patch("apps.billing.services.requests.post")
    def test_unpaid_stripe_session_does_not_generate_key(self, post_mock, get_mock):
        post_mock.return_value = Mock(
            status_code=200,
            json=lambda: {"id": "cs_test_unpaid", "url": "https://checkout.stripe.test/unpaid"},
        )
        get_mock.return_value = Mock(status_code=200, json=lambda: {"payment_status": "unpaid"})

        checkout = self.client.post("/api/billing/checkout", {"plan": "year"}, format="json")
        self.assertEqual(checkout.status_code, 200)

        complete = self.client.post("/api/billing/complete", {"sessionId": "cs_test_unpaid"}, format="json")
        self.assertEqual(complete.status_code, 400)
        self.assertEqual(complete.data["code"], "payment_not_paid")
        self.assertEqual(LicenseKey.objects.count(), 0)

    def test_profile_does_not_return_plaintext_key(self):
        checkout = self.client.post(
            "/api/billing/checkout",
            {"plan": "year", "activationCount": 2},
            format="json",
        )
        self.client.post("/api/billing/complete", {"sessionId": checkout.data["sessionId"]}, format="json")
        profile = self.client.get("/api/billing/profile")
        self.assertEqual(profile.status_code, 200)
        self.assertEqual(profile.data["orders"][0]["currency"], "uah")
        self.assertEqual(profile.data["orders"][0]["activationCount"], 2)
        self.assertEqual(profile.data["orders"][0]["baseAmount"], 89900)
        self.assertEqual(profile.data["orders"][0]["extraSeatAmount"], 8000)
        self.assertIn("generatedLicense", profile.data["orders"][0])
        self.assertNotIn("plaintextKey", profile.data["orders"][0])