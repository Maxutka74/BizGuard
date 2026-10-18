from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.accounts.models import User
from apps.gmail.models import EmailAccount

from .models import LicensePlan
from .services import (
    LicenseServiceError,
    activate_license_for_user,
    confirm_license_for_user,
    create_gate_token,
    create_license_key,
    get_plan_capabilities,
    get_license_plans,
    license_key_preview,
    validate_license_key,
)


class LicenseServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(email="first@example.com")
        self.other_user = User.objects.create(email="second@example.com")

    def test_valid_and_invalid_key_validation(self):
        plaintext, license_key = create_license_key(LicensePlan.FREE_1_DAY)

        self.assertEqual(validate_license_key(plaintext), license_key)

        with self.assertRaises(LicenseServiceError) as ctx:
            validate_license_key("BG-NOT-A-REAL-KEY")
        self.assertEqual(ctx.exception.code, "invalid_key")

    def test_disabled_key_is_rejected(self):
        plaintext, license_key = create_license_key(LicensePlan.FREE_1_DAY)
        license_key.active = False
        license_key.save(update_fields=["active"])

        with self.assertRaises(LicenseServiceError) as ctx:
            validate_license_key(plaintext)
        self.assertEqual(ctx.exception.code, "disabled_key")

    def test_plan_durations_start_at_activation_time(self):
        expected = {
            LicensePlan.FREE_1_DAY: 1,
            LicensePlan.HALF_YEAR: 183,
            LicensePlan.YEAR: 365,
        }

        for plan, days in expected.items():
            plaintext, license_key = create_license_key(plan)
            activation = activate_license_for_user(self.user, validate_license_key(plaintext))
            delta = activation.expires_at - activation.activated_at
            self.assertAlmostEqual(delta.total_seconds(), timedelta(days=days).total_seconds(), delta=2)
            self.user.license_activations.all().delete()

    def test_free_plan_does_not_require_monthly_confirmation(self):
        plaintext, _ = create_license_key(LicensePlan.FREE_1_DAY)
        activation = activate_license_for_user(self.user, validate_license_key(plaintext))

        self.assertIsNone(activation.confirmation_due_at)
        self.assertEqual(activation.last_confirmed_at, activation.activated_at)

    def test_paid_plan_sets_monthly_confirmation_due_date(self):
        plaintext, _ = create_license_key(LicensePlan.HALF_YEAR)
        activation = activate_license_for_user(self.user, validate_license_key(plaintext))

        self.assertIsNotNone(activation.confirmation_due_at)
        self.assertAlmostEqual(
            (activation.confirmation_due_at - activation.activated_at).total_seconds(),
            timedelta(days=30).total_seconds(),
            delta=2,
        )

    def test_correct_key_confirms_paid_license_for_next_month(self):
        plaintext, _ = create_license_key(LicensePlan.YEAR)
        activation = activate_license_for_user(self.user, validate_license_key(plaintext))
        activation.confirmation_due_at = timezone.now() - timedelta(minutes=1)
        activation.save(update_fields=["confirmation_due_at"])

        confirmed = confirm_license_for_user(self.user, plaintext)

        self.assertGreater(confirmed.confirmation_due_at, timezone.now() + timedelta(days=29))

    def test_wrong_key_does_not_confirm_paid_license(self):
        plaintext, _ = create_license_key(LicensePlan.YEAR)
        activate_license_for_user(self.user, validate_license_key(plaintext))
        wrong_key, _ = create_license_key(LicensePlan.YEAR)

        with self.assertRaises(LicenseServiceError) as ctx:
            confirm_license_for_user(self.user, wrong_key)
        self.assertEqual(ctx.exception.code, "invalid_confirmation_key")

    def test_plan_capabilities_are_available_for_each_plan(self):
        self.assertEqual(get_plan_capabilities(LicensePlan.FREE_1_DAY)["maxMessagesPerRun"], 5)
        self.assertEqual(get_plan_capabilities(LicensePlan.HALF_YEAR)["maxMessagesPerRun"], 15)
        self.assertEqual(get_plan_capabilities(LicensePlan.YEAR)["maxMessagesPerRun"], 30)
        self.assertEqual(get_plan_capabilities(LicensePlan.HALF_YEAR)["autoMonitorIntervalMinutes"], 30)
        self.assertTrue(get_plan_capabilities(LicensePlan.HALF_YEAR)["autoSpamCritical"])
        self.assertTrue(get_plan_capabilities(LicensePlan.YEAR)["priorityAi"])
        self.assertTrue(get_plan_capabilities(LicensePlan.YEAR)["trustedSenderAllowlist"])

    def test_plan_labels_are_ukrainian_and_consistent(self):
        labels = {item["plan"]: item["planLabel"] for item in get_license_plans()}
        self.assertEqual(labels, {
            "free_1_day": "Free на 1 день",
            "half_year": "Пів року",
            "year": "Рік",
        })
        _, key = create_license_key(LicensePlan.YEAR)
        self.assertEqual(license_key_preview(key)["planLabel"], labels["year"])

    def test_multi_use_key_activates_multiple_users(self):
        plaintext, license_key = create_license_key(LicensePlan.HALF_YEAR, max_activations=2)

        activate_license_for_user(self.user, validate_license_key(plaintext))
        activate_license_for_user(self.other_user, validate_license_key(plaintext))

        self.assertEqual(license_key.activations.count(), 2)

    def test_new_key_defaults_to_single_activation(self):
        plaintext, license_key = create_license_key(LicensePlan.HALF_YEAR)

        activate_license_for_user(self.user, validate_license_key(plaintext))

        with self.assertRaises(LicenseServiceError) as ctx:
            activate_license_for_user(self.other_user, validate_license_key(plaintext))
        self.assertEqual(ctx.exception.code, "activation_limit_reached")
        self.assertEqual(license_key.max_activations, 1)

    def test_max_activations_blocks_extra_users(self):
        plaintext, license_key = create_license_key(LicensePlan.YEAR, max_activations=1)

        activate_license_for_user(self.user, validate_license_key(plaintext))

        with self.assertRaises(LicenseServiceError) as ctx:
            activate_license_for_user(self.other_user, validate_license_key(plaintext))
        self.assertEqual(ctx.exception.code, "activation_limit_reached")
        self.assertEqual(license_key.activations.count(), 1)

    def test_invalid_max_activations_is_rejected(self):
        with self.assertRaises(LicenseServiceError) as ctx:
            create_license_key(LicensePlan.YEAR, max_activations=0)
        self.assertEqual(ctx.exception.code, "invalid_max_activations")


class LicenseApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(email="licensed@example.com")
        self.other_user = User.objects.create(email="other-licensed@example.com")
        self.client = APIClient()

    def _authenticate(self):
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {refresh.access_token}")

    def test_validate_key_returns_gate_token_without_activation(self):
        plaintext, license_key = create_license_key(LicensePlan.FREE_1_DAY)

        response = self.client.post("/api/licenses/validate-key", {"key": plaintext}, format="json")

        self.assertEqual(response.status_code, 200)
        self.assertIn("gateToken", response.data)
        self.assertEqual(response.data["plan"], LicensePlan.FREE_1_DAY)
        self.assertEqual(response.data["maxActivations"], 1)
        self.assertEqual(response.data["activationCount"], 0)
        self.assertEqual(response.data["remainingActivations"], 1)
        self.assertEqual(license_key.activations.count(), 0)

    def test_validate_key_returns_gate_token_when_capacity_is_full(self):
        plaintext, _ = create_license_key(LicensePlan.FREE_1_DAY)
        activate_license_for_user(self.user, validate_license_key(plaintext))

        response = self.client.post("/api/licenses/validate-key", {"key": plaintext}, format="json")

        self.assertEqual(response.status_code, 200)
        self.assertIn("gateToken", response.data)
        self.assertTrue(response.data["capacityFull"])
        self.assertEqual(response.data["remainingActivations"], 0)

    def test_revoked_activation_frees_a_seat(self):
        plaintext, license_key = create_license_key(LicensePlan.FREE_1_DAY)
        activation = activate_license_for_user(self.user, validate_license_key(plaintext))
        activation.revoked = True
        activation.revoked_at = timezone.now()
        activation.save(update_fields=["revoked", "revoked_at"])

        response = self.client.post("/api/licenses/validate-key", {"key": plaintext}, format="json")

        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.data["capacityFull"])
        self.assertEqual(license_key.activation_count, 0)
        self.assertEqual(license_key.remaining_activations, 1)

    @patch("apps.accounts.views._trigger_initial_scan")
    @patch("apps.accounts.views.get_or_create_user_from_google")
    @patch("apps.accounts.views.fetch_google_userinfo")
    @patch("apps.accounts.views.exchange_code_for_tokens")
    def test_google_callback_allows_same_user_when_key_is_full(
        self,
        token_mock,
        userinfo_mock,
        get_user_mock,
        scan_mock,
    ):
        plaintext, license_key = create_license_key(LicensePlan.FREE_1_DAY)
        activate_license_for_user(self.user, validate_license_key(plaintext))
        token_mock.return_value = {"access_token": "google-access"}
        userinfo_mock.return_value = {"email": self.user.email}
        get_user_mock.return_value = self.user

        response = self.client.post(
            "/api/accounts/google/callback",
            {
                "code": "dummy",
                "redirect_uri": "http://localhost:5173/auth/callback",
                "license_gate_token": create_gate_token(license_key),
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(license_key.activation_count, 1)
        scan_mock.assert_not_called()

    @patch("apps.accounts.views.get_or_create_user_from_google")
    @patch("apps.accounts.views.fetch_google_userinfo")
    @patch("apps.accounts.views.exchange_code_for_tokens")
    def test_google_callback_allows_new_user_to_login_before_license_activation(
        self,
        token_mock,
        userinfo_mock,
        get_user_mock,
    ):
        plaintext, license_key = create_license_key(LicensePlan.FREE_1_DAY)
        activate_license_for_user(self.user, validate_license_key(plaintext))
        token_mock.return_value = {"access_token": "google-access"}
        userinfo_mock.return_value = {"email": self.other_user.email}
        get_user_mock.return_value = self.other_user

        response = self.client.post(
            "/api/accounts/google/callback",
            {
                "code": "dummy",
                "redirect_uri": "http://localhost:5173/auth/callback",
                "license_gate_token": create_gate_token(license_key),
            },
            format="json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["user"]["license"]["status"], "missing")
        self.assertEqual(license_key.activation_count, 1)

    def test_me_returns_license_status_without_active_license(self):
        self._authenticate()

        response = self.client.get("/api/accounts/me")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["license"]["status"], "missing")

    def test_business_api_requires_active_license(self):
        self._authenticate()

        response = self.client.get("/api/gmail/auth/status/")

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data["code"], "license_required")

    def test_business_api_allows_active_license(self):
        plaintext, _ = create_license_key(LicensePlan.FREE_1_DAY)
        activate_license_for_user(self.user, validate_license_key(plaintext))
        self._authenticate()

        response = self.client.get("/api/gmail/auth/status/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["connected"], False)

    def test_expired_license_blocks_business_api(self):
        plaintext, license_key = create_license_key(LicensePlan.FREE_1_DAY)
        activation = activate_license_for_user(self.user, validate_license_key(plaintext))
        activation.expires_at = timezone.now() - timedelta(seconds=1)
        activation.save(update_fields=["expires_at"])
        self._authenticate()

        response = self.client.get("/api/gmail/auth/status/")

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data["code"], "license_required")
        self.assertEqual(response.data["license"]["status"], "expired")

    def test_monthly_confirmation_required_blocks_business_api(self):
        plaintext, _ = create_license_key(LicensePlan.HALF_YEAR)
        activation = activate_license_for_user(self.user, validate_license_key(plaintext))
        activation.confirmation_due_at = timezone.now() - timedelta(minutes=1)
        activation.save(update_fields=["confirmation_due_at"])
        self._authenticate()

        response = self.client.get("/api/gmail/auth/status/")

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.data["code"], "license_required")
        self.assertEqual(response.data["license"]["status"], "confirmation_required")
        self.assertTrue(response.data["license"]["confirmationRequired"])

    def test_confirm_endpoint_unlocks_monthly_confirmation(self):
        plaintext, _ = create_license_key(LicensePlan.YEAR)
        activation = activate_license_for_user(self.user, validate_license_key(plaintext))
        activation.confirmation_due_at = timezone.now() - timedelta(minutes=1)
        activation.save(update_fields=["confirmation_due_at"])
        self._authenticate()

        response = self.client.post("/api/licenses/confirm", {"key": plaintext}, format="json")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["license"]["status"], "active")
        self.assertFalse(response.data["license"]["confirmationRequired"])

    def test_capabilities_returned_in_license_status(self):
        plaintext, _ = create_license_key(LicensePlan.YEAR)
        activate_license_for_user(self.user, validate_license_key(plaintext))
        self._authenticate()

        response = self.client.get("/api/accounts/me")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["license"]["capabilities"]["maxMessagesPerRun"], 30)
        self.assertEqual(response.data["license"]["capabilities"]["recentLookbackDays"], 14)
        self.assertEqual(response.data["license"]["capabilities"]["maxUrlsPerEmail"], 15)

    def test_plans_endpoint_returns_all_subscription_capabilities(self):
        response = self.client.get("/api/licenses/plans")

        self.assertEqual(response.status_code, 200)
        plans = {item["plan"]: item for item in response.data["plans"]}
        self.assertEqual(set(plans.keys()), set(LicensePlan.values))
        self.assertEqual(plans[LicensePlan.FREE_1_DAY]["capabilities"]["maxMessagesPerRun"], 5)
        self.assertEqual(plans[LicensePlan.HALF_YEAR]["capabilities"]["maxMessagesPerRun"], 15)
        self.assertEqual(plans[LicensePlan.YEAR]["capabilities"]["maxMessagesPerRun"], 30)
        self.assertEqual(plans[LicensePlan.HALF_YEAR]["capabilities"]["autoMonitorIntervalMinutes"], 30)
        self.assertTrue(plans[LicensePlan.YEAR]["capabilities"]["priorityAi"])

    @patch("apps.gmail.tasks.sync_gmail_account.delay")
    def test_scan_limits_are_taken_from_license_plan(self, delay_mock):
        delay_mock.return_value.id = "scan-123"
        plaintext, _ = create_license_key(LicensePlan.HALF_YEAR)
        activate_license_for_user(self.user, validate_license_key(plaintext))
        account = EmailAccount.objects.create(
            user=self.user,
            email=self.user.email,
            access_token="access",
            refresh_token="refresh",
            is_active=True,
        )
        self._authenticate()

        response = self.client.post("/api/gmail/scan/", {"max_results": 999}, format="json")

        self.assertEqual(response.status_code, 202)
        delay_mock.assert_called_once()
        self.assertEqual(delay_mock.call_args.args, (account.id, 15, 7, False, True))


    @patch("apps.accounts.google_oauth._trigger_initial_scan")
    def test_activate_endpoint_queues_initial_scan_after_google_login(self, scan_mock):
        plaintext, _ = create_license_key(LicensePlan.FREE_1_DAY)
        EmailAccount.objects.create(
            user=self.user,
            email=self.user.email,
            access_token="access",
            refresh_token="refresh",
            is_active=True,
        )
        self._authenticate()

        response = self.client.post("/api/licenses/activate", {"key": plaintext}, format="json")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["license"]["status"], "active")
        scan_mock.assert_called_once()

    def test_same_email_expired_same_key_gets_buy_new_key_error(self):
        plaintext, _ = create_license_key(LicensePlan.FREE_1_DAY)
        activation = activate_license_for_user(self.user, validate_license_key(plaintext))
        activation.expires_at = timezone.now() - timedelta(seconds=1)
        activation.save(update_fields=["expires_at"])
        self._authenticate()

        response = self.client.post("/api/licenses/activate", {"key": plaintext}, format="json")

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data["code"], "expired_license")
        self.assertIn("Купіть новий ключ", response.data["detail"])

