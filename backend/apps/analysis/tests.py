"""
Tests for apps/analysis.

Run with:
    python manage.py test apps.analysis
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from .gemini_service import (
    AIAnalysisResult,
    _compute_ai_score,
    compute_threat_score,
    score_to_risk_level,
)
from .models import EmailAnalysisResult

User = get_user_model()


# ---------------------------------------------------------------------------
# Scoring helpers
# ---------------------------------------------------------------------------

class TestScoringHelpers(TestCase):

    def test_compute_ai_score_all_zero(self):
        self.assertEqual(_compute_ai_score(0, 0, 0, 0, 0), 0)

    def test_compute_ai_score_all_hundred(self):
        self.assertEqual(_compute_ai_score(100, 100, 100, 100, 100), 100)

    def test_compute_ai_score_weights(self):
        # credential_theft dominates at 30%
        score = _compute_ai_score(
            urgency=0,
            fear=0,
            credential_theft=100,
            financial_fraud=0,
            authority_impersonation=0,
        )
        self.assertEqual(score, 30)

    def test_compute_threat_score_formula(self):
        self.assertEqual(compute_threat_score(90, 70), round(90 * 0.7 + 70 * 0.3))

    def test_compute_threat_score_caps_at_100(self):
        self.assertEqual(compute_threat_score(100, 100), 100)

    def test_score_to_risk_level_thresholds(self):
        self.assertEqual(score_to_risk_level(90), "Critical")
        self.assertEqual(score_to_risk_level(80), "Critical")
        self.assertEqual(score_to_risk_level(79), "High")
        self.assertEqual(score_to_risk_level(60), "High")
        self.assertEqual(score_to_risk_level(59), "Medium")
        self.assertEqual(score_to_risk_level(35), "Medium")
        self.assertEqual(score_to_risk_level(34), "Safe")
        self.assertEqual(score_to_risk_level(0), "Safe")


# ---------------------------------------------------------------------------
# Gemini service (mocked)
# ---------------------------------------------------------------------------

MOCK_GEMINI_RESPONSE = {
    "urgency": 92,
    "fear": 88,
    "credential_theft": 95,
    "financial_fraud": 65,
    "authority_impersonation": 78,
    "ai_summary": "Classic phishing attempt impersonating PayPal.",
}


class TestGeminiService(TestCase):

    @patch("apps.analysis.gemini_service.genai")
    def test_analyse_email_returns_correct_scores(self, mock_genai):
        import json

        mock_response = MagicMock()
        mock_response.text = json.dumps(MOCK_GEMINI_RESPONSE)
        mock_model = MagicMock()
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model
        mock_genai.GenerationConfig = MagicMock()

        from .gemini_service import analyse_email

        result = analyse_email(
            subject="URGENT: Your PayPal account",
            sender="security@paypa1-support.com",
            body="Your account is suspended.",
            fallback_on_error=False,
        )

        self.assertEqual(result.urgency, 92)
        self.assertEqual(result.fear, 88)
        self.assertEqual(result.credential_theft, 95)
        self.assertEqual(result.financial_fraud, 65)
        self.assertEqual(result.authority_impersonation, 78)
        self.assertIn("PayPal", result.ai_summary)
        self.assertGreater(result.ai_score, 0)

    @patch("apps.analysis.gemini_service.genai")
    def test_analyse_email_falls_back_on_error(self, mock_genai):
        mock_genai.GenerativeModel.side_effect = RuntimeError("API down")

        from .gemini_service import analyse_email

        result = analyse_email(
            subject="Test",
            sender="a@b.com",
            body="Hello",
            fallback_on_error=True,
        )
        self.assertEqual(result.ai_score, 0)
        self.assertIn("unavailable", result.ai_summary.lower())


# ---------------------------------------------------------------------------
# API views
# ---------------------------------------------------------------------------

class TestAnalysisViews(TestCase):

    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser", password="testpassword"
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def _make_cached_result(self, message_id: str = "msg_001") -> EmailAnalysisResult:
        return EmailAnalysisResult.objects.create(
            gmail_message_id=message_id,
            urgency=92,
            fear=88,
            credential_theft=95,
            financial_fraud=65,
            authority_impersonation=78,
            ai_summary="Classic phishing.",
            ai_score=90,
            domain_score=96,
            threat_score=92,
            risk_level="Critical",
        )

    # --- GET /api/analysis/<id>/ -----------------------------------------

    def test_detail_returns_cached_result(self):
        self._make_cached_result("msg_001")
        response = self.client.get("/api/analysis/msg_001/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["riskLevel"], "Critical")
        self.assertEqual(data["threatScore"], 92)
        self.assertEqual(data["credentialTheft"], 95)

    def test_detail_returns_404_for_unknown(self):
        response = self.client.get("/api/analysis/not_exists/")
        self.assertEqual(response.status_code, 404)

    # --- POST /api/analysis/analyse/ -------------------------------------

    @patch("apps.analysis.views.analyse_email")
    def test_analyse_creates_new_record(self, mock_analyse):
        mock_analyse.return_value = AIAnalysisResult(
            urgency=92,
            fear=88,
            credential_theft=95,
            financial_fraud=65,
            authority_impersonation=78,
            ai_summary="Phishing.",
            ai_score=90,
        )

        payload = {
            "gmail_message_id": "msg_new",
            "subject": "URGENT: Verify now",
            "sender": "evil@fake.com",
            "body": "Click here or lose access.",
            "domain_score": 96,
        }
        response = self.client.post("/api/analysis/analyse/", payload, format="json")
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data["riskLevel"], "Critical")
        self.assertIn("threatScore", data)
        self.assertTrue(
            EmailAnalysisResult.objects.filter(gmail_message_id="msg_new").exists()
        )

    def test_analyse_returns_cached_without_gemini_call(self):
        self._make_cached_result("msg_cached")
        with patch("apps.analysis.views.analyse_email") as mock_analyse:
            payload = {
                "gmail_message_id": "msg_cached",
                "subject": "Whatever",
                "sender": "x@y.com",
                "body": "body",
                "domain_score": 50,
            }
            response = self.client.post("/api/analysis/analyse/", payload, format="json")
            self.assertEqual(response.status_code, 200)
            mock_analyse.assert_not_called()

    @patch("apps.analysis.views.analyse_email")
    def test_analyse_force_bypasses_cache(self, mock_analyse):
        self._make_cached_result("msg_force")
        mock_analyse.return_value = AIAnalysisResult(
            urgency=10, fear=5, credential_theft=8,
            financial_fraud=3, authority_impersonation=2,
            ai_summary="Legit email.", ai_score=5,
        )
        payload = {
            "gmail_message_id": "msg_force",
            "subject": "Q2 Meeting",
            "sender": "hr@company.com",
            "body": "Let's meet.",
            "domain_score": 2,
        }
        response = self.client.post(
            "/api/analysis/analyse/?force=true", payload, format="json"
        )
        self.assertEqual(response.status_code, 200)
        mock_analyse.assert_called_once()

    # --- POST /api/analysis/batch/ ---------------------------------------

    def test_batch_returns_matching_results(self):
        self._make_cached_result("msg_a")
        self._make_cached_result("msg_b")
        response = self.client.post(
            "/api/analysis/batch/",
            {"ids": ["msg_a", "msg_b", "msg_missing"]},
            format="json",
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("msg_a", data)
        self.assertIn("msg_b", data)
        self.assertNotIn("msg_missing", data)

    def test_batch_invalid_body(self):
        response = self.client.post(
            "/api/analysis/batch/",
            {"ids": "not-a-list"},
            format="json",
        )
        self.assertEqual(response.status_code, 400)

    # --- Auth guard -------------------------------------------------------

    def test_unauthenticated_requests_are_rejected(self):
        anon = APIClient()
        self.assertEqual(anon.get("/api/analysis/msg_001/").status_code, 401)
        self.assertEqual(
            anon.post("/api/analysis/analyse/", {}, format="json").status_code, 401
        )
