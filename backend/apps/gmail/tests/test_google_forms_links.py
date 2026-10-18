from datetime import datetime, timezone
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from apps.reputation.url_service import (
    _enrich_google_form_url,
    _resolve_google_form_destination,
    scan_urls_in_text,
)


SHORT_URL = "https://forms.gle/FvU56RiEaXkfrpAd6"
FORM_URL = "https://docs.google.com/forms/d/e/example/viewform"


def reputation(url, *, verdict="Clean", score=0, malicious=False, provider="google_web_risk"):
    return SimpleNamespace(
        normalized_url=url,
        verdict=verdict,
        score=score,
        is_phishing=False,
        is_malicious=malicious,
        raw_stats={
            "provider": provider,
            "confidence": "google_clean" if verdict == "Clean" else "high",
            "malicious": 0 if verdict == "Clean" else 2,
            "harmless": 59 if verdict == "Malicious" else 0,
        },
        raw_results={},
        fetched_at=datetime.now(timezone.utc),
        error="",
    )


class GoogleFormsLinkTests(TestCase):
    @patch("apps.reputation.url_service.requests.head")
    def test_only_google_forms_https_redirect_is_followed(self, head_mock):
        head_mock.side_effect = [
            SimpleNamespace(status_code=302, headers={"Location": FORM_URL}),
            SimpleNamespace(status_code=200, headers={}),
        ]

        self.assertEqual(_resolve_google_form_destination(SHORT_URL), FORM_URL)
        self.assertEqual(head_mock.call_count, 2)

    @patch("apps.reputation.url_service.requests.head")
    def test_redirect_to_another_host_is_rejected_before_request(self, head_mock):
        head_mock.return_value = SimpleNamespace(
            status_code=302,
            headers={"Location": "https://attacker.example/login"},
        )

        self.assertIsNone(_resolve_google_form_destination(SHORT_URL))
        head_mock.assert_called_once()

    @patch("apps.reputation.url_service.requests.head")
    def test_http_downgrade_is_rejected(self, head_mock):
        head_mock.return_value = SimpleNamespace(
            status_code=302,
            headers={"Location": "http://docs.google.com/forms/d/e/example/viewform"},
        )

        self.assertIsNone(_resolve_google_form_destination(SHORT_URL))
        head_mock.assert_called_once()

    @patch("apps.reputation.url_service.get_url_reputation")
    @patch("apps.reputation.url_service._resolve_google_form_destination", return_value=FORM_URL)
    def test_conflicting_clean_form_is_review_not_confirmed_malware(self, resolver_mock, reputation_mock):
        reputation_mock.return_value = reputation(FORM_URL)
        short_link = {
            "url": SHORT_URL,
            "verdict": "Malicious",
            "score": 85,
            "confidence": "high",
            "is_malicious": True,
            "is_phishing": False,
            "stats": {"provider": "virustotal", "malicious": 2, "harmless": 59},
            "detections": {"Scanner A": {"category": "malicious", "result": "malicious"}},
        }

        result = _enrich_google_form_url(short_link)

        self.assertEqual(result["form_resolution"], "conflicting_reputation")
        self.assertEqual(result["score"], 45)
        self.assertEqual(result["verdict"], "Suspicious")
        self.assertFalse(result["is_malicious"])
        self.assertEqual(result["resolved_url"], FORM_URL)
        resolver_mock.assert_called_once()

    @patch("apps.reputation.url_service.get_url_reputation")
    @patch("apps.reputation.url_service._resolve_google_form_destination", return_value=FORM_URL)
    def test_one_phishing_hit_among_many_clean_results_is_still_review(self, resolver_mock, reputation_mock):
        reputation_mock.return_value = reputation(FORM_URL)
        short_link = {
            "url": SHORT_URL, "verdict": "Malicious", "score": 85,
            "is_malicious": True, "is_phishing": True,
            "stats": {"provider": "virustotal", "malicious": 2, "harmless": 59},
            "detections": {
                "Bkav": {"category": "malicious", "result": "malicious"},
                "SafeToOpen": {"category": "malicious", "result": "phishing"},
            },
        }

        result = _enrich_google_form_url(short_link)

        self.assertEqual(result["form_resolution"], "conflicting_reputation")
        self.assertEqual(result["score"], 45)
        self.assertFalse(result["is_phishing"])
        resolver_mock.assert_called_once()

    @patch("apps.reputation.url_service.get_url_reputation")
    @patch("apps.reputation.url_service._resolve_google_form_destination", return_value=FORM_URL)
    def test_malicious_destination_remains_malicious(self, resolver_mock, reputation_mock):
        reputation_mock.return_value = reputation(
            FORM_URL, verdict="Malicious", score=90, malicious=True,
        )
        short_link = {
            "url": SHORT_URL, "verdict": "Malicious", "score": 85,
            "is_malicious": True, "is_phishing": False,
            "stats": {"provider": "virustotal", "malicious": 2, "harmless": 59},
            "detections": {},
        }

        result = _enrich_google_form_url(short_link)

        self.assertEqual(result["form_resolution"], "destination_threat")
        self.assertEqual(result["score"], 90)
        self.assertTrue(result["is_malicious"])
        resolver_mock.assert_called_once()

    @patch("apps.reputation.url_service.get_url_reputation")
    @patch("apps.reputation.url_service._resolve_google_form_destination", return_value=FORM_URL)
    def test_scan_keeps_conflicting_form_as_suspicious(self, resolver_mock, reputation_mock):
        reputation_mock.side_effect = [
            reputation(SHORT_URL, verdict="Malicious", score=85, malicious=True, provider="virustotal"),
            reputation(FORM_URL),
        ]

        result = scan_urls_in_text(
            f"Conference application: {SHORT_URL}", vt_enrichment=True,
        )

        self.assertEqual(result["url_score"], 45)
        self.assertFalse(result["any_malicious"])
        self.assertEqual(result["scanned_urls"][0]["form_resolution"], "conflicting_reputation")
        self.assertIn("suspicious", result["url_summary"])

    @patch("apps.reputation.url_service.get_url_reputation")
    @patch("apps.reputation.url_service._resolve_google_form_destination", return_value=FORM_URL)
    def test_phishing_detection_on_short_link_is_not_downgraded(self, resolver_mock, reputation_mock):
        reputation_mock.return_value = reputation(FORM_URL)
        short_link = {
            "url": SHORT_URL, "verdict": "Malicious", "score": 85,
            "is_malicious": True, "is_phishing": True,
            "stats": {"provider": "virustotal", "malicious": 2, "harmless": 59},
            "detections": {
                "Scanner A": {"category": "phishing", "result": "phishing"},
                "Scanner B": {"category": "phishing", "result": "phishing"},
            },
        }

        result = _enrich_google_form_url(short_link)

        self.assertEqual(result["verdict"], "Malicious")
        self.assertTrue(result["is_malicious"])
        resolver_mock.assert_called_once()
