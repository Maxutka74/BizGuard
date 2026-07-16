from datetime import timedelta
from types import SimpleNamespace
import os
import time
import requests

from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from django.core.cache import cache
from unittest.mock import patch
from rest_framework.test import APIClient

from apps.accounts.google_oauth import get_or_create_user_from_google
from apps.accounts.models import User
from apps.gmail.models import GMAIL_MODIFY_SCOPE, EmailAccount, EmailMessage, TrustedSenderRule
from apps.gmail.services.gmail_fetcher import clean_email_text, fetch_inbox_messages
from apps.gmail.services.attachment_analysis import _qr_findings
from apps.gmail.services.ai_providers import (
    AIAnalysisTimedOut,
    AIProviderUnavailable,
    FINAL_VERDICTS_BY_RISK,
    analyze_email_with_providers,
    _clamp_false_fear_from_disclaimer,
    _clamp_newsletter_market_false_positive,
    _clamp_contextual_false_positive,
    EMAIL_CONTEXT_RECEIPT,
    EMAIL_CONTEXT_MEETING,
    EMAIL_CONTEXT_NEWSLETTER,
    EMAIL_CONTEXT_COURSE,
    EMAIL_CONTEXT_SURVEY,
    EMAIL_CONTEXT_SERVICE_SETUP,
    email_context_for_analysis,
    sanitize_security_recommendations_for_risk,
    _sanitize_security_recommendations,
    is_transactional_verification_email,
    normalize_summary,
    normalize_verdict,
)
from apps.gmail.services.security_checks import analyze_security_signals
from apps.gmail.services.sync import (
    AIPendingReputation,
    AIAnalysisTimedOut as QueueAnalysisTimedOut,
    _deep_scan_limits,
    _fast_safe_analysis,
    _final_verdict_for_risk,
    _needs_deep_analysis_before_vt,
    _process_message,
    _run_detailed_evidence_scan,
    analyze_saved_email_message,
)
from apps.gmail.tasks import analyze_pending_email, process_ai_queue, sync_due_accounts
from apps.reputation.models import UrlReputation
from apps.reputation import url_service
from apps.reputation.url_service import _score_url, extract_meaningful_urls, get_url_reputation, scan_urls_in_text
from apps.licenses.models import LicensePlan
from apps.licenses.services import activate_license_for_user, create_license_key, validate_license_key
from apps.threats.scoring import compute_threat_result


class EmailBodyCleanupTests(SimpleTestCase):
    def test_clean_email_text_removes_css_dump(self):
        raw = """
        @import url("https://use.typekit.net/vyq6kag.css");
        td, h1, h2 { font-family: Arial; color: #fff; line-height: 1.4; }
        @media only screen and (max-width: 480px) { .new-badge { display: none; } }
        Weekly Digest Hi LeetCoder! Sometimes the best career moves start with taking a risk.
        Check out this post for the full experience.
        """

        cleaned = clean_email_text(raw)

        self.assertNotIn("@import", cleaned)
        self.assertNotIn("@media", cleaned)
        self.assertNotIn("font-family", cleaned)
        self.assertIn("Weekly Digest", cleaned)
        self.assertIn("Hi LeetCoder", cleaned)


class GmailFetcherBackfillTests(SimpleTestCase):
    @patch("apps.gmail.services.gmail_fetcher._normalize", side_effect=lambda raw: {"gmail_id": raw["id"]})
    @patch("apps.gmail.services.gmail_fetcher._get_message", side_effect=lambda _service, msg_id: {"id": msg_id, "payload": {}})
    @patch("apps.gmail.services.gmail_fetcher._list_message_ids")
    def test_manual_scan_backfills_to_plan_limit(self, list_mock, get_mock, normalize_mock):
        list_mock.side_effect = [["a", "b"], ["a", "b", "c", "d", "e"]]

        result = fetch_inbox_messages(
            object(),
            max_results=5,
            newer_than_days=1,
            backfill_to_limit=True,
        )

        self.assertEqual([item["gmail_id"] for item in result], ["a", "b", "c", "d", "e"])
        self.assertEqual(list_mock.call_args_list[0].kwargs["newer_than_days"], 1)
        self.assertIsNone(list_mock.call_args_list[1].kwargs["newer_than_days"])
        self.assertEqual(get_mock.call_count, 5)
        self.assertEqual(normalize_mock.call_count, 5)

    @patch("apps.gmail.services.gmail_fetcher._normalize", side_effect=lambda raw: {"gmail_id": raw["id"]})
    @patch("apps.gmail.services.gmail_fetcher._get_message", side_effect=lambda _service, msg_id: {"id": msg_id, "payload": {}})
    @patch("apps.gmail.services.gmail_fetcher._list_message_ids", return_value=["a", "b"])
    def test_periodic_scan_keeps_fresh_window_without_backfill(self, list_mock, get_mock, normalize_mock):
        result = fetch_inbox_messages(
            object(),
            max_results=5,
            newer_than_days=1,
            backfill_to_limit=False,
        )

        self.assertEqual([item["gmail_id"] for item in result], ["a", "b"])
        list_mock.assert_called_once()
        self.assertEqual(list_mock.call_args.kwargs["newer_than_days"], 1)
        self.assertEqual(get_mock.call_count, 2)
        self.assertEqual(normalize_mock.call_count, 2)
    @patch("apps.gmail.services.gmail_fetcher._normalize", side_effect=lambda raw: {"gmail_id": raw["id"]})
    @patch("apps.gmail.services.gmail_fetcher._get_message", side_effect=lambda _service, msg_id: {"id": msg_id, "payload": {}})
    @patch("apps.gmail.services.gmail_fetcher._list_message_ids", return_value=["new-1", "known-1", "old-1"])
    def test_incremental_scan_stops_at_first_known_message(self, list_mock, get_mock, normalize_mock):
        result = fetch_inbox_messages(
            object(),
            max_results=5,
            newer_than_days=7,
            backfill_to_limit=True,
            known_message_ids={"known-1"},
            stop_at_known=True,
        )

        self.assertEqual([item["gmail_id"] for item in result], ["new-1"])
        list_mock.assert_called_once()
        self.assertEqual(get_mock.call_count, 1)
        self.assertEqual(normalize_mock.call_count, 1)


class ReputationScoringTests(SimpleTestCase):
    def test_single_phishing_hit_is_not_malicious(self):
        score, verdict, is_phishing, is_malicious, confidence = _score_url(
            "http://goo.gl/XLxpy1",
            {"malicious": 0, "suspicious": 0, "harmless": 20, "undetected": 75},
            {"Engine": {"category": "phishing", "result": "phishing"}},
        )

        self.assertEqual(score, 45)
        self.assertEqual(verdict, UrlReputation.VERDICT_SUSPICIOUS)
        self.assertTrue(is_phishing)
        self.assertFalse(is_malicious)
        self.assertEqual(confidence, "medium")

    def test_shortener_without_detections_is_low_warning(self):
        score, verdict, is_phishing, is_malicious, confidence = _score_url(
            "http://goo.gl/XLxpy1",
            {"malicious": 0, "suspicious": 0, "harmless": 20, "undetected": 75},
            {},
        )

        self.assertEqual(score, 15)
        self.assertEqual(verdict, UrlReputation.VERDICT_SUSPICIOUS)
        self.assertFalse(is_phishing)
        self.assertFalse(is_malicious)
        self.assertEqual(confidence, "unknown_redirect")

    def test_suspicious_mode_keeps_tracking_urls(self):
        text = "https://example.com/login https://track.customer.io/click/abc https://example.com/unsubscribe"

        safe_urls, skipped = extract_meaningful_urls(text, max_urls=3, include_tracking=False)
        suspicious_urls, suspicious_skipped = extract_meaningful_urls(text, max_urls=None, include_tracking=True)

        self.assertEqual(safe_urls, ["https://example.com/login"])
        self.assertEqual(skipped, 2)
        self.assertEqual(len(suspicious_urls), 3)
        self.assertEqual(suspicious_skipped, 0)

    def test_deep_url_scan_checks_all_links_without_first_three_summary(self):
        text = (
            "https://example.com/login "
            "https://track.customer.io/click/abc "
            "https://example.com/unsubscribe "
            "https://cdn.example.com/file "
            "https://example.net/profile"
        )

        def fake_reputation(url, use_vt_enrichment=False):
            return SimpleNamespace(
                normalized_url=url,
                verdict=UrlReputation.VERDICT_CLEAN,
                score=0,
                raw_stats={"confidence": "none"},
                is_phishing=False,
                is_malicious=False,
                raw_results={},
                fetched_at=timezone.now(),
                error="",
            )

        with patch("apps.reputation.url_service.get_url_reputation", side_effect=fake_reputation):
            result = scan_urls_in_text(text, max_urls=None, include_tracking=True, vt_enrichment=True)

        self.assertEqual(len(result["scanned_urls"]), 5)
        self.assertNotIn("Checked first", result["url_summary"])

    @override_settings(VIRUSTOTAL_PENDING_RECHECK_SECONDS=60)
    def test_pending_url_reputation_rechecks_quickly(self):
        rep = UrlReputation(
            normalized_url="https://example.com/login",
            verdict=UrlReputation.VERDICT_PENDING,
            fetched_at=timezone.now() - timedelta(seconds=61),
        )

        self.assertTrue(rep.is_stale())


class SecuritySignalTests(SimpleTestCase):
    def test_same_root_domain_links_are_not_mismatch(self):
        result = analyze_security_signals(
            {
                "domain": "smailer1.binance.com",
                "body": "Новини акаунта: https://www.binance.com/activity/kyc",
                "attachments": [],
            }
        )

        self.assertNotIn("link_domain_mismatch", result["signals"]["linkFindings"])
        self.assertEqual(result["signals"]["externalLinkDomains"], [])

    def test_safe_content_with_same_domain_link_skips_deep_vt(self):
        msg = {
            "subject": "Product update",
            "body": "Read the changelog: https://docs.example.com/changelog",
            "attachments": [],
        }
        security_result = analyze_security_signals({"domain": "example.com", **msg})
        domain_result = {"domainScore": 10, "domainReputation": "Trusted"}
        attachment_scan = {"attachment_score": 0}

        self.assertFalse(_needs_deep_analysis_before_vt(msg, security_result, domain_result, attachment_scan))

    def test_suspicious_login_content_triggers_deep_vt(self):
        msg = {
            "subject": "KYC required today",
            "body": "Verify your wallet now: https://secure-account-dashboard.com/login",
            "attachments": [],
        }
        security_result = analyze_security_signals({"domain": "example.com", **msg})
        domain_result = {"domainScore": 10, "domainReputation": "Trusted"}
        attachment_scan = {"attachment_score": 0}

        self.assertTrue(_needs_deep_analysis_before_vt(msg, security_result, domain_result, attachment_scan))


class ThreatScoringTests(SimpleTestCase):
    def test_clean_newsletter_is_not_critical(self):
        result = compute_threat_result(
            ai_score=20,
            domain_score=10,
            url_score=15,
            credential_theft=0,
            urgency=0,
            authority_impersonation=0,
            any_phishing_url=False,
            any_malicious_url=False,
        )

        self.assertIn(result.risk_level, {"Safe", "Medium"})
        self.assertLess(result.threat_score, 61)

    def test_bonus_login_phishing_intent_reaches_high(self):
        result = compute_threat_result(
            ai_score=58,
            domain_score=10,
            url_score=0,
            credential_theft=75,
            urgency=70,
            authority_impersonation=55,
            any_phishing_url=False,
            any_malicious_url=False,
        )

        self.assertEqual(result.risk_level, "High")

    def test_severe_credential_extortion_reaches_critical_without_url_hit(self):
        result = compute_threat_result(
            ai_score=80,
            domain_score=10,
            url_score=0,
            credential_theft=95,
            urgency=85,
            fear=80,
            financial_fraud=70,
            authority_impersonation=65,
            any_phishing_url=False,
            any_malicious_url=False,
        )

        self.assertEqual(result.risk_level, "Critical")
        self.assertGreaterEqual(result.threat_score, 81)
    def test_weak_vt_hit_does_not_force_critical(self):
        result = compute_threat_result(
            ai_score=20,
            domain_score=10,
            url_score=45,
            credential_theft=10,
            urgency=5,
            authority_impersonation=5,
            any_phishing_url=True,
            any_malicious_url=False,
        )

        self.assertEqual(result.risk_level, "Medium")
        self.assertLess(result.threat_score, 81)

    def test_final_verdict_follows_final_risk_level(self):
        result = compute_threat_result(
            ai_score=20,
            domain_score=10,
            url_score=45,
            credential_theft=10,
            urgency=5,
            authority_impersonation=5,
            any_phishing_url=True,
            any_malicious_url=False,
        )

        self.assertGreaterEqual(result.threat_score, 31)
        self.assertEqual(_final_verdict_for_risk(result.risk_level), FINAL_VERDICTS_BY_RISK[result.risk_level])

    def test_final_verdicts_are_deterministic_ukrainian_security_text(self):
        for risk_level, expected in FINAL_VERDICTS_BY_RISK.items():
            self.assertEqual(_final_verdict_for_risk(risk_level), expected)

    def test_transactional_otp_stays_safe_or_medium(self):
        result = compute_threat_result(
            ai_score=14,
            domain_score=35,
            url_score=0,
            credential_theft=20,
            urgency=25,
            authority_impersonation=20,
            any_phishing_url=False,
            any_malicious_url=False,
        )

        self.assertIn(result.risk_level, {"Safe", "Medium"})
        self.assertLess(result.threat_score, 61)


class OtpAndLanguageGuardTests(SimpleTestCase):
    def test_investment_disclaimer_does_not_become_fear_tactic(self):
        result = _clamp_false_fear_from_disclaimer(
            {"fear": 100},
            "Risk warning: digital assets can be volatile. You may lose your investment.",
        )

        self.assertLessEqual(result["fear"], 15)

    def test_market_newsletter_ai_hallucination_is_clamped(self):
        result = _clamp_newsletter_market_false_positive(
            {
                "urgency": 100,
                "fear": 20,
                "credential_theft": 100,
                "financial_fraud": 0,
                "authority_impersonation": 90,
            },
            (
                "How long do Bitcoin bear markets last? "
                "Bitcoin fell below $60,000. Read the full research publication. "
                "Download our app. You may unsubscribe from this newsletter."
            ),
            {
                "url_score": 0,
                "any_phishing": False,
                "any_malicious": False,
                "scanned_urls": [
                    {"url": "https://www.coingecko.com/research/publications/how-long-do-bitcoin-bear-markets-last", "score": 0},
                    {"url": "https://newsletter.coingecko.com/email_marketing_click.html", "score": 0},
                ],
            },
        )

        self.assertLessEqual(result["credential_theft"], 20)
        self.assertLessEqual(result["authority_impersonation"], 25)
        self.assertLessEqual(result["urgency"], 25)
        self.assertLessEqual(result["fear"], 10)

    def test_course_promo_is_not_otp_or_credential_theft(self):
        body = (
            'ITVDN Angular 21 course. Take your course access code and register for a free lesson. '
            'This is a marketing newsletter for a programming course, not an account verification message.'
        )
        context = email_context_for_analysis('Angular 21 course access for 15 days', body)
        self.assertEqual(context, EMAIL_CONTEXT_COURSE)
        self.assertFalse(is_transactional_verification_email(
            subject='Angular 21 course access for 15 days',
            sender='info@itvdn.com',
            domain='itvdn.com',
            body=body,
            url_scan_agg={'scanned_urls': [], 'scanned_attachments': [], 'url_score': 0},
        ))

        result = _clamp_contextual_false_positive(
            {
                'urgency': 100,
                'fear': 40,
                'credential_theft': 100,
                'financial_fraud': 20,
                'authority_impersonation': 90,
            },
            body,
            {'url_score': 0, 'any_phishing': False, 'any_malicious': False, 'scanned_urls': [], 'scanned_attachments': []},
        )
        self.assertLessEqual(result['credential_theft'], 10)
        self.assertLessEqual(result['urgency'], 20)
        self.assertLessEqual(result['authority_impersonation'], 20)
        self.assertLessEqual(result['fear'], 10)

        recommendations = sanitize_security_recommendations_for_risk(
            ['If you did not request this code, ignore this message.'],
            'Medium',
            {'scanned_urls': [], 'scanned_attachments': [], 'url_score': 0},
            context,
        )
        joined = ' '.join(recommendations).lower()
        self.assertNotIn('sms', joined)
        self.assertNotIn('2fa', joined)
        self.assertNotIn('password', joined)
        self.assertNotIn('\u043a\u043e\u0434', joined)

    def test_survey_tracking_urls_do_not_force_high_or_password_recommendations(self):
        context = email_context_for_analysis(
            'We have a quick question for you',
            'Tell us what you would like to see when exploring crypto projects. Take the survey via newsletter redirect links.',
        )
        self.assertEqual(context, EMAIL_CONTEXT_SURVEY)
        result = compute_threat_result(
            ai_score=15,
            domain_score=10,
            url_score=45,
            credential_theft=0,
            urgency=10,
            authority_impersonation=10,
            any_phishing_url=False,
            any_malicious_url=False,
            email_context=context,
            explicit_security_intent=False,
        )
        self.assertLessEqual(result.threat_score, 30)
        self.assertEqual(result.risk_level, 'Safe')

        recommendations = sanitize_security_recommendations_for_risk(
            ['Do not enter password, SMS/2FA code, or payment data after following this email.'],
            result.risk_level,
            {
                'scanned_urls': [{'url': 'https://newsletter.coingecko.com/email_marketing_click.html', 'score': 45, 'confidence': 'low'}],
                'scanned_attachments': [],
                'url_score': 45,
            },
            context,
        )
        joined = ' '.join(recommendations).lower()
        self.assertNotIn('sms', joined)
        self.assertNotIn('2fa', joined)
        self.assertNotIn('password', joined)
        self.assertIn('\u0434\u043e\u043c\u0435\u043d', joined)


    def test_stripe_setup_guide_gets_contextual_recommendations(self):
        body = (
            "Start building on Stripe. Welcome to Stripe. Visit the Dashboard and create your custom setup guide. "
            "You can test in a sandbox, configure your business profile, payment links and integration. "
            "Unsubscribe or manage email preferences. https://info-link.stripe.com/setup-guide"
        )
        url_context = {
            "scanned_urls": [
                {"url": "https://info-link.stripe.com/setup-guide", "score": 0, "confidence": "low"}
            ],
            "url_score": 0,
            "scanned_attachments": [],
        }

        context = email_context_for_analysis("Your Stripe setup guide", body, url_context)
        self.assertEqual(context, EMAIL_CONTEXT_SERVICE_SETUP)

        result = compute_threat_result(
            ai_score=22,
            domain_score=10,
            url_score=45,
            attachment_score=0,
            email_context=context,
            explicit_security_intent=False,
        )
        self.assertLessEqual(result.threat_score, 30)
        self.assertIn(result.risk_level, {"Safe", "Medium"})

        recommendations = sanitize_security_recommendations_for_risk(
            ["Не вводьте SMS/2FA-код або пароль після переходу з цього листа."],
            result.risk_level,
            url_context,
            context,
        )
        joined = " ".join(recommendations).lower()
        self.assertNotIn("sms", joined)
        self.assertNotIn("2fa", joined)
        self.assertNotIn("парол", joined)
        self.assertIn("dashboard", joined)
        self.assertIn("домен", joined)

    def test_receipt_is_not_otp_and_gets_receipt_recommendations(self):
        body = (
            "ФОП САВОНОВ ПАВЛО ВОЛОДИМИРОВИЧ МАГАЗИН Race Expert "
            "1 x 80.99 Енергетичний напій 330 мл 80.99 "
            "Безготівкова 324.00 ГРН Інтернет банкінг Сума 324.00 ГРН "
            "Чек № Vy3b2MGbf5o 29.06.2026 об 22-28-25 ОНЛАЙН ФН ПРРО 4000412562 ФІСКАЛЬНИЙ ЧЕК"
        )

        self.assertFalse(
            is_transactional_verification_email(
                subject="Фіскальний чек",
                sender="receipt@race-expert.example",
                domain="race-expert.example",
                body=body,
                url_scan_agg={"scanned_urls": [], "scanned_attachments": [], "url_score": 0},
            )
        )
        context = email_context_for_analysis("Фіскальний чек", body, {"scanned_urls": [], "scanned_attachments": []})
        self.assertEqual(context, EMAIL_CONTEXT_RECEIPT)

        recommendations = sanitize_security_recommendations_for_risk(
            ["Не передавайте код підтвердження іншим людям."],
            "Safe",
            {"scanned_urls": [], "scanned_attachments": []},
            context,
        )

        joined = " ".join(recommendations).lower()
        self.assertIn("сума", joined)
        self.assertIn("продав", joined)
        self.assertNotIn("код підтвердження", joined)
        self.assertNotIn("sms", joined)
        self.assertNotIn("парол", joined)

    def test_meeting_invite_date_is_not_phishing_urgency(self):
        body = "Запрошення на зустріч команди 10.07.2026 о 15:00. Додайте подію в календар, якщо плануєте участь."
        result = _clamp_contextual_false_positive(
            {
                "urgency": 85,
                "fear": 40,
                "credential_theft": 70,
                "financial_fraud": 0,
                "authority_impersonation": 60,
            },
            body,
            {"scanned_urls": [], "scanned_attachments": [], "url_score": 0},
        )

        self.assertEqual(email_context_for_analysis("Зустріч", body), EMAIL_CONTEXT_MEETING)
        self.assertLessEqual(result["urgency"], 15)
        self.assertLessEqual(result["credential_theft"], 15)
        self.assertLessEqual(result["authority_impersonation"], 20)
    def test_simple_verification_code_email_is_transactional(self):
        self.assertTrue(
            is_transactional_verification_email(
                subject="Verify Email",
                sender="support@monvirex.online",
                domain="monvirex.online",
                body=(
                    "Ласкаво просимо до Monvirex. Щоб завершити створення акаунта, "
                    "підтвердіть свою електронну адресу, використовуючи код нижче: 373624. "
                    "Цей код дійсний протягом 15 хвилин."
                ),
                url_scan_agg={"scanned_urls": [], "scanned_attachments": [], "url_score": 0},
            )
        )

    def test_verification_email_with_external_login_is_not_transactional_safe(self):
        self.assertFalse(
            is_transactional_verification_email(
                subject="Verify Email",
                sender="support@monvirex.online",
                domain="monvirex.online",
                body="Ваш код 373624. Введіть код за посиланням: https://secure-account-dashboard.com/login",
                url_scan_agg={
                    "scanned_urls": [{"url": "https://secure-account-dashboard.com/login", "score": 0}],
                    "scanned_attachments": [],
                    "url_score": 0,
                },
            )
        )

    def test_verdict_and_recommendations_are_ukrainian_security_text(self):
        self.assertEqual(normalize_verdict("Suspicious", 55), "Підозрілий лист")
        self.assertEqual(
            normalize_summary("Suspicious phishing attempt with urgency.", 70),
            "Лист має високий ризик фішингу або шахрайства. Не відкривайте посилання чи вкладення без окремої перевірки.",
        )

        recommendations = _sanitize_security_recommendations(
            ["Click the link", "Update your account", "Перейдите до профілю", "Дійте звичайно.", "Ваше замовлення отримало новий статус доставки.", "Скористайтеся Telegram-ботом."],
            70,
            {"scanned_urls": [{"url": "https://example.com"}]},
        )

        self.assertGreaterEqual(len(recommendations), 2)
        self.assertTrue(all("http" not in item.lower() for item in recommendations))
        self.assertTrue(all("перейдите" not in item.lower() for item in recommendations))
        self.assertTrue(all("дійте звичайно" not in item.lower() for item in recommendations))
        self.assertTrue(all("замовлення" not in item.lower() for item in recommendations))
        self.assertTrue(all("telegram" not in item.lower() for item in recommendations))


    def test_recommendations_are_deduped_and_evidence_filled(self):
        recommendations = _sanitize_security_recommendations(
            [
                "Будьте уважні до фішингу.",
                "Не вводьте пароль або SMS-код після переходу з цього листа.",
                "Не вводьте пароль або SMS-код після переходу з цього листа.",
                "Перевірте домен відправника перед будь-якою дією.",
            ],
            85,
            {
                "scanned_urls": [{"url": "https://secure-account-dashboard.com/login", "score": 0}],
                "scanned_attachments": [],
                "url_summary": "login page asks for password and SMS code",
            },
        )

        joined = " ".join(recommendations).lower()
        self.assertGreaterEqual(len(recommendations), 3)
        self.assertEqual(len(recommendations), len(set(recommendations)))
        self.assertNotIn("будьте уважні", joined)
        self.assertIn("пароль", joined)
        self.assertIn("sms", joined)
        self.assertIn("посилан", joined)

    def test_bad_recommendations_are_replaced_with_specific_security_actions(self):
        recommendations = _sanitize_security_recommendations(
            [
                "Натисніть посилання для входу.",
                "Ваше замовлення отримало новий статус доставки.",
                "Перейдите в аккаунт.",
            ],
            85,
            {
                "scanned_urls": [{"url": "https://secure-account-dashboard.com/login", "score": 0}],
                "scanned_attachments": [{"filename": "invoice.pdf", "verdict": "Pending"}],
                "url_summary": "login and payment request",
                "attachment_summary": "pending invoice attachment",
            },
        )

        joined = " ".join(recommendations).lower()
        self.assertGreaterEqual(len(recommendations), 3)
        self.assertNotIn("натисніть", joined)
        self.assertNotIn("замовлення", joined)
        self.assertNotIn("перейдите", joined)
        self.assertIn("посилан", joined)
        self.assertIn("вкладен", joined)
        self.assertIn("пароль", joined)
    def test_unsafe_specific_link_recommendation_is_replaced(self):
        recommendations = _sanitize_security_recommendations(
            [
                "Переглянути повідомлення на вказаному посиланні.",
                "Відкрийте посилання для перевірки.",
            ],
            70,
            {"scanned_urls": [{"url": "https://example.com"}]},
        )

        joined = " ".join(recommendations).lower()
        self.assertGreaterEqual(len(recommendations), 2)
        self.assertNotIn("вказан", joined)
        self.assertNotIn("відкрийте посилання", joined)


class FastPathTests(SimpleTestCase):
    def test_trusted_newsletter_can_skip_llama(self):
        msg = {
            "body": "Weekly Digest: practice graph problems.",
            "attachments": [],
        }
        security_result = {
            "headerScore": 0,
            "linkScore": 30,
            "signals": {"linkFindings": ["link_domain_mismatch"]},
        }
        domain_result = {"domainScore": 5, "domainReputation": "Trusted"}
        attachment_scan = {"attachment_score": 0}
        url_scan = {
            "url_score": 0,
            "any_phishing": False,
            "any_malicious": False,
            "scanned_urls": [{"url": "https://leetcode.com/problems/two-sum", "score": 0}],
        }

        result = _fast_safe_analysis(
            msg=msg,
            subject="LeetCode Weekly Digest",
            sender_domain="leetcode.com",
            security_result=security_result,
            domain_result=domain_result,
            attachment_scan_agg=attachment_scan,
            url_scan_agg=url_scan,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["_analysis_source"], "Fast security rules")
        self.assertEqual(result["riskLevel"], "Safe")

    def test_trusted_same_domain_links_can_skip_llama(self):
        msg = {
            "body": "Product update: https://docs.example.com/changelog",
            "attachments": [],
        }
        security_result = {
            "headerScore": 0,
            "linkScore": 0,
            "signals": {"linkFindings": []},
        }
        domain_result = {"domainScore": 0, "domainReputation": "Trusted"}
        attachment_scan = {"attachment_score": 0}
        url_scan = {
            "url_score": 0,
            "any_phishing": False,
            "any_malicious": False,
            "scanned_urls": [{"url": "https://docs.example.com/changelog", "score": 0}],
        }

        result = _fast_safe_analysis(
            msg=msg,
            subject="Product update",
            sender_domain="example.com",
            security_result=security_result,
            domain_result=domain_result,
            attachment_scan_agg=attachment_scan,
            url_scan_agg=url_scan,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["riskLevel"], "Safe")

    def test_coingecko_market_newsletter_can_skip_llama(self):
        msg = {
            "body": (
                "Bitcoin fell below $60,000 yesterday and is now down 30% year-to-date. "
                "Read the full breakdown here https://www.coingecko.com/research/publications/how-long-do-bitcoin-bear-markets-last "
                "View Bitcoin Chart https://newsletter.coingecko.com/email_marketing_click.html?x=a62e "
                "Download our app https://coingecko.app.link/6M3XVxIckLb "
                "https://bit.ly/coingecko-app-apk Visit our Twitter page https://us-as.gr-cdn.com/images/common/templates/messages/v2/social/twitter2.png "
                "You may unsubscribe https://newsletter.coingecko.com/unsubscribe.html?x=a62e"
            ),
            "attachments": [],
        }
        security_result = {
            "headerScore": 0,
            "linkScore": 30,
            "signals": {"linkFindings": ["link_domain_mismatch", "shortened_url"]},
        }
        domain_result = {"domainScore": 5, "domainReputation": "Trusted"}
        attachment_scan = {"attachment_score": 0}
        url_scan = {
            "url_score": 0,
            "any_phishing": False,
            "any_malicious": False,
            "scanned_urls": [
                {"url": "https://www.coingecko.com/research/publications/how-long-do-bitcoin-bear-markets-last", "score": 0},
                {"url": "https://newsletter.coingecko.com/email_marketing_click.html?x=a62e", "score": 0},
                {"url": "https://coingecko.app.link/6M3XVxIckLb", "score": 0},
                {"url": "https://bit.ly/coingecko-app-apk", "score": 0},
                {"url": "https://us-as.gr-cdn.com/images/common/templates/messages/v2/social/twitter2.png", "score": 0},
            ],
        }

        result = _fast_safe_analysis(
            msg=msg,
            subject="How long do Bitcoin bear markets last?",
            sender_domain="newsletter.coingecko.com",
            security_result=security_result,
            domain_result=domain_result,
            attachment_scan_agg=attachment_scan,
            url_scan_agg=url_scan,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["riskLevel"], "Safe")
        self.assertEqual(result["urgency"], 0)
        self.assertEqual(result["credential_theft"], 0)
        self.assertEqual(result["authority_impersonation"], 0)
    def test_trusted_domain_with_external_link_does_not_skip_llama(self):
        msg = {
            "body": "Product update: https://secure-account-dashboard.com/login",
            "attachments": [],
        }
        security_result = {
            "headerScore": 0,
            "linkScore": 0,
            "signals": {"linkFindings": []},
        }
        domain_result = {"domainScore": 0, "domainReputation": "Trusted"}
        attachment_scan = {"attachment_score": 0}
        url_scan = {
            "url_score": 0,
            "any_phishing": False,
            "any_malicious": False,
            "scanned_urls": [{"url": "https://secure-account-dashboard.com/login", "score": 0}],
        }

        result = _fast_safe_analysis(
            msg=msg,
            subject="Product update",
            sender_domain="example.com",
            security_result=security_result,
            domain_result=domain_result,
            attachment_scan_agg=attachment_scan,
            url_scan_agg=url_scan,
        )

        self.assertIsNone(result)

    def test_masked_login_bonus_forces_deep_analysis(self):
        msg = {
            "subject": "Ваш бонус діє до кінця дня",
            "body": "Оновіть статус профілю: https://secure-account-dashboard.com/login",
            "attachments": [],
        }
        security_result = {
            "headerScore": 0,
            "linkScore": 0,
            "signals": {"linkFindings": []},
        }
        domain_result = {"domainScore": 5, "domainReputation": "Trusted"}
        attachment_scan = {"attachment_score": 0}

        self.assertTrue(_needs_deep_analysis_before_vt(msg, security_result, domain_result, attachment_scan))


class LightweightAnalysisPipelineTests(TestCase):
    def setUp(self):
        self.user = User.objects.create(email="pipeline@example.com")
        self.account = EmailAccount.objects.create(
            user=self.user,
            email=self.user.email,
            access_token="access",
            refresh_token="refresh",
            is_active=True,
        )

    def _message(self, **overrides):
        defaults = {
            "account": self.account,
            "gmail_id": "msg-1",
            "subject": "Product update",
            "sender": "news@example.com",
            "senderName": "Example",
            "domain": "example.com",
            "date": timezone.now(),
            "body": "Read the changelog at https://docs.example.com/changelog",
            "domainAge": "Known",
            "domainReputation": "Trusted",
            "domainScore": 10,
            "headerScore": 0,
            "linkScore": 0,
            "attachmentScore": 0,
            "analysis_status": "pending_ai",
        }
        defaults.update(overrides)
        return EmailMessage.objects.create(**defaults)

    def _activate_plan(self, plan: str):
        plaintext, _ = create_license_key(plan)
        return activate_license_for_user(self.user, validate_license_key(plaintext))

    def _critical_ai_result(self):
        return {
            "urgency": 90,
            "fear": 60,
            "credential_theft": 95,
            "financial_fraud": 20,
            "authority_impersonation": 85,
            "ai_score": 95,
            "ai_summary": "Critical credential theft attempt.",
            "verdict": "Suspicious",
            "recommendations": ["Do not click."],
            "_analysis_status": "done",
        }

    def _critical_message(self, **overrides):
        defaults = {
            "gmail_id": "critical-msg",
            "subject": "Verify your account now",
            "body": "Your account will be suspended. Verify now.",
            "urlScore": 90,
            "hasMaliciousUrl": True,
            "scannedUrls": [
                {
                    "url": "https://bad.example/login",
                    "verdict": "Malicious",
                    "score": 90,
                    "confidence": "high",
                    "is_malicious": True,
                    "is_phishing": True,
                }
            ],
        }
        defaults.update(overrides)
        return self._message(**defaults)

    @patch("apps.gmail.services.sync.analyze_domain")
    def test_done_message_same_hash_is_not_reanalyzed_by_normal_scan(self, domain_mock):
        existing = self._message(
            gmail_id="already-done",
            body="Original body",
            contentHash="same-hash",
            analysis_done=True,
            analysis_status="done",
            analysisVersion=1,
            verdict="Лист безпечний",
        )
        stats = {"fetched": 0, "processed": 0, "created": 0, "updated": 0, "errors": 0, "pending_ai": 0}

        _process_message(
            self.account,
            {
                "gmail_id": "already-done",
                "subject": existing.subject,
                "sender": existing.sender,
                "senderName": existing.senderName,
                "domain": existing.domain,
                "date": existing.date,
                "body": existing.body,
                "replyTo": "",
                "returnPath": "",
                "messageId": "",
                "authenticationResults": "",
                "receivedHeaders": [],
                "dkimSignature": "",
                "contentHash": "same-hash",
                "attachments": [],
            },
            stats,
        )

        domain_mock.assert_not_called()
        existing.refresh_from_db()
        self.assertEqual(stats["updated"], 1)
        self.assertEqual(existing.analysis_status, "done")
        self.assertEqual(existing.analysisVersion, 1)
    @patch("apps.gmail.services.sync.analyze_domain")
    @patch("apps.gmail.services.sync._run_detailed_evidence_scan")
    @patch("apps.gmail.services.sync.analyze_email_with_providers")
    def test_safe_email_finishes_without_url_file_or_link_domain_vt(self, ai_mock, deep_mock, domain_mock):
        ai_mock.return_value = {
            "urgency": 0,
            "fear": 0,
            "credential_theft": 0,
            "financial_fraud": 0,
            "authority_impersonation": 0,
            "ai_score": 5,
            "ai_summary": "No risky intent.",
            "verdict": "Безпечний лист",
            "recommendations": ["Перевірте відправника.", "Дійте звичайно."],
            "_analysis_status": "done",
        }
        message = self._message()

        self.assertTrue(analyze_saved_email_message(message))

        deep_mock.assert_not_called()
        domain_mock.assert_not_called()
        message.refresh_from_db()
        self.assertEqual(message.analysis_status, "done")
        self.assertEqual(message.riskLevel, "Safe")
        self.assertEqual(message.scannedUrls, [])
        self.assertEqual(message.scannedAttachments, [])

    @patch("apps.gmail.services.sync.analyze_email_with_providers")
    def test_ai_summary_cannot_repeat_email_or_hallucinated_text(self, ai_mock):
        ai_mock.return_value = {
            "urgency": 0,
            "fear": 0,
            "credential_theft": 0,
            "financial_fraud": 0,
            "authority_impersonation": 0,
            "ai_score": 5,
            "ai_summary": "Безпечний лист. Звісно, ви можете здатися у Telegram-боті для отримання нових деталей.",
            "verdict": "Безпечний лист",
            "recommendations": ["Перевірте відправника.", "Дійте звичайно."],
            "_analysis_status": "done",
        }
        message = self._message(
            subject="Ваше замовлення отримало новий статус",
            body="Вітаємо, Максим. Ваше замовлення отримало новий статус: Доставка.",
        )

        self.assertTrue(analyze_saved_email_message(message))

        message.refresh_from_db()
        self.assertEqual(message.riskLevel, "Safe")
        self.assertNotIn("Telegram", message.aiSummary)
        self.assertNotIn("замовлення", message.aiSummary.lower())
        self.assertEqual(message.aiSummary, "Ознак фішингу, шахрайства, небезпечних посилань або вкладень не виявлено.")

    @patch("apps.gmail.services.sync._run_detailed_evidence_scan")
    @patch("apps.gmail.services.sync.analyze_email_with_providers")
    def test_explicit_credential_extortion_is_critical_even_with_clean_url(self, ai_mock, deep_mock):
        ai_mock.return_value = {
            "urgency": 0,
            "fear": 0,
            "credential_theft": 0,
            "financial_fraud": 0,
            "authority_impersonation": 0,
            "ai_score": 5,
            "ai_summary": "No risky intent.",
            "verdict": "Безпечний лист",
            "recommendations": ["Перевірте відправника.", "Дійте звичайно."],
            "_analysis_status": "done",
        }
        deep_mock.return_value = (
            {
                "attachment_score": 0,
                "scanned_attachments": [],
                "attachment_summary": "No attachments found.",
                "attachment_text": "",
            },
            {
                "url_score": 0,
                "any_phishing": False,
                "any_malicious": False,
                "malicious_urls": [],
                "phishing_urls": [],
                "scanned_urls": [
                    {
                        "url": "https://secure-account-dashboard.com/login",
                        "verdict": "Clean",
                        "score": 0,
                        "confidence": "none",
                        "is_phishing": False,
                        "is_malicious": False,
                    }
                ],
                "url_summary": "No malicious indicators.",
            },
        )
        message = self._message(
            sender="Security Verification Department <security@gmail.com>",
            senderName="Security Verification Department",
            domain="gmail.com",
            subject="Терміново: ваш акаунт буде заблоковано сьогодні",
            body=(
                "Ми виявили підозрілу активність у вашому акаунті. "
                "Якщо ви не підтвердите особу протягом 30 хвилин, доступ до акаунта буде назавжди заблоковано. "
                "Для відновлення доступу негайно перейдіть за посиланням: "
                "https://secure-account-dashboard.com/login "
                "Після входу введіть пароль, код підтвердження з SMS та платіжні дані для перевірки власника акаунта."
            ),
        )

        self.assertTrue(analyze_saved_email_message(message))

        message.refresh_from_db()
        self.assertEqual(message.riskLevel, "Critical")
        self.assertGreaterEqual(message.threatScore, 81)
        self.assertGreaterEqual(message.aiScore, 75)
        self.assertGreaterEqual(message.credentialTheft, 90)
        self.assertEqual(message.urlScore, 0)
        self.assertFalse(message.hasMaliciousUrl)
        joined_recommendations = " ".join(message.recommendations).lower()
        self.assertGreaterEqual(len(message.recommendations), 3)
        self.assertIn("посилан", joined_recommendations)
        self.assertIn("пароль", joined_recommendations)
        self.assertIn("sms", joined_recommendations)
        self.assertIn("сес", joined_recommendations)
    @patch("apps.gmail.services.sync.analyze_domain", return_value={"domainScore": 30})
    @patch("apps.gmail.services.sync._run_detailed_evidence_scan")
    @patch("apps.gmail.services.sync.analyze_email_with_providers")
    def test_suspicious_ai_triggers_deep_scan_and_second_ai_pass(self, ai_mock, deep_mock, domain_mock):
        ai_mock.side_effect = [
            {
                "urgency": 70,
                "fear": 20,
                "credential_theft": 75,
                "financial_fraud": 0,
                "authority_impersonation": 45,
                "ai_score": 55,
                "ai_summary": "Suspicious login intent.",
                "verdict": "Підозрілий лист",
                "recommendations": ["Не вводьте пароль.", "Перевірте сервіс."],
                "_analysis_status": "done",
            },
            {
                "urgency": 75,
                "fear": 20,
                "credential_theft": 85,
                "financial_fraud": 0,
                "authority_impersonation": 55,
                "ai_score": 65,
                "ai_summary": "Deep evidence confirms login risk.",
                "verdict": "Підозрілий лист",
                "recommendations": ["Не переходьте за посиланням.", "Відкрийте сервіс вручну."],
                "_analysis_status": "done",
            },
        ]
        deep_mock.return_value = (
            {
                "attachment_score": 0,
                "scanned_attachments": [],
                "attachment_summary": "No attachments found.",
                "attachment_text": "",
            },
            {
                "url_score": 45,
                "any_phishing": True,
                "any_malicious": False,
                "malicious_urls": [],
                "phishing_urls": ["https://secure-account-dashboard.com/login"],
                "scanned_urls": [
                    {
                        "url": "https://secure-account-dashboard.com/login",
                        "verdict": "Suspicious",
                        "score": 45,
                        "confidence": "medium",
                        "is_phishing": True,
                        "is_malicious": False,
                    }
                ],
                "url_summary": "Suspicious URL.",
            },
        )
        message = self._message(
            body="Verify your wallet now: https://secure-account-dashboard.com/login",
            linkScore=30,
        )

        self.assertTrue(analyze_saved_email_message(message))

        deep_mock.assert_called_once()
        self.assertEqual(ai_mock.call_count, 2)
        domain_mock.assert_called()
        message.refresh_from_db()
        self.assertEqual(message.analysis_status, "done")
        self.assertTrue(message.scannedUrls)

    @patch("apps.gmail.services.sync.scan_email_attachments")
    @patch("apps.gmail.services.sync.scan_urls_in_text")
    def test_deep_scan_limits_match_subscription_caps(self, url_mock, attachment_mock):
        attachment_mock.return_value = {
            "attachment_score": 0,
            "scanned_attachments": [],
            "attachment_summary": "No attachments found.",
            "attachment_text": "",
        }
        url_mock.return_value = {
            "url_score": 0,
            "any_phishing": False,
            "any_malicious": False,
            "scanned_urls": [],
            "url_summary": "No URLs found.",
        }
        attachments = [
            {"filename": f"file-{idx}.pdf", "attachment_id": f"att-{idx}", "mime_type": "application/pdf"}
            for idx in range(10)
        ]
        expected = [
            (LicensePlan.FREE_1_DAY, 3, 1),
            (LicensePlan.HALF_YEAR, 6, 3),
            (LicensePlan.YEAR, 15, 8),
        ]

        for plan, expected_urls, expected_attachments in expected:
            self.user.license_activations.all().delete()
            self._activate_plan(plan)
            max_urls, max_attachments = _deep_scan_limits(self.account)
            self.assertEqual((max_urls, max_attachments), (expected_urls, expected_attachments))

            _run_detailed_evidence_scan(
                email_account=self.account,
                service=object(),
                gmail_id="msg-limits",
                attachments=attachments,
                subject="Security check",
                body=" ".join(f"https://example.com/path/{idx}" for idx in range(20)),
                include_tracking=True,
                max_urls=max_urls,
                max_attachments=max_attachments,
            )

            self.assertEqual(len(attachment_mock.call_args.kwargs["attachments"]), expected_attachments)
            self.assertEqual(url_mock.call_args.kwargs["max_urls"], expected_urls)

    @patch("apps.gmail.services.spam_actions.move_message_to_spam")
    @patch("apps.gmail.services.sync.analyze_email_with_providers")
    def test_free_plan_does_not_auto_spam_critical_email(self, ai_mock, spam_mock):
        self._activate_plan(LicensePlan.FREE_1_DAY)
        self.account.granted_scopes = GMAIL_MODIFY_SCOPE
        self.account.save(update_fields=["granted_scopes"])
        ai_mock.return_value = self._critical_ai_result()
        message = self._critical_message()

        self.assertTrue(analyze_saved_email_message(message))

        spam_mock.assert_not_called()
        message.refresh_from_db()
        self.assertEqual(message.riskLevel, "Critical")
        self.assertEqual(message.spamActionStatus, "none")

    @patch("apps.gmail.services.spam_actions.move_message_to_spam")
    @patch("apps.gmail.services.sync.analyze_email_with_providers")
    def test_paid_plan_auto_spams_critical_email(self, ai_mock, spam_mock):
        self._activate_plan(LicensePlan.HALF_YEAR)
        self.account.granted_scopes = GMAIL_MODIFY_SCOPE
        self.account.save(update_fields=["granted_scopes"])
        ai_mock.return_value = self._critical_ai_result()
        message = self._critical_message()

        self.assertTrue(analyze_saved_email_message(message))

        spam_mock.assert_called_once_with(self.account, message.gmail_id)
        message.refresh_from_db()
        self.assertEqual(message.spamActionStatus, "moved")
        self.assertIsNotNone(message.spamActionAt)
        self.assertEqual(message.spamActionError, "")

    @patch("apps.gmail.services.sync.analyze_email_with_providers")
    def test_paid_plan_without_gmail_modify_scope_records_reconnect_required(self, ai_mock):
        self._activate_plan(LicensePlan.HALF_YEAR)
        ai_mock.return_value = self._critical_ai_result()
        message = self._critical_message()

        self.assertTrue(analyze_saved_email_message(message))

        message.refresh_from_db()
        self.assertEqual(message.spamActionStatus, "failed")
        self.assertIn("gmail.modify", message.spamActionError)

    @patch("apps.gmail.services.spam_actions.move_message_to_spam")
    @patch("apps.gmail.services.sync.analyze_email_with_providers")
    def test_year_allowlist_skips_auto_spam(self, ai_mock, spam_mock):
        self._activate_plan(LicensePlan.YEAR)
        self.account.granted_scopes = GMAIL_MODIFY_SCOPE
        self.account.save(update_fields=["granted_scopes"])
        TrustedSenderRule.objects.create(
            user=self.user,
            rule_type=TrustedSenderRule.RULE_TYPE_DOMAIN,
            value="example.com",
        )
        ai_mock.return_value = self._critical_ai_result()
        message = self._critical_message(sender="Security <security@example.com>", domain="example.com")

        self.assertTrue(analyze_saved_email_message(message))

        spam_mock.assert_not_called()
        message.refresh_from_db()
        self.assertEqual(message.spamActionStatus, "skipped")
        self.assertIn("allowlist", message.spamActionError)


class SubscriptionMonitoringTests(TestCase):
    def _licensed_account(self, email: str, plan: str) -> EmailAccount:
        user = User.objects.create(email=email)
        plaintext, _ = create_license_key(plan)
        activate_license_for_user(user, validate_license_key(plaintext))
        return EmailAccount.objects.create(
            user=user,
            email=email,
            access_token="access",
            refresh_token="refresh",
            granted_scopes=GMAIL_MODIFY_SCOPE,
            is_active=True,
        )

    @patch("apps.gmail.tasks.sync_gmail_account.delay")
    def test_sync_due_accounts_uses_paid_plan_limits(self, delay_mock):
        self._licensed_account("free@example.com", LicensePlan.FREE_1_DAY)
        half = self._licensed_account("half@example.com", LicensePlan.HALF_YEAR)
        year = self._licensed_account("year@example.com", LicensePlan.YEAR)

        result = sync_due_accounts.run()

        self.assertEqual(result["checked"], 3)
        self.assertEqual(result["queued"], 2)
        self.assertEqual(
            [call.args for call in delay_mock.call_args_list],
            [
                (half.id, 15, 7, False),
                (year.id, 30, 14, True),
            ],
        )


class AiQueueTimeoutTests(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create(email="queue@example.com")
        self.account = EmailAccount.objects.create(
            user=self.user,
            email=self.user.email,
            access_token="access",
            refresh_token="refresh",
            is_active=True,
        )

    def _message(self, gmail_id: str, minutes_ago: int = 0) -> EmailMessage:
        return EmailMessage.objects.create(
            account=self.account,
            gmail_id=gmail_id,
            subject=f"Message {gmail_id}",
            sender="sender@example.com",
            senderName="Sender",
            domain="example.com",
            date=timezone.now() - timedelta(minutes=minutes_ago),
            body="Hello",
            domainAge="Known",
            domainReputation="Trusted",
            domainScore=10,
            analysis_status="pending_ai",
        )

    @override_settings(AI_MESSAGE_TIME_BUDGET_SECONDS=30)
    @patch("apps.gmail.services.sync.analyze_saved_email_message")
    def test_timeout_does_not_block_next_message_and_fallbacks_after_tail_retry(self, analyze_mock):
        first = self._message("a-timeout", minutes_ago=0)
        second = self._message("b-safe", minutes_ago=1)
        attempts = []

        def fake_analyze(message, **kwargs):
            attempts.append(message.gmail_id)
            self.assertEqual(kwargs["time_budget_seconds"], 30.0)
            if message.gmail_id == "a-timeout":
                raise QueueAnalysisTimedOut("slow message")
            message.analysis_status = "done"
            message.analysis_done = True
            message.save(update_fields=["analysis_status", "analysis_done", "synced_at"])
            return True

        analyze_mock.side_effect = fake_analyze

        with patch.object(analyze_pending_email, "retry", side_effect=AssertionError("retry should not run")):
            with patch.object(process_ai_queue, "apply_async") as apply_async_mock:
                first_result = analyze_pending_email.run(first.id)
                second_result = analyze_pending_email.run(second.id)
                fallback_result = analyze_pending_email.run(first.id)

        self.assertEqual(attempts, ["a-timeout", "b-safe", "a-timeout"])
        self.assertEqual(first_result["state"], "deferred")
        self.assertEqual(first_result["reason"], "timed_out")
        self.assertEqual(second_result["state"], "done")
        self.assertEqual(fallback_result["state"], "fallback_done")
        self.assertGreaterEqual(apply_async_mock.call_count, 1)
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertEqual(first.analysis_status, "done")
        self.assertEqual(first.analysisSource, "AI unavailable")
        self.assertEqual(second.analysis_status, "done")

    @override_settings(AI_PROCESSING_STALE_SECONDS=60)
    def test_stale_processing_message_is_recovered_and_scheduled(self):
        message = self._message("stale-processing")
        EmailMessage.objects.filter(pk=message.pk).update(
            analysis_status="processing",
            analysis_done=False,
            synced_at=timezone.now() - timedelta(minutes=10),
        )

        with patch.object(process_ai_queue, "retry", side_effect=AssertionError("retry should not run")):
            with patch.object(analyze_pending_email, "apply_async") as apply_async_mock:
                result = process_ai_queue.run(self.account.id, max_batch=1)

        self.assertEqual(result["recovered_processing"], 1)
        self.assertEqual(result["claimed"], 1)
        self.assertEqual(result["remaining"], 1)
        apply_async_mock.assert_called_once()
        self.assertEqual(apply_async_mock.call_args.kwargs["args"], [message.id])
        message.refresh_from_db()
        self.assertEqual(message.analysis_status, "processing")

    @override_settings(AI_MESSAGE_TIME_BUDGET_SECONDS=30)
    @patch("apps.gmail.services.sync.analyze_saved_email_message")
    def test_provider_unavailable_completes_with_fallback_without_retry(self, analyze_mock):
        message = self._message("provider-unavailable")
        analyze_mock.side_effect = AIProviderUnavailable("ollama unavailable")

        with patch.object(analyze_pending_email, "retry", side_effect=AssertionError("retry should not run")):
            with patch.object(process_ai_queue, "apply_async") as apply_async_mock:
                result = analyze_pending_email.run(message.id)

        self.assertEqual(result["state"], "fallback_done")
        message.refresh_from_db()
        self.assertEqual(message.analysis_status, "done")
        self.assertEqual(message.analysisSource, "AI unavailable")

    @override_settings(AI_MESSAGE_TIME_BUDGET_SECONDS=30)
    @patch("apps.gmail.services.sync.analyze_saved_email_message")
    def test_deferred_message_can_complete_on_tail_retry(self, analyze_mock):
        message = self._message("a-slow-then-safe")
        attempts = []

        def fake_analyze(email_message, **kwargs):
            attempts.append(email_message.gmail_id)
            if len(attempts) == 1:
                raise QueueAnalysisTimedOut("first attempt slow")
            email_message.analysis_status = "done"
            email_message.analysis_done = True
            email_message.save(update_fields=["analysis_status", "analysis_done", "synced_at"])
            return True

        analyze_mock.side_effect = fake_analyze

        with patch.object(analyze_pending_email, "retry", side_effect=AssertionError("retry should not run")):
            with patch.object(process_ai_queue, "apply_async") as apply_async_mock:
                first_result = analyze_pending_email.run(message.id)
                second_result = analyze_pending_email.run(message.id)

        self.assertEqual(attempts, ["a-slow-then-safe", "a-slow-then-safe"])
        self.assertEqual(first_result["state"], "deferred")
        self.assertEqual(first_result["reason"], "timed_out")
        self.assertEqual(second_result["state"], "done")
        self.assertGreaterEqual(apply_async_mock.call_count, 1)
        message.refresh_from_db()
        self.assertEqual(message.analysis_status, "done")

    @override_settings(AI_MESSAGE_TIME_BUDGET_SECONDS=30)
    @patch("apps.gmail.services.sync.analyze_saved_email_message")
    def test_pending_reputation_does_not_block_next_message(self, analyze_mock):
        first = self._message("a-pending-url", minutes_ago=0)
        second = self._message("b-safe", minutes_ago=1)
        attempts = []

        def fake_analyze(message, **kwargs):
            attempts.append((message.gmail_id, kwargs.get("allow_pending_reputation", False)))
            if message.gmail_id == "a-pending-url" and not kwargs.get("allow_pending_reputation", False):
                raise AIPendingReputation("url pending")
            message.analysis_status = "done"
            message.analysis_done = True
            message.save(update_fields=["analysis_status", "analysis_done", "synced_at"])
            return True

        analyze_mock.side_effect = fake_analyze

        with patch.object(analyze_pending_email, "retry", side_effect=AssertionError("retry should not run")):
            with patch.object(process_ai_queue, "apply_async") as apply_async_mock:
                first_result = analyze_pending_email.run(first.id)
                second_result = analyze_pending_email.run(second.id)
                final_result = analyze_pending_email.run(first.id)

        self.assertEqual(
            attempts,
            [("a-pending-url", False), ("b-safe", False), ("a-pending-url", True)],
        )
        self.assertEqual(first_result["state"], "deferred")
        self.assertEqual(first_result["reason"], "pending_reputation")
        self.assertEqual(second_result["state"], "done")
        self.assertEqual(final_result["state"], "done")
        self.assertGreaterEqual(apply_async_mock.call_count, 1)
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertEqual(first.analysis_status, "done")
        self.assertEqual(second.analysis_status, "done")

    def test_queue_scheduler_claims_pending_without_inline_analysis(self):
        first = self._message("pending-a")
        second = self._message("pending-b")

        with patch.object(analyze_pending_email, "apply_async") as apply_async_mock:
            result = process_ai_queue.run(self.account.id, max_batch=2)

        self.assertEqual(result["claimed"], 2)
        self.assertEqual(result["processing"], 2)
        self.assertEqual(result["remaining"], 2)
        self.assertCountEqual(
            [call.kwargs["args"] for call in apply_async_mock.call_args_list],
            [[first.id], [second.id]],
        )
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertEqual(first.analysis_status, "processing")
        self.assertEqual(second.analysis_status, "processing")

    def test_email_list_triggers_queue_when_pending_exists(self):
        self._message("pending-from-list")
        client = APIClient()
        client.force_authenticate(self.user)

        with patch.object(process_ai_queue, "apply_async") as apply_async_mock:
            response = client.get("/api/gmail/emails/")

        self.assertEqual(response.status_code, 200)
        apply_async_mock.assert_called_once()
        self.assertEqual(apply_async_mock.call_args.kwargs["args"], [self.account.id])

class AiProviderTimeoutTests(SimpleTestCase):
    @patch.dict(
        os.environ,
        {
            "AI_PROVIDER_ORDER": "ollama",
            "OLLAMA_BASE_URL": "http://ollama:11434",
            "OLLAMA_MODEL": "qwen2.5:1.5b",
            "OLLAMA_TIMEOUT_SECONDS": "30",
        },
    )
    @patch("apps.gmail.services.ai_providers.requests.post", side_effect=requests.Timeout("slow"))
    def test_ollama_request_timeout_becomes_defer_timeout(self, post_mock):
        from apps.gmail.services import ai_providers

        ai_providers._OLLAMA_MODEL_READY_UNTIL = time.time() + 60

        with self.assertRaises(AIAnalysisTimedOut):
            analyze_email_with_providers(
                subject="Hello",
                sender="sender@example.com",
                body="Body",
                domain="example.com",
                deadline=time.monotonic() + 30,
            )

        post_mock.assert_called_once()


class UrlProviderChainTests(TestCase):
    @override_settings(GOOGLE_WEB_RISK_API_KEY="web-risk-key", VIRUSTOTAL_API_KEY="vt-key")
    @patch("apps.reputation.url_service.requests.get")
    def test_url_reputation_uses_web_risk_before_virustotal(self, get_mock):
        url_service._WEB_RISK_URL_DISABLED_UNTIL = 0
        url_service._VT_URL_DISABLED_UNTIL = 0
        get_mock.return_value = SimpleNamespace(
            status_code=200,
            ok=True,
            text="{}",
            json=lambda: {},
        )

        rep = get_url_reputation("https://example.com/login", use_vt_enrichment=True)

        self.assertEqual(rep.raw_stats.get("provider"), "google_web_risk")
        self.assertIn("webrisk.googleapis.com", get_mock.call_args.args[0])

    @override_settings(GOOGLE_WEB_RISK_API_KEY="web-risk-key", VIRUSTOTAL_API_KEY="")
    @patch("apps.reputation.url_service.requests.get")
    def test_url_reputation_rate_limit_falls_back_without_blocking_scan(self, get_mock):
        url_service._WEB_RISK_URL_DISABLED_UNTIL = 0
        url_service._VT_URL_DISABLED_UNTIL = 0
        get_mock.return_value = SimpleNamespace(
            status_code=429,
            ok=False,
            text="rate limit",
            json=lambda: {},
        )

        rep = get_url_reputation("https://example.com/login", use_vt_enrichment=True)

        self.assertEqual(rep.raw_stats.get("provider"), "local_heuristic")
        self.assertEqual(rep.verdict, UrlReputation.VERDICT_SUSPICIOUS)


class GoogleOAuthUserTests(TestCase):
    @patch("apps.accounts.google_oauth._trigger_initial_scan")
    def test_existing_email_user_gets_google_id_without_duplicate_create(self, trigger_initial_scan):
        user = User.objects.create(email="person@example.com", name="Person")
        token_data = {
            "access_token": "access-token",
            "refresh_token": "refresh-token",
            "expires_in": 3600,
        }
        userinfo = {
            "sub": "google-123",
            "email": "person@example.com",
            "name": "Person Example",
            "picture": "https://example.com/avatar.png",
        }

        result = get_or_create_user_from_google(token_data, userinfo)

        self.assertEqual(result.id, user.id)
        self.assertEqual(result.google_id, "google-123")
        self.assertEqual(User.objects.filter(email="person@example.com").count(), 1)
        trigger_initial_scan.assert_called_once()


class AttachmentQrTests(SimpleTestCase):
    def test_qr_payload_with_login_url_is_sensitive_evidence(self):
        findings = _qr_findings(["https://secure-account-dashboard.com/login?token=abc"])

        self.assertIn("qr_code_detected", findings)
        self.assertIn("qr_contains_url", findings)
        self.assertIn("qr_contains_sensitive_url", findings)
