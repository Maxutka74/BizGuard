from types import SimpleNamespace
from unittest import TestCase

from apps.gmail.services.phishing_evidence import calibrate_phishing_scores, technical_context_for_ai
from apps.gmail.services.threat_scoring import compute_threat_result


def message(**changes):
    values = {
        "subject": "Security notification",
        "sender": "alerts@accounts.google.com",
        "domain": "accounts.google.com",
        "body": "Review activity at https://myaccount.google.com/notifications",
        "authenticationResults": "mx.google.com; spf=pass; dkim=pass; dmarc=pass",
        "domainReputation": "Trusted",
        "domainScore": 10,
        "headerScore": 0,
        "linkScore": 0,
        "attachmentScore": 0,
        "urlScore": 0,
        "securitySignals": {"headerFindings": [], "linkFindings": []},
        "scannedUrls": [{
            "url": "https://myaccount.google.com/notifications",
            "verdict": "Clean", "score": 0,
        }],
        "scannedAttachments": [],
        "attachments": [],
        "hasMaliciousUrl": False,
        "hasPhishingUrl": False,
        "lookalikeDomain": None,
        "urlScanSummary": "No malicious indicators.",
        "attachmentScanSummary": "",
    }
    values.update(changes)
    return SimpleNamespace(**values)


class EvidenceCalibrationTests(TestCase):
    def test_authenticated_google_notice_does_not_inherit_model_hallucinations(self):
        email = message(
            subject="Оповещение системы безопасности",
            body="Проверьте события аккаунта: https://myaccount.google.com/notifications",
        )
        inflated = {
            "urgency": 70, "fear": 70, "credential_theft": 80,
            "financial_fraud": 70, "authority_impersonation": 70,
            "_evidence": {key: "Оповещение системы безопасности" for key in (
                "urgency", "fear", "credential_theft", "financial_fraud", "authority_impersonation",
            )},
        }

        result = calibrate_phishing_scores(inflated, email, require_model_evidence=True)
        self.assertTrue(technical_context_for_ai(email)["authenticated_sender"])
        self.assertTrue(result["_evidence_signals"]["clean_external"])
        self.assertTrue(all(result[key] <= 15 for key in inflated if not key.startswith("_")))
        threat = compute_threat_result(
            ai_score=15, domain_score=email.domainScore, header_score=email.headerScore,
        )
        self.assertEqual(threat.risk_level, "Safe")

    def test_spoofed_google_with_malicious_url_stays_critical(self):
        email = message(
            sender="Google Security <alert@gooogle-alerts.net>",
            domain="gooogle-alerts.net",
            subject="Your Google account will be blocked",
            body="Enter your password at https://google-verify-login.net/login within 30 minutes.",
            authenticationResults="mx.google.com; spf=fail; dkim=fail; dmarc=fail",
            domainReputation="Suspicious",
            domainScore=60,
            headerScore=35,
            linkScore=30,
            urlScore=90,
            securitySignals={
                "headerFindings": ["auth_failure"],
                "linkFindings": ["link_domain_mismatch"],
            },
            scannedUrls=[{
                "url": "https://google-verify-login.net/login",
                "verdict": "Malicious", "score": 90, "is_malicious": True,
            }],
            hasMaliciousUrl=True,
        )
        result = calibrate_phishing_scores({
            "urgency": 0, "fear": 0, "credential_theft": 0,
            "financial_fraud": 0, "authority_impersonation": 0,
        }, email, require_model_evidence=True)

        self.assertFalse(technical_context_for_ai(email)["authenticated_sender"])
        self.assertGreaterEqual(result["credential_theft"], 85)
        threat = compute_threat_result(
            ai_score=50, domain_score=email.domainScore, header_score=email.headerScore,
            credential_theft=result["credential_theft"], urgency=result["urgency"],
            url_score=email.urlScore, any_malicious_url=True,
        )
        self.assertEqual(threat.risk_level, "Critical")

    def test_explicit_secret_request_is_not_erased_by_clean_virustotal(self):
        email = message(
            domain="gmail.com",
            sender="Security <security@gmail.com>",
            subject="Терміново: акаунт буде заблоковано",
            body=(
                "Протягом 30 хвилин введіть пароль і код підтвердження на "
                "https://account-verification.example/login або акаунт буде заблоковано."
            ),
            authenticationResults="",
            domainScore=10,
            linkScore=30,
            securitySignals={"headerFindings": [], "linkFindings": ["link_domain_mismatch"]},
            scannedUrls=[{
                "url": "https://account-verification.example/login",
                "verdict": "Clean", "score": 0,
            }],
        )
        result = calibrate_phishing_scores({
            "urgency": 85, "fear": 80, "credential_theft": 95,
            "financial_fraud": 0, "authority_impersonation": 70,
            "_evidence": {},
        }, email, require_model_evidence=True)

        self.assertGreaterEqual(result["credential_theft"], 90)
        self.assertGreaterEqual(result["urgency"], 80)
        self.assertTrue(result["_evidence_signals"]["credential_request"])

    def test_safety_advice_is_not_a_password_request(self):
        email = message(body="Do not enter your password in any email or website.")
        result = calibrate_phishing_scores({
            "urgency": 70, "fear": 70, "credential_theft": 80,
            "financial_fraud": 70, "authority_impersonation": 70,
        }, email, require_model_evidence=True)
        self.assertFalse(result["_evidence_signals"]["credential_request"])
        self.assertLessEqual(result["credential_theft"], 15)

    def test_forged_authentication_header_does_not_make_sender_trusted(self):
        email = message(authenticationResults="attacker.invalid; spf=pass; dkim=pass; dmarc=pass")
        self.assertFalse(technical_context_for_ai(email)["authenticated_sender"])

    def test_unknown_url_reputation_is_not_mistaken_for_clean(self):
        email = message(scannedUrls=[])
        result = calibrate_phishing_scores({key: 70 for key in (
            "urgency", "fear", "credential_theft", "financial_fraud",
            "authority_impersonation",
        )}, email, require_model_evidence=True)
        self.assertFalse(result["_evidence_signals"]["clean_external"])

    def test_different_co_uk_sites_are_not_treated_as_aligned(self):
        email = message(
            domain="accounts.google.co.uk",
            sender="Google <notice@accounts.google.co.uk>",
            body="Review https://account-help.evil.co.uk/login",
            scannedUrls=[{
                "url": "https://account-help.evil.co.uk/login",
                "verdict": "Clean", "score": 0,
            }],
        )
        self.assertFalse(technical_context_for_ai(email)["sender_and_link_domains_aligned"])
