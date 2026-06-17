"""
Tests for apps/emails

Covers:
  - HTML stripping (parsers.strip_html)
  - Sender/address parsing
  - Domain extraction
  - Gmail payload normalization
  - Snippet generation
  - EmailNormalizationService upsert idempotency
  - Serializer output shapes (list vs detail)
"""

import pytest
from unittest.mock import patch
from django.test import TestCase
from django.utils import timezone

from .parsers import (
    strip_html,
    parse_address,
    parse_address_list,
    extract_domain,
    make_snippet,
    parse_gmail_message,
)
from .models import Email, Attachment
from .services import EmailNormalizationService
from .serializers import EmailListSerializer, EmailDetailSerializer


# ---------------------------------------------------------------------------
# Parser unit tests
# ---------------------------------------------------------------------------

class TestStripHtml(TestCase):

    def test_removes_tags(self):
        result = strip_html("<p>Hello <b>world</b></p>")
        self.assertNotIn("<p>", result)
        self.assertIn("Hello", result)
        self.assertIn("world", result)

    def test_removes_script_content(self):
        result = strip_html("<script>alert('xss')</script><p>Safe</p>")
        self.assertNotIn("alert", result)
        self.assertIn("Safe", result)

    def test_removes_style_block(self):
        result = strip_html("<style>body { color: red }</style><p>Text</p>")
        self.assertNotIn("color", result)
        self.assertIn("Text", result)

    def test_decodes_html_entities(self):
        result = strip_html("&lt;b&gt;bold&lt;/b&gt; &amp; more")
        self.assertIn("<b>bold</b>", result)
        self.assertIn("&", result)

    def test_empty_input(self):
        self.assertEqual(strip_html(""), "")

    def test_plain_text_unchanged(self):
        result = strip_html("No tags here at all.")
        self.assertEqual(result, "No tags here at all.")


class TestParseAddress(TestCase):

    def test_full_address(self):
        r = parse_address("John Doe <john@example.com>")
        self.assertEqual(r["name"], "John Doe")
        self.assertEqual(r["email"], "john@example.com")

    def test_bare_email(self):
        r = parse_address("john@example.com")
        self.assertEqual(r["email"], "john@example.com")
        self.assertEqual(r["name"], "")

    def test_empty_string(self):
        r = parse_address("")
        self.assertEqual(r["email"], "")

    def test_email_lowercased(self):
        r = parse_address("USER@EXAMPLE.COM")
        self.assertEqual(r["email"], "user@example.com")


class TestParseAddressList(TestCase):

    def test_multiple(self):
        result = parse_address_list("Alice <a@a.com>, Bob <b@b.com>")
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["email"], "a@a.com")

    def test_empty(self):
        self.assertEqual(parse_address_list(""), [])


class TestExtractDomain(TestCase):

    def test_normal(self):
        self.assertEqual(extract_domain("user@example.com"), "example.com")

    def test_subdomain(self):
        self.assertEqual(extract_domain("user@mail.example.co.uk"), "mail.example.co.uk")

    def test_no_at(self):
        self.assertEqual(extract_domain("notanemail"), "")

    def test_uppercase(self):
        self.assertEqual(extract_domain("user@EXAMPLE.COM"), "example.com")


class TestMakeSnippet(TestCase):

    def test_short_text_unchanged(self):
        self.assertEqual(make_snippet("Short text"), "Short text")

    def test_long_text_truncated(self):
        long = "A" * 300
        result = make_snippet(long, max_length=200)
        self.assertLessEqual(len(result), 203)  # 200 + ellipsis
        self.assertTrue(result.endswith("…"))

    def test_strips_leading_whitespace(self):
        result = make_snippet("   Hello   ")
        self.assertEqual(result, "Hello")


class TestParseGmailMessage(TestCase):

    def _make_raw(self, **overrides):
        base = {
            "id": "abc123",
            "threadId": "thread1",
            "labelIds": ["INBOX"],
            "payload": {
                "headers": [
                    {"name": "From", "value": "Alice <alice@sender.com>"},
                    {"name": "To", "value": "Bob <bob@recv.com>"},
                    {"name": "Subject", "value": "Test Subject"},
                    {"name": "Date", "value": "Mon, 12 Jun 2023 10:00:00 +0000"},
                ],
                "mimeType": "text/plain",
                "body": {"data": "SGVsbG8gV29ybGQ="},  # base64 "Hello World"
                "parts": [],
            },
        }
        base.update(overrides)
        return base

    def test_basic_parse(self):
        result = parse_gmail_message(self._make_raw())
        self.assertEqual(result["message_id"], "abc123")
        self.assertEqual(result["sender_email"], "alice@sender.com")
        self.assertEqual(result["sender_domain"], "sender.com")
        self.assertEqual(result["subject"], "Test Subject")
        self.assertIn("Hello World", result["body_plain"])

    def test_labels_passed_through(self):
        result = parse_gmail_message(self._make_raw())
        self.assertIn("INBOX", result["labels"])

    def test_snippet_generated(self):
        result = parse_gmail_message(self._make_raw())
        self.assertTrue(len(result["snippet"]) > 0)


# ---------------------------------------------------------------------------
# Service tests
# ---------------------------------------------------------------------------

class TestEmailNormalizationService(TestCase):

    def _parsed(self, **kwargs):
        base = {
            "message_id": "msg-001",
            "thread_id": "thread-001",
            "sender_name": "Alice",
            "sender_email": "alice@example.com",
            "sender_domain": "example.com",
            "recipients_to": [{"name": "Bob", "email": "bob@dest.com"}],
            "recipients_cc": [],
            "recipients_bcc": [],
            "subject": "Hello",
            "body_plain": "Hello Bob!",
            "body_html": "<p>Hello Bob!</p>",
            "snippet": "Hello Bob!",
            "sent_at": timezone.now(),
            "has_attachments": False,
            "attachment_count": 0,
            "raw_headers": {},
            "labels": ["INBOX"],
        }
        base.update(kwargs)
        return base

    def test_creates_email(self):
        email = EmailNormalizationService.upsert(self._parsed())
        self.assertIsNotNone(email.pk)
        self.assertEqual(email.sender_email, "alice@example.com")

    def test_idempotent_upsert(self):
        EmailNormalizationService.upsert(self._parsed())
        EmailNormalizationService.upsert(self._parsed(subject="Updated Subject"))
        self.assertEqual(Email.objects.count(), 1)
        self.assertEqual(Email.objects.first().subject, "Updated Subject")

    def test_domain_inferred_if_missing(self):
        parsed = self._parsed()
        parsed["sender_domain"] = ""
        email = EmailNormalizationService.upsert(parsed)
        self.assertEqual(email.sender_domain, "example.com")

    def test_snippet_trimmed(self):
        parsed = self._parsed(snippet="X" * 600)
        email = EmailNormalizationService.upsert(parsed)
        self.assertLessEqual(len(email.snippet), 512)


# ---------------------------------------------------------------------------
# Serializer output shape tests
# ---------------------------------------------------------------------------

class TestSerializerShapes(TestCase):

    def setUp(self):
        self.email = Email.objects.create(
            message_id="test-001",
            sender_name="Alice",
            sender_email="alice@example.com",
            sender_domain="example.com",
            subject="Test",
            body_plain="Hello there.",
            snippet="Hello there.",
            received_at=timezone.now(),
            risk_score=0.8,
            is_flagged=True,
            flag_reason="Suspicious domain",
        )

    def test_list_serializer_has_sender(self):
        data = EmailListSerializer(self.email).data
        self.assertIn("sender", data)
        self.assertEqual(data["sender"]["email"], "alice@example.com")
        self.assertNotIn("body", data)  # body not in list view

    def test_detail_serializer_has_body(self):
        data = EmailDetailSerializer(self.email).data
        self.assertIn("body", data)
        self.assertIn("plain", data["body"])
        self.assertNotIn("body_html", data)  # raw HTML never exposed

    def test_detail_risk_field(self):
        data = EmailDetailSerializer(self.email).data
        self.assertEqual(data["risk"]["level"], "high")
        self.assertTrue(data["risk"]["is_flagged"])

    def test_detail_sender_initials(self):
        data = EmailDetailSerializer(self.email).data
        self.assertEqual(data["sender"]["initials"], "A")
