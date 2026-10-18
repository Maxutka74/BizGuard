"""Reassess old phishing verdicts from evidence already saved with each email."""

from django.core.management.base import BaseCommand

from apps.gmail.models import EmailMessage
from apps.gmail.services.sync import (
    ANALYSIS_VERSION,
    reassess_saved_email_message,
    refresh_saved_email_analysis,
)


class Command(BaseCommand):
    help = (
        "Re-score older completed emails using saved evidence, or use --message-id "
        "--refresh-urls to recheck URLs and rerun AI. Dry-run unless --apply is supplied. "
        "Never changes Gmail labels."
    )

    def add_arguments(self, parser):
        parser.add_argument("--apply", action="store_true", help="Save the new verdicts.")
        parser.add_argument("--limit", type=int, default=1000, help="Maximum emails to inspect (default: 1000).")
        parser.add_argument("--email", help="Only emails belonging to this Gmail account.")
        parser.add_argument("--message-id", type=int, help="Only this stored email ID.")
        parser.add_argument(
            "--refresh-urls", action="store_true",
            help="With --message-id, recheck URLs and rerun Ollama before saving. Does not alter Gmail labels.",
        )

    def handle(self, *args, **options):
        limit = options["limit"]
        if limit < 1:
            self.stderr.write(self.style.ERROR("--limit must be positive."))
            return
        if options["refresh_urls"] and not options["message_id"]:
            self.stderr.write(self.style.ERROR("--refresh-urls requires --message-id."))
            return
        messages = EmailMessage.objects.filter(analysis_status="done")
        if not options["refresh_urls"]:
            messages = messages.filter(analysisVersion__lt=ANALYSIS_VERSION)
        messages = messages.select_related("account").order_by("id")
        if options["email"]:
            messages = messages.filter(account__email=options["email"])
        if options["message_id"]:
            messages = messages.filter(pk=options["message_id"])
        inspected = changed = failed = 0
        for message in messages[:limit].iterator(chunk_size=100):
            inspected += 1
            if not options["apply"]:
                continue
            try:
                before = (message.riskLevel, message.threatScore)
                if options["refresh_urls"]:
                    refresh_saved_email_analysis(message)
                else:
                    reassess_saved_email_message(message)
                if before != (message.riskLevel, message.threatScore):
                    changed += 1
            except Exception as exc:
                failed += 1
                self.stderr.write(f"Could not reassess email {message.pk}: {exc}")
        if options["apply"]:
            self.stdout.write(
                f"Applied: inspected={inspected}, changed={changed}, failed={failed}, "
                f"analysis_version={ANALYSIS_VERSION}"
            )
        else:
            self.stdout.write(
                f"Dry run: eligible={inspected}, analysis_version={ANALYSIS_VERSION}"
            )
