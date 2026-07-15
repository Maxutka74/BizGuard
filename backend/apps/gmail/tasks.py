"""
apps/gmail/tasks.py

Celery tasks for async Gmail operations.
If Celery is not configured, these are never called
(views.py falls back to inline sync).
"""
from __future__ import annotations

import logging
import time
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)

AI_RETRY_BACKOFFS = [30, 120, 300, 900]

try:
    from celery import shared_task

    @shared_task(
        bind=True,
        max_retries=3,
        default_retry_delay=60,
        name="gmail.sync_account",
    )
    def sync_gmail_account(
        self,
        account_id: int,
        max_results: int = 30,
        recent_lookback_days: int | None = None,
        priority_ai: bool = False,
        backfill_to_limit: bool = False,
    ) -> dict:
        """
        Async task: fetch + analyse emails for one EmailAccount.
        Retries up to 3 times on transient failures.
        """
        from apps.gmail.models import EmailAccount
        from apps.gmail.services.sync import sync_account

        try:
            account = EmailAccount.objects.get(pk=account_id, is_active=True)
        except EmailAccount.DoesNotExist:
            logger.warning("EmailAccount %d not found or inactive", account_id)
            return {}

        try:
            def progress_callback(stats: dict) -> None:
                self.update_state(
                    state="PROGRESS",
                    meta={
                        "state": "PROGRESS",
                        **stats,
                    },
                )

            result = sync_account(
                account,
                max_results=max_results,
                recent_lookback_days=recent_lookback_days,
                priority_ai=priority_ai,
                backfill_to_limit=backfill_to_limit,
                progress_callback=progress_callback,
            )
            self.update_state(state="SUCCESS", meta={"state": "SUCCESS", **result})
            return {"state": "SUCCESS", **result}
        except Exception as exc:
            logger.exception("Sync task failed for account %d: %s", account_id, exc)
            raise self.retry(exc=exc)

    @shared_task(
        bind=True,
        max_retries=3,
        default_retry_delay=30,
        name="gmail.analyze_pending_email",
        queue="ai",
    )
    def analyze_pending_email(self, message_id: int, final_attempt: bool = False) -> dict:
        from django.conf import settings
        from django.core.cache import cache

        from apps.gmail.models import EmailMessage
        from apps.gmail.services.ai_providers import AIProviderUnavailable
        from apps.gmail.services.queue import enqueue_ai_queue
        from apps.gmail.services.sync import (
            ANALYSIS_VERSION,
            AIPendingReputation,
            AIAnalysisTimedOut,
            analyze_saved_email_message,
            finalize_saved_email_with_local_fallback,
        )

        time_budget_seconds = max(1.0, float(getattr(settings, "AI_MESSAGE_TIME_BUDGET_SECONDS", 30)))
        lock_key = f"gmail:ai-message-lock:{message_id}"
        attempt_key = f"gmail:ai-message-attempt:{message_id}:v{ANALYSIS_VERSION}"
        lock_ttl = int(max(90, time_budget_seconds * 3))
        if not cache.add(lock_key, "1", lock_ttl):
            return {"state": "locked", "message_id": message_id}

        account_id = None

        def mark_pending(source: str = "AI pending") -> None:
            EmailMessage.objects.filter(pk=message_id).update(
                analysis_status="pending_ai",
                analysisSource=source,
                analysis_done=False,
            )

        def complete_with_fallback(reason: str) -> dict:
            nonlocal account_id
            message = EmailMessage.objects.select_related("account").get(pk=message_id)
            account_id = message.account_id
            finalized = finalize_saved_email_with_local_fallback(
                message,
                reason=reason,
                allow_pending_reputation=True,
                run_missing_deep_scan=False,
            )
            if not finalized:
                mark_pending()
                return {"state": "pending", "message_id": message_id, "account_id": account_id}
            cache.delete(attempt_key)
            return {"state": "fallback_done", "message_id": message_id, "account_id": account_id}

        try:
            with transaction.atomic():
                message = (
                    EmailMessage.objects.select_for_update(skip_locked=True)
                    .select_related("account")
                    .filter(pk=message_id)
                    .first()
                )
                if not message:
                    existing_meta = EmailMessage.objects.filter(pk=message_id).values("account_id", "analysis_status").first()
                    if existing_meta:
                        account_id = existing_meta["account_id"]
                        if existing_meta["analysis_status"] != "done":
                            EmailMessage.objects.filter(pk=message_id).update(
                                analysis_status="pending_ai",
                                analysisSource="AI pending",
                                analysis_done=False,
                            )
                        return {"state": "db_locked", "message_id": message_id, "account_id": account_id}
                    return {"state": "missing", "message_id": message_id}
                account_id = message.account_id
                if message.analysis_status == "done":
                    return {"state": "done", "message_id": message_id, "account_id": account_id}
                message.analysis_status = "processing"
                message.analysisSource = "AI pending"
                message.analysis_done = False
                message.analysisVersion = ANALYSIS_VERSION
                message.save(
                    update_fields=[
                        "analysis_status",
                        "analysisSource",
                        "analysis_done",
                        "analysisVersion",
                        "synced_at",
                    ]
                )

            attempts = int(cache.get(attempt_key, 0) or 0) + 1
            cache.set(attempt_key, attempts, 3600)
            started = time.monotonic()
            try:
                message = EmailMessage.objects.select_related("account").get(pk=message_id)
                analyzed = analyze_saved_email_message(
                    message,
                    time_budget_seconds=time_budget_seconds,
                    allow_pending_reputation=final_attempt or attempts >= 2,
                )
                if not analyzed:
                    if final_attempt or attempts >= 2:
                        return complete_with_fallback(
                            "AI provider did not produce a completed analysis on final queue attempt."
                        )
                    raise RuntimeError("AI provider did not produce a completed analysis.")
                cache.delete(attempt_key)
                logger.info("AI analyzed message %s in %.2fs", message.gmail_id, time.monotonic() - started)
                return {"state": "done", "message_id": message_id, "account_id": account_id}
            except AIPendingReputation as exc:
                if final_attempt or attempts >= 2:
                    return complete_with_fallback(f"Reputation evidence remained pending: {exc}")
                mark_pending("Waiting for reputation")
                return {"state": "deferred", "reason": "pending_reputation", "message_id": message_id, "account_id": account_id}
            except AIProviderUnavailable as exc:
                return complete_with_fallback(f"AI provider unavailable: {exc}")
            except AIAnalysisTimedOut as exc:
                if final_attempt or attempts >= 2:
                    return complete_with_fallback(f"AI analysis timed out: {exc}")
                mark_pending()
                return {"state": "deferred", "reason": "timed_out", "message_id": message_id, "account_id": account_id}
            except Exception as exc:
                message_text = str(exc).lower()
                retries = int(getattr(self.request, "retries", 0) or 0)
                if retries >= 2 or "invalid json" in message_text or "unterminated string" in message_text:
                    return complete_with_fallback(str(exc))
                mark_pending()
                countdown = AI_RETRY_BACKOFFS[min(retries, len(AI_RETRY_BACKOFFS) - 1)]
                raise self.retry(exc=exc, countdown=countdown)
        finally:
            cache.delete(lock_key)
            if account_id:
                try:
                    has_remaining = EmailMessage.objects.filter(account_id=account_id).exclude(analysis_status="done").exists()
                    if has_remaining:
                        enqueue_ai_queue(account_id, countdown=1, debounce_seconds=1, force=True)
                except Exception:
                    logger.debug("Could not enqueue follow-up AI queue for account %s", account_id, exc_info=True)

    @shared_task(
        bind=True,
        max_retries=3,
        default_retry_delay=30,
        name="gmail.process_ai_queue",
        queue="ai",
    )
    def process_ai_queue(self, account_id: int, max_batch: int = 30) -> dict:
        """
        Per-account AI scheduler. It claims pending messages and fans them out into
        per-message tasks, while per-message DB/cache locks prevent duplicate work.
        """
        from django.conf import settings

        from apps.gmail.models import EmailMessage
        from apps.gmail.services.sync import ANALYSIS_VERSION

        max_batch_setting = int(getattr(settings, "AI_QUEUE_MAX_BATCH", 30))
        max_batch = max(1, min(int(max_batch or max_batch_setting), max_batch_setting, 100))
        parallel_cap = max(1, int(getattr(settings, "AI_QUEUE_MAX_PARALLEL_PER_ACCOUNT", 2)))
        time_budget_seconds = max(1.0, float(getattr(settings, "AI_MESSAGE_TIME_BUDGET_SECONDS", 30)))
        stale_after_seconds = max(
            1,
            int(getattr(settings, "AI_PROCESSING_STALE_SECONDS", max(90, int(time_budget_seconds * 3)))),
        )

        cutoff = timezone.now() - timedelta(seconds=stale_after_seconds)
        recovered_processing = EmailMessage.objects.filter(
            account_id=account_id,
            analysis_status="processing",
            synced_at__lt=cutoff,
        ).update(
            analysis_status="pending_ai",
            analysisSource="AI pending",
            analysis_done=False,
        )

        processing = EmailMessage.objects.filter(account_id=account_id, analysis_status="processing").count()
        slots = max(0, parallel_cap - processing)
        claimed_ids: list[int] = []
        if slots:
            claim_limit = min(max_batch, slots)
            with transaction.atomic():
                messages = list(
                    EmailMessage.objects.select_for_update(skip_locked=True)
                    .filter(account_id=account_id)
                    .exclude(analysis_status="done")
                    .exclude(analysis_status="processing")
                    .order_by("-date", "id")[:claim_limit]
                )
                for message in messages:
                    message.analysis_status = "processing"
                    message.analysisSource = "AI pending"
                    message.analysis_done = False
                    message.analysisVersion = ANALYSIS_VERSION
                    message.save(
                        update_fields=[
                            "analysis_status",
                            "analysisSource",
                            "analysis_done",
                            "analysisVersion",
                            "synced_at",
                        ]
                    )
                    claimed_ids.append(message.id)

        for message_id in claimed_ids:
            analyze_pending_email.apply_async(args=[message_id], queue="ai")

        remaining = EmailMessage.objects.filter(account_id=account_id).exclude(analysis_status="done").count()
        return {
            "state": "scheduled" if claimed_ids else "idle",
            "account_id": account_id,
            "claimed": len(claimed_ids),
            "processing": processing + len(claimed_ids),
            "recovered_processing": recovered_processing,
            "remaining": remaining,
        }
    @shared_task(name="gmail.sync_all_accounts")
    def sync_all_accounts() -> None:
        """
        Periodic task: sync every active EmailAccount.
        Schedule in Celery Beat settings:

            CELERY_BEAT_SCHEDULE = {
                "sync-all-gmail": {
                    "task": "gmail.sync_all_accounts",
                    "schedule": crontab(minute="*/15"),
                },
            }
        """
        from apps.gmail.models import EmailAccount

        accounts = EmailAccount.objects.filter(is_active=True)
        logger.info("Scheduling sync for %d accounts", accounts.count())
        for account in accounts:
            sync_gmail_account.delay(account.id)

    @shared_task(name="gmail.sync_due_accounts")
    def sync_due_accounts() -> dict:
        from datetime import timedelta

        from django.utils import timezone

        from apps.gmail.models import EmailAccount
        from apps.licenses.services import get_active_activation_for_user, get_plan_capabilities

        checked = 0
        queued = 0
        now = timezone.now()
        accounts = EmailAccount.objects.select_related("user").filter(is_active=True)
        for account in accounts:
            checked += 1
            activation = get_active_activation_for_user(account.user)
            if not activation:
                continue
            caps = get_plan_capabilities(activation.license_key.plan)
            if not caps.get("autoMonitor"):
                continue

            interval_minutes = int(caps.get("autoMonitorIntervalMinutes") or 0)
            if interval_minutes <= 0:
                continue
            if account.last_synced_at and account.last_synced_at > now - timedelta(minutes=interval_minutes):
                continue

            sync_gmail_account.delay(
                account.id,
                int(caps["maxMessagesPerRun"]),
                int(caps["recentLookbackDays"]),
                bool(caps["priorityAi"]),
            )
            queued += 1

        return {"checked": checked, "queued": queued}

except ImportError:
    # Celery not installed — tasks module is a no-op
    logger.debug("Celery not available; gmail.tasks disabled")

