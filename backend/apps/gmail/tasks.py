"""
apps/gmail/tasks.py

Celery tasks for async Gmail operations.
If Celery is not configured, these are never called
(views.py falls back to inline sync).
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

try:
    from celery import shared_task

    @shared_task(
        bind=True,
        max_retries=3,
        default_retry_delay=60,
        name="gmail.sync_account",
    )
    def sync_gmail_account(self, account_id: int) -> dict:
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
            return sync_account(account)
        except Exception as exc:
            logger.exception("Sync task failed for account %d: %s", account_id, exc)
            raise self.retry(exc=exc)

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

except ImportError:
    # Celery not installed — tasks module is a no-op
    logger.debug("Celery not available; gmail.tasks disabled")
