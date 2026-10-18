from __future__ import annotations

import logging

from django.core.cache import cache

logger = logging.getLogger(__name__)


def enqueue_ai_queue(
    account_id: int,
    *,
    max_batch: int | None = None,
    priority_ai: bool = False,
    countdown: int = 0,
    debounce_seconds: int = 2,
    force: bool = False,
) -> bool:
    """
    Queue the per-account AI scheduler with a short debounce.

    The scheduler itself claims rows with DB locks, so the debounce is only a
    queue-storm guard for views/status polling.
    """
    if not account_id:
        return False

    cache_key = f"gmail:ai-queue:account:{account_id}"
    if not force and debounce_seconds > 0 and not cache.add(cache_key, "1", debounce_seconds):
        return False

    try:
        from apps.gmail.tasks import process_ai_queue

        kwargs = {}
        if max_batch is not None:
            kwargs["max_batch"] = max_batch
        process_ai_queue.apply_async(
            args=[account_id],
            kwargs=kwargs,
            countdown=max(0, int(countdown or 0)),
            queue="ai",
            priority=9 if priority_ai else 5,
        )
        return True
    except Exception as exc:
        logger.debug("Could not enqueue AI queue for account %s: %s", account_id, exc)
        cache.delete(cache_key)
        return False
