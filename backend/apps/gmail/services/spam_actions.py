from __future__ import annotations

import logging

from apps.gmail.models import GMAIL_MODIFY_SCOPE
from apps.gmail.services.oauth import build_gmail_service

logger = logging.getLogger(__name__)

RECONNECT_REQUIRED_MESSAGE = (
    "Потрібно перепідключити Google для автоматичного перенесення критичних листів у спам, бо поточний доступ не має gmail.modify."
)


class GmailSpamActionError(Exception):
    pass


class GmailModifyScopeRequired(GmailSpamActionError):
    pass


def move_message_to_spam(email_account, gmail_id: str) -> dict:
    if not email_account.has_gmail_modify_scope:
        raise GmailModifyScopeRequired(RECONNECT_REQUIRED_MESSAGE)

    try:
        service = build_gmail_service(email_account)
        return (
            service.users()
            .messages()
            .modify(
                userId="me",
                id=gmail_id,
                body={
                    "addLabelIds": ["SPAM"],
                    "removeLabelIds": ["INBOX"],
                },
            )
            .execute()
        )
    except Exception as exc:
        if _is_scope_or_auth_error(exc):
            raise GmailModifyScopeRequired(RECONNECT_REQUIRED_MESSAGE) from exc
        logger.warning("Could not move Gmail message %s to spam: %s", gmail_id, exc)
        raise GmailSpamActionError(str(exc)) from exc


def _is_scope_or_auth_error(exc: Exception) -> bool:
    status = getattr(getattr(exc, "resp", None), "status", None)
    if status in {401, 403}:
        return True
    text = str(exc).lower()
    return "forbidden" in text or ("insufficient" in text and ("permission" in text or "scope" in text))

