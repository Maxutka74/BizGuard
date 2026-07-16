import base64
import hashlib
import secrets

import requests
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.db import transaction

from apps.licenses.models import LicenseKey, LicensePlan
from apps.licenses.services import LicenseServiceError, create_license_key

from .models import PurchaseOrder


MAX_ACTIVATIONS_PER_ORDER = 1000
PLAN_PRICES = {
    LicensePlan.FREE_1_DAY: {
        "base_amount": 0,
        "extra_seat_amount": 0,
        "currency": "uah",
        "label": "0 грн",
    },
    LicensePlan.HALF_YEAR: {
        "base_amount": 49900,
        "extra_seat_amount": 5000,
        "currency": "uah",
        "label": "499 грн",
    },
    LicensePlan.YEAR: {
        "base_amount": 89900,
        "extra_seat_amount": 8000,
        "currency": "uah",
        "label": "899 грн",
    },
}


class BillingError(Exception):
    def __init__(self, code: str, detail: str):
        self.code = code
        self.detail = detail
        super().__init__(detail)


def encrypt_license_key(plaintext: str) -> str:
    """Encrypt a purchased key for owner-only recovery in the billing profile."""
    return _license_cipher().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_license_key(ciphertext: str) -> str | None:
    """Return the purchased key or None for legacy/unreadable records."""
    if not ciphertext:
        return None
    try:
        return _license_cipher().decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeError, ValueError):
        return None


def _license_cipher() -> Fernet:
    secret = settings.BILLING_LICENSE_ENCRYPTION_SECRET
    derived_key = hashlib.sha256(secret.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(derived_key))


def plan_catalog() -> list[dict]:
    return [
        {
            "plan": plan.value,
            "price": price_quote(plan.value, 1),
        }
        for plan in LicensePlan
    ]


def price_quote(plan: str, activation_count: int) -> dict:
    plan_enum, activation_count = _validate_plan_and_activation_count(plan, activation_count)
    price = PLAN_PRICES[plan_enum]
    base_amount = price["base_amount"]
    unit_extra = price["extra_seat_amount"]
    extra_seats = max(0, activation_count - 1)
    extra_amount = extra_seats * unit_extra
    total = base_amount + extra_amount
    return {
        "amount": total,
        "baseAmount": base_amount,
        "extraSeatAmount": extra_amount,
        "unitExtraSeatAmount": unit_extra,
        "activationCount": activation_count,
        "currency": price["currency"],
        "label": price["label"],
    }


def create_checkout(user, plan: str, activation_count: int = 1) -> dict:
    plan_enum, activation_count = _validate_plan_and_activation_count(plan, activation_count)
    quote = price_quote(plan_enum.value, activation_count)
    order = PurchaseOrder.objects.create(
        user=user,
        plan=plan_enum.value,
        amount=quote["amount"],
        base_amount=quote["baseAmount"],
        extra_seat_amount=quote["extraSeatAmount"],
        unit_extra_seat_amount=quote["unitExtraSeatAmount"],
        activation_count=activation_count,
        currency=quote["currency"],
    )

    if quote["amount"] == 0:
        return _create_direct_checkout(order)

    if settings.BILLING_FAKE_MODE:
        return _create_direct_checkout(order)

    if not settings.STRIPE_SECRET_KEY:
        raise BillingError("stripe_not_configured", "Stripe key не налаштований.")

    success_url = settings.PURCHASE_SITE_URL.rstrip("/") + "/payment/success?session_id={CHECKOUT_SESSION_ID}"
    cancel_url = settings.PURCHASE_SITE_URL.rstrip("/") + "/payment/cancel"
    payload = {
        "mode": "payment",
        "success_url": success_url,
        "cancel_url": cancel_url,
        "client_reference_id": str(order.id),
        "metadata[order_id]": str(order.id),
        "metadata[plan]": plan_enum.value,
        "metadata[activation_count]": str(activation_count),
        "line_items[0][quantity]": "1",
        "line_items[0][price_data][currency]": quote["currency"],
        "line_items[0][price_data][unit_amount]": str(quote["baseAmount"]),
        "line_items[0][price_data][product_data][name]": _plan_name(plan_enum.value),
    }
    if activation_count > 1:
        payload.update(
            {
                "line_items[1][quantity]": str(activation_count - 1),
                "line_items[1][price_data][currency]": quote["currency"],
                "line_items[1][price_data][unit_amount]": str(quote["unitExtraSeatAmount"]),
                "line_items[1][price_data][product_data][name]": "Додаткова активація BizGuard",
            }
        )

    resp = requests.post(
        "https://api.stripe.com/v1/checkout/sessions",
        data=payload,
        auth=(settings.STRIPE_SECRET_KEY, ""),
        timeout=15,
    )
    if resp.status_code >= 400:
        order.status = PurchaseOrder.Status.FAILED
        order.save(update_fields=["status", "updated_at"])
        raise BillingError("stripe_checkout_failed", "Stripe Checkout не створив платіжну сесію.")

    data = resp.json()
    order.provider_session_id = data["id"]
    order.save(update_fields=["provider_session_id", "updated_at"])
    return {
        "checkoutUrl": data["url"],
        "sessionId": data["id"],
        "orderId": str(order.id),
        "fakeMode": False,
        "price": quote,
    }


@transaction.atomic
def complete_checkout(user, session_id: str) -> dict:
    order = (
        PurchaseOrder.objects.select_for_update()
        .filter(user=user, provider_session_id=session_id)
        .first()
    )
    if not order:
        raise BillingError("order_not_found", "Замовлення не знайдено.")

    if order.generated_license_key:
        return {
            "order": order,
            "plaintextKey": decrypt_license_key(order.encrypted_license_key),
            "alreadyCompleted": True,
        }

    if not settings.BILLING_FAKE_MODE and not session_id.startswith("direct_"):
        _verify_stripe_paid(session_id)

    order.mark_paid()
    try:
        plaintext, license_key = create_license_key(
            order.plan,
            max_activations=order.activation_count,
            note=f"Purchase order {order.id}",
        )
    except LicenseServiceError as exc:
        raise BillingError(exc.code, exc.detail)

    order.generated_license_key = license_key
    order.encrypted_license_key = encrypt_license_key(plaintext)
    order.save(
        update_fields=[
            "status",
            "paid_at",
            "generated_license_key",
            "encrypted_license_key",
            "updated_at",
        ]
    )
    return {"order": order, "plaintextKey": plaintext, "alreadyCompleted": False}


@transaction.atomic
def reissue_legacy_key(user, order_id) -> dict:
    """
    Replace a legacy, unrecoverable key only when it has never been activated.

    The old hash-only key is disabled so both keys can never be valid at once.
    """
    order = (
        PurchaseOrder.objects.select_for_update()
        .filter(id=order_id, user=user)
        .first()
    )
    if not order:
        raise BillingError("order_not_found", "Замовлення не знайдено.")
    if order.status != PurchaseOrder.Status.PAID or not order.generated_license_key:
        raise BillingError(
            "license_not_issued",
            "Для цього замовлення ще немає оплаченого ключа.",
        )

    existing_plaintext = decrypt_license_key(order.encrypted_license_key)
    if existing_plaintext:
        return {"order": order, "plaintextKey": existing_plaintext, "reissued": False}
    if order.encrypted_license_key:
        raise BillingError(
            "license_decryption_failed",
            "Ключ не вдалося розшифрувати. Зверніться до адміністратора.",
        )

    old_key = LicenseKey.objects.select_for_update().get(pk=order.generated_license_key_id)
    if old_key.activation_count > 0:
        raise BillingError(
            "legacy_key_already_activated",
            "Старий ключ уже активували, тому автоматичне перевидання може позбавити користувачів доступу.",
        )

    try:
        plaintext, replacement = create_license_key(
            order.plan,
            max_activations=order.activation_count,
            note=f"Reissued for purchase order {order.id}",
        )
    except LicenseServiceError as exc:
        raise BillingError(exc.code, exc.detail)

    old_key.active = False
    old_key.save(update_fields=["active", "updated_at"])
    order.generated_license_key = replacement
    order.encrypted_license_key = encrypt_license_key(plaintext)
    order.save(update_fields=["generated_license_key", "encrypted_license_key", "updated_at"])
    return {"order": order, "plaintextKey": plaintext, "reissued": True}


def _create_direct_checkout(order: PurchaseOrder) -> dict:
    session_id = f"direct_{order.id}_{secrets.token_urlsafe(8)}"
    order.provider_session_id = session_id
    order.save(update_fields=["provider_session_id", "updated_at"])
    return {
        "checkoutUrl": settings.PURCHASE_SITE_URL.rstrip("/") + f"/payment/success?session_id={session_id}",
        "sessionId": session_id,
        "orderId": str(order.id),
        "fakeMode": True,
        "price": {
            "amount": order.amount,
            "baseAmount": order.base_amount,
            "extraSeatAmount": order.extra_seat_amount,
            "unitExtraSeatAmount": order.unit_extra_seat_amount,
            "activationCount": order.activation_count,
            "currency": order.currency,
        },
    }


def _verify_stripe_paid(session_id: str) -> None:
    if not settings.STRIPE_SECRET_KEY:
        raise BillingError("stripe_not_configured", "Stripe key не налаштований.")
    resp = requests.get(
        f"https://api.stripe.com/v1/checkout/sessions/{session_id}",
        auth=(settings.STRIPE_SECRET_KEY, ""),
        timeout=15,
    )
    if resp.status_code >= 400:
        raise BillingError("stripe_session_failed", "Не вдалося перевірити Stripe-сесію.")
    data = resp.json()
    if data.get("payment_status") != "paid":
        raise BillingError("payment_not_paid", "Оплату ще не підтверджено.")


def _validate_plan_and_activation_count(plan: str, activation_count: int) -> tuple[LicensePlan, int]:
    if plan not in LicensePlan.values:
        raise BillingError("invalid_plan", "Невідомий тариф.")
    try:
        activation_count = int(activation_count)
    except (TypeError, ValueError):
        raise BillingError("invalid_activation_count", "Кількість активацій має бути числом.")
    if activation_count < 1:
        raise BillingError("invalid_activation_count", "Кількість активацій має бути не меншою за 1.")
    if activation_count > MAX_ACTIVATIONS_PER_ORDER:
        raise BillingError("activation_count_too_large", "Максимум 1000 активацій на одне замовлення.")
    plan_enum = LicensePlan(plan)
    if plan_enum == LicensePlan.FREE_1_DAY and activation_count != 1:
        raise BillingError(
            "free_plan_single_activation_only",
            "Безкоштовний тариф доступний лише для однієї активації.",
        )
    return plan_enum, activation_count


def _plan_name(plan: str) -> str:
    return {
        "free_1_day": "BizGuard Free на 1 день",
        "half_year": "BizGuard Пів року",
        "year": "BizGuard Рік",
    }.get(plan, "BizGuard license")
