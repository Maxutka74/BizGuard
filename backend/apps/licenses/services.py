import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import timedelta

from django.conf import settings
from django.core import signing
from django.db import IntegrityError, transaction
from django.utils import timezone

from .models import LicenseActivation, LicenseKey, LicensePlan, PLAN_DURATION_DAYS

GATE_TOKEN_SALT = "apps.licenses.gate-token"
KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
CONFIRMATION_INTERVAL_DAYS = 30

PLAN_CAPABILITIES = {
    LicensePlan.FREE_1_DAY: {
        "manualScan": True,
        "autoMonitor": False,
        "autoMonitorIntervalMinutes": None,
        "recentLookbackDays": 1,
        "maxMessagesPerRun": 5,
        "maxUrlsPerEmail": 3,
        "maxAttachmentsPerEmail": 1,
        "priorityAi": False,
        "criticalAlerts": False,
        "monthlyConfirmation": False,
        "autoSpamCritical": False,
        "spamActionAudit": False,
        "trustedSenderAllowlist": False,
        "priorityRecheck": False,
    },
    LicensePlan.HALF_YEAR: {
        "manualScan": True,
        "autoMonitor": True,
        "autoMonitorIntervalMinutes": 30,
        "recentLookbackDays": 7,
        "maxMessagesPerRun": 15,
        "maxUrlsPerEmail": 6,
        "maxAttachmentsPerEmail": 3,
        "priorityAi": False,
        "criticalAlerts": True,
        "monthlyConfirmation": True,
        "autoSpamCritical": True,
        "spamActionAudit": True,
        "trustedSenderAllowlist": False,
        "priorityRecheck": False,
    },
    LicensePlan.YEAR: {
        "manualScan": True,
        "autoMonitor": True,
        "autoMonitorIntervalMinutes": 15,
        "recentLookbackDays": 14,
        "maxMessagesPerRun": 30,
        "maxUrlsPerEmail": 15,
        "maxAttachmentsPerEmail": 8,
        "priorityAi": True,
        "criticalAlerts": True,
        "monthlyConfirmation": True,
        "autoSpamCritical": True,
        "spamActionAudit": True,
        "trustedSenderAllowlist": True,
        "priorityRecheck": True,
    },
}


@dataclass
class LicenseServiceError(Exception):
    code: str
    detail: str


def normalize_license_key(raw_key: str) -> str:
    return "".join(ch for ch in raw_key.upper().strip() if ch.isalnum())


def hash_license_key(raw_key: str) -> str:
    normalized = normalize_license_key(raw_key)
    secret = settings.LICENSE_KEY_HASH_SECRET.encode("utf-8")
    return hmac.new(secret, normalized.encode("utf-8"), hashlib.sha256).hexdigest()


def generate_plaintext_key() -> str:
    body = "".join(secrets.choice(KEY_ALPHABET) for _ in range(16))
    grouped = "-".join(body[i : i + 4] for i in range(0, len(body), 4))
    return f"BG-{grouped}"


def create_license_key(plan: str, max_activations: int | None = None, note: str = ""):
    if plan not in LicensePlan.values:
        raise LicenseServiceError("invalid_plan", "Невідомий тариф ліцензії.")
    if max_activations is None:
        max_activations = 1
    max_activations = int(max_activations)
    if max_activations <= 0:
        raise LicenseServiceError("invalid_max_activations", "max_activations має бути не менше 1.")

    for _ in range(10):
        plaintext = generate_plaintext_key()
        normalized = normalize_license_key(plaintext)
        key_hash = hash_license_key(normalized)
        try:
            license_key = LicenseKey.objects.create(
                key_hash=key_hash,
                key_prefix=plaintext[:12],
                plan=plan,
                duration_days=PLAN_DURATION_DAYS[LicensePlan(plan)],
                max_activations=max_activations,
                note=note,
            )
            return plaintext, license_key
        except IntegrityError:
            continue

    raise LicenseServiceError("key_generation_failed", "Не вдалося згенерувати унікальний ліцензійний ключ.")


def find_license_key(raw_key: str) -> LicenseKey | None:
    normalized = normalize_license_key(raw_key)
    if not normalized:
        return None
    return LicenseKey.objects.filter(key_hash=hash_license_key(normalized)).first()


def validate_license_key(raw_key: str, *, require_capacity: bool = True) -> LicenseKey:
    license_key = find_license_key(raw_key)
    if not license_key:
        raise LicenseServiceError("invalid_key", "Ліцензійний ключ недійсний.")
    _ensure_key_is_enabled(license_key)
    if require_capacity:
        _ensure_key_has_capacity(license_key)
    return license_key


def create_gate_token(license_key: LicenseKey) -> str:
    return signing.dumps(
        {
            "key_hash": license_key.key_hash,
            "nonce": secrets.token_urlsafe(12),
        },
        salt=GATE_TOKEN_SALT,
        compress=True,
    )


def validate_gate_token(gate_token: str | None) -> LicenseKey:
    if not gate_token:
        raise LicenseServiceError("missing_gate_token", "Потрібен токен перевірки ліцензійного ключа.")

    max_age = getattr(settings, "LICENSE_GATE_TOKEN_MAX_AGE_SECONDS", 600)
    try:
        payload = signing.loads(gate_token, salt=GATE_TOKEN_SALT, max_age=max_age)
    except signing.SignatureExpired:
        raise LicenseServiceError("gate_token_expired", "Термін дії токена перевірки ліцензійного ключа завершився.")
    except signing.BadSignature:
        raise LicenseServiceError("invalid_gate_token", "Токен перевірки ліцензійного ключа недійсний.")

    key_hash = payload.get("key_hash")
    license_key = LicenseKey.objects.filter(key_hash=key_hash).first()
    if not license_key:
        raise LicenseServiceError("invalid_gate_token", "Токен перевірки ліцензійного ключа недійсний.")

    _ensure_key_is_enabled(license_key)
    return license_key


def activate_license_for_user(user, license_key: LicenseKey) -> LicenseActivation:
    existing = LicenseActivation.objects.filter(user=user, license_key=license_key).first()
    if existing:
        if existing.is_active and not activation_requires_confirmation(existing):
            return existing
        if existing.is_active and activation_requires_confirmation(existing):
            raise LicenseServiceError(
                "confirmation_required",
                "Цей ліцензійний ключ потрібно підтвердити для цього акаунта.",
            )
        raise LicenseServiceError(
            "key_already_used",
            "Цей ліцензійний ключ уже використовувався цим акаунтом.",
        )

    with transaction.atomic():
        locked_key = LicenseKey.objects.select_for_update().get(pk=license_key.pk)
        _ensure_key_is_enabled(locked_key)
        _ensure_key_has_capacity(locked_key)
        activated_at = timezone.now()
        expires_at = locked_key.expires_at_from(activated_at)
        confirmation_due_at = _next_confirmation_due_at(locked_key.plan, activated_at, expires_at)
        try:
            return LicenseActivation.objects.create(
                user=user,
                license_key=locked_key,
                activated_at=activated_at,
                last_confirmed_at=activated_at,
                confirmation_due_at=confirmation_due_at,
                expires_at=expires_at,
            )
        except IntegrityError:
            existing = LicenseActivation.objects.get(user=user, license_key=locked_key)
            if existing.is_active:
                return existing
            raise LicenseServiceError(
                "key_already_used",
                "Цей ліцензійний ключ уже використовувався цим акаунтом.",
            )


def get_active_activation_for_user(user) -> LicenseActivation | None:
    activation = get_unexpired_activation_for_user(user)
    if not activation or activation_requires_confirmation(activation):
        return None
    return activation


def get_unexpired_activation_for_user(user) -> LicenseActivation | None:
    if not user or not user.is_authenticated:
        return None
    return (
        LicenseActivation.objects.select_related("license_key")
        .filter(user=user, revoked=False, expires_at__gt=timezone.now())
        .order_by("-expires_at")
        .first()
    )


def get_license_status_for_user(user) -> dict:
    current = get_unexpired_activation_for_user(user)
    if current:
        if activation_requires_confirmation(current):
            return _status_payload("confirmation_required", current)
        return _status_payload("active", current)

    latest = (
        LicenseActivation.objects.select_related("license_key")
        .filter(user=user)
        .order_by("-expires_at")
        .first()
        if user and user.is_authenticated
        else None
    )
    if latest:
        status = "revoked" if latest.revoked else "expired"
        return _status_payload(status, latest)

    return {
        "status": "missing",
        "plan": None,
        "planLabel": None,
        "expiresAt": None,
        "activatedAt": None,
        "confirmationRequired": False,
        "confirmationDueAt": None,
        "lastConfirmedAt": None,
        "capabilities": get_plan_capabilities(None),
        "maxActivations": None,
        "activationCount": 0,
        "remainingActivations": 0,
        "capacityFull": False,
    }


def user_has_active_license(user) -> bool:
    return get_active_activation_for_user(user) is not None


def confirm_license_for_user(user, raw_key: str) -> LicenseActivation:
    activation = get_unexpired_activation_for_user(user)
    if not activation:
        latest = (
            LicenseActivation.objects.filter(user=user)
            .order_by("-expires_at")
            .first()
            if user and user.is_authenticated
            else None
        )
        if latest and latest.expires_at <= timezone.now():
            raise LicenseServiceError("expired_license", "Термін дії ліцензії завершився. Активуйте новий ключ.")
        raise LicenseServiceError("missing_license", "Немає активної ліцензії для підтвердження.")

    if not plan_requires_monthly_confirmation(activation.license_key.plan):
        return activation

    normalized_hash = hash_license_key(raw_key)
    if not hmac.compare_digest(normalized_hash, activation.license_key.key_hash):
        raise LicenseServiceError("invalid_confirmation_key", "Введіть той самий ліцензійний ключ, який використано для цього акаунта.")

    now = timezone.now()
    activation.last_confirmed_at = now
    activation.confirmation_due_at = _next_confirmation_due_at(
        activation.license_key.plan,
        now,
        activation.expires_at,
    )
    activation.save(update_fields=["last_confirmed_at", "confirmation_due_at"])
    return activation


def plan_requires_monthly_confirmation(plan: str) -> bool:
    return bool(get_plan_capabilities(plan).get("monthlyConfirmation"))


def activation_requires_confirmation(activation: LicenseActivation) -> bool:
    if not activation or not activation.is_active:
        return False
    if not plan_requires_monthly_confirmation(activation.license_key.plan):
        return False
    due_at = activation.confirmation_due_at or (
        (activation.last_confirmed_at or activation.activated_at) + timedelta(days=CONFIRMATION_INTERVAL_DAYS)
    )
    return due_at <= timezone.now()


def get_plan_capabilities(plan: str | None) -> dict:
    if plan in LicensePlan.values:
        return dict(PLAN_CAPABILITIES[LicensePlan(plan)])
    return {
        "manualScan": False,
        "autoMonitor": False,
        "autoMonitorIntervalMinutes": None,
        "recentLookbackDays": 1,
        "maxMessagesPerRun": 0,
        "maxUrlsPerEmail": 0,
        "maxAttachmentsPerEmail": 0,
        "priorityAi": False,
        "criticalAlerts": False,
        "monthlyConfirmation": False,
        "autoSpamCritical": False,
        "spamActionAudit": False,
        "trustedSenderAllowlist": False,
        "priorityRecheck": False,
    }


def get_license_plans() -> list[dict]:
    return [
        {
            "plan": plan.value,
            "planLabel": plan.label,
            "durationDays": PLAN_DURATION_DAYS[plan],
            "capabilities": get_plan_capabilities(plan.value),
        }
        for plan in LicensePlan
    ]


def get_user_capabilities(user) -> dict:
    activation = get_active_activation_for_user(user)
    if not activation:
        return get_plan_capabilities(None)
    return get_plan_capabilities(activation.license_key.plan)


def license_key_preview(license_key: LicenseKey) -> dict:
    return {
        "plan": license_key.plan,
        "planLabel": license_key.get_plan_display(),
        "durationDays": license_key.duration_days,
        "capabilities": get_plan_capabilities(license_key.plan),
        "maxActivations": license_key.max_activations,
        "activationCount": license_key.activation_count,
        "remainingActivations": license_key.remaining_activations,
        "capacityFull": not license_key.has_activation_capacity,
    }


def _ensure_key_is_enabled(license_key: LicenseKey) -> None:
    if not license_key.active:
        raise LicenseServiceError("disabled_key", "Ліцензійний ключ вимкнено.")


def _ensure_key_has_capacity(license_key: LicenseKey) -> None:
    if not license_key.has_activation_capacity:
        raise LicenseServiceError("activation_limit_reached", "Ліміт активацій цього ліцензійного ключа вичерпано.")


def _status_payload(status: str, activation: LicenseActivation) -> dict:
    return {
        "status": status,
        "plan": activation.license_key.plan,
        "planLabel": activation.license_key.get_plan_display(),
        "expiresAt": activation.expires_at.isoformat(),
        "activatedAt": activation.activated_at.isoformat(),
        "confirmationRequired": status == "confirmation_required",
        "confirmationDueAt": _confirmation_due_at_for_payload(activation),
        "lastConfirmedAt": activation.last_confirmed_at.isoformat() if activation.last_confirmed_at else None,
        "capabilities": get_plan_capabilities(activation.license_key.plan),
        "maxActivations": activation.license_key.max_activations,
        "activationCount": activation.license_key.activation_count,
        "remainingActivations": activation.license_key.remaining_activations,
        "capacityFull": not activation.license_key.has_activation_capacity,
    }


def _next_confirmation_due_at(plan: str, confirmed_at, expires_at):
    if not plan_requires_monthly_confirmation(plan):
        return None
    next_due = confirmed_at + timedelta(days=CONFIRMATION_INTERVAL_DAYS)
    return min(next_due, expires_at)


def _confirmation_due_at_for_payload(activation: LicenseActivation):
    due_at = activation.confirmation_due_at
    if not due_at and plan_requires_monthly_confirmation(activation.license_key.plan):
        due_at = _next_confirmation_due_at(
            activation.license_key.plan,
            activation.last_confirmed_at or activation.activated_at,
            activation.expires_at,
        )
    return due_at.isoformat() if due_at else None

