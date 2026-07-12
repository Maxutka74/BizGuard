from rest_framework import serializers

from .models import PurchaseOrder
from .services import MAX_ACTIVATIONS_PER_ORDER


PLAN_LABELS = {
    "free_1_day": "Free на 1 день",
    "half_year": "Пів року",
    "year": "Рік",
}


class CheckoutSerializer(serializers.Serializer):
    plan = serializers.ChoiceField(choices=["free_1_day", "half_year", "year"])
    activationCount = serializers.IntegerField(min_value=1, max_value=MAX_ACTIVATIONS_PER_ORDER, required=False, default=1)


class CompleteCheckoutSerializer(serializers.Serializer):
    sessionId = serializers.CharField()


class PurchaseOrderSerializer(serializers.ModelSerializer):
    planLabel = serializers.SerializerMethodField()
    generatedLicense = serializers.SerializerMethodField()
    activationCount = serializers.IntegerField(source="activation_count", read_only=True)
    baseAmount = serializers.IntegerField(source="base_amount", read_only=True)
    extraSeatAmount = serializers.IntegerField(source="extra_seat_amount", read_only=True)
    unitExtraSeatAmount = serializers.IntegerField(source="unit_extra_seat_amount", read_only=True)
    createdAt = serializers.DateTimeField(source="created_at", read_only=True)
    paidAt = serializers.DateTimeField(source="paid_at", read_only=True)

    class Meta:
        model = PurchaseOrder
        fields = (
            "id",
            "plan",
            "planLabel",
            "provider",
            "provider_session_id",
            "status",
            "amount",
            "baseAmount",
            "extraSeatAmount",
            "unitExtraSeatAmount",
            "activationCount",
            "currency",
            "generatedLicense",
            "createdAt",
            "paidAt",
        )

    def get_planLabel(self, obj):
        return PLAN_LABELS.get(obj.plan, obj.plan)

    def get_generatedLicense(self, obj):
        key = obj.generated_license_key
        if not key:
            return None
        return {
            "keyPrefix": key.key_prefix,
            "plan": key.plan,
            "planLabel": PLAN_LABELS.get(key.plan, key.get_plan_display()),
            "maxActivations": key.max_activations,
            "activationCount": key.activation_count,
            "remainingActivations": key.remaining_activations,
        }