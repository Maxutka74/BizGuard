from rest_framework import serializers
from django.core.exceptions import ObjectDoesNotExist

from .models import User


class UserSerializer(serializers.ModelSerializer):
    first_name = serializers.SerializerMethodField()
    last_name = serializers.SerializerMethodField()
    picture = serializers.CharField(source="avatar_url", allow_null=True)
    license = serializers.SerializerMethodField()
    gmailConnected = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "first_name",
            "last_name",
            "picture",
            "gmailConnected",
            "license",
        )

    def get_first_name(self, obj):
        if not obj.name:
            return ""
        return obj.name.split(" ")[0]

    def get_last_name(self, obj):
        if not obj.name:
            return ""
        parts = obj.name.split(" ")
        return " ".join(parts[1:]) if len(parts) > 1 else ""

    def get_license(self, obj):
        from apps.licenses.services import get_license_status_for_user

        return get_license_status_for_user(obj)

    def get_gmailConnected(self, obj):
        try:
            return bool(obj.email_account.is_active)
        except (AttributeError, ObjectDoesNotExist):
            return False


class GoogleAuthCallbackSerializer(serializers.Serializer):
    """Payload sent by BizGuard app after Google OAuth redirect/callback."""
    code = serializers.CharField()
    redirect_uri = serializers.CharField(required=False)
    license_gate_token = serializers.CharField(required=False, allow_blank=True)


class GooglePublicAuthCallbackSerializer(serializers.Serializer):
    """Payload sent by purchase site after public Google OAuth redirect/callback."""
    code = serializers.CharField()
    redirect_uri = serializers.CharField(required=False)


class TokenResponseSerializer(serializers.Serializer):
    """Response shape returned to frontend after successful auth."""
    access = serializers.CharField()
    refresh = serializers.CharField()
    user = UserSerializer()


