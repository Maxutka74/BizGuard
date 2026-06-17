from rest_framework import serializers
from .models import User


class UserSerializer(serializers.ModelSerializer):
    first_name = serializers.SerializerMethodField()
    last_name = serializers.SerializerMethodField()
    picture = serializers.CharField(source="avatar_url", allow_null=True)

    class Meta:
        model = User
        fields = (
            "id",
            "email",
            "first_name",
            "last_name",
            "picture",
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


class GoogleAuthCallbackSerializer(serializers.Serializer):
    """Payload sent by frontend after Google OAuth redirect/callback."""
    code = serializers.CharField()
    redirect_uri = serializers.CharField(required=False)


class TokenResponseSerializer(serializers.Serializer):
    """Response shape returned to frontend after successful auth."""
    access = serializers.CharField()
    refresh = serializers.CharField()
    user = UserSerializer()
