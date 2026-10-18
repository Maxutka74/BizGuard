from rest_framework import serializers


class LicenseKeyInputSerializer(serializers.Serializer):
    key = serializers.CharField(trim_whitespace=True, min_length=4, max_length=128)


class LicenseGateResponseSerializer(serializers.Serializer):
    gateToken = serializers.CharField()
    plan = serializers.CharField()
    planLabel = serializers.CharField()
    durationDays = serializers.IntegerField()
    capabilities = serializers.DictField()
    maxActivations = serializers.IntegerField()
    activationCount = serializers.IntegerField()
    remainingActivations = serializers.IntegerField()
    capacityFull = serializers.BooleanField()
    expiresInSeconds = serializers.IntegerField()


class LicenseStatusSerializer(serializers.Serializer):
    status = serializers.CharField()
    plan = serializers.CharField(allow_null=True)
    planLabel = serializers.CharField(allow_null=True)
    expiresAt = serializers.DateTimeField(allow_null=True)
    activatedAt = serializers.DateTimeField(allow_null=True)
    confirmationRequired = serializers.BooleanField()
    confirmationDueAt = serializers.DateTimeField(allow_null=True)
    lastConfirmedAt = serializers.DateTimeField(allow_null=True)
    capabilities = serializers.DictField()
    maxActivations = serializers.IntegerField(allow_null=True)
    activationCount = serializers.IntegerField()
    remainingActivations = serializers.IntegerField()
    capacityFull = serializers.BooleanField()
