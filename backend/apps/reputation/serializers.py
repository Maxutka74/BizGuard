from rest_framework import serializers


class DomainReputationSerializer(serializers.Serializer):
    """
    Serializes the reputation service response into the exact shape
    the BizGuard frontend expects for the EmailDetail domain analysis section.
    """

    domain = serializers.CharField()
    domainAge = serializers.CharField()
    domainReputation = serializers.ChoiceField(
        choices=["Trusted", "Suspicious", "Malicious"]
    )
    domainScore = serializers.IntegerField(min_value=0, max_value=100)
    lookalikeDomain = serializers.CharField(allow_null=True)
    cached = serializers.BooleanField(default=False)
    error = serializers.CharField(allow_null=True, required=False)


class BulkDomainRequestSerializer(serializers.Serializer):
    """Validates request body for the bulk lookup endpoint."""

    domains = serializers.ListField(
        child=serializers.CharField(max_length=253),
        min_length=1,
        max_length=50,
    )
    force_refresh = serializers.BooleanField(default=False, required=False)


class BulkDomainResponseSerializer(serializers.Serializer):
    """Wraps a list of DomainReputationSerializer results."""

    results = DomainReputationSerializer(many=True)
    total = serializers.IntegerField()
