from rest_framework import serializers

from .models import ThreatAssessment


class ThreatAssessmentSerializer(serializers.ModelSerializer):
    """Field names/shape match what `EmailDetail.tsx` and `Dashboard.tsx`
    read directly off `EmailAnalysis`:

        aiScore, domainScore, threatScore, riskLevel

    plus the static weight labels ("70%" / "30%") so the frontend doesn't
    need to hardcode them either.
    """

    aiScore = serializers.IntegerField(source="ai_score")
    domainScore = serializers.IntegerField(source="domain_score")
    threatScore = serializers.IntegerField(source="threat_score")
    riskLevel = serializers.CharField(source="risk_level")

    aiScoreWeight = serializers.SerializerMethodField()
    domainScoreWeight = serializers.SerializerMethodField()

    class Meta:
        model = ThreatAssessment
        fields = [
            "aiScore",
            "aiScoreWeight",
            "domainScore",
            "domainScoreWeight",
            "threatScore",
            "riskLevel",
        ]

    def get_aiScoreWeight(self, obj) -> str:
        return "70%"

    def get_domainScoreWeight(self, obj) -> str:
        return "30%"
