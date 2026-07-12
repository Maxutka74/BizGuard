"""
API views for the domain reputation module.

Endpoints consumed by the BizGuard frontend:

  GET  /api/reputation/<domain>/       → single domain lookup
  POST /api/reputation/bulk/           → batch lookup (up to 50 domains)
  GET  /api/reputation/<domain>/raw/   → raw VirusTotal stats (debug / admin)

The single-domain endpoint is the primary one: it is called by the email
analysis pipeline and the EmailDetail component indirectly (via the
analysis result that already embeds domainReputation, domainScore, etc.).
"""

import logging

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import DomainReputation
from .serializers import (
    BulkDomainRequestSerializer,
    BulkDomainResponseSerializer,
    DomainReputationSerializer,
)
from .service import get_domain_reputation

logger = logging.getLogger(__name__)


class DomainReputationView(APIView):
    """
    GET /api/reputation/<domain>/

    Returns domain reputation data normalized to the frontend contract.
    Accepts optional query param `?refresh=true` to bypass the cache.

    Response 200:
    {
        "domain":           "paypa1-support.com",
        "domainAge":        "4 days",
        "domainReputation": "Malicious",
        "domainScore":      96,
        "lookalikeDomain":  "paypal.com",
        "cached":           false,
        "error":            null
    }
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request, domain: str) -> Response:
        force_refresh = request.query_params.get("refresh", "").lower() == "true"

        result = get_domain_reputation(domain, force_refresh=force_refresh)

        serializer = DomainReputationSerializer(result)
        return Response(serializer.data, status=status.HTTP_200_OK)


class BulkDomainReputationView(APIView):
    """
    POST /api/reputation/bulk/

    Accepts up to 50 domains and returns reputation data for each.
    Used by the email analysis pipeline to check multiple sender domains
    in a single request without blocking the main thread sequentially.

    Request body:
    {
        "domains": ["paypa1-support.com", "google.com", ...],
        "force_refresh": false
    }

    Response 200:
    {
        "total": 2,
        "results": [
            { "domain": "paypa1-support.com", "domainReputation": "Malicious", ... },
            { "domain": "google.com", "domainReputation": "Trusted", ... }
        ]
    }
    """

    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        req_serializer = BulkDomainRequestSerializer(data=request.data)
        if not req_serializer.is_valid():
            return Response(req_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        domains: list[str] = req_serializer.validated_data["domains"]
        force_refresh: bool = req_serializer.validated_data.get("force_refresh", False)

        results = []
        for domain in domains:
            result = get_domain_reputation(domain, force_refresh=force_refresh)
            results.append(result)

        response_data = {"total": len(results), "results": results}
        serializer = BulkDomainResponseSerializer(response_data)
        return Response(serializer.data, status=status.HTTP_200_OK)


class DomainReputationRawView(APIView):
    """
    GET /api/reputation/<domain>/raw/

    Returns the raw cached VirusTotal stats for debugging and admin dashboards.
    Not consumed directly by the frontend — useful for IT security teams.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request, domain: str) -> Response:
        try:
            obj = DomainReputation.objects.get(domain=domain.lower())
        except DomainReputation.DoesNotExist:
            return Response(
                {"detail": f"No cached reputation data for '{domain}'."},
                status=status.HTTP_404_NOT_FOUND,
            )

        data = {
            "domain": obj.domain,
            "domainAge": obj.domain_age,
            "domainReputation": obj.reputation,
            "domainScore": obj.domain_score,
            "lookalikeDomain": obj.lookalike_domain,
            "cachedAt": obj.fetched_at.isoformat(),
            "isStale": obj.is_stale(),
            "virustotal": {
                "malicious": obj.vt_malicious,
                "suspicious": obj.vt_suspicious,
                "harmless": obj.vt_harmless,
                "undetected": obj.vt_undetected,
                "communityVotesMalicious": obj.vt_total_votes_malicious,
                "communityVotesHarmless": obj.vt_total_votes_harmless,
                "reputation": obj.vt_reputation,
                "creationDate": (
                    obj.vt_creation_date.isoformat() if obj.vt_creation_date else None
                ),
            },
        }
        return Response(data, status=status.HTTP_200_OK)
