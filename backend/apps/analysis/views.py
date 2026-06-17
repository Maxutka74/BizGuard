"""
API views for apps/analysis.

Endpoints
---------
POST /api/analysis/analyse/
    Analyse an email with Gemini. Returns full AIAnalysisResult.
    - If a cached result exists for this gmail_message_id it is returned
      immediately (no Gemini call).
    - Pass ?force=true to bypass cache and re-analyse.

GET  /api/analysis/<gmail_message_id>/
    Retrieve a previously cached analysis result.

GET  /api/analysis/batch/
    Accept a JSON body with {"ids": [...]} and return cached results for
    multiple message IDs in one call (used by the Dashboard to populate
    the email list with risk levels without N separate requests).
"""

from __future__ import annotations

import logging

from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from .gemini_service import (
    analyse_email,
    compute_threat_score,
    score_to_risk_level,
)
from .models import EmailAnalysisResult
from .serializers import AIAnalysisResultSerializer, AnalyseEmailRequestSerializer

logger = logging.getLogger(__name__)


class AnalyseEmailView(APIView):
    """
    POST /api/analysis/analyse/

    Request body:
        {
            "gmail_message_id": "18f3a...",
            "subject":          "URGENT: Your account...",
            "sender":           "support@fake.com",
            "body":             "Dear customer ...",
            "domain_score":     85          // from apps/reputation
        }

    Response 200 (cache hit):
        { ...AIAnalysisResult fields... }

    Response 201 (newly analysed):
        { ...AIAnalysisResult fields... }

    Query params:
        force=true  — bypass cache and re-run Gemini analysis
    """

    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        serializer = AnalyseEmailRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        message_id = data["gmail_message_id"]
        force = request.query_params.get("force", "").lower() == "true"

        # --- Cache check --------------------------------------------------
        if not force:
            try:
                cached = EmailAnalysisResult.objects.get(
                    gmail_message_id=message_id
                )
                logger.debug("Cache hit for message_id=%s", message_id)
                return Response(
                    AIAnalysisResultSerializer(cached).data,
                    status=status.HTTP_200_OK,
                )
            except EmailAnalysisResult.DoesNotExist:
                pass

        # --- Gemini analysis ----------------------------------------------
        logger.info("Running Gemini analysis for message_id=%s", message_id)
        result = analyse_email(
            subject=data["subject"],
            sender=data["sender"],
            body=data["body"],
        )

        domain_score: int = data["domain_score"]
        threat_score = compute_threat_score(result.ai_score, domain_score)
        risk_level = score_to_risk_level(threat_score)

        # --- Persist / update cache entry ---------------------------------
        obj, created = EmailAnalysisResult.objects.update_or_create(
            gmail_message_id=message_id,
            defaults={
                "urgency": result.urgency,
                "fear": result.fear,
                "credential_theft": result.credential_theft,
                "financial_fraud": result.financial_fraud,
                "authority_impersonation": result.authority_impersonation,
                "ai_summary": result.ai_summary,
                "ai_score": result.ai_score,
                "domain_score": domain_score,
                "threat_score": threat_score,
                "risk_level": risk_level,
            },
        )

        return Response(
            AIAnalysisResultSerializer(obj).data,
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class AnalysisDetailView(APIView):
    """
    GET /api/analysis/<gmail_message_id>/

    Returns a cached analysis result. 404 if not yet analysed.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request: Request, gmail_message_id: str) -> Response:
        obj = get_object_or_404(EmailAnalysisResult, gmail_message_id=gmail_message_id)
        return Response(AIAnalysisResultSerializer(obj).data)


class BatchAnalysisView(APIView):
    """
    POST /api/analysis/batch/

    Body: {"ids": ["id1", "id2", ...]}

    Returns a mapping { message_id: analysis_result } for IDs that have
    been analysed. IDs not yet in the cache are silently omitted — the
    caller should trigger /analyse/ for those.

    Used by the Dashboard to enrich the email list without N separate
    HTTP calls.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request: Request) -> Response:
        ids = request.data.get("ids", [])
        if not isinstance(ids, list):
            return Response(
                {"detail": "'ids' must be a list."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        results = EmailAnalysisResult.objects.filter(gmail_message_id__in=ids)
        mapping = {
            r.gmail_message_id: AIAnalysisResultSerializer(r).data
            for r in results
        }
        return Response(mapping)
