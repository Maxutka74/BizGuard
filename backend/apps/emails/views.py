"""
Email REST views.

Endpoints consumed by the frontend:
  GET  /api/emails/                  → inbox list
  GET  /api/emails/<id>/             → email detail
  POST /api/emails/<id>/mark-read/   → mark as read
  GET  /api/emails/search/           → search emails
  POST /api/emails/ingest/           → internal: receive parsed email from Gmail sync
"""

import logging
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from rest_framework.views import APIView
from django.db.models import Q

from .models import Email, Attachment
from .serializers import (
    EmailListSerializer,
    EmailDetailSerializer,
    GmailMessageIngestSerializer,
)
from .parsers import parse_gmail_message, parse_attachments_from_gmail
from .services import EmailNormalizationService

logger = logging.getLogger(__name__)


class EmailViewSet(ModelViewSet):
    """
    Primary viewset for email screens.

    List  → EmailListSerializer  (lightweight, paginated)
    Detail → EmailDetailSerializer (full body, attachments, risk)
    """
    http_method_names = ["get", "post", "patch", "head", "options"]
    filterset_fields = ["is_read", "is_flagged", "sender_domain"]
    ordering_fields = ["received_at", "sent_at", "risk_score"]
    ordering = ["-received_at"]

    def get_queryset(self):
        qs = Email.objects.all()

        # Filter by label (e.g. ?label=INBOX)
        label = self.request.query_params.get("label")
        if label:
            qs = qs.filter(labels__contains=[label])

        # Filter by sender domain
        domain = self.request.query_params.get("domain")
        if domain:
            qs = qs.filter(sender_domain__iexact=domain)

        # Flagged only
        flagged = self.request.query_params.get("flagged")
        if flagged == "true":
            qs = qs.filter(is_flagged=True)

        return qs

    def get_serializer_class(self):
        if self.action == "retrieve":
            return EmailDetailSerializer
        return EmailListSerializer

    def retrieve(self, request, *args, **kwargs):
        """Mark email as read on open (frontend expectation)."""
        instance = self.get_object()
        if not instance.is_read:
            instance.is_read = True
            instance.save(update_fields=["is_read", "updated_at"])
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    @action(detail=True, methods=["post"], url_path="mark-read")
    def mark_read(self, request, pk=None):
        """POST /api/emails/<id>/mark-read/"""
        email = self.get_object()
        email.is_read = True
        email.save(update_fields=["is_read", "updated_at"])
        return Response({"status": "ok", "is_read": True})

    @action(detail=True, methods=["post"], url_path="mark-unread")
    def mark_unread(self, request, pk=None):
        email = self.get_object()
        email.is_read = False
        email.save(update_fields=["is_read", "updated_at"])
        return Response({"status": "ok", "is_read": False})

    @action(detail=False, methods=["get"], url_path="search")
    def search(self, request):
        """
        GET /api/emails/search/?q=<query>
        Searches subject, sender email/name, and snippet.
        """
        q = request.query_params.get("q", "").strip()
        if not q:
            return Response({"results": [], "count": 0})

        qs = Email.objects.filter(
            Q(subject__icontains=q) |
            Q(sender_email__icontains=q) |
            Q(sender_name__icontains=q) |
            Q(snippet__icontains=q)
        ).order_by("-received_at")[:50]

        serializer = EmailListSerializer(qs, many=True, context={"request": request})
        return Response({"results": serializer.data, "count": qs.count()})


class EmailIngestView(APIView):
    """
    POST /api/emails/ingest/

    Internal endpoint called by the Gmail sync service.
    Accepts a raw Gmail API message, parses it, and upserts the Email record.
    Not exposed to the frontend directly.
    """

    def post(self, request):
        ingest_serializer = GmailMessageIngestSerializer(data=request.data)
        if not ingest_serializer.is_valid():
            return Response(ingest_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        raw_message = ingest_serializer.validated_data

        try:
            parsed = parse_gmail_message(raw_message)
            email = EmailNormalizationService.upsert(parsed)

            # Upsert attachments
            att_data = parse_attachments_from_gmail(raw_message, email.id)
            EmailNormalizationService.upsert_attachments(email, att_data)

        except Exception as exc:
            logger.exception("Failed to parse/ingest email message_id=%s", raw_message.get("id"))
            return Response(
                {"error": "Failed to parse email.", "detail": str(exc)},
                status=status.HTTP_422_UNPROCESSABLE_ENTITY,
            )

        return Response(
            {"status": "ok", "email_id": email.id},
            status=status.HTTP_201_CREATED,
        )
