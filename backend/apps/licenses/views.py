from django.conf import settings
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .serializers import LicenseKeyInputSerializer
from .services import (
    LicenseServiceError,
    activate_license_for_user,
    confirm_license_for_user,
    create_gate_token,
    get_license_plans,
    get_license_status_for_user,
    license_key_preview,
    validate_license_key,
)


class ValidateLicenseKeyView(APIView):
    permission_classes = [AllowAny]
    throttle_scope = "license_validate"

    def post(self, request):
        serializer = LicenseKeyInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            license_key = validate_license_key(serializer.validated_data["key"], require_capacity=False)
        except LicenseServiceError as exc:
            return _license_error_response(exc, status.HTTP_400_BAD_REQUEST)

        preview = license_key_preview(license_key)
        return Response(
            {
                "gateToken": create_gate_token(license_key),
                **preview,
                "expiresInSeconds": settings.LICENSE_GATE_TOKEN_MAX_AGE_SECONDS,
            }
        )


class LicenseStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response(get_license_status_for_user(request.user))


class LicensePlansView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        return Response({"plans": get_license_plans()})


class ActivateLicenseView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_scope = "license_activate"

    def post(self, request):
        serializer = LicenseKeyInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            license_key = validate_license_key(serializer.validated_data["key"], require_capacity=False)
            activate_license_for_user(request.user, license_key)
            _queue_initial_scan_for_user(request.user)
        except LicenseServiceError as exc:
            return _license_error_response(exc, status.HTTP_400_BAD_REQUEST)

        return Response({"license": get_license_status_for_user(request.user)})


class ConfirmLicenseView(APIView):
    permission_classes = [IsAuthenticated]
    throttle_scope = "license_confirm"

    def post(self, request):
        serializer = LicenseKeyInputSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            confirm_license_for_user(request.user, serializer.validated_data["key"])
        except LicenseServiceError as exc:
            return _license_error_response(exc, status.HTTP_400_BAD_REQUEST)

        return Response({"license": get_license_status_for_user(request.user)})


def _license_error_response(exc: LicenseServiceError, response_status: int):
    return Response(
        {
            "detail": exc.detail,
            "code": exc.code,
        },
        status=response_status,
    )



def _queue_initial_scan_for_user(user):
    try:
        from apps.accounts.google_oauth import _trigger_initial_scan
        from apps.gmail.models import EmailAccount

        account = EmailAccount.objects.filter(user=user, is_active=True).first()
        if account:
            _trigger_initial_scan(account)
    except Exception:
        # Activation must not fail just because scan scheduling failed.
        pass
