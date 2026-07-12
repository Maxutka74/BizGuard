from django.conf import settings
from rest_framework.authentication import CSRFCheck
from rest_framework.exceptions import PermissionDenied
from rest_framework_simplejwt.authentication import JWTAuthentication

from .services import get_license_status_for_user, user_has_active_license


class LicenseAwareJWTAuthentication(JWTAuthentication):
    exempt_prefixes = (
        "/api/accounts/",
        "/api/licenses/",
        "/api/schema/",
        "/api/docs/",
        "/admin/",
    )

    def get_header(self, request):
        request._jwt_from_cookie = False
        header = super().get_header(request)
        if header is not None:
            return header

        access = request.COOKIES.get(getattr(settings, "JWT_ACCESS_COOKIE_NAME", "bizguard_access"))
        if not access:
            return None
        request._jwt_from_cookie = True
        return f"Bearer {access}".encode()

    def authenticate(self, request):
        result = super().authenticate(request)
        if result is None:
            return None

        user, token = result
        if getattr(request, "_jwt_from_cookie", False):
            self._enforce_csrf(request)
        if self._requires_license(request.path_info) and not user_has_active_license(user):
            raise PermissionDenied(
                {
                    "detail": "Потрібна активна ліцензія.",
                    "code": "license_required",
                    "license": get_license_status_for_user(user),
                }
            )

        return user, token

    def _enforce_csrf(self, request) -> None:
        if request.method in {"GET", "HEAD", "OPTIONS", "TRACE"}:
            return
        check = CSRFCheck(lambda req: None)
        check.process_request(request)
        reason = check.process_view(request, None, (), {})
        if reason:
            raise PermissionDenied({"detail": f"CSRF перевірку не пройдено: {reason}", "code": "csrf_failed"})

    def _requires_license(self, path: str) -> bool:
        return path.startswith("/api/") and not any(
            path.startswith(prefix) for prefix in self.exempt_prefixes
        )

