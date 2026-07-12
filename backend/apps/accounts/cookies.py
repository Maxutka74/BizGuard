from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.http import HttpResponse


ACCESS_COOKIE = getattr(settings, "JWT_ACCESS_COOKIE_NAME", "bizguard_access")
REFRESH_COOKIE = getattr(settings, "JWT_REFRESH_COOKIE_NAME", "bizguard_refresh")


def set_auth_cookies(response: HttpResponse, access: str, refresh: str) -> None:
    access_age = int(settings.SIMPLE_JWT["ACCESS_TOKEN_LIFETIME"].total_seconds())
    refresh_age = int(settings.SIMPLE_JWT["REFRESH_TOKEN_LIFETIME"].total_seconds())
    secure = bool(getattr(settings, "JWT_COOKIE_SECURE", not settings.DEBUG))
    same_site = getattr(settings, "JWT_COOKIE_SAMESITE", "Lax")

    response.set_cookie(
        ACCESS_COOKIE,
        access,
        max_age=access_age,
        httponly=True,
        secure=secure,
        samesite=same_site,
        path="/api/",
    )
    response.set_cookie(
        REFRESH_COOKIE,
        refresh,
        max_age=refresh_age,
        httponly=True,
        secure=secure,
        samesite=same_site,
        path="/api/accounts/",
    )


def clear_auth_cookies(response: HttpResponse) -> None:
    response.delete_cookie(ACCESS_COOKIE, path="/api/")
    response.delete_cookie(REFRESH_COOKIE, path="/api/accounts/")
