
"""
apps/gmail/urls.py  — FIXED for hackathon
 
ВАЖЛИВО: stats/ та scan/ мають бути ПЕРЕД <str:email_id>/,
інакше Django матчить "stats" як email_id і повертає 404.
"""
from django.urls import path
from apps.gmail import views
 
app_name = "gmail"
 
urlpatterns = [
    # ── Auth ──────────────────────────────────────────────────────────────────
    path("auth/init/",        views.oauth_init,         name="auth-init"),
    path("auth/callback/",    views.oauth_callback,     name="auth-callback"),
    path("auth/disconnect/",  views.disconnect_account, name="auth-disconnect"),
    path("auth/status/",      views.account_status,     name="auth-status"),
 
    # ── Emails — ПОРЯДОК КРИТИЧНИЙ ────────────────────────────────────────────
    # stats/ і scan/ ОБОВ'ЯЗКОВО перед <str:email_id>/, інакше Django
    # матчить рядок "stats" або "scan" як email_id.
    path("emails/stats/",          views.email_stats,  name="email-stats"),
    path("emails/",                views.email_list,   name="email-list"),
    path("emails/<str:email_id>/", views.email_detail, name="email-detail"),
 
    # ── Scan ──────────────────────────────────────────────────────────────────
    path("scan/", views.scan_emails, name="scan"),
]
