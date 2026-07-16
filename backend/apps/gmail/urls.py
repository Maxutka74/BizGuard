from django.urls import path

from apps.gmail import views


app_name = "gmail"

urlpatterns = [
    path("auth/disconnect/", views.disconnect_account, name="auth-disconnect"),
    path("auth/status/", views.account_status, name="auth-status"),
    # Static paths must stay before <str:email_id>.
    path("emails/stats/", views.email_stats, name="email-stats"),
    path("emails/progress/", views.email_progress, name="email-progress"),
    path("emails/", views.email_list, name="email-list"),
    path("emails/<str:email_id>/", views.email_detail, name="email-detail"),
    path("trusted-senders/", views.trusted_sender_rules, name="trusted-senders"),
    path("trusted-senders/<int:rule_id>/", views.trusted_sender_rule_delete, name="trusted-sender-delete"),
    path("scan/", views.scan_emails, name="scan"),
    path("scan/<str:scan_id>/status/", views.scan_status, name="scan-status"),
]
