from django.apps import AppConfig


class ThreatsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.threats"
    label = "threats"
    verbose_name = "Threat Scoring"
