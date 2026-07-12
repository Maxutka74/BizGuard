import uuid

import django.conf
from django.conf import settings
import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="EmailAnalysisRecord",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("subject", models.CharField(blank=True, default="", max_length=998)),
                ("sender", models.CharField(max_length=320)),
                (
                    "sender_name",
                    models.CharField(blank=True, default="", max_length=255),
                ),
                ("domain", models.CharField(db_index=True, max_length=255)),
                ("date", models.DateTimeField(db_index=True)),
                ("body", models.TextField(blank=True, default="")),
                (
                    "domain_age",
                    models.CharField(blank=True, default="", max_length=64),
                ),
                (
                    "domain_reputation",
                    models.CharField(
                        choices=[
                            ("Trusted", "Trusted"),
                            ("Suspicious", "Suspicious"),
                            ("Malicious", "Malicious"),
                        ],
                        max_length=16,
                    ),
                ),
                (
                    "lookalike_domain",
                    models.CharField(blank=True, max_length=255, null=True),
                ),
                ("urgency", models.PositiveSmallIntegerField(default=0)),
                ("fear", models.PositiveSmallIntegerField(default=0)),
                ("credential_theft", models.PositiveSmallIntegerField(default=0)),
                ("financial_fraud", models.PositiveSmallIntegerField(default=0)),
                (
                    "authority_impersonation",
                    models.PositiveSmallIntegerField(default=0),
                ),
                ("ai_summary", models.TextField(blank=True, default="")),
                ("ai_score", models.PositiveSmallIntegerField(default=0)),
                ("domain_score", models.PositiveSmallIntegerField(default=0)),
                ("threat_score", models.PositiveSmallIntegerField(default=0)),
                (
                    "risk_level",
                    models.CharField(
                        choices=[
                            ("Critical", "Critical"),
                            ("High", "High"),
                            ("Medium", "Medium"),
                            ("Safe", "Safe"),
                        ],
                        db_index=True,
                        max_length=16,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="email_analyses",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-date"],
            },
        ),
        migrations.CreateModel(
            name="ScanRun",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4,
                        editable=False,
                        primary_key=True,
                        serialize=False,
                    ),
                ),
                ("started_at", models.DateTimeField(auto_now_add=True)),
                ("finished_at", models.DateTimeField(blank=True, null=True)),
                ("emails_scanned", models.PositiveIntegerField(default=0)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="scan_runs",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-started_at"],
            },
        ),
        migrations.AddIndex(
            model_name="emailanalysisrecord",
            index=models.Index(
                fields=["user", "risk_level"],
                name="dashboard_e_user_id_3a1f5c_idx",
            ),
        ),
        migrations.AddIndex(
            model_name="emailanalysisrecord",
            index=models.Index(
                fields=["user", "date"], name="dashboard_e_user_id_8c2b41_idx"
            ),
        ),
    ]
