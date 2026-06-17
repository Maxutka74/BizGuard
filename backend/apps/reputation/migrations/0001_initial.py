from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="DomainReputation",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                (
                    "domain",
                    models.CharField(db_index=True, max_length=253, unique=True),
                ),
                (
                    "reputation",
                    models.CharField(
                        choices=[
                            ("Trusted", "Trusted"),
                            ("Suspicious", "Suspicious"),
                            ("Malicious", "Malicious"),
                        ],
                        default="Suspicious",
                        max_length=20,
                    ),
                ),
                (
                    "domain_score",
                    models.IntegerField(
                        default=0,
                        help_text="0-100 risk score used as domainScore",
                    ),
                ),
                (
                    "domain_age",
                    models.CharField(blank=True, default="", max_length=64),
                ),
                (
                    "lookalike_domain",
                    models.CharField(
                        blank=True,
                        default=None,
                        help_text="Detected lookalike / typosquat target domain, or null",
                        max_length=253,
                        null=True,
                    ),
                ),
                ("vt_malicious", models.IntegerField(default=0)),
                ("vt_suspicious", models.IntegerField(default=0)),
                ("vt_harmless", models.IntegerField(default=0)),
                ("vt_undetected", models.IntegerField(default=0)),
                ("vt_total_votes_malicious", models.IntegerField(default=0)),
                ("vt_total_votes_harmless", models.IntegerField(default=0)),
                (
                    "vt_reputation",
                    models.IntegerField(
                        default=0,
                        help_text="VirusTotal community reputation score (can be negative)",
                    ),
                ),
                (
                    "vt_creation_date",
                    models.DateTimeField(blank=True, null=True),
                ),
                (
                    "fetched_at",
                    models.DateTimeField(default=django.utils.timezone.now),
                ),
                ("error", models.TextField(blank=True, default="")),
            ],
            options={
                "verbose_name": "Domain Reputation",
                "verbose_name_plural": "Domain Reputations",
                "ordering": ["-fetched_at"],
            },
        ),
    ]
