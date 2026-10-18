from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ("reputation", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="UrlReputation",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("normalized_url", models.TextField(unique=True)),
                ("url_hash", models.CharField(max_length=64)),
                ("vt_url_id", models.CharField(blank=True, default="", max_length=512)),
                (
                    "verdict",
                    models.CharField(
                        choices=[
                            ("Clean", "Clean"),
                            ("Suspicious", "Suspicious"),
                            ("Malicious", "Malicious"),
                            ("Pending", "Pending"),
                            ("Error", "Error"),
                        ],
                        default="Pending",
                        max_length=20,
                    ),
                ),
                ("score", models.IntegerField(default=0)),
                ("is_phishing", models.BooleanField(default=False)),
                ("is_malicious", models.BooleanField(default=False)),
                ("vt_malicious", models.IntegerField(default=0)),
                ("vt_suspicious", models.IntegerField(default=0)),
                ("vt_harmless", models.IntegerField(default=0)),
                ("vt_undetected", models.IntegerField(default=0)),
                ("raw_stats", models.JSONField(blank=True, default=dict)),
                ("raw_results", models.JSONField(blank=True, default=dict)),
                ("fetched_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("error", models.TextField(blank=True, default="")),
            ],
            options={
                "verbose_name": "URL Reputation",
                "verbose_name_plural": "URL Reputations",
                "ordering": ["-fetched_at"],
            },
        ),
        migrations.AddIndex(
            model_name="urlreputation",
            index=models.Index(fields=["url_hash"], name="reputation__url_has_08139a_idx"),
        ),
        migrations.AddIndex(
            model_name="urlreputation",
            index=models.Index(fields=["verdict", "fetched_at"], name="reputation__verdict_4dbdbb_idx"),
        ),
    ]
