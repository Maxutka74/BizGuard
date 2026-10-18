from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ("reputation", "0002_urlreputation"),
    ]

    operations = [
        migrations.CreateModel(
            name="AttachmentReputation",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("file_hash", models.CharField(max_length=64, unique=True)),
                ("filename", models.CharField(blank=True, default="", max_length=512)),
                ("mime_type", models.CharField(blank=True, default="", max_length=255)),
                ("size_bytes", models.IntegerField(default=0)),
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
                ("is_malicious", models.BooleanField(default=False)),
                ("is_suspicious", models.BooleanField(default=False)),
                ("extracted_text_preview", models.TextField(blank=True, default="")),
                ("local_findings", models.JSONField(blank=True, default=list)),
                ("raw_stats", models.JSONField(blank=True, default=dict)),
                ("raw_results", models.JSONField(blank=True, default=dict)),
                ("fetched_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("error", models.TextField(blank=True, default="")),
            ],
            options={
                "verbose_name": "Attachment Reputation",
                "verbose_name_plural": "Attachment Reputations",
                "ordering": ["-fetched_at"],
            },
        ),
        migrations.AddIndex(
            model_name="attachmentreputation",
            index=models.Index(fields=["verdict", "fetched_at"], name="reputation__verdict_5d9629_idx"),
        ),
    ]
