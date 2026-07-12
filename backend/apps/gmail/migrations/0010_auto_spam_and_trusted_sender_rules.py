from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("gmail", "0009_emailmessage_analysis_version_pending_ai"),
    ]

    operations = [
        migrations.AddField(
            model_name="emailaccount",
            name="granted_scopes",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="emailmessage",
            name="spamActionAt",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="emailmessage",
            name="spamActionError",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="emailmessage",
            name="spamActionStatus",
            field=models.CharField(
                choices=[
                    ("none", "None"),
                    ("moved", "Moved"),
                    ("failed", "Failed"),
                    ("skipped", "Skipped"),
                ],
                default="none",
                max_length=16,
            ),
        ),
        migrations.CreateModel(
            name="TrustedSenderRule",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("rule_type", models.CharField(choices=[("email", "Email"), ("domain", "Domain")], max_length=12)),
                ("value", models.CharField(max_length=255)),
                ("active", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="trusted_sender_rules",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "db_table": "gmail_trusted_sender_rule",
                "ordering": ["rule_type", "value"],
            },
        ),
        migrations.AddIndex(
            model_name="trustedsenderrule",
            index=models.Index(fields=["user", "active"], name="gmail_trust_user_id_34cf9f_idx"),
        ),
        migrations.AddIndex(
            model_name="trustedsenderrule",
            index=models.Index(fields=["rule_type", "value"], name="gmail_trust_rule_ty_9bfbd2_idx"),
        ),
        migrations.AddConstraint(
            model_name="trustedsenderrule",
            constraint=models.UniqueConstraint(
                fields=("user", "rule_type", "value"),
                name="unique_trusted_sender_rule_per_user",
            ),
        ),
    ]
