import django.db.models.deletion
import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]
    operations = [
        migrations.CreateModel(
            name="EmailAccount",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("email", models.EmailField(max_length=254, unique=True)),
                ("access_token", models.TextField()),
                ("refresh_token", models.TextField(blank=True)),
                ("token_expiry", models.DateTimeField(blank=True, null=True)),
                ("is_active", models.BooleanField(default=True)),
                ("connected_at", models.DateTimeField(auto_now_add=True)),
                ("last_synced_at", models.DateTimeField(blank=True, null=True)),
                ("user", models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name="email_account", to=settings.AUTH_USER_MODEL)),
            ],
            options={"db_table": "gmail_email_account"},
        ),
        migrations.CreateModel(
            name="EmailMessage",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("gmail_id", models.CharField(max_length=255, unique=True)),
                ("subject", models.TextField(blank=True)),
                ("sender", models.CharField(max_length=512)),
                ("senderName", models.CharField(blank=True, max_length=512)),
                ("domain", models.CharField(blank=True, max_length=255)),
                ("date", models.DateTimeField()),
                ("body", models.TextField(blank=True)),
                ("domainAge", models.CharField(blank=True, max_length=100)),
                ("domainReputation", models.CharField(choices=[("Trusted", "Trusted"), ("Suspicious", "Suspicious"), ("Malicious", "Malicious")], default="Trusted", max_length=20)),
                ("lookalikeDomain", models.CharField(blank=True, max_length=255, null=True)),
                ("urgency", models.IntegerField(default=0)),
                ("fear", models.IntegerField(default=0)),
                ("credentialTheft", models.IntegerField(default=0)),
                ("financialFraud", models.IntegerField(default=0)),
                ("authorityImpersonation", models.IntegerField(default=0)),
                ("aiSummary", models.TextField(blank=True)),
                ("aiScore", models.IntegerField(default=0)),
                ("domainScore", models.IntegerField(default=0)),
                ("threatScore", models.IntegerField(default=0)),
                ("riskLevel", models.CharField(choices=[("Critical", "Critical"), ("High", "High"), ("Medium", "Medium"), ("Safe", "Safe")], default="Safe", max_length=10)),
                ("synced_at", models.DateTimeField(auto_now=True)),
                ("analysis_done", models.BooleanField(default=False)),
                ("account", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="messages", to="gmail.emailaccount")),
            ],
            options={"db_table": "gmail_email_message", "ordering": ["-date"]},
        ),
        migrations.AddIndex(model_name="emailmessage", index=models.Index(fields=["account", "date"], name="gmail_email_account_date_idx")),
        migrations.AddIndex(model_name="emailmessage", index=models.Index(fields=["account", "riskLevel"], name="gmail_email_account_risk_idx")),
        migrations.AddIndex(model_name="emailmessage", index=models.Index(fields=["domain"], name="gmail_email_domain_idx")),
    ]
