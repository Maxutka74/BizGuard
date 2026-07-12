import django.db.models.deletion
import django.utils.timezone
import uuid
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="LicenseKey",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("key_hash", models.CharField(db_index=True, max_length=64, unique=True)),
                ("key_prefix", models.CharField(db_index=True, max_length=12)),
                ("plan", models.CharField(choices=[("free_1_day", "Free 1 day"), ("half_year", "6 months"), ("year", "1 year")], max_length=32)),
                ("duration_days", models.PositiveIntegerField()),
                ("active", models.BooleanField(default=True)),
                ("max_activations", models.PositiveIntegerField(blank=True, null=True)),
                ("note", models.CharField(blank=True, max_length=255)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="LicenseActivation",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("activated_at", models.DateTimeField(default=django.utils.timezone.now)),
                ("expires_at", models.DateTimeField(db_index=True)),
                ("revoked", models.BooleanField(default=False)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("license_key", models.ForeignKey(on_delete=django.db.models.deletion.PROTECT, related_name="activations", to="licenses.licensekey")),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="license_activations", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "ordering": ["-expires_at"],
            },
        ),
        migrations.AddIndex(
            model_name="licenseactivation",
            index=models.Index(fields=["user", "expires_at"], name="licenses_li_user_id_e20930_idx"),
        ),
        migrations.AddIndex(
            model_name="licenseactivation",
            index=models.Index(fields=["license_key", "activated_at"], name="licenses_li_license_644d00_idx"),
        ),
        migrations.AddConstraint(
            model_name="licenseactivation",
            constraint=models.UniqueConstraint(fields=("user", "license_key"), name="unique_license_key_activation_per_user"),
        ),
    ]
