from django.db import migrations, models
import django.db.models.deletion
import uuid
from django.conf import settings


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("licenses", "0003_licensekey_activation_limit_default"),
    ]

    operations = [
        migrations.CreateModel(
            name="PurchaseOrder",
            fields=[
                ("id", models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ("plan", models.CharField(choices=[("free_1_day", "Free 1 day"), ("half_year", "6 months"), ("year", "1 year")], max_length=32)),
                ("provider", models.CharField(choices=[("stripe", "Stripe")], default="stripe", max_length=32)),
                ("provider_session_id", models.CharField(blank=True, max_length=255, null=True, unique=True)),
                ("status", models.CharField(choices=[("pending", "Pending"), ("paid", "Paid"), ("canceled", "Canceled"), ("failed", "Failed")], db_index=True, default="pending", max_length=32)),
                ("amount", models.PositiveIntegerField(default=0)),
                ("currency", models.CharField(default="usd", max_length=8)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("paid_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("generated_license_key", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="purchase_orders", to="licenses.licensekey")),
                ("user", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="purchase_orders", to=settings.AUTH_USER_MODEL)),
            ],
            options={
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="purchaseorder",
            index=models.Index(fields=["user", "status"], name="billing_pur_user_id_861e39_idx"),
        ),
        migrations.AddIndex(
            model_name="purchaseorder",
            index=models.Index(fields=["provider_session_id"], name="billing_pur_provide_284fe2_idx"),
        ),
    ]
