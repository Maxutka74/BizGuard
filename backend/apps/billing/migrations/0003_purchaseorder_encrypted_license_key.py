from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0002_business_seats"),
    ]

    operations = [
        migrations.AddField(
            model_name="purchaseorder",
            name="encrypted_license_key",
            field=models.TextField(blank=True, default=""),
        ),
    ]
