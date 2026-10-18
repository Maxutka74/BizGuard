from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("licenses", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="licenseactivation",
            name="confirmation_due_at",
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
        migrations.AddField(
            model_name="licenseactivation",
            name="last_confirmed_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
