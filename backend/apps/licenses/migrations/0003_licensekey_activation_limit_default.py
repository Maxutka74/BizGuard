from django.db import migrations, models


def set_existing_unlimited_to_single_activation(apps, schema_editor):
    LicenseKey = apps.get_model("licenses", "LicenseKey")
    LicenseKey.objects.filter(max_activations__isnull=True).update(max_activations=1)


class Migration(migrations.Migration):
    dependencies = [
        ("licenses", "0002_licenseactivation_confirmation_fields"),
    ]

    operations = [
        migrations.RunPython(set_existing_unlimited_to_single_activation, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="licensekey",
            name="max_activations",
            field=models.PositiveIntegerField(default=1),
        ),
    ]
