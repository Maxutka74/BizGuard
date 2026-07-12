from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("gmail", "0006_emailmessage_security_and_analysis_status"),
    ]

    operations = [
        migrations.AddField(
            model_name="emailmessage",
            name="urlScanSummary",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="emailmessage",
            name="urlScore",
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name="emailmessage",
            name="scannedUrls",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="emailmessage",
            name="hasPhishingUrl",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="emailmessage",
            name="hasMaliciousUrl",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="emailmessage",
            name="analysisSource",
            field=models.CharField(blank=True, default="", max_length=50),
        ),
    ]
