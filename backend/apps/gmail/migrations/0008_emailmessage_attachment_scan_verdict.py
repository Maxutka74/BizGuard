from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("gmail", "0007_emailmessage_url_scan_and_source"),
    ]

    operations = [
        migrations.AddField(
            model_name="emailmessage",
            name="attachments",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="emailmessage",
            name="attachmentScanSummary",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="emailmessage",
            name="scannedAttachments",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="emailmessage",
            name="verdict",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="emailmessage",
            name="recommendations",
            field=models.JSONField(blank=True, default=list),
        ),
    ]
