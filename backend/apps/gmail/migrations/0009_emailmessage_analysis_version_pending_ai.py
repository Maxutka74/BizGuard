from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("gmail", "0008_emailmessage_attachment_scan_verdict"),
    ]

    operations = [
        migrations.AddField(
            model_name="emailmessage",
            name="analysisVersion",
            field=models.IntegerField(default=1),
        ),
        migrations.AlterField(
            model_name="emailmessage",
            name="analysis_status",
            field=models.CharField(
                choices=[
                    ("pending", "Pending"),
                    ("pending_ai", "Pending AI"),
                    ("processing", "Processing"),
                    ("done", "Done"),
                    ("fallback", "Fallback"),
                    ("failed", "Failed"),
                ],
                default="pending",
                max_length=20,
            ),
        ),
    ]
