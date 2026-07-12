from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("reputation", "0003_attachmentreputation"),
    ]

    operations = [
        migrations.AlterField(
            model_name="urlreputation",
            name="normalized_url",
            field=models.TextField(),
        ),
        migrations.AlterField(
            model_name="urlreputation",
            name="url_hash",
            field=models.CharField(db_index=True, max_length=64, unique=True),
        ),
        migrations.AlterField(
            model_name="urlreputation",
            name="vt_url_id",
            field=models.TextField(blank=True, default=""),
        ),
    ]
