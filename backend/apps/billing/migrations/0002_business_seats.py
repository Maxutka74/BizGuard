from django.db import migrations, models


def backfill_order_amount_parts(apps, schema_editor):
    PurchaseOrder = apps.get_model("billing", "PurchaseOrder")
    for order in PurchaseOrder.objects.all().iterator():
        order.activation_count = order.activation_count or 1
        order.base_amount = order.amount or 0
        order.extra_seat_amount = 0
        order.unit_extra_seat_amount = 0
        if not order.currency:
            order.currency = "uah"
        order.save(update_fields=["activation_count", "base_amount", "extra_seat_amount", "unit_extra_seat_amount", "currency"])


class Migration(migrations.Migration):
    dependencies = [
        ("billing", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="purchaseorder",
            name="activation_count",
            field=models.PositiveIntegerField(default=1),
        ),
        migrations.AddField(
            model_name="purchaseorder",
            name="base_amount",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="purchaseorder",
            name="extra_seat_amount",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="purchaseorder",
            name="unit_extra_seat_amount",
            field=models.PositiveIntegerField(default=0),
        ),
        migrations.AlterField(
            model_name="purchaseorder",
            name="currency",
            field=models.CharField(default="uah", max_length=8),
        ),
        migrations.RunPython(backfill_order_amount_parts, migrations.RunPython.noop),
    ]