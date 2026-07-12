from django.core.management.base import BaseCommand, CommandError

from apps.licenses.models import LicensePlan
from apps.licenses.services import LicenseServiceError, create_license_key


class Command(BaseCommand):
    help = "Generate plaintext license keys and store only their hashes."

    def add_arguments(self, parser):
        parser.add_argument("--plan", required=True, choices=LicensePlan.values)
        parser.add_argument("--count", type=int, default=1)
        parser.add_argument("--max-activations", type=int, default=None)
        parser.add_argument("--note", default="")

    def handle(self, *args, **options):
        count = options["count"]
        if count < 1:
            raise CommandError("--count must be at least 1")
        max_activations = options["max_activations"]
        if max_activations is not None and max_activations < 1:
            raise CommandError("--max-activations must be at least 1")

        for _ in range(count):
            try:
                plaintext, license_key = create_license_key(
                    plan=options["plan"],
                    max_activations=max_activations,
                    note=options["note"],
                )
            except LicenseServiceError as exc:
                raise CommandError(exc.detail) from exc

            self.stdout.write(
                f"{plaintext} plan={license_key.plan} max_activations={license_key.max_activations}"
            )
