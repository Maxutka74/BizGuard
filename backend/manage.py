#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import socket
import sys
import time
from urllib.parse import urlparse


DB_WAIT_COMMANDS = {
    "migrate",
    "runserver",
    "test",
    "createsuperuser",
    "dbshell",
}


def _wait_for_database(argv):
    """Wait for DATABASE_URL host before Django opens the first DB cursor."""
    if len(argv) < 2 or argv[1] not in DB_WAIT_COMMANDS:
        return
    if os.environ.get("DB_WAIT_DISABLED", "False").lower() == "true":
        return

    database_url = os.environ.get("DATABASE_URL", "")
    parsed = urlparse(database_url)
    if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname:
        return

    timeout = int(os.environ.get("DB_WAIT_TIMEOUT_SECONDS", "60"))
    interval = float(os.environ.get("DB_WAIT_INTERVAL_SECONDS", "1"))
    deadline = time.monotonic() + timeout
    host = parsed.hostname
    port = parsed.port or 5432
    last_error = None

    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=3):
                return
        except OSError as exc:
            last_error = exc
            print(f"Waiting for database {host}:{port}... ({exc})", file=sys.stderr)
            time.sleep(interval)

    raise RuntimeError(f"Database {host}:{port} was not reachable within {timeout}s: {last_error}")


def main():
    """Run administrative tasks."""
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
    _wait_for_database(sys.argv)
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
