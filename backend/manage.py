#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import socket
import sys
import time
from urllib.parse import urlparse, urlunparse


DB_WAIT_COMMANDS = {
    "migrate",
    "runserver",
    "test",
    "createsuperuser",
    "dbshell",
}


DEV_POSTGRES_FALLBACK_HOSTS = (
    "host.docker.internal",
    "localhost",
    "127.0.0.1",
)


def _database_candidates(parsed):
    host = parsed.hostname
    port = parsed.port or 5432
    yield host, port, False

    fallback_hosts = os.environ.get("DB_HOST_FALLBACKS")
    if fallback_hosts:
        candidates = [item.strip() for item in fallback_hosts.split(",") if item.strip()]
    elif os.environ.get("DEBUG", "True") == "True" and host in {"postgres", "db"}:
        candidates = list(DEV_POSTGRES_FALLBACK_HOSTS)
    else:
        candidates = []

    for fallback_host in candidates:
        if fallback_host != host:
            yield fallback_host, port, True


def _url_with_host(parsed, host, port):
    netloc = ""
    if parsed.username:
        netloc += parsed.username
        if parsed.password:
            netloc += f":{parsed.password}"
        netloc += "@"
    netloc += host
    if port:
        netloc += f":{port}"
    return urlunparse(parsed._replace(netloc=netloc))


def _is_name_resolution_error(exc):
    if isinstance(exc, socket.gaierror):
        return True
    cause = getattr(exc, "__cause__", None)
    return isinstance(cause, socket.gaierror) or "Temporary failure in name resolution" in str(exc) or "Name or service not known" in str(exc)


def _check_database_connection(database_url, host, port):
    candidate_url = _url_with_host(urlparse(database_url), host, port)
    try:
        import psycopg
    except Exception:
        with socket.create_connection((host, port), timeout=3):
            return candidate_url

    connection = psycopg.connect(candidate_url, connect_timeout=3)
    connection.close()
    return candidate_url


def _compose_dns_hint(host):
    return (
        f"Database host '{host}' не резолвиться. Якщо ви запускаєте backend як окремий контейнер, "
        "він не бачить docker compose service DNS. Запускайте Django-команди так: "
        "docker compose run --rm backend python manage.py migrate або "
        "docker compose exec backend python manage.py migrate. "
        "Або явно задайте DATABASE_URL з host, який доступний з цього контейнера."
    )


def _wait_for_database(argv):
    """Wait for DATABASE_URL and verify real Postgres auth before Django opens a DB cursor."""
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
    last_error = None
    primary_resolution_failed = False

    while time.monotonic() < deadline:
        for host, port, is_fallback in _database_candidates(parsed):
            try:
                candidate_url = _check_database_connection(database_url, host, port)
                if is_fallback:
                    os.environ["DATABASE_URL"] = candidate_url
                    print(f"Using database fallback host {host}:{port}", file=sys.stderr)
                return
            except Exception as exc:
                last_error = exc
                if not is_fallback and _is_name_resolution_error(exc):
                    primary_resolution_failed = True
                print(f"Waiting for database {host}:{port}... ({exc})", file=sys.stderr)

        if primary_resolution_failed and parsed.hostname in {"postgres", "db"}:
            raise RuntimeError(f"{_compose_dns_hint(parsed.hostname)} Last error: {last_error}")
        time.sleep(interval)

    raise RuntimeError(f"Database was not reachable within {timeout}s: {last_error}")


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
