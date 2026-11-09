"""Gunicorn entrypoint. Maintenance and DNS run in a separate process."""

from dns_host.app import create_app

app = create_app()
