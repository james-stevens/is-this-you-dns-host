"""Exec gunicorn. The shell that started us is replaced."""

from __future__ import annotations

import os

from dns_host.config import Settings, log_effective


def main() -> None:
    settings = Settings.load()
    settings.require_service_ns()
    log_effective(settings)
    os.execvp(
        "gunicorn",
        [
            "gunicorn",
            "-c",
            "/app/gunicorn.conf.py",
            "--bind",
            settings.gunicorn_bind,
            "--workers",
            str(settings.gunicorn_workers),
            "--timeout",
            "60",
            "dns_host.wsgi:app",
        ],
    )


if __name__ == "__main__":
    main()
