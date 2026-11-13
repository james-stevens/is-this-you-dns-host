"""Write nginx.conf under /opt/data and exec nginx in the foreground."""

from __future__ import annotations

import os
from pathlib import Path

from dns_host.config import Settings, log_effective
from dns_host.render_nginx import render
from dns_host.zonesync import atomic_write


def main() -> None:
    settings = Settings.load()
    settings.require_service_ns()
    log_effective(settings)
    text = render(
        settings.http_port,
        settings.max_body_bytes,
        list(settings.trusted_proxies),
        upstream=settings.gunicorn_bind,
        internal_port=settings.internal_http_port,
    )
    path = Path(settings.data_dir) / "etc" / "nginx.conf"
    atomic_write(path, text)
    os.execvp("nginx", ["nginx", "-e", "/tmp/nginx-startup.log", "-c", str(path), "-g", "daemon off;"])


if __name__ == "__main__":
    main()
