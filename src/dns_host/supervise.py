"""Start nginx, gunicorn and the DNS listener. No TLS is configured."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from dns_host.config import Settings
from dns_host.render_nginx import render


def main() -> None:
    settings = Settings.from_env()
    for directory in (
        Path("/tmp/nginx-body"),
        Path("/tmp/nginx-proxy"),
        Path("/tmp/nginx-fastcgi"),
        Path("/tmp/nginx-uwsgi"),
        Path("/tmp/nginx-scgi"),
    ):
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o1777)
    config = render(
        settings.http_port,
        settings.max_body_bytes,
        settings.trusted_proxies,
        upstream=settings.gunicorn_bind,
    )
    path = Path("/tmp/nginx.conf")
    path.write_text(config, encoding="utf-8")
    env = os.environ.copy()
    env["PYTHONPATH"] = env.get("PYTHONPATH", "/app/src")
    gunicorn = [
        "gunicorn",
        "--bind",
        settings.gunicorn_bind,
        "--workers",
        str(settings.gunicorn_workers),
        "--timeout",
        "60",
        "--access-logfile",
        "-",
        "--error-logfile",
        "-",
        "dns_host.wsgi:app",
    ]
    processes = [
        subprocess.Popen(gunicorn, env=env),
        subprocess.Popen([sys.executable, "-m", "dns_host.dns_server"], env=env),
        subprocess.Popen(["nginx", "-c", str(path), "-g", "daemon off;"], env=env),
    ]

    def stop(_signum=None, _frame=None) -> None:
        for process in processes:
            if process.poll() is None:
                process.terminate()

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    exit_code = 0
    try:
        while True:
            for process in processes:
                code = process.poll()
                if code is not None:
                    exit_code = code if code else 1
                    stop()
                    raise SystemExit
            time.sleep(0.5)
    except SystemExit:
        pass
    for process in processes:
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
