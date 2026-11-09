"""Render the plain-HTTP nginx config.

This process does not terminate TLS. A trusted reverse proxy may send
``X-Forwarded-For`` and ``X-Forwarded-Proto``. nginx's real-ip module applies
those headers only when the immediate peer is in ``TRUSTED_PROXIES``. The
rewritten client address is what gunicorn, and therefore the rate limiter,
sees as ``X-Real-IP``.
"""

from __future__ import annotations

import sys

from dns_host.config import Settings, parse_trusted_proxies


def render(
    listen_port: int,
    max_body_bytes: int,
    trusted_proxies: list[str],
    upstream: str = "127.0.0.1:8000",
) -> str:
    real_ip = ["    real_ip_header X-Forwarded-For;", "    real_ip_recursive on;"]
    for proxy in trusted_proxies:
        real_ip.append(f"    set_real_ip_from {proxy};")
    real_ip_block = "\n".join(real_ip)
    return f"""worker_processes auto;
error_log stderr warn;
pid /tmp/nginx.pid;
user www-data;

events {{
    worker_connections 1024;
}}

http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log /dev/stdout combined;
    sendfile on;
    server_tokens off;
    client_body_temp_path /tmp/nginx-body;
    proxy_temp_path /tmp/nginx-proxy;
    fastcgi_temp_path /tmp/nginx-fastcgi;
    uwsgi_temp_path /tmp/nginx-uwsgi;
    scgi_temp_path /tmp/nginx-scgi;

{real_ip_block}

    # $realip_remote_addr is set only when the connecting address was rewritten.
    map $realip_remote_addr $pass_forwarded_proto {{
        default 0;
        ~. 1;
    }}
    map $pass_forwarded_proto $raw_forwarded_proto {{
        default http;
        1 $http_x_forwarded_proto;
    }}
    map $raw_forwarded_proto $forwarded_proto {{
        default http;
        ~*^https$ https;
        ~*^http$ http;
    }}

    server {{
        listen {int(listen_port)};
        client_max_body_size {int(max_body_bytes)};
        error_page 413 =413 @too_large;

        location @too_large {{
            default_type application/json;
            return 413 '{{"error":"payload_too_large","message":"request body exceeds configured limit"}}';
        }}

        location / {{
            proxy_pass http://{upstream};
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Forwarded-Proto $forwarded_proto;
            proxy_set_header Connection "";
            proxy_read_timeout 60s;
        }}
    }}
}}
"""


def main() -> None:
    settings = Settings.from_env()
    # Allow the renderer to be tested without the rest of the environment.
    proxies = parse_trusted_proxies(os.environ.get("TRUSTED_PROXIES", ""))
    sys.stdout.write(
        render(
            settings.http_port,
            settings.max_body_bytes,
            proxies or settings.trusted_proxies,
            upstream=settings.gunicorn_bind,
        )
    )


if __name__ == "__main__":
    main()
