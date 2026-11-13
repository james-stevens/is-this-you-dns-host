"""Render the plain-HTTP nginx config.

Two listeners. The external one is port 80 and presents ``/ext/`` as ``/api/``.
The internal one is bound to localhost and presents ``/int/`` as ``/api/``.
This process does not terminate TLS. A trusted reverse proxy may send
``X-Forwarded-For`` and ``X-Forwarded-Proto``. nginx's real-ip module applies
those headers only on the external listener, and only when the immediate peer
is in ``trusted_proxies``.

Runtime files stay on tmpfs (``/run``, ``/tmp``). The generated config itself
is written under ``/opt/data``.
"""

from __future__ import annotations

import sys

from dns_host.config import Settings


def render(
    listen_port: int,
    max_body_bytes: int,
    trusted_proxies: list[str],
    upstream: str = "127.0.0.1:8000",
    internal_port: int = 8081,
) -> str:
    real_ip = ["        real_ip_header X-Forwarded-For;", "        real_ip_recursive on;"]
    for proxy in trusted_proxies:
        real_ip.append(f"        set_real_ip_from {proxy};")
    real_ip_block = "\n".join(real_ip)
    return f"""worker_processes auto;
error_log syslog:server=unix:/dev/log warn;
pid /run/nginx.pid;
user nginx;

events {{
    worker_connections 1024;
}}

http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log syslog:server=unix:/dev/log combined;
    sendfile on;
    server_tokens off;
    client_body_temp_path /tmp/nginx-body;
    proxy_temp_path /tmp/nginx-proxy;
    fastcgi_temp_path /tmp/nginx-fastcgi;
    uwsgi_temp_path /tmp/nginx-uwsgi;
    scgi_temp_path /tmp/nginx-scgi;

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

    # External: the TLS shedder's upstream. /api/ is the public /ext/ tree.
    server {{
        listen {int(listen_port)};
        client_max_body_size {int(max_body_bytes)};
{real_ip_block}
        error_page 413 =413 @too_large;

        location @too_large {{
            default_type application/json;
            return 413 '{{"error":"payload_too_large","message":"request body exceeds configured limit"}}';
        }}

        location = /health {{
            proxy_pass http://{upstream}/ext/health;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Forwarded-Proto $forwarded_proto;
            proxy_set_header Connection "";
            proxy_read_timeout 60s;
        }}

        location = /metrics {{
            proxy_pass http://{upstream}/ext/metrics;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Forwarded-Proto $forwarded_proto;
            proxy_set_header Connection "";
            proxy_read_timeout 60s;
        }}

        location /api/ {{
            proxy_pass http://{upstream}/ext/;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Forwarded-Proto $forwarded_proto;
            proxy_set_header Connection "";
            proxy_read_timeout 60s;
        }}

        location /int/ {{
            default_type application/json;
            return 404 '{{"error":"not_found","message":"not found"}}';
        }}
    }}

    # Internal: localhost only. /api/ is the /int/ tree (expire and delete).
    server {{
        listen 127.0.0.1:{int(internal_port)};
        client_max_body_size {int(max_body_bytes)};

        location /api/ {{
            proxy_pass http://{upstream}/int/;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header Connection "";
            proxy_read_timeout 60s;
        }}
    }}
}}
"""


def main() -> None:
    settings = Settings.load()
    sys.stdout.write(
        render(
            settings.http_port,
            settings.max_body_bytes,
            list(settings.trusted_proxies),
            upstream=settings.gunicorn_bind,
            internal_port=settings.internal_http_port,
        )
    )


if __name__ == "__main__":
    main()
