FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/src \
    DATA_DIR=/data \
    HTTP_PORT=8080 \
    GUNICORN_BIND=127.0.0.1:8000 \
    DNS_BIND=0.0.0.0 \
    DNS_PORT=5353

RUN apt-get update \
    && apt-get install -y --no-install-recommends nginx \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /etc/nginx/sites-enabled/default \
    && mkdir -p /data /tmp/nginx-body /tmp/nginx-proxy

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY deploy/root-anchors.ds ./deploy/root-anchors.ds

VOLUME ["/data"]
EXPOSE 8080 5353/tcp 5353/udp

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).read()"

ENTRYPOINT ["python", "-m", "dns_host.supervise"]
