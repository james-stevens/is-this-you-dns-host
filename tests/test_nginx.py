from dns_host.render_nginx import render


def test_nginx_is_plain_http_and_trusts_only_configured_proxies():
    text = render(80, 1048576, ["172.28.9.0/24", "10.1.2.3/32"], internal_port=8081)
    assert "listen 80;" in text
    assert "listen 127.0.0.1:8081;" in text
    assert "user nginx;" in text
    assert "listen 443" not in text
    assert "ssl_certificate" not in text
    assert "set_real_ip_from 172.28.9.0/24;" in text
    assert "set_real_ip_from 10.1.2.3/32;" in text
    assert "real_ip_header X-Forwarded-For;" in text
    assert "X-Forwarded-Proto $forwarded_proto;" in text
    assert "proxy_pass http://127.0.0.1:8000/ext/;" in text
    assert "proxy_pass http://127.0.0.1:8000/int/;" in text
    assert "pid /run/nginx.pid;" in text
    assert "/tmp/nginx-body" in text
    assert "/opt/data" not in text


def test_nginx_without_trusted_proxies_does_not_rewrite_addresses():
    text = render(80, 100, [])
    assert "\n        set_real_ip_from " not in text
    assert "listen 80;" in text
