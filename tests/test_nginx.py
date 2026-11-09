from dns_host.render_nginx import render


def test_nginx_is_plain_http_and_trusts_only_configured_proxies():
    text = render(8080, 1048576, ["172.28.9.0/24", "10.1.2.3/32"])
    assert "listen 8080;" in text
    assert "user www-data;" in text
    assert "listen 443" not in text
    assert "ssl_certificate" not in text
    assert "set_real_ip_from 172.28.9.0/24;" in text
    assert "set_real_ip_from 10.1.2.3/32;" in text
    assert "real_ip_header X-Forwarded-For;" in text
    assert "X-Forwarded-Proto $forwarded_proto;" in text
    assert "proxy_pass http://127.0.0.1:8000;" in text


def test_nginx_without_trusted_proxies_does_not_rewrite_addresses():
    text = render(8080, 100, [])
    assert "\n    set_real_ip_from " not in text
    assert "listen 8080;" in text
