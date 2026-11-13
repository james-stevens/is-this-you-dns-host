"""Flask HTTP API: zone upload, health, metrics."""

from __future__ import annotations

import ipaddress
import json

import dns.message
import dns.query
import dns.rdatatype
import dns.rcode
from flask import Flask, jsonify, request

from dns_host.admit import admit
from dns_host.catalog import catalog_soa
from dns_host.config import Settings
from dns_host.doh import DohClient
from dns_host.errors import ApiError
from dns_host.logutil import log
from dns_host.names import normalise_apex
from dns_host.notify import UdpNotifier
from dns_host.storage import Store

_LOOPBACK = {"127.0.0.1", "::1"}


def create_app(settings: Settings | None = None, lookup=None, store: Store | None = None, notifier=None) -> Flask:
    settings = settings or Settings.load()
    if store is None:
        store = Store(settings.db_path)
    store.ensure_catalog(settings.now())
    if lookup is None:
        lookup = DohClient(settings.resolver_base_url, settings.doh_timeout_seconds)
    if notifier is None:
        notifier = UdpNotifier(settings, store)

    app = Flask("dns_host")
    app.config["MAX_CONTENT_LENGTH"] = settings.max_body_bytes
    app.config["settings"] = settings
    app.config["store"] = store
    app.config["lookup"] = lookup
    app.config["notifier"] = notifier

    @app.get("/")
    def index():
        return jsonify(service="is-this-you-dns-host")

    @app.get("/health")
    def health():
        serial = store.catalog_serial()
        body = {
            "status": "ok",
            "catalogZone": settings.catalog_zone.to_text(),
            "catalogSerial": serial,
            "dns": "skipped",
        }
        if not settings.health_check_dns:
            return jsonify(body)
        if _dns_soa_ok(settings):
            body["dns"] = "ok"
            return jsonify(body)
        body["status"] = "degraded"
        body["dns"] = "down"
        return jsonify(body), 503

    @app.get("/metrics")
    def metrics():
        now = settings.now()
        zones = store.list_zones()
        failed = {}
        with store._read() as conn:
            rows = conn.execute("SELECT name, value FROM counters").fetchall()
        counters = {row["name"]: int(row["value"]) for row in rows}
        for key, value in list(counters.items()):
            if key.startswith("upload_fail_"):
                failed[key.removeprefix("upload_fail_")] = value
        return jsonify(
            {
                "uploads_ok": counters.get("upload_ok", 0),
                "uploads_failed": failed,
                "axfr_ok": counters.get("axfr_ok", 0),
                "axfr_denied": counters.get("axfr_denied", 0),
                "notify_ok": counters.get("notify_ok", 0),
                "notify_fail": counters.get("notify_fail", 0),
                "zones_dropped": counters.get("zones_dropped", 0),
                "zones": len(zones),
                "zones_in_grace": store.zones_in_grace(now),
                "parent_lookup_ms_sum": counters.get("parent_lookup_ms_sum", 0),
                "parent_lookup_ms_count": counters.get("parent_lookup_ms_count", 0),
                "validate_ms_sum": counters.get("validate_ms_sum", 0),
                "validate_ms_count": counters.get("validate_ms_count", 0),
            }
        )

    @app.post("/v1/zones/<path:apex>")
    def upload(apex: str):
        client_ip = _client_ip()
        try:
            raw = _read_body(settings)
        except _PayloadTooLarge:
            return jsonify(error="payload_too_large", message="request body exceeds configured limit"), 413
        if not store.allow_rate(
            f"upload:{client_ip}",
            settings.rate_limit_requests,
            settings.rate_limit_window_seconds,
            settings.now(),
        ):
            store.incr("upload_fail_rate_limited")
            log("info", "rate limited", client_ip=client_ip, error="rate_limited")
            return jsonify(error="rate_limited", message="upload rate limit exceeded"), 429
        content_type = request.content_type or ""
        if not content_type.startswith("application/json"):
            return jsonify(error="bad_request", message="Content-Type must be application/json"), 400
        try:
            url_apex = normalise_apex(apex)
        except ApiError as exc:
            return jsonify(exc.as_dict()), exc.status
        try:
            body = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            store.incr("upload_fail_bad_request")
            return jsonify(error="bad_request", message="body is not JSON"), 400
        try:
            payload, status = admit(body, url_apex, settings, store, lookup, notifier, client_ip)
        except ApiError as exc:
            return jsonify(exc.as_dict()), exc.status
        return jsonify(payload), status

    @app.get("/int/zones/meta")
    def zones_meta():
        zones = []
        for row in store.list_zones():
            zones.append(
                {
                    "apex": row.apex,
                    "serial": row.serial,
                    "rrsig_max_expiry": row.rrsig_max_expiry,
                    "rrsig_min_expiry": row.rrsig_min_expiry,
                    "parent_ok": row.parent_ok,
                    "parent_drift_since": row.parent_drift_since,
                    "parent_zone": row.parent_zone,
                }
            )
        return jsonify(zones=zones, catalogSerial=store.catalog_serial())

    @app.post("/int/zones/drop")
    def drop_zones():
        body = request.get_json(silent=True) or {}
        apexes = body.get("apexes") or []
        reason = str(body.get("reason") or "dropped")
        if not isinstance(apexes, list) or not apexes:
            return jsonify(error="bad_request", message="apexes must be a non-empty list"), 400
        dropped = []
        for apex in apexes:
            serial = store.delete_zone(str(apex), settings.now())
            if serial is None:
                continue
            store.incr("zones_dropped")
            log("info", "zone dropped", apex=str(apex), reason=reason, catalog_serial=serial)
            try:
                notifier.notify(settings.catalog_zone.to_text(), catalog_soa(settings, serial))
            except Exception as exc:
                log("warning", "catalog NOTIFY after drop failed", apex=str(apex), error=str(exc))
            dropped.append(str(apex))
        return jsonify(dropped=dropped)

    @app.post("/int/zones/parent-state")
    def parent_state():
        body = request.get_json(silent=True) or {}
        apex = body.get("apex")
        if not apex:
            return jsonify(error="bad_request", message="apex is required"), 400
        drift = body.get("drift_since")
        if drift is not None:
            drift = int(drift)
        store.set_parent_state(str(apex), now=settings.now(), ok=bool(body.get("ok")), drift_since=drift)
        return jsonify(ok=True)

    app.add_url_rule("/ext/health", endpoint="ext_health", view_func=health, methods=["GET"])
    app.add_url_rule("/int/health", endpoint="int_health", view_func=health, methods=["GET"])
    app.add_url_rule("/ext/metrics", endpoint="ext_metrics", view_func=metrics, methods=["GET"])
    app.add_url_rule("/int/metrics", endpoint="int_metrics", view_func=metrics, methods=["GET"])
    app.add_url_rule("/ext/v1/zones/<path:apex>", endpoint="ext_upload", view_func=upload, methods=["POST"])

    @app.errorhandler(413)
    def too_large(_exc):
        return jsonify(error="payload_too_large", message="request body exceeds configured limit"), 413

    @app.errorhandler(404)
    def not_found(_exc):
        return jsonify(error="not_found", message="not found"), 404

    return app


def _read_body(settings: Settings) -> bytes:
    length = request.content_length
    if length is not None and length > settings.max_body_bytes:
        raise _PayloadTooLarge()
    data = request.get_data(cache=False, as_text=False) or b""
    if len(data) > settings.max_body_bytes:
        raise _PayloadTooLarge()
    return data


class _PayloadTooLarge(Exception):
    pass


def _client_ip() -> str:
    remote = request.remote_addr or ""
    # Gunicorn is bound to loopback and nginx overwrites X-Real-IP, so the
    # header is only honoured from the local proxy.
    if _is_loopback(remote):
        forwarded = (request.headers.get("X-Real-IP") or "").strip()
        if forwarded:
            return forwarded
    return remote


def _is_loopback(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_loopback


def _dns_soa_ok(settings: Settings) -> bool:
    try:
        query = dns.message.make_query(settings.catalog_zone, dns.rdatatype.SOA)
        response = dns.query.udp(query, "127.0.0.1", port=settings.dns_port, timeout=0.5)
    except Exception:
        return False
    return response.rcode() == dns.rcode.NOERROR and any(
        rrset.rdtype == dns.rdatatype.SOA for rrset in response.answer
    )
