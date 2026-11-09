"""Upload admission: validate, store, then NOTIFY.

Catalog changes are notified before the member zone.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from dns_host.catalog import catalog_soa
from dns_host.errors import ApiError
from dns_host.logutil import log
from dns_host.pipeline import (
    ds_matches,
    next_expire_hint,
    offline_checks,
    parent_checks,
    verify_signatures,
)
from dns_host.zone import parse_upload

_PARENT_CACHE_ERRORS = {
    "parent_ns_incomplete",
    "parent_ds_missing",
    "parent_ds_mismatch",
    "parent_chain_invalid",
    "parent_lookup_unavailable",
    "ns_set_mismatch",
}


def admit(body: dict, url_apex, settings, store, lookup, notifier, client_ip: str) -> tuple[dict, int]:
    try:
        held = store.get_zone(url_apex.to_text())
        held_serial = held.serial if held else None
        zone = parse_upload(body, url_apex)
        # RRset and name caps need a parsed document. Body size and the per-IP
        # limit are enforced by the HTTP layer before parse.
        serial = offline_checks(zone, settings, held_serial)
        cached = store.negative_get(url_apex.to_text(), settings.now())
        if cached is not None:
            raise ApiError(cached.http_status, cached.reason, cached.message)
        _enforce_parent_budget(settings, store, client_ip)
        if not store.allow_rate(
            f"parent:{client_ip}",
            settings.parent_query_budget,
            settings.parent_query_window_seconds,
            settings.now(),
        ):
            raise ApiError(429, "rate_limited", "parent lookup budget exceeded")
        lookup_started = time.perf_counter()
        try:
            delegation = parent_checks(zone, settings, lookup)
            matched = ds_matches(zone, delegation, settings)
        except ApiError as exc:
            _remember_parent_failure(store, settings, url_apex.to_text(), exc)
            raise
        finally:
            store.incr("parent_lookup_ms_sum", int((time.perf_counter() - lookup_started) * 1000))
            store.incr("parent_lookup_ms_count")
        crypto_started = time.perf_counter()
        verify_signatures(zone, matched, settings.now())
        store.incr("validate_ms_sum", int((time.perf_counter() - crypto_started) * 1000))
        store.incr("validate_ms_count")
        _enforce_parent_cap(settings, store, delegation.parent_zone.to_text(), url_apex.to_text())
        expiries = zone.rrsig_expiries()
        catalog_updated, _catalog_serial = store.replace_zone(
            apex=url_apex.to_text(),
            serial=serial,
            document=zone.to_document(),
            now=settings.now(),
            rrsig_min_expiry=min(expiries),
            rrsig_max_expiry=max(expiries),
            parent_zone=delegation.parent_zone.to_text(),
        )
        store.remember_parent_day(
            delegation.parent_zone.to_text(),
            url_apex.to_text(),
            datetime.fromtimestamp(settings.now(), timezone.utc).strftime("%Y-%m-%d"),
        )
        _notify(settings, store, notifier, url_apex.to_text(), zone, catalog_updated)
        store.incr("upload_ok")
        log(
            "info",
            "zone accepted",
            apex=url_apex.to_text(),
            serial=serial,
            client_ip=client_ip,
            catalog_updated=catalog_updated,
        )
        payload = {
            "apex": url_apex.to_text(),
            "serial": serial,
            "catalogUpdated": catalog_updated,
            "nextExpireHint": next_expire_hint(zone),
        }
        return payload, (201 if catalog_updated else 200)
    except ApiError as exc:
        store.incr(f"upload_fail_{exc.error}")
        log(
            "info",
            "zone rejected",
            apex=url_apex.to_text(),
            error=exc.error,
            client_ip=client_ip,
            message=exc.message,
        )
        raise


def _enforce_parent_budget(settings, store, client_ip: str) -> None:
    """Stage 10 re-checks the per-IP parent budget without consuming it.

    The token is consumed only when a lookup is about to be sent. A negative
    cache hit does not spend budget. The upload rate limit still applies.
    """

    if settings.parent_query_budget <= 0:
        return
    # Peek by attempting a zero-cost read of the bucket via a dry count.
    # ``allow_rate`` consumes a token, so the real consume happens immediately
    # before the lookup, after the cache check. This function only rejects
    # when the bucket is already exhausted.
    if _bucket_exhausted(
        store,
        f"parent:{client_ip}",
        settings.parent_query_budget,
        settings.parent_query_window_seconds,
        settings.now(),
    ):
        raise ApiError(429, "rate_limited", "parent lookup budget exceeded")


def _bucket_exhausted(store, bucket: str, limit: int, window: int, now: int) -> bool:
    with store._read() as conn:
        row = conn.execute(
            "SELECT window_start, count FROM rate_limit WHERE bucket = ?",
            (bucket,),
        ).fetchone()
    if row is None or now >= int(row["window_start"]) + window:
        return False
    return int(row["count"]) >= limit


def _remember_parent_failure(store, settings, apex: str, exc: ApiError) -> None:
    if exc.error not in _PARENT_CACHE_ERRORS:
        return
    store.negative_put(
        apex,
        exc.error,
        exc.status,
        exc.message,
        settings.now() + settings.negative_cache_ttl_seconds,
    )


def _enforce_parent_cap(settings, store, parent_zone: str, apex: str) -> None:
    cap = settings.apexes_per_parent_per_day
    if cap <= 0:
        return
    day = datetime.fromtimestamp(settings.now(), timezone.utc).strftime("%Y-%m-%d")
    if store.parent_day_has(parent_zone, apex, day):
        return
    if store.count_parent_day(parent_zone, day) >= cap:
        raise ApiError(429, "rate_limited", "distinct apex cap for this parent has been reached today")


def _notify(settings, store, notifier, apex: str, zone, catalog_updated: bool) -> None:
    try:
        if catalog_updated:
            soa = catalog_soa(settings, store.catalog_serial())
            notifier.notify(settings.catalog_zone.to_text(), soa)
        import dns.rdatatype

        notifier.notify(apex, zone.get(dns.rdatatype.SOA))
    except Exception as exc:
        log("warning", "NOTIFY sequence failed", apex=apex, error=str(exc))
