"""Retention: RRSIG expiry and parent DS/NS drift share one grace period.

A failed parent re-check starts the grace clock and keeps the last stored
zone. Restoring a matching DS clears it. A resolver outage (503) does not
move the clock. When the grace period ends the zone is removed from the
catalog and secondaries are notified of the catalog change only.
"""

from __future__ import annotations

import threading

from dns_host.catalog import catalog_soa
from dns_host.chain import _keys_matching_ds, authenticate_parent
from dns_host.doh import DohClient
from dns_host.errors import ApiError
from dns_host.logutil import log
from dns_host.names import normalise_name
from dns_host.notify import UdpNotifier
from dns_host.zone import document_to_zone


class Maintenance:
    def __init__(self, settings, store, lookup=None, notifier=None):
        self.settings = settings
        self.store = store
        self.lookup = lookup or DohClient(settings.resolver_base_url, settings.doh_timeout_seconds)
        self.notifier = notifier or UdpNotifier(settings, store)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="maintenance", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception as exc:
                log("error", "maintenance failed", error=str(exc))
            self._stop.wait(self.settings.maintenance_interval_seconds)

    def run_once(self) -> None:
        if not self._lock.acquire(blocking=False):
            return
        try:
            now = self.settings.now()
            for row in self.store.list_zones():
                if now > row.rrsig_max_expiry + self.settings.grace_seconds:
                    self._drop(row.apex, now, "rrsig grace elapsed")
                    continue
                self._recheck_parent(row, now)
        finally:
            self._lock.release()

    def _recheck_parent(self, row, now: int) -> None:
        try:
            apex = normalise_name(row.apex)
            zone = document_to_zone(apex, row.document)
            delegation = authenticate_parent(self.lookup, self.settings, apex)
            if _delegation_matches(zone, delegation, self.settings):
                if row.parent_drift_since is not None or not row.parent_ok:
                    log("info", "parent match restored", apex=row.apex)
                self.store.set_parent_state(row.apex, now=now, ok=True, drift_since=None)
                return
            self._note_drift(row, now, "parent DS or NS no longer matches")
        except ApiError as exc:
            if exc.status == 503 or exc.error == "parent_lookup_unavailable":
                log("warning", "parent recheck unavailable", apex=row.apex, error=exc.error, message=exc.message)
                return
            self._note_drift(row, now, exc.error)

    def _note_drift(self, row, now: int, reason: str) -> None:
        since = row.parent_drift_since if row.parent_drift_since is not None else now
        self.store.set_parent_state(row.apex, now=now, ok=False, drift_since=since)
        log("info", "parent drift", apex=row.apex, reason=reason, since=since)
        if now > since + self.settings.grace_seconds:
            self._drop(row.apex, now, "parent drift grace elapsed")

    def _drop(self, apex: str, now: int, reason: str) -> None:
        serial = self.store.delete_zone(apex, now)
        if serial is None:
            return
        self.store.incr("zones_dropped")
        log("info", "zone dropped", apex=apex, reason=reason, catalog_serial=serial)
        try:
            self.notifier.notify(self.settings.catalog_zone.to_text(), catalog_soa(self.settings, serial))
        except Exception as exc:
            log("warning", "catalog NOTIFY after drop failed", apex=apex, error=str(exc))


def _delegation_matches(zone, delegation, settings) -> bool:
    parent_ns = {name.canonicalize() for name in delegation.ns_names}
    apex_ns = {name.canonicalize() for name in zone.apex_ns_names()}
    service = {name.canonicalize() for name in settings.service_ns}
    if not service <= parent_ns or parent_ns != apex_ns:
        return False
    if delegation.proved_ds_absent or delegation.ds_rrset is None or len(delegation.ds_rrset) == 0:
        return False
    matched = _keys_matching_ds(zone.apex, zone.get(dns_dnskey()), list(delegation.ds_rrset), settings.ds_digest_types)
    return bool(matched)


def dns_dnskey():
    import dns.rdatatype

    return dns.rdatatype.DNSKEY
