"""NOTIFY (RFC 1996) to configured secondaries.

Failures are logged and do not fail an upload that has already been stored.
Secondaries can still poll SOA.
"""

from __future__ import annotations

import dns.flags
import dns.message
import dns.query
import dns.rdatatype

from dns_host.logutil import log


class Notifier:
    def notify(self, zone: str, soa) -> None:
        raise NotImplementedError


class RecordingNotifier(Notifier):
    def __init__(self):
        self.zones: list[str] = []

    def notify(self, zone: str, soa) -> None:
        self.zones.append(zone)


class UdpNotifier(Notifier):
    def __init__(self, settings, store):
        self.settings = settings
        self.store = store

    def notify(self, zone: str, soa) -> None:
        if not self.settings.secondaries:
            return
        query = dns.message.make_query(zone, dns.rdatatype.SOA)
        query.set_opcode(dns.opcode.NOTIFY)
        query.flags |= dns.flags.AA
        if soa is not None:
            query.answer.append(soa)
        for host, port in self.settings.secondaries:
            try:
                response = dns.query.udp(query, host, port=port, timeout=2)
                if response.rcode() != dns.rcode.NOERROR:
                    self.store.incr("notify_fail")
                    log(
                        "warning",
                        "NOTIFY rejected",
                        apex=zone,
                        secondary=host,
                        port=port,
                        rcode=dns.rcode.to_text(response.rcode()),
                    )
                    continue
                self.store.incr("notify_ok")
                log("info", "NOTIFY sent", apex=zone, secondary=host, port=port)
            except Exception as exc:
                self.store.incr("notify_fail")
                log("warning", "NOTIFY failed", apex=zone, secondary=host, port=port, error=str(exc))
