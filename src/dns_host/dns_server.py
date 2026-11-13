"""Hidden primary DNS listener.

Serves SOA (UDP and TCP) and AXFR (TCP) for the catalog zone and member
zones. Every other query is refused. AXFR requires the client address to be
in SECONDARIES, or a valid TSIG signature. A bad TSIG is refused even when
the address is allowed. IXFR is not implemented.
"""

from __future__ import annotations

import ipaddress
import socket
import threading

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.tsig
import dns.tsigkeyring

from dns_host.catalog import catalog_rrsets
from dns_host.logutil import log
from dns_host.zone import document_to_zone
from dns_host.zonesync import ZoneIndex

_TSIG_ALGORITHMS = {
    "hmac-sha256": dns.tsig.HMAC_SHA256,
    "hmac-sha1": dns.tsig.HMAC_SHA1,
    "hmac-sha384": dns.tsig.HMAC_SHA384,
    "hmac-sha512": dns.tsig.HMAC_SHA512,
}


class DnsServer:
    def __init__(self, settings, store):
        self.settings = settings
        self.store = store
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.tcp: socket.socket | None = None
        self.udp: socket.socket | None = None
        self.port = settings.dns_port
        self.index = ZoneIndex(settings, store)

    def start(self) -> int:
        bind = self.settings.dns_bind
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((bind, self.settings.dns_port if self.settings.dns_port else 0))
        self.tcp.listen(16)
        self.port = self.tcp.getsockname()[1]
        self.settings.dns_port = self.port
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.bind((bind, self.port))
        self.tcp.settimeout(0.5)
        self.udp.settimeout(0.5)
        self.index.refresh()
        self._threads = [
            threading.Thread(target=self._udp_loop, name="dns-udp", daemon=True),
            threading.Thread(target=self._tcp_loop, name="dns-tcp", daemon=True),
            threading.Thread(target=self._poll_loop, name="dns-catalogue", daemon=True),
        ]
        for thread in self._threads:
            thread.start()
        log("info", "DNS listener started", port=self.port, bind=bind)
        return self.port

    def stop(self) -> None:
        self._stop.set()
        for sock in (self.udp, self.tcp):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        for thread in self._threads:
            thread.join(timeout=2)

    def _poll_loop(self) -> None:
        while not self._stop.wait(1.0):
            try:
                self.index.refresh()
            except Exception as exc:
                log("error", "catalogue poll failed", error=str(exc))

    def _udp_loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.udp.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            wire = self._handle(data, addr[0], tcp=False)
            if wire:
                try:
                    self.udp.sendto(wire, addr)
                except OSError:
                    pass

    def _tcp_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(
                target=self._tcp_client, args=(conn, addr[0]), name="dns-axfr", daemon=True
            )
            thread.start()

    def _tcp_client(self, conn: socket.socket, peer: str) -> None:
        with conn:
            conn.settimeout(10)
            try:
                header = _read_exact(conn, 2)
                if header is None:
                    return
                length = int.from_bytes(header, "big")
                data = _read_exact(conn, length)
                if data is None:
                    return
                messages = self._handle(data, peer, tcp=True)
                for wire in messages:
                    conn.sendall(len(wire).to_bytes(2, "big") + wire)
            except OSError:
                return

    def _handle(self, data: bytes, peer: str, tcp: bool):
        keyring = _keyring(self.settings)
        try:
            query = dns.message.from_wire(data, keyring=keyring)
        except Exception:
            refused = _bare_response(data, dns.rcode.REFUSED)
            return [refused] if tcp else refused
        self.index.refresh()
        if query.had_tsig and query.tsig_error:
            wire = _error_response(query, dns.rcode.REFUSED).to_wire()
            return [wire] if tcp else wire
        if not query.question or len(query.question) != 1:
            wire = _error_response(query, dns.rcode.FORMERR).to_wire()
            return [wire] if tcp else wire
        question = query.question[0]
        qtype = question.rdtype
        if int(question.rdclass) != int(dns.rdataclass.IN):
            wire = _error_response(query, dns.rcode.REFUSED).to_wire()
            return [wire] if tcp else wire
        if qtype == dns.rdatatype.IXFR:
            wire = _error_response(query, dns.rcode.NOTIMP).to_wire()
            return [wire] if tcp else wire
        if qtype == dns.rdatatype.AXFR:
            if not tcp:
                wire = _error_response(query, dns.rcode.FORMERR).to_wire()
                return [wire]
            if not self._axfr_allowed(query, peer):
                self.store.incr("axfr_denied")
                log("info", "AXFR denied", apex=question.name.to_text(), client_ip=peer)
                wire = _error_response(query, dns.rcode.REFUSED).to_wire()
                return [wire]
            messages = self._axfr(query, question.name)
            if messages is None:
                wire = _error_response(query, dns.rcode.REFUSED).to_wire()
                return [wire]
            self.store.incr("axfr_ok")
            log("info", "AXFR served", apex=question.name.to_text(), client_ip=peer)
            return messages
        if qtype != dns.rdatatype.SOA:
            wire = _error_response(query, dns.rcode.REFUSED).to_wire()
            return [wire] if tcp else wire
        soa = self._soa(question.name)
        response = dns.message.make_response(query)
        response.flags |= dns.flags.AA
        if soa is None:
            response.set_rcode(dns.rcode.REFUSED)
        else:
            response.answer.append(soa)
        wire = response.to_wire()
        return [wire] if tcp else wire

    def _axfr_allowed(self, query, peer: str) -> bool:
        if query.had_tsig and not query.tsig_error:
            return True
        if self.settings.axfr_require_tsig:
            return False
        if self.settings.allow_localhost_xfr and _is_loopback(peer):
            return True
        return _ip_allowed(peer, self.settings.allowed_axfr_ips)

    def _catalog_serial(self) -> int:
        if self.index.loaded:
            return self.index.catalog_serial
        return self.store.catalog_serial()

    def _members(self) -> list[str]:
        if self.index.loaded:
            return self.index.member_names()
        return self.store.list_members()

    def _zone(self, name: dns.name.Name):
        text = name.to_text().lower()
        if self.index.loaded:
            return self.index.zones.get(text)
        row = self.store.get_zone(text)
        if row is None:
            return None
        return document_to_zone(name, row.document)

    def _soa(self, name: dns.name.Name):
        text = name.to_text().lower()
        if text == self.settings.catalog_zone.to_text():
            return catalog_rrsets(self.settings, self._catalog_serial(), [])[0]
        zone = self._zone(name)
        if zone is None:
            return None
        return zone.get(dns.rdatatype.SOA)

    def _axfr(self, query, name: dns.name.Name):
        text = name.to_text().lower()
        if text == self.settings.catalog_zone.to_text():
            rrsets = catalog_rrsets(self.settings, self._catalog_serial(), self._members())
        else:
            zone = self._zone(name)
            if zone is None:
                return None
            rrsets = zone.axfr_rrsets()
        if not rrsets:
            return None
        soa = rrsets[0]
        middle = rrsets[1:]
        chunks: list[list] = []
        current: list = [soa]
        for rrset in middle:
            current.append(rrset)
            if len(current) >= 8:
                chunks.append(current)
                current = []
        chunks.append(current + [soa])
        wires = []
        ctx = None
        for index, records in enumerate(chunks):
            response = dns.message.make_response(query) if index == 0 else dns.message.Message(id=query.id)
            response.flags |= dns.flags.QR | dns.flags.AA
            if index != 0 and query.had_tsig:
                response.use_tsig(
                    query.keyring,
                    query.keyname,
                    algorithm=query.keyalgorithm,
                )
            for rrset in records:
                response.answer.append(rrset)
            # The AXFR client verifies every TCP message with multi=True.
            if query.had_tsig:
                wires.append(response.to_wire(multi=True, tsig_ctx=ctx))
                ctx = response.tsig_ctx
            else:
                wires.append(response.to_wire())
        return wires


def _configured_tsig_keys(settings) -> list[tuple[str, str, str]]:
    found: list[tuple[str, str, str]] = []
    if settings.tsig_secret and settings.tsig_key_name:
        found.append((settings.tsig_key_name, settings.tsig_secret, settings.tsig_algo))
    for secondary in settings.secondaries:
        name = getattr(secondary, "tsig_key_name", "") or ""
        secret = getattr(secondary, "tsig_secret", "") or ""
        algo = getattr(secondary, "tsig_algo", "") or "hmac-sha256"
        if name and secret:
            found.append((name, secret, algo))
    return found


def _keyring(settings):
    keys = _configured_tsig_keys(settings)
    if not keys:
        return None
    ring = {}
    for name, secret, algo in keys:
        algorithm = _TSIG_ALGORITHMS.get(str(algo).lower(), dns.tsig.HMAC_SHA256)
        try:
            parsed = dns.tsigkeyring.from_text({name: secret})
        except Exception:
            log("error", "TSIG secret is not valid base64", key=name)
            continue
        for keyname, key in parsed.items():
            raw = key.secret if hasattr(key, "secret") else key
            owner = key.name if hasattr(key, "name") else keyname
            ring[keyname] = dns.tsig.Key(owner, raw, algorithm)
    return ring or None


def _is_loopback(peer: str) -> bool:
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return bool(ip.is_loopback)


def _ip_allowed(peer: str, allowed: set[str]) -> bool:
    try:
        ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return str(ip) in allowed


def _read_exact(conn: socket.socket, count: int) -> bytes | None:
    buf = b""
    while len(buf) < count:
        chunk = conn.recv(count - len(buf))
        if not chunk:
            return None
        buf += chunk
    return buf


def _error_response(query, rcode):
    response = dns.message.make_response(query)
    response.set_rcode(rcode)
    return response


def _bare_response(data: bytes, rcode) -> bytes:
    try:
        ident = int.from_bytes(data[:2], "big") if len(data) >= 2 else 0
    except Exception:
        ident = 0
    response = dns.message.Message(id=ident)
    response.flags |= dns.flags.QR
    response.set_rcode(rcode)
    return response.to_wire()


def main() -> None:
    from dns_host.config import Settings, log_effective
    from dns_host.maintenance import RemoteMaintenance
    from dns_host.storage import Store

    settings = Settings.load()
    settings.require_service_ns()
    log_effective(settings)
    if not _is_loopback(settings.dns_bind):
        log("error", "refusing to start", error="dns master must bind a loopback address")
        raise SystemExit("dns_bind must be a loopback address")
    store = Store(settings.db_path)
    store.ensure_catalog(settings.now())
    server = DnsServer(settings, store)
    server.index.refresh()
    if settings.manage_nsd:
        server.index.write_nsd()
    server.start()
    maintenance = RemoteMaintenance(settings)
    maintenance.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        maintenance.stop()
        server.stop()


if __name__ == "__main__":
    main()
