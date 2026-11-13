"""Operator configuration from ``/opt/data/etc/config.yaml``.

A missing file is empty configuration and the defaults below apply. The
process refuses to start when ``service_ns`` is unset. Tests construct
``Settings`` directly. TSIG secrets may be inline or read from a file; they
are never taken from a zone upload.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from dns_host.names import normalise_name
from dns_host.rrtypes import DEFAULT_TYPES

_REPO_ANCHORS = Path(__file__).resolve().parents[2] / "deploy" / "root-anchors.ds"
CONFIG_PATH = Path("/opt/data/etc/config.yaml")


def _now() -> int:
    import time

    return int(time.time())


def parse_trusted_proxies(raw: str) -> list[str]:
    """Return nginx-ready CIDRs. A bare address becomes a /32 or /128."""

    out: list[str] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        out.append(str(ipaddress.ip_network(part, strict=False)))
    return out


@dataclass
class Secondary:
    """One configured secondary. Iterates as ``(host, port)`` for existing callers."""

    host: str
    port: int = 53
    tsig_key_name: str = ""
    tsig_secret: str = ""
    tsig_algo: str = "hmac-sha256"

    def __iter__(self):
        yield self.host
        yield self.port

    def __getitem__(self, index: int):
        return (self.host, self.port)[index]


def parse_secondaries(raw: str) -> list[tuple[str, int]]:
    """Parse ``ip``, ``ip:port``, or ``[ipv6]:port`` entries.

    IPv6 addresses must be in brackets. The port is the NOTIFY destination.
    AXFR authorisation uses the address only.
    """

    out: list[tuple[str, int]] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        if part.startswith("["):
            host, _, rest = part[1:].partition("]")
            if rest.startswith(":"):
                port = int(rest[1:])
            elif rest == "":
                port = 53
            else:
                raise ValueError(f"bad secondary address {part}")
        elif part.count(":") == 1:
            host, port_s = part.split(":")
            port = int(port_s)
        elif ":" in part:
            raise ValueError(f"bracket IPv6 secondaries, got {part}")
        else:
            host, port = part, 53
        ipaddress.ip_address(host)
        out.append((host, port))
    return out


def parse_csv_names(raw: str) -> list:
    names = []
    for part in raw.split(","):
        part = part.strip()
        if part:
            names.append(normalise_name(part, what="configured name"))
    return names


def load_ds_anchors(path: Path) -> list:
    """Load DS (or DNSKEY, ignored) presentation lines from a file."""

    if not path.is_file():
        return []
    anchors = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = line.split(";", 1)[0].strip()
        if not stripped or stripped.startswith("#"):
            continue
        upper = stripped.upper()
        if " DS " not in f" {upper} ":
            # Allow a bare rdata line: "20326 8 2 HEX"
            if stripped.split()[0].isdigit():
                rdata_text = stripped
            else:
                continue
        else:
            marker = upper.index(" DS ")
            rdata_text = stripped[marker + 4 :].strip()
        try:
            anchors.append(
                dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.DS, rdata_text)
            )
        except Exception as exc:
            raise ValueError(f"{path}:{lineno}: {exc}") from exc
    return anchors


@dataclass
class Settings:
    service_ns: list = field(default_factory=list)
    secondaries: list = field(default_factory=list)
    resolver_base_url: str = "https://api.isthisyou.org/"
    catalog_zone: object = None
    catalog_rname: object = None
    data_dir: Path = Path("/opt/data")
    http_port: int = 80
    internal_http_port: int = 8081
    gunicorn_bind: str = "127.0.0.1:8000"
    gunicorn_workers: int = 2
    dns_bind: str = "127.0.0.1"
    dns_port: int = 5353
    nsd_bind: str = "0.0.0.0"
    nsd_port: int = 53
    max_body_bytes: int = 1048576
    max_rrsets: int = 2000
    max_names: int = 1000
    max_rdata_bytes: int = 4096
    rate_limit_requests: int = 30
    rate_limit_window_seconds: int = 60
    parent_query_budget: int = 15
    parent_query_window_seconds: int = 60
    max_doh_queries_per_walk: int = 32
    serial_future_seconds: int = 300
    serial_past_seconds: int = 3600
    rrsig_max_lifetime_seconds: int = 30 * 86400
    rrsig_inception_future_seconds: int = 300
    rrsig_min_remaining_seconds: int = 0
    grace_days: int = 90
    negative_cache_ttl_seconds: int = 60
    min_ttl: int = 30
    max_ttl: int = 86400
    ds_digest_types: tuple = (2,)
    apexes_per_parent_per_day: int = 0
    doh_timeout_seconds: float = 5.0
    doh_cd: int = 1
    trust_anchors: list = field(default_factory=list)
    handshake_root_servers: list = field(default_factory=list)
    handshake_trust_anchors: list = field(default_factory=list)
    tsig_key_name: str = ""
    tsig_secret: str = ""
    tsig_algo: str = "hmac-sha256"
    axfr_require_tsig: bool = False
    allow_localhost_xfr: bool = True
    manage_nsd: bool = False
    maintenance_interval_seconds: int = 300
    soa_refresh: int = 3600
    soa_retry: int = 600
    soa_expire: int = 864000
    soa_minimum: int = 300
    catalog_ttl: int = 300
    type_allowlist: frozenset = field(default_factory=frozenset)
    trusted_proxies: list = field(default_factory=list)
    health_check_dns: bool = True
    now_fn: Callable[[], int] = _now

    def now(self) -> int:
        return int(self.now_fn())

    def require_service_ns(self) -> None:
        """Refuse to start when the public nameserver list was not configured."""

        if self.service_ns:
            return
        from dns_host.logutil import log

        log("error", "refusing to start", error="service_ns is unset")
        raise SystemExit("service_ns is required in /opt/data/etc/config.yaml")

    @property
    def grace_seconds(self) -> int:
        return self.grace_days * 86400

    @property
    def db_path(self) -> Path:
        return Path(self.data_dir) / "host.db"

    @property
    def allowed_axfr_ips(self) -> set[str]:
        return {host for host, _port in self.secondaries}

    @classmethod
    def load(cls, path: Path | None = None) -> "Settings":
        """Load ``/opt/data/etc/config.yaml``. A missing file is empty configuration."""

        config_path = Path(path) if path is not None else CONFIG_PATH
        raw: dict = {}
        if config_path.is_file():
            import yaml

            loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
            if loaded is None:
                loaded = {}
            if not isinstance(loaded, dict):
                raise SystemExit(f"{config_path} must be a mapping")
            raw = loaded
        return cls.from_mapping(raw)

    @classmethod
    def from_mapping(cls, raw: dict) -> "Settings":
        service_ns = _names_value(raw.get("service_ns", []))
        catalog = normalise_name(
            str(raw.get("catalog_zone") or "catalog.example.net."),
            what="catalog zone",
        )
        rname_raw = str(raw.get("catalog_rname") or "")
        if rname_raw:
            rname = normalise_name(rname_raw, what="catalog rname")
        else:
            rname = normalise_name("hostmaster." + catalog.to_text(), what="catalog rname")
        anchor_path = Path(str(raw.get("trust_anchor_file") or _REPO_ANCHORS))
        hs_path = str(raw.get("handshake_trust_anchor_file") or "")
        if raw.get("type_allowlist"):
            types = frozenset(
                item.strip().upper()
                for item in _string_list(raw.get("type_allowlist"))
                if item.strip()
            )
        else:
            types = frozenset(item.strip().upper() for item in DEFAULT_TYPES.split(",") if item.strip())
        digests = tuple(int(item) for item in _string_list(raw.get("ds_digest_types", "2")) if str(item).strip())
        tsig_name, tsig_secret, tsig_algo = _global_tsig(raw)
        return cls(
            service_ns=service_ns,
            secondaries=_secondaries_value(raw.get("secondaries", [])),
            resolver_base_url=str(raw.get("resolver_base_url") or "https://api.isthisyou.org/"),
            catalog_zone=catalog,
            catalog_rname=rname,
            data_dir=Path(str(raw.get("data_dir") or "/opt/data")),
            http_port=_map_int(raw, "http_port", 80),
            internal_http_port=_map_int(raw, "internal_http_port", 8081),
            gunicorn_bind=str(raw.get("gunicorn_bind") or "127.0.0.1:8000"),
            gunicorn_workers=_map_int(raw, "gunicorn_workers", 2),
            dns_bind=str(raw.get("dns_bind") or "127.0.0.1"),
            dns_port=_map_int(raw, "dns_port", 5353),
            nsd_bind=str(raw.get("nsd_bind") or "0.0.0.0"),
            nsd_port=_map_int(raw, "nsd_port", 53),
            max_body_bytes=_map_int(raw, "max_body_bytes", 1048576),
            max_rrsets=_map_int(raw, "max_rrsets", 2000),
            max_names=_map_int(raw, "max_names", 1000),
            max_rdata_bytes=_map_int(raw, "max_rdata_bytes", 4096),
            rate_limit_requests=_map_int(raw, "rate_limit_requests", 30),
            rate_limit_window_seconds=_map_int(raw, "rate_limit_window_seconds", 60),
            parent_query_budget=_map_int(raw, "parent_query_budget", 15),
            parent_query_window_seconds=_map_int(raw, "parent_query_window_seconds", 60),
            max_doh_queries_per_walk=_map_int(raw, "max_doh_queries_per_walk", 32),
            serial_future_seconds=_map_int(raw, "serial_future_seconds", 300),
            serial_past_seconds=_map_int(raw, "serial_past_seconds", 3600),
            rrsig_max_lifetime_seconds=_map_int(raw, "rrsig_max_lifetime_seconds", 30 * 86400),
            rrsig_inception_future_seconds=_map_int(raw, "rrsig_inception_future_seconds", 300),
            rrsig_min_remaining_seconds=_map_int(raw, "rrsig_min_remaining_seconds", 0),
            grace_days=_map_int(raw, "grace_days", 90),
            negative_cache_ttl_seconds=_map_int(raw, "negative_cache_ttl_seconds", 60),
            min_ttl=_map_int(raw, "min_ttl", 30),
            max_ttl=_map_int(raw, "max_ttl", 86400),
            ds_digest_types=digests,
            apexes_per_parent_per_day=_map_int(raw, "apexes_per_parent_per_day", 0),
            doh_timeout_seconds=float(raw.get("doh_timeout_seconds") if raw.get("doh_timeout_seconds") not in (None, "") else 5),
            doh_cd=_map_int(raw, "doh_cd", 1),
            trust_anchors=load_ds_anchors(anchor_path),
            handshake_root_servers=_names_value(raw.get("handshake_root_servers", [])),
            handshake_trust_anchors=load_ds_anchors(Path(hs_path)) if hs_path else [],
            tsig_key_name=tsig_name,
            tsig_secret=tsig_secret,
            tsig_algo=tsig_algo,
            axfr_require_tsig=_map_bool(raw, "axfr_require_tsig", False),
            allow_localhost_xfr=_map_bool(raw, "allow_localhost_xfr", True),
            manage_nsd=_map_bool(raw, "manage_nsd", True),
            maintenance_interval_seconds=_map_int(raw, "maintenance_interval_seconds", 300),
            soa_refresh=_map_int(raw, "soa_refresh", 3600),
            soa_retry=_map_int(raw, "soa_retry", 600),
            soa_expire=_map_int(raw, "soa_expire", 864000),
            soa_minimum=_map_int(raw, "soa_minimum", 300),
            catalog_ttl=_map_int(raw, "catalog_ttl", 300),
            type_allowlist=types,
            trusted_proxies=parse_trusted_proxies(_csv(raw.get("trusted_proxies", ""))),
            health_check_dns=_map_bool(raw, "health_check_dns", True),
        )


def _map_int(raw: dict, key: str, default: int) -> int:
    value = raw.get(key)
    if value is None or value == "":
        return default
    return int(value)


def _map_bool(raw: dict, key: str, default: bool) -> bool:
    value = raw.get(key)
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _csv(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value)
    return str(value)


def _string_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value]
    return [item.strip() for item in str(value).split(",") if item.strip()]


def _names_value(value) -> list:
    if value is None or value == "" or value == []:
        return []
    if isinstance(value, (list, tuple)):
        return [normalise_name(str(item), what="configured name") for item in value if str(item).strip()]
    return parse_csv_names(str(value))


def _read_secret(item: dict) -> str:
    path = item.get("tsig_secret_file") or ""
    if path:
        secret_path = Path(str(path))
        if not secret_path.is_file():
            raise SystemExit(f"TSIG secret file {secret_path} is missing")
        return secret_path.read_text(encoding="utf-8").strip()
    return str(item.get("tsig_secret") or "")


def _global_tsig(raw: dict) -> tuple[str, str, str]:
    block = raw.get("tsig") or {}
    if not isinstance(block, dict):
        block = {}
    name = str(raw.get("tsig_key_name") or block.get("name") or "")
    algo = str(raw.get("tsig_algo") or block.get("algorithm") or "hmac-sha256")
    secret = _read_secret(
        {
            "tsig_secret": raw.get("tsig_secret", block.get("secret", "")),
            "tsig_secret_file": raw.get("tsig_secret_file", block.get("secret_file", "")),
        }
    )
    return name, secret, algo


def _secondaries_value(value) -> list:
    if value is None or value == "" or value == []:
        return []
    if isinstance(value, str):
        return [Secondary(host, port) for host, port in parse_secondaries(value)]
    out = []
    for item in value:
        if isinstance(item, str):
            host, port = parse_secondaries(item)[0]
            out.append(Secondary(host, port))
            continue
        if not isinstance(item, dict):
            raise SystemExit("each secondary must be a mapping or an address")
        host = str(item.get("ip") or item.get("address") or item.get("host") or "")
        if not host:
            raise SystemExit("a secondary is missing ip")
        ipaddress.ip_address(host)
        secret = _read_secret(item)
        out.append(
            Secondary(
                host=host,
                port=int(item.get("port") or 53),
                tsig_key_name=str(item.get("tsig_key_name") or item.get("key_name") or ""),
                tsig_secret=secret,
                tsig_algo=str(item.get("tsig_algo") or item.get("algorithm") or "hmac-sha256"),
            )
        )
    return out


def log_effective(settings: Settings) -> None:
    """Log the configuration actually in use. TSIG secrets are not included."""

    from dns_host.logutil import log

    secondaries = []
    for item in settings.secondaries:
        host, port = item[0], item[1]
        secondaries.append(
            {
                "ip": host,
                "port": port,
                "tsig": bool(getattr(item, "tsig_key_name", "") and getattr(item, "tsig_secret", "")),
            }
        )
    log(
        "info",
        "configuration",
        service_ns=[name.to_text() for name in settings.service_ns],
        resolver_base_url=settings.resolver_base_url,
        catalog_zone=settings.catalog_zone.to_text() if settings.catalog_zone is not None else "",
        secondaries=secondaries,
        grace_days=settings.grace_days,
        dns_bind=settings.dns_bind,
        dns_port=settings.dns_port,
        nsd_bind=settings.nsd_bind,
        nsd_port=settings.nsd_port,
        http_port=settings.http_port,
        internal_http_port=settings.internal_http_port,
        data_dir=str(settings.data_dir),
        allow_localhost_xfr=settings.allow_localhost_xfr,
    )
