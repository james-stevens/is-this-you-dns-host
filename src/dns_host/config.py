"""Environment configuration.

Numeric limits and policy windows are environment variables so a self-hoster
can change them without editing code. Defaults are the production-shaped
values documented in the README. Tests construct ``Settings`` directly.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rrset

from dns_host.names import normalise_name

_REPO_ANCHORS = Path(__file__).resolve().parents[2] / "deploy" / "root-anchors.ds"

DEFAULT_TYPES = (
    "SOA,NS,A,AAAA,DNSKEY,RRSIG,NSEC3,NSEC3PARAM,NSEC,TXT,URI,WALLET,CNAME,MX,SRV,"
    "TLSA,CAA,PTR,OPENPGPKEY,SVCB,HTTPS,SMIMEA,HINFO,NAPTR,SPF"
)


def _now() -> int:
    import time

    return int(time.time())


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return int(raw)


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def parse_trusted_proxies(raw: str) -> list[str]:
    """Return nginx-ready CIDRs. A bare address becomes a /32 or /128."""

    out: list[str] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        out.append(str(ipaddress.ip_network(part, strict=False)))
    return out


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
    resolver_base_url: str = "https://api.web3dns.net/"
    catalog_zone: object = None
    catalog_rname: object = None
    data_dir: Path = Path("/data")
    http_port: int = 8080
    gunicorn_bind: str = "127.0.0.1:8000"
    gunicorn_workers: int = 2
    dns_bind: str = "0.0.0.0"
    dns_port: int = 5353
    max_body_bytes: int = 1048576
    max_rrsets: int = 2000
    max_names: int = 1000
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
    def from_env(cls) -> "Settings":
        service_ns = parse_csv_names(
            _env("SERVICE_NS", "ns1.example.net.,ns2.example.net.")
        )
        catalog = normalise_name(_env("CATALOG_ZONE", "catalog.example.net."), what="catalog zone")
        rname_raw = _env("CATALOG_RNAME", "")
        if rname_raw:
            rname = normalise_name(rname_raw, what="catalog rname")
        else:
            rname = normalise_name("hostmaster." + catalog.to_text(), what="catalog rname")
        anchor_path = Path(_env("TRUST_ANCHOR_FILE", str(_REPO_ANCHORS)))
        hs_path = _env("HANDSHAKE_TRUST_ANCHOR_FILE", "")
        types = frozenset(
            item.strip().upper()
            for item in _env("TYPE_ALLOWLIST", DEFAULT_TYPES).split(",")
            if item.strip()
        )
        digests = tuple(
            int(item.strip())
            for item in _env("DS_DIGEST_TYPES", "2").split(",")
            if item.strip()
        )
        return cls(
            service_ns=service_ns,
            secondaries=parse_secondaries(_env("SECONDARIES", "")),
            resolver_base_url=_env("RESOLVER_BASE_URL", "https://api.web3dns.net/"),
            catalog_zone=catalog,
            catalog_rname=rname,
            data_dir=Path(_env("DATA_DIR", "/data")),
            http_port=_env_int("HTTP_PORT", 8080),
            gunicorn_bind=_env("GUNICORN_BIND", "127.0.0.1:8000"),
            gunicorn_workers=_env_int("GUNICORN_WORKERS", 2),
            dns_bind=_env("DNS_BIND", "0.0.0.0"),
            dns_port=_env_int("DNS_PORT", 5353),
            max_body_bytes=_env_int("MAX_BODY_BYTES", 1048576),
            max_rrsets=_env_int("MAX_RRSETS", 2000),
            max_names=_env_int("MAX_NAMES", 1000),
            rate_limit_requests=_env_int("RATE_LIMIT_REQUESTS", 30),
            rate_limit_window_seconds=_env_int("RATE_LIMIT_WINDOW_SECONDS", 60),
            parent_query_budget=_env_int("PARENT_QUERY_BUDGET", 15),
            parent_query_window_seconds=_env_int("PARENT_QUERY_WINDOW_SECONDS", 60),
            max_doh_queries_per_walk=_env_int("MAX_DOH_QUERIES_PER_WALK", 32),
            serial_future_seconds=_env_int("SERIAL_FUTURE_SECONDS", 300),
            serial_past_seconds=_env_int("SERIAL_PAST_SECONDS", 3600),
            rrsig_max_lifetime_seconds=_env_int("RRSIG_MAX_LIFETIME_SECONDS", 30 * 86400),
            rrsig_inception_future_seconds=_env_int("RRSIG_INCEPTION_FUTURE_SECONDS", 300),
            rrsig_min_remaining_seconds=_env_int("RRSIG_MIN_REMAINING_SECONDS", 0),
            grace_days=_env_int("GRACE_DAYS", 90),
            negative_cache_ttl_seconds=_env_int("NEGATIVE_CACHE_TTL_SECONDS", 60),
            min_ttl=_env_int("MIN_TTL", 30),
            max_ttl=_env_int("MAX_TTL", 86400),
            ds_digest_types=digests,
            apexes_per_parent_per_day=_env_int("APEXES_PER_PARENT_PER_DAY", 0),
            doh_timeout_seconds=float(_env("DOH_TIMEOUT_SECONDS", "5")),
            doh_cd=_env_int("DOH_CD", 1),
            trust_anchors=load_ds_anchors(anchor_path),
            handshake_root_servers=parse_csv_names(_env("HANDSHAKE_ROOT_SERVERS", "")),
            handshake_trust_anchors=load_ds_anchors(Path(hs_path)) if hs_path else [],
            tsig_key_name=_env("TSIG_KEY_NAME", ""),
            tsig_secret=_env("TSIG_SECRET", ""),
            tsig_algo=_env("TSIG_ALGO", "hmac-sha256"),
            axfr_require_tsig=_env_bool("AXFR_REQUIRE_TSIG", False),
            maintenance_interval_seconds=_env_int("MAINTENANCE_INTERVAL_SECONDS", 300),
            soa_refresh=_env_int("SOA_REFRESH", 3600),
            soa_retry=_env_int("SOA_RETRY", 600),
            soa_expire=_env_int("SOA_EXPIRE", 864000),
            soa_minimum=_env_int("SOA_MINIMUM", 300),
            catalog_ttl=_env_int("CATALOG_TTL", 300),
            type_allowlist=types,
            trusted_proxies=parse_trusted_proxies(_env("TRUSTED_PROXIES", "")),
            health_check_dns=_env_bool("HEALTH_CHECK_DNS", True),
        )
