# Is this you? — DNS hosting service

Account-less hidden primary for DNSSEC-signed zones. Anyone may upload a zone. It is accepted only when the zone validates, the parent DS matches a KSK in the zone, the parent NS set equals the apex NS set, and that set includes every nameserver of this deployment. The service never holds zone-signing keys.

NSD is the public DNS relay. A Python master on localhost holds the zones and answers SOA and AXFR to NSD. NSD transfers from that master and is the only listener secondaries should use. The API is the only writer of zone files and the zone catalogue. The DNS side polls that catalogue about once a second.

This repository is MIT licensed.

## Run it

The image is Alpine 3.24. The container root is read-only. Persistent data is the `/opt/data` volume. `/run` and `/tmp` are tmpfs. Copy the example config if you want different nameservers; Compose bind-mounts it at `/opt/data/etc/config.yaml`.

```sh
docker compose up --build
```

`docker compose up` does not publish TLS. Put a reverse proxy in front if you want HTTPS. `docker-compose.tls.yml` adds the owner's [easy-nginx](https://github.com/james-stevens/easy-nginx) image (`jamesstevens/easy-nginx`, MIT) as that proxy. Use `deploy/config.tls.yaml` so `trusted_proxies` is the compose network of the terminator:

```sh
docker compose -f docker-compose.yml -f docker-compose.tls.yml up --build
```

Place a PEM containing both the certificate and the private key at `deploy/easy-nginx/pems/upload.pem`, and set the public name in `deploy/easy-nginx/etc/nginx.input`. Port 80 on the terminator redirects to HTTPS. The service itself speaks plain HTTP only.

### Ports

| Port | Bind | Process | Published |
| --- | --- | --- | --- |
| 53/udp, 53/tcp | `0.0.0.0` | NSD, the public relay | yes |
| 80/tcp | `0.0.0.0` | nginx external listener (`/api/` is the `/ext/` tree) | yes |
| 5353/udp, 5353/tcp | `127.0.0.1` | Python master (SOA, AXFR; IXFR is NOTIMP and NSD falls back to AXFR) | no |
| 8081/tcp | `127.0.0.1` | nginx internal listener (`/api/` is the `/int/` tree) | no |
| 8000/tcp | `127.0.0.1` | gunicorn | no |

Syslog is local. busybox `syslogd` listens on the `/dev/log` socket and writes `/opt/data/log/messages`. It is not a network service; a networked syslog would use port 514.

NSD binds port 53 as root and then drops to the `nsd` user. nginx's master binds port 80 as root; workers run as `nginx`. Compose adds `NET_BIND_SERVICE` and starts the container as root so those binds succeed on a read-only root. After the drop, NSD writes zone state under `/opt/data/nsd` and its pid under `/run/nsd`. nginx temp files are under `/tmp`. Nothing else is writable: `PYTHONDONTWRITEBYTECODE=1`, and pid, socket, and temp paths are `/run` or `/tmp`.

### Layout

| Path | Contents |
| --- | --- |
| `/opt/data/etc/config.yaml` | Operator configuration. A missing file is empty configuration. |
| `/opt/data/zones` | Zone files, `catalogue.json`, and their temp files |
| `/opt/data/nsd` | Generated `nsd.conf`, TSIG control keys, transferred zones |
| `/opt/data/log` | Syslog output |
| `/opt/data/host.db` | API state (admission, grace, counters). The DNS side does not serve from this file. |
| `/run`, `/tmp` | tmpfs: pid files, the NSD control socket, nginx temp files |

### HTTP

nginx presents each application tree as `/api/` on its own listener.

* External, port 80: `GET /health`, `GET /metrics`, `POST /api/v1/zones/{apex}`, and the same paths under `/ext/` on gunicorn.
* Internal, `127.0.0.1:8081`: `POST /api/zones/drop` and `POST /api/zones/parent-state` (gunicorn paths `/int/zones/...`). Expire and delete are not on the public listener.

`/health` reports the process, the catalog serial, and a localhost SOA query to the Python master. `/metrics` reports upload, lookup, AXFR, NOTIFY and grace counters.

## Configuration

`/opt/data/etc/config.yaml` is the configuration. Environment variables are not read. TSIG secrets may be inline or in `tsig_secret_file` (a Docker secret mount is a normal place). They are never taken from a zone upload.

| Key | Default | Role |
| --- | --- | --- |
| `service_ns` | unset; the process refuses to start | Public nameservers. All of them must appear in the apex NS and in the parent delegation. |
| `secondaries` | empty | IP, optional port, optional TSIG. NSD `provide-xfr` and `notify` are generated from this list. |
| `resolver_base_url` | `https://api.isthisyou.org/` | DoH JSON resolver for parent lookups. |
| `catalog_zone` | `catalog.example.net.` | Catalog zone apex (RFC 9432). |
| `trusted_proxies` | empty | CIDRs allowed to supply `X-Forwarded-For` / `X-Forwarded-Proto` on the external listener. |
| `trust_anchor_file` | image copy of the IANA root DS set | DS records for the ICANN root. |
| `grace_days` | `90` | How long to keep serving after RRSIG expiry or parent DS/NS drift. |
| `max_body_bytes` / `max_rrsets` / `max_names` / `max_rdata_bytes` | 1 MiB / 2000 / 1000 / 4096 | Upload and rdata caps. |

The example file lists the rate limits, the serial window, and the DS digest list. `handshake_root_servers` and `handshake_trust_anchor_file` together enable a second walk when the name is proved absent from the ICANN root.

Secondaries are one list. Each entry is an IP, an optional port, and an optional TSIG key name, secret (or `tsig_secret_file`), and algorithm. The generated NSD pattern emits `provide-xfr` and `notify` for those addresses only.

## Try an upload

The phone builds and signs the zone. For a dry run on a workstation:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=src python3 -m dns_host.demo_zone \
  --apex user.example. \
  --service-ns ns1.example.net.,ns2.example.net. \
  > /tmp/zone.json
```

The command writes the upload JSON to stdout and the KSK DS to stderr. Before the first upload can succeed, the parent zone must already delegate to every `service_ns` name and publish that DS. A missing DS is the kill switch: new uploads fail, and the stored zone is dropped after `grace_days`.

```sh
curl -sS -X POST "http://127.0.0.1/api/v1/zones/user.example" \
  -H "content-type: application/json" \
  --data-binary @/tmp/zone.json
```

A success body is `{"apex", "serial", "catalogUpdated", "nextExpireHint"}`. `nextExpireHint` is the earliest RRSIG expiration. The first accept is HTTP 201; a later higher serial is HTTP 200.

The sample zone will not pass against the public resolver unless `user.example` is really delegated to this host. Point `resolver_base_url` at your own copy of the same DoH JSON API, or run the test suite, which signs a zone and answers the parent walk itself.

### Upload body

```json
{
  "kind": "dnsauth#signedZone",
  "apex": "user.example.",
  "rrsets": [
    {
      "kind": "dns#resourceRecordSet",
      "name": "user.example.",
      "type": "SOA",
      "ttl": 300,
      "rrdatas": ["ns1.example.net. hostmaster.user.example. 1731000000 3600 600 864000 300"]
    }
  ]
}
```

Names are stored absolute, lowercased, with one trailing dot. Unicode labels are converted with IDNA. A missing trailing dot is added; it does not make the name relative to the apex, so send `www.user.example.` and not `www`. Names inside rdata follow zone-file rules: no trailing dot means relative to the apex. Wildcards are rejected. Labels may contain underscore (`_auth`).

SOA serial is unix time. It must be greater than the serial already stored, not more than 5 minutes ahead of the service clock, and not older than one hour.

User zones are NSEC3 as in RFC 9276: iterations 0, empty salt, Opt-Out off. Plain NSEC zones are rejected. DNSKEY algorithm 13 or 15 (P-256 or Ed25519), with a flags-257 KSK. RRSIG lifetime is at most 30 days and the signature must be valid now. Current standard RR types plus WALLET (IANA type 262) are accepted when they validate. Obsolete, experimental, and private-use types (NULL, HINFO, MD, MF, MB, private-use numbers, and the like) are rejected before signature checks. `URI` and `WALLET` are accepted only at the zone apex. Each WALLET rdata is either two character-strings (type, identifier) or four (type, identifier, description, sort order). If the installed dnspython has no WALLET class, the same rdata is stored as RFC 3597 unknown-type wire.

### What the service checks, in order

Body size, then the per-IP upload rate, then JSON. After that, still offline: RRset, name, and rdata caps, owner names, one apex SOA, serial freshness, type policy, TTL bounds, DNSKEY, RRSIG metadata, the NSEC3 chain, apex NS contains every `service_ns`, and in-bailiwick NS names have A or AAAA glue. Glue is checked before any parent query because it does not need the parent.

Only then does the service spend a parent-lookup token. Failed parent results are cached per apex for `negative_cache_ttl_seconds` and a retry in that window does not query again. The walk uses the DoH JSON resolver and only these parameters: `name`, `type`, `do=1`, `rd=0`, `server=<parent NS>`, `cd`. `do=1` answers are read from base64 `rdata`. The resolver's AD bit is not trusted.

The parent NS name set must equal the apex NS set. If the parent is missing a service NS the error is `parent_ns_incomplete` (403). Any other difference is `ns_set_mismatch` (422). The DS digest is compared to the uploaded KSK before any signature in the upload is verified. Signature verification is last.

On success the API writes the zone file under `/opt/data/zones`, then rewrites `catalogue.json` (apex and SOA serial) by rename. The Python master notices the new mtime, parses the JSON into wire form, and NSD is reconfigured from the same secondary list.

## Secondaries

NOTIFY is UDP. The API notifies the catalog zone first when membership changed, then the member zone. NSD is generated with the same `notify` targets, so a missed API notify is repeated after NSD has the zone. SOA is answered so a secondary can poll. AXFR from the public internet hits NSD, which allows exactly the configured secondary addresses. The Python master allows those addresses, a valid TSIG, and localhost (so NSD can transfer). A bad TSIG is refused. Set `axfr_require_tsig: true` to require TSIG as well.

The catalog is schema version 2 (`version.<catalog> TXT "2"`, member PTRs at `<label>.zones.<catalog>`). It is not signed. The tests speak AXFR with dnspython. NSD on the public port is what a real secondary talks to.

The 90-day clear-out runs on the DNS side. It asks the API, over the internal listener, to delete a zone. The API updates the catalogue and notifies the catalog zone.

## Tests

```sh
pip install -r requirements-dev.txt
python3 -m pytest
```

The tests generate and sign fixture zones (algorithm 13 and 15, NSEC3). They do not use the network. GitHub Actions runs the tests, ruff (pyflakes), and a read-only container boot that checks HTTP, the public DNS port, and an empty `docker diff`.

Dev dependencies are pip-installed on the workstation and in CI. The image does not use pip: Alpine 3.24 supplies `py3-flask`, `py3-gunicorn`, `py3-dnspython`, `py3-cryptography`, and `py3-yaml`.

## Decisions

* **Secondary in CI.** dnspython performs AXFR in the tests. The container runs NSD as the relay. No Knot or BIND container.
* **Limits.** 1 MiB body, 2000 RRsets, 1000 names, 4096-byte rdata, 30 uploads per IP per minute, 15 parent lookups per IP per minute.
* **Extra parent NS names.** The apex NS set and the parent delegation must be equal, and both must include every `service_ns`. An extra name at the parent fails `ns_set_mismatch` unless the apex has it too.
* **DS digests.** SHA-256 only, unless `ds_digest_types` lists more (1 = SHA-1, 4 = SHA-384).
* **Remaining RRSIG lifetime.** A signature only has to be valid now (`rrsig_min_remaining_seconds` defaults to 0). Lifetime is at most 30 days.
* **Negative cache.** 60 seconds, one entry per apex (the latest parent-check failure).
* **Apex text.** Trim, IDNA, lowercase, one trailing dot. The URL apex and the JSON apex must match after that.
* **Glue.** `glue_missing` is returned before a parent query.
* **Handshake.** Off unless both handshake settings are provided.
* **Parent chain failures** that are not a clean DS or NS answer use `parent_chain_invalid` (403). Transport failure is `parent_lookup_unavailable` (503). A resolver outage does not start the drift clock.
* **Drop.** Removing a zone notifies the catalog only.
* **SOA** on the master is for NSD and for polling. Public clients use NSD.

## Not in this MVP

* IXFR from the Python master (NOTIMP). NSD falls back to AXFR.
* More than one hidden primary.
* A bundled secondary beside NSD.
* Re-checking individual RRsets against the previous zone (the serial is the replay control).
* The phone app, enrolment, and JWS verification.
* TLS on this container.
