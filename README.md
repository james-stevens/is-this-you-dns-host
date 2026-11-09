# Is this you? — DNS hosting service

Account-less hidden primary for DNSSEC-signed zones. Anyone may upload a zone. It is accepted only when the zone validates, the parent DS matches a KSK in the zone, the parent NS set equals the apex NS set, and that set includes every nameserver of this deployment. The service never holds zone-signing keys.

The zone is stored and served to configured secondaries: SOA queries, NOTIFY (catalog first, then the member, when the catalog changes), and AXFR. There is no open recursion and no open AXFR. IXFR is not implemented.

This repository is MIT licensed.

## Run it

Docker Compose is enough. Copy the example environment if you want to change the defaults; Compose substitutes `${VAR:-default}` from `.env` when that file exists.

```sh
cp .env.example .env
# edit SERVICE_NS, CATALOG_ZONE, SECONDARIES
docker compose up --build
```

The container listens on plain HTTP port **8080** and DNS port **5353** (UDP and TCP). It does not terminate TLS. Put a reverse proxy in front if you want HTTPS. Map `5353` to `53` on the host when a secondary expects the usual port.

* `GET /health` — process, catalog serial, and a localhost SOA query for the catalog zone.
* `GET /metrics` — upload, lookup, AXFR, NOTIFY and grace counters.
* `POST /v1/zones/{apex}` — upload a signed zone (`Content-Type: application/json`).

Zone files live in the `zone-data` volume (`/data/host.db` inside the container).

### TLS in front (optional)

`docker-compose.yml` is TLS-free. `docker-compose.tls.yml` adds the owner's [easy-nginx](https://github.com/james-stevens/easy-nginx) image (`jamesstevens/easy-nginx`, MIT) as a terminator:

```sh
# Put a PEM containing BOTH the certificate and the private key at
# deploy/easy-nginx/pems/upload.pem
# and set the public name in deploy/easy-nginx/etc/nginx.input.
docker compose -f docker-compose.yml -f docker-compose.tls.yml up --build
```

easy-nginx reads `/opt/data/etc/nginx.input`. The shipped line uses mode `W`, which is the mode in that image that sets `X-Forwarded-For` and `X-Forwarded-Proto` (it also turns on WebSocket upgrade headers). Mode `P` sets `Host` and `X-Forwarded-For` only. Do not set `NGINX_PLAIN_WEB=Y`; that serves static files instead of proxying. Port 80 on the terminator redirects to HTTPS.

The overlay sets `TRUSTED_PROXIES=172.28.9.0/24`, the compose network of the terminator. This service's nginx applies `X-Forwarded-For` only when the TCP peer is in that list (`real_ip`), and it honours `X-Forwarded-Proto` only after that rewrite. Gunicorn is bound to `127.0.0.1` and is not published. The rate limiter uses the address nginx puts in `X-Real-IP`.

## Configuration

| Variable | Default | Role |
| --- | --- | --- |
| `SERVICE_NS` | `ns1.example.net.,ns2.example.net.` | Public nameservers. All of them must appear in the apex NS and in the parent delegation. |
| `SECONDARIES` | empty | `ip`, `ip:port`, or `[ipv6]:port`. NOTIFY targets and the AXFR allow-list (address only). |
| `RESOLVER_BASE_URL` | `https://api.web3dns.net/` | DoH JSON resolver for parent lookups. |
| `CATALOG_ZONE` | `catalog.example.net.` | Catalog zone apex (RFC 9432). |
| `TRUSTED_PROXIES` | empty | CIDRs allowed to supply `X-Forwarded-For` / `X-Forwarded-Proto`. |
| `TRUST_ANCHOR_FILE` | image copy of the IANA root DS set | DS records for the ICANN root (key tags 20326 and 38696). |
| `TSIG_KEY_NAME` / `TSIG_SECRET` | empty | Optional AXFR TSIG. Secret is base64. |
| `GRACE_DAYS` | `90` | How long to keep serving after RRSIG expiry or parent DS/NS drift. |
| `NEGATIVE_CACHE_TTL_SECONDS` | `60` | Hosting-side cache of a failed parent check, per apex. |
| `DS_DIGEST_TYPES` | `2` | DS digest algorithms accepted (2 = SHA-256). |
| `RRSIG_MIN_REMAINING_SECONDS` | `0` | Extra lifetime required beyond "valid right now". |
| `APEXES_PER_PARENT_PER_DAY` | `0` | Soft cap on new apexes under one parent. `0` disables it. |

The full list, including body size, RRset caps, rate limits and the serial window, is in `.env.example`.

`HANDSHAKE_ROOT_SERVERS` and `HANDSHAKE_TRUST_ANCHOR_FILE` together enable a second walk when the name is proved absent from the ICANN root. Leave them empty to stay on the ICANN root only.

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

The command writes the upload JSON to stdout and the KSK DS to stderr. Before the first upload can succeed, the parent zone must already delegate to every `SERVICE_NS` name and publish that DS. A missing DS is the kill switch: new uploads fail, and the stored zone is dropped after `GRACE_DAYS`.

```sh
curl -sS -X POST "http://127.0.0.1:8080/v1/zones/user.example" \
  -H "content-type: application/json" \
  --data-binary @/tmp/zone.json
```

A success body is `{"apex", "serial", "catalogUpdated", "nextExpireHint"}`. `nextExpireHint` is the earliest RRSIG expiration. The first accept is HTTP 201; a later higher serial is HTTP 200.

The sample zone will not pass against the public resolver unless `user.example` is really delegated to this host. Point `RESOLVER_BASE_URL` at your own copy of the same DoH JSON API, or run the test suite, which signs a zone and answers the parent walk itself.

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

Names are stored absolute, lowercased, with one trailing dot. Unicode labels are converted with IDNA. A missing trailing dot is added; it does **not** make the name relative to the apex, so send `www.user.example.` and not `www`. Names inside rdata follow zone-file rules: no trailing dot means relative to the apex. Wildcards are rejected. Labels may contain underscore (`_auth`, `_web._tcp`).

SOA serial is unix time. It must be greater than the serial already stored, not more than 5 minutes ahead of the service clock, and not older than one hour.

User zones are NSEC3 as in RFC 9276: iterations 0, empty salt, Opt-Out off. An NSEC chain with no NSEC3PARAM is accepted for experiments. DNSKEY algorithm 13 only, with a flags-257 KSK. RRSIG lifetime is at most 30 days and the signature must be valid now. WALLET (IANA type 262) is allowed. Each WALLET rdata is either two character-strings (type, identifier) or four (type, identifier, description, sort order). If the installed dnspython has no WALLET class, the same rdata is stored as RFC 3597 unknown-type wire.

### What the service checks, in order

Body size, then the per-IP upload rate, then JSON. After that, still offline: RRset and name caps, owner names, one apex SOA, serial freshness, type allow-list, TTL bounds, DNSKEY, RRSIG metadata, the NSEC3 (or NSEC) chain, apex NS contains every `SERVICE_NS`, and in-bailiwick NS names have A or AAAA glue. Glue is checked before any parent query because it does not need the parent.

Only then does the service spend a parent-lookup token. Failed parent results are cached per apex for `NEGATIVE_CACHE_TTL_SECONDS` and a retry in that window does not query again. The walk uses the DoH JSON resolver and only these parameters: `name`, `type`, `do=1`, `rd=0`, `server=<parent NS>`, `cd`. `do=1` answers are read from base64 `rdata`. The resolver's AD bit is not trusted. The root is read with `rd=0` and no `server` (the resolver's local root copy); the parent DS and NS used for admission are read with `server=<parent NS>`.

The parent NS name set must equal the apex NS set. If the parent is missing a service NS the error is `parent_ns_incomplete` (403). Any other difference is `ns_set_mismatch` (422). The DS digest is compared to the uploaded KSK before any signature in the upload is verified. Signature verification is last: the DNSKEY RRset must validate under the KSK that matched the DS, then every other RRSIG.

## Secondaries

NOTIFY is UDP, catalog zone first when the membership changed, then the member zone. SOA is answered to any address so a secondary can poll. AXFR is TCP and requires the source address to be in `SECONDARIES` or a valid TSIG. A bad TSIG is refused even from an allowed address. Set `AXFR_REQUIRE_TSIG=true` to require both.

The catalog is schema version 2 (`version.<catalog> TXT "2"`, member PTRs at `<label>.zones.<catalog>`). It is not signed; secondaries authenticate the transfer with the allow-list and TSIG. The tests speak AXFR with dnspython. Knot or BIND on the secondary is an operator choice and is not started by Compose.

## Tests

```sh
pip install -r requirements-dev.txt
python3 -m pytest
```

The tests generate and sign fixture zones (algorithm 13, NSEC3 and NSEC). They do not use the network. `tests/test_doh.py` points `RESOLVER_BASE_URL` at a local stub and checks that only the documented query parameters are sent.

## Decisions

These were open in the spec. Defaults are the environment variables above.

* **Secondary in CI.** dnspython performs AXFR in the tests. No Knot or BIND container.
* **Limits.** 1 MiB body, 2000 RRsets, 1000 names, 30 uploads per IP per minute, 15 parent lookups per IP per minute. Dev and production share these defaults; change them in `.env`.
* **Extra parent NS names.** The apex NS set and the parent delegation must be equal, and both must include every `SERVICE_NS`. An extra name at the parent fails `ns_set_mismatch` unless the apex has it too.
* **DS digests.** SHA-256 only, unless `DS_DIGEST_TYPES` lists more (1 = SHA-1, 4 = SHA-384).
* **Remaining RRSIG lifetime.** A signature only has to be valid now (`RRSIG_MIN_REMAINING_SECONDS=0`). Lifetime (expiration minus inception) is at most 30 days.
* **Catalog name.** Whatever `CATALOG_ZONE` is. The example is `catalog.example.net.` with `SERVICE_NS` of `ns1.example.net.` and `ns2.example.net.`
* **Negative cache.** 60 seconds, one entry per apex (the latest parent-check failure). It is this service's cache, not the resolver's.
* **Apex text.** Trim, IDNA, lowercase, one trailing dot. The URL apex and the JSON apex must match after that.
* **Glue.** `glue_missing` is returned before a parent query.
* **Handshake.** Off unless both handshake settings are provided.
* **Parent chain failures** that are not a clean DS or NS answer use `parent_chain_invalid` (403). Transport failure is `parent_lookup_unavailable` (503). A resolver outage does not start the drift clock.
* **Drop.** Removing a zone notifies the catalog only. The member is not notified; secondaries learn the removal from the catalog.
* **SOA.** Answered to any client. AXFR is not.

## Not in this MVP

* IXFR (the server answers NOTIMP).
* More than one hidden primary, or any hand-off between primaries.
* A bundled Knot or BIND secondary.
* Re-checking individual RRsets against the previous zone (the serial is the replay control).
* The phone app, enrolment, and JWS verification. Those are a different project; this service only publishes the signed zone.
* Serving anything other than SOA and AXFR. Other queries are REFUSED.
* TLS on this container.
