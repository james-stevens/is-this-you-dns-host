"""Write a signed example upload to stdout and the matching DS to stderr.

The hosting service does not sign zones. Use this only to see the JSON shape
or to produce a zone you will sign again on the phone. Publish the printed DS
and the service NS set at the parent before the first upload will succeed.
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from dns_host.zonesign import ds_text, generate_key, signed_zone_document


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Sign a sample zone and print the upload JSON")
    parser.add_argument("--apex", required=True, help="Zone apex, with or without a trailing dot")
    parser.add_argument(
        "--service-ns",
        required=True,
        help="Comma-separated public nameserver names that the apex NS must include",
    )
    parser.add_argument("--serial", type=int, default=None, help="SOA serial (default: current unix time)")
    parser.add_argument("--ttl", type=int, default=300)
    parser.add_argument(
        "--out",
        default="-",
        help="Where to write the JSON (default stdout)",
    )
    args = parser.parse_args(argv)
    now = int(time.time())
    serial = args.serial if args.serial is not None else now
    ns_names = [part.strip() for part in args.service_ns.split(",") if part.strip()]
    if len(ns_names) < 1:
        parser.error("--service-ns is required")
    ksk_private, ksk = generate_key(257)
    zsk_private, zsk = generate_key(256)
    apex = args.apex if args.apex.endswith(".") else args.apex + "."
    document = signed_zone_document(
        apex=apex,
        serial=serial,
        ns_names=ns_names,
        ksk_private=ksk_private,
        ksk=ksk,
        zsk_private=zsk_private,
        zsk=zsk,
        inception=now - 60,
        expiration=now + 7 * 86400,
        ttl=args.ttl,
        extras=[
            (f"_auth.7e9a2f4c8b1d.{apex}", "TXT", ['"v=dnsauth1 alg=ES256 k=example"']),
            (apex, "URI", ['10 1 "https://example.org/j"']),
            (
                apex,
                "WALLET",
                [
                    '"btc" "bc1qexampleaddress"',
                    '"eth" "0xabc" "cold wallet" "20"',
                ],
            ),
        ],
    )
    payload = json.dumps(document, indent=2) + "\n"
    if args.out == "-":
        sys.stdout.write(payload)
    else:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(payload)
    print(ds_text(apex, ksk), file=sys.stderr)
    print(
        "Publish this DS and every --service-ns name at the parent before uploading.",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
