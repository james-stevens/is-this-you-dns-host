"""Apex and owner-name normalisation.

Choice (configurable only by the rules below, which are fixed):

* Trim surrounding whitespace.
* If the text has no trailing dot, one is added. A name is always stored absolute.
* Non-ASCII labels are converted with IDNA (punycode). ASCII is lowercased.
* The result is a single fully-qualified name with one trailing dot.
* Labels may contain letters, digits, underscore and hyphen. A hyphen may not
  start or end a label. Wildcards are rejected. This admits ``_auth`` labels.
* URL apex and JSON apex must be identical after this normalisation.
"""

from __future__ import annotations

import re

import dns.exception
import dns.name

from dns_host.errors import ApiError

_LABEL = re.compile(rb"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?")


def bad_label(message: str) -> ApiError:
    return ApiError(422, "bad_label", message)


def normalise_name(text: str, *, what: str = "name", allow_root: bool = False) -> dns.name.Name:
    if not isinstance(text, str):
        raise ApiError(400, "bad_request", f"{what} must be a string")
    raw = text.strip()
    if not raw or "/" in raw or " " in raw or "\\" in raw:
        raise bad_label(f"{what} is not a DNS name")
    if not raw.endswith("."):
        raw = raw + "."
    try:
        parsed = dns.name.from_text(raw)
    except dns.exception.DNSException as exc:
        raise bad_label(f"{what} is not a valid DNS name") from exc
    try:
        lowered = dns.name.from_text(parsed.to_text().lower())
    except dns.exception.DNSException as exc:
        raise bad_label(f"{what} is not a valid DNS name") from exc
    if lowered == dns.name.root and not allow_root:
        raise bad_label(f"{what} must not be the root")
    wire = lowered.to_wire()
    if len(wire) > 255:
        raise bad_label(f"{what} is longer than 255 octets")
    for label in lowered.labels[:-1]:
        if label == b"*":
            raise bad_label(f"{what} must not contain a wildcard label")
        if not _LABEL.fullmatch(label):
            raise bad_label(f"{what} has an illegal label")
    return lowered


def normalise_apex(text: str) -> dns.name.Name:
    return normalise_name(text, what="apex")


def name_in_bailiwick(owner: dns.name.Name, apex: dns.name.Name) -> bool:
    return owner == apex or owner.is_subdomain(apex)
