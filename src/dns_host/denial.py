"""Offline NSEC3 checks (RFC 5155 / RFC 9276).

NSEC3 parameters required for admission: hash algorithm 1, flags 0 (Opt-Out
off), iterations 0, empty salt. The chain must cover every authoritative
owner name and every empty non-terminal, and must be a single cycle.
Plain NSEC zones are rejected before this walk.
"""

from __future__ import annotations

import dns.name
import dns.rdatatype
import dns.dnssec

from dns_host.errors import ApiError

NSEC3 = dns.rdatatype.NSEC3
NSEC = dns.rdatatype.NSEC
RRSIG = dns.rdatatype.RRSIG
NSEC3PARAM = dns.rdatatype.NSEC3PARAM


def _fail(error: str, message: str) -> ApiError:
    return ApiError(422, error, message)


def zone_names_and_ents(owners: set[dns.name.Name], apex: dns.name.Name) -> set[dns.name.Name]:
    names = set(owners)
    names.add(apex)
    for name in list(owners):
        parent = name.parent()
        while parent != apex and parent.is_subdomain(apex):
            names.add(parent)
            parent = parent.parent()
    return names


def hash_label(name: dns.name.Name, salt: bytes, iterations: int, algorithm: int) -> str:
    hashed = dns.dnssec.nsec3_hash(name, salt, iterations, algorithm)
    return hashed.rstrip("=").upper()


def bitmap_types(windows) -> set[int]:
    found: set[int] = set()
    for window, bitmap in windows:
        for index, byte in enumerate(bitmap):
            for bit in range(8):
                if byte & (0x80 >> bit):
                    found.add(window * 256 + index * 8 + bit)
    return found


def expected_types(present: set[int]) -> set[int]:
    """Types that belong in the denial bitmap for an original owner name.

    A name that has data is signed, so the RRSIG bit is set. An empty
    non-terminal has an empty bitmap. NSEC3 itself lives at the hashed name
    and is not part of this set.
    """

    types = {int(item) for item in present if int(item) not in (int(NSEC3), int(RRSIG), int(NSEC))}
    if types:
        types.add(int(RRSIG))
    return types


def check_nsec3(apex: dns.name.Name, owners_types: dict[dns.name.Name, set[int]], nsec3_rrsets, param) -> None:
    if param is None:
        raise _fail("bad_nsec3param", "NSEC3 zone is missing NSEC3PARAM")
    if len(param) != 1:
        raise _fail("bad_nsec3param", "zone must contain exactly one NSEC3PARAM")
    nsec3param = list(param)[0]
    if (
        int(nsec3param.algorithm) != 1
        or int(nsec3param.flags) != 0
        or int(nsec3param.iterations) != 0
        or nsec3param.salt != b""
    ):
        raise _fail(
            "bad_nsec3param",
            "NSEC3PARAM must be algorithm 1, flags 0 (Opt-Out off), iterations 0, empty salt (RFC 9276)",
        )
    covered = zone_names_and_ents(set(owners_types), apex)
    by_hash: dict[str, object] = {}
    for rrset in nsec3_rrsets:
        if rrset.name.parent() != apex or len(rrset.name) != len(apex) + 1:
            raise _fail("nsec3_chain_broken", f"NSEC3 {rrset.name} is not a single label under the apex")
        if len(rrset) != 1:
            raise _fail("nsec3_chain_broken", f"NSEC3 {rrset.name} must contain one record")
        record = list(rrset)[0]
        if (
            int(record.algorithm) != 1
            or int(record.flags) != 0
            or int(record.iterations) != 0
            or record.salt != b""
        ):
            raise _fail(
                "nsec3_chain_broken",
                f"NSEC3 {rrset.name} must use iterations 0, empty salt and Opt-Out off",
            )
        label = rrset.name.labels[0].decode("ascii").upper()
        if label in by_hash:
            raise _fail("nsec3_chain_broken", f"duplicate NSEC3 hash {label}")
        by_hash[label] = record

    expected_hashes: dict[str, dns.name.Name] = {}
    for name in covered:
        label = hash_label(name, b"", 0, 1)
        if label in expected_hashes:
            raise _fail("nsec3_chain_broken", f"NSEC3 hash collision for {name}")
        expected_hashes[label] = name
    if set(expected_hashes) != set(by_hash):
        missing = set(expected_hashes) - set(by_hash)
        extra = set(by_hash) - set(expected_hashes)
        raise _fail(
            "nsec3_chain_broken",
            f"NSEC3 set does not match the zone ({len(missing)} missing, {len(extra)} extra)",
        )
    for label, name in expected_hashes.items():
        record = by_hash[label]
        present = owners_types.get(name, set())
        if bitmap_types(record.windows) != expected_types(present):
            raise _fail("nsec3_chain_broken", f"NSEC3 type bitmap for {name} does not match the RRsets")
        nxt = record._next_text().rstrip("=").upper()
        if nxt not in by_hash:
            raise _fail("nsec3_chain_broken", f"NSEC3 next hash {nxt} is not in the chain")
    if not by_hash:
        raise _fail("nsec3_chain_broken", "NSEC3 chain is empty")
    start = next(iter(by_hash))
    seen: set[str] = set()
    current = start
    while current not in seen:
        seen.add(current)
        current = by_hash[current]._next_text().rstrip("=").upper()
    if seen != set(by_hash) or current != start:
        raise _fail("nsec3_chain_broken", "NSEC3 records do not form a single closed chain")


def check_nsec(apex: dns.name.Name, owners_types: dict[dns.name.Name, set[int]], nsec_by_name) -> None:
    covered = zone_names_and_ents(set(owners_types), apex)
    if set(nsec_by_name) != covered:
        raise _fail("nsec3_chain_broken", "NSEC set does not cover every owner name")
    # Canonical DNS order compares labels from the right.
    names = sorted(covered, key=lambda name: tuple(reversed(name.canonicalize().labels)))
    for index, name in enumerate(names):
        record = nsec_by_name[name]
        if len(record) != 1:
            raise _fail("nsec3_chain_broken", f"NSEC at {name} must contain one record")
        nsec = list(record)[0]
        nxt = names[(index + 1) % len(names)]
        if nsec.next.canonicalize() != nxt.canonicalize():
            raise _fail("nsec3_chain_broken", f"NSEC at {name} does not point at the next owner name")
        present = owners_types.get(name, set())
        if bitmap_types(nsec.windows) != expected_types(present):
            raise _fail("nsec3_chain_broken", f"NSEC type bitmap for {name} does not match the RRsets")
    if apex not in nsec_by_name:
        raise _fail("nsec3_chain_broken", "NSEC chain is missing the apex")
