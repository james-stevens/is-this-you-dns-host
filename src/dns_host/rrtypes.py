"""RR type helpers, including WALLET (IANA type 262).

WALLET rdata is a sequence of character-strings: type and identifier, or
those two plus a description and a sort order. Both forms are accepted.

When this dnspython build has no WALLET implementation, the type is still
registered as mnemonic 262 and the rdata is carried as RFC 3597 unknown-type
wire (the same length-prefixed character-strings a native WALLET uses).
"""

from __future__ import annotations

import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.tokenizer

WALLET_TYPE = 262
_WALLET_COUNTS = (2, 4)
# Tests set this to exercise the RFC 3597 path on a build that does have WALLET.
_force_generic_wallet = False


def ensure_wallet_type() -> None:
    """Make ``WALLET`` parse as type 262 even if dnspython does not know it."""

    try:
        if int(dns.rdatatype.from_text("WALLET")) == WALLET_TYPE:
            return
    except Exception:
        pass
    dns.rdatatype.register_type(WALLET_TYPE, "WALLET")


def parse_type(text: str):
    ensure_wallet_type()
    token = str(text).strip()
    try:
        return dns.rdatatype.from_text(token)
    except Exception:
        if token.upper() == "WALLET":
            return dns.rdatatype.RdataType.make(WALLET_TYPE)
        raise


def type_name(rdtype) -> str:
    """Mnemonic used for the allow-list. Type 262 is always ``WALLET``."""

    if int(rdtype) == WALLET_TYPE:
        return "WALLET"
    return dns.rdatatype.to_text(rdtype).upper()


def _native_wallet_class():
    if _force_generic_wallet:
        return None
    ensure_wallet_type()
    cls = dns.rdata.get_rdata_class(dns.rdataclass.IN, WALLET_TYPE, use_generic=False)
    if cls is None or cls is dns.rdata.GenericRdata:
        return None
    return cls


def _character_strings(text: str) -> list[bytes]:
    tokenizer = dns.tokenizer.Tokenizer(text)
    strings: list[bytes] = []
    for token in tokenizer.get_remaining():
        token = token.unescape_to_bytes()
        if not (token.is_quoted_string() or token.is_identifier()):
            raise ValueError("WALLET rdata must be character-strings")
        if len(token.value) > 255:
            raise ValueError("WALLET character-string is longer than 255 bytes")
        strings.append(bytes(token.value))
    return strings


def _strings_from_wire(wire: bytes) -> list[bytes]:
    strings: list[bytes] = []
    offset = 0
    while offset < len(wire):
        length = wire[offset]
        offset += 1
        end = offset + length
        if end > len(wire):
            raise ValueError("WALLET rdata is not a sequence of character-strings")
        strings.append(wire[offset:end])
        offset = end
    return strings


def _require_wallet_shape(strings: list[bytes]) -> None:
    if len(strings) not in _WALLET_COUNTS:
        raise ValueError(
            "WALLET rdata must contain 2 character-strings (type, identifier) "
            "or 4 (type, identifier, description, sort order)"
        )


def _encode_strings(strings: list[bytes]) -> bytes:
    return b"".join(bytes([len(item)]) + item for item in strings)


def rdata_from_text(rdtype, text: str, origin=None):
    """Parse one presentation-format rdata, with WALLET 2/4-string rules."""

    rdtype = parse_type(rdtype) if isinstance(rdtype, str) else dns.rdatatype.RdataType.make(int(rdtype))
    if int(rdtype) != WALLET_TYPE:
        return dns.rdata.from_text(
            dns.rdataclass.IN, rdtype, text, origin=origin, relativize=False
        )
    stripped = text.strip()
    if stripped.startswith("\\#"):
        # RFC 3597 unknown-type form. ``\#`` is the usual spelling.
        parsed = dns.rdata.from_text(
            dns.rdataclass.IN, rdtype, text, origin=origin, relativize=False
        )
        _require_wallet_shape(_strings_from_wire(parsed.to_wire()))
        if _native_wallet_class() is None and not isinstance(parsed, dns.rdata.GenericRdata):
            return dns.rdata.GenericRdata(dns.rdataclass.IN, rdtype, parsed.to_wire())
        if _native_wallet_class() is None:
            return parsed
        return parsed
    strings = _character_strings(text)
    _require_wallet_shape(strings)
    if _native_wallet_class() is not None:
        return dns.rdata.from_text(
            dns.rdataclass.IN, rdtype, text, origin=origin, relativize=False
        )
    # No WALLET class: keep the same wire a native implementation would emit.
    return dns.rdata.GenericRdata(dns.rdataclass.IN, rdtype, _encode_strings(strings))


ensure_wallet_type()
