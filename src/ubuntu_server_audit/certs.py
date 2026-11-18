"""Just enough X.509 parsing to read certificate expiry dates, without third-party packages.

Only the outer structure of a DER certificate is decoded (RFC 5280, section 4.1): the validity period and the
subject common name. Signatures are not checked; this is an expiry report, not a trust decision.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from datetime import datetime, timezone

_PEM = re.compile(r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", re.DOTALL)
_OID_COMMON_NAME = bytes((0x55, 0x04, 0x03))  # 2.5.4.3

SEQUENCE, SET, OID, UTC_TIME, GENERALIZED_TIME = 0x30, 0x31, 0x06, 0x17, 0x18
_STRING_TAGS = {0x0C: "utf-8", 0x13: "ascii", 0x14: "latin-1", 0x16: "ascii", 0x1E: "utf-16-be"}


class CertificateError(ValueError):
    """The data is not a certificate this parser understands."""


@dataclass(frozen=True)
class Certificate:
    subject: str
    not_before: datetime
    not_after: datetime

    def days_left(self, now: datetime) -> float:
        return (self.not_after - now).total_seconds() / 86400


def _tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """Return ``(tag, value_start, value_end)`` of the element at ``pos``."""
    if pos + 2 > len(data):
        raise CertificateError("truncated DER element")
    tag = data[pos]
    length = data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise CertificateError("unsupported DER length")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise CertificateError("truncated DER element")
    return tag, pos, end


def _children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    items = []
    pos = start
    while pos < end:
        tag, value_start, value_end = _tlv(data, pos)
        items.append((tag, value_start, value_end))
        pos = value_end
    return items


def _time(tag: int, raw: bytes) -> datetime:
    text = raw.decode("ascii", "replace")
    try:
        if tag == UTC_TIME:
            parsed = datetime.strptime(text, "%y%m%d%H%M%SZ")
            # RFC 5280: YY >= 50 means 19YY, otherwise 20YY (strptime pivots at 69).
            year = parsed.year % 100
            parsed = parsed.replace(year=(1900 if year >= 50 else 2000) + year)
        elif tag == GENERALIZED_TIME:
            parsed = datetime.strptime(text, "%Y%m%d%H%M%SZ")
        else:
            raise CertificateError(f"unexpected time tag 0x{tag:02x}")
    except ValueError as exc:
        raise CertificateError(f"invalid certificate time {text!r}") from exc
    return parsed.replace(tzinfo=timezone.utc)


def _common_name(data: bytes, start: int, end: int) -> str:
    for set_tag, set_start, set_end in _children(data, start, end):
        if set_tag != SET:
            continue
        for seq_tag, seq_start, seq_end in _children(data, set_start, set_end):
            if seq_tag != SEQUENCE:
                continue
            parts = _children(data, seq_start, seq_end)
            if len(parts) == 2 and parts[0][0] == OID and data[parts[0][1] : parts[0][2]] == _OID_COMMON_NAME:
                tag, value_start, value_end = parts[1]
                return data[value_start:value_end].decode(_STRING_TAGS.get(tag, "latin-1"), "replace")
    return ""


def parse_der(data: bytes) -> Certificate:
    """Read the subject CN and validity period of a DER-encoded certificate."""
    tag, start, end = _tlv(data, 0)
    if tag != SEQUENCE:
        raise CertificateError("not a DER certificate")
    parts = _children(data, start, end)
    if not parts or parts[0][0] != SEQUENCE:
        raise CertificateError("missing tbsCertificate")
    tbs = _children(data, parts[0][1], parts[0][2])
    if tbs and tbs[0][0] == 0xA0:  # explicit [0] version
        tbs = tbs[1:]
    # serialNumber, signature, issuer, validity, subject, ...
    if len(tbs) < 5 or tbs[3][0] != SEQUENCE:
        raise CertificateError("missing validity")
    validity = _children(data, tbs[3][1], tbs[3][2])
    if len(validity) != 2:
        raise CertificateError("invalid validity")
    not_before = _time(validity[0][0], data[validity[0][1] : validity[0][2]])
    not_after = _time(validity[1][0], data[validity[1][1] : validity[1][2]])
    return Certificate(_common_name(data, tbs[4][1], tbs[4][2]), not_before, not_after)


def parse_pem(text: str) -> list[Certificate]:
    """Every certificate in a PEM bundle (leaf first, as nginx expects)."""
    certs = []
    for block in _PEM.findall(text):
        try:
            der = base64.b64decode("".join(block.split()), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CertificateError("invalid base64 in PEM block") from exc
        certs.append(parse_der(der))
    if not certs:
        raise CertificateError("no PEM certificate found")
    return certs
