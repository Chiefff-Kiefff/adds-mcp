"""Decoder for AD's binary dnsRecord attribute (MS-DNSP DNS_RECORD).

Format:
  offset  size  field
    0     2     DataLength (little-endian)
    2     2     Type        (little-endian, DNS RR type)
    4     1     Version     (usually 5)
    5     1     Rank
    6     2     Flags
    8     4     Serial      (little-endian)
   12     4     TtlSeconds  (BIG-endian per MS-DNSP)
   16     4     Reserved
   20     4     TimeStamp   (hours since 1601-01-01 UTC, 0 = static/tombstone-exempt)
   24    ...    Data (type-specific)

Names inside record data use DNS_COUNT_NAME encoding:
  byte 0: cchNameLength (label bytes + one length-byte per label)
  byte 1: cLabelCount   (number of labels)
  then: [ 1-byte label length, label bytes ] repeated
No trailing null; root name has cchNameLength == 0.
"""

from __future__ import annotations

import ipaddress
import socket
import struct
from datetime import datetime, timedelta, timezone
from typing import Any

DNS_TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    13: "HINFO",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    39: "DNAME",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    50: "NSEC3",
    51: "NSEC3PARAM",
    52: "TLSA",
    257: "CAA",
    0xFF01: "WINS",
    0xFF02: "WINSR",
}

RANK_NAMES = {
    0x00: "CACHE_BIT",
    0x10: "ROOT_HINT",
    0x20: "OUTSIDE_GLUE",
    0x30: "CACHE_NA_ADDITIONAL",
    0x40: "CACHE_NA_AUTHORITY",
    0x50: "CACHE_A_ADDITIONAL",
    0x60: "CACHE_NA_ANSWER",
    0x70: "CACHE_A_AUTHORITY",
    0x80: "GLUE",
    0xC0: "NS_GLUE",
    0xF0: "ZONE",
}


def _decode_count_name(buf: bytes, offset: int) -> tuple[str, int]:
    """Decode DNS_COUNT_NAME. Returns (name, bytes_consumed)."""
    if offset >= len(buf):
        return "", 0
    total_len = buf[offset]
    label_count = buf[offset + 1] if offset + 1 < len(buf) else 0
    if total_len == 0 or label_count == 0:
        return ".", 2
    labels: list[str] = []
    pos = offset + 2
    for _ in range(label_count):
        if pos >= len(buf):
            break
        label_len = buf[pos]
        pos += 1
        label = buf[pos : pos + label_len].decode("utf-8", errors="replace")
        labels.append(label)
        pos += label_len
    name = ".".join(labels) + "."
    return name, (pos - offset)


def _decode_hours_since_1601(hours: int) -> str | None:
    if hours == 0:
        return None  # static / non-aging record
    try:
        dt = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(hours=hours)
    except (OverflowError, OSError):
        return None
    return dt.isoformat()


def _decode_payload(rr_type: int, data: bytes) -> Any:
    if rr_type == 1:  # A
        if len(data) < 4:
            return None
        return socket.inet_ntoa(data[:4])
    if rr_type == 28:  # AAAA
        if len(data) < 16:
            return None
        return str(ipaddress.IPv6Address(data[:16]))
    if rr_type in (2, 5, 12, 39):  # NS, CNAME, PTR, DNAME
        name, _ = _decode_count_name(data, 0)
        return name
    if rr_type == 15:  # MX
        if len(data) < 3:
            return None
        preference = struct.unpack(">H", data[:2])[0]
        # MS-DNSP MX preference is big-endian per docs; some sources say LE — accept both.
        preference_le = struct.unpack("<H", data[:2])[0]
        exchange, _ = _decode_count_name(data, 2)
        return {"preference": preference if preference <= 65535 else preference_le,
                "exchange": exchange}
    if rr_type == 33:  # SRV
        if len(data) < 6:
            return None
        priority, weight, port = struct.unpack(">HHH", data[:6])
        target, _ = _decode_count_name(data, 6)
        return {"priority": priority, "weight": weight, "port": port, "target": target}
    if rr_type == 16:  # TXT
        strings = []
        pos = 0
        while pos < len(data):
            slen = data[pos]
            pos += 1
            strings.append(data[pos : pos + slen].decode("utf-8", errors="replace"))
            pos += slen
        return strings
    if rr_type == 6:  # SOA
        if len(data) < 20:
            return None
        serial, refresh, retry, expire, minimum = struct.unpack(">IIIII", data[:20])
        primary, consumed = _decode_count_name(data, 20)
        admin, _ = _decode_count_name(data, 20 + consumed)
        return {
            "serial": serial,
            "refresh": refresh,
            "retry": retry,
            "expire": expire,
            "minimum_ttl": minimum,
            "primary_ns": primary,
            "responsible_email": admin,
        }
    # Fallback: return hex.
    return {"raw_hex": data.hex()}


def decode_record(blob: bytes) -> dict[str, Any] | None:
    """Decode a single dnsRecord binary blob into a JSON-friendly dict."""
    if len(blob) < 24:
        return None
    data_len, rr_type = struct.unpack("<HH", blob[:4])
    version = blob[4]
    rank = blob[5]
    flags = struct.unpack("<H", blob[6:8])[0]
    serial = struct.unpack("<I", blob[8:12])[0]
    ttl = struct.unpack(">I", blob[12:16])[0]  # big-endian per MS-DNSP
    timestamp_hours = struct.unpack("<I", blob[20:24])[0]
    payload = blob[24 : 24 + data_len]
    return {
        "type": DNS_TYPE_NAMES.get(rr_type, str(rr_type)),
        "type_id": rr_type,
        "ttl": ttl,
        "version": version,
        "rank": RANK_NAMES.get(rank, rank),
        "flags": flags,
        "serial": serial,
        "aging_timestamp": _decode_hours_since_1601(timestamp_hours),
        "static": timestamp_hours == 0,
        "value": _decode_payload(rr_type, payload),
    }


def decode_records(blobs: list[bytes] | bytes | None) -> list[dict[str, Any]]:
    if blobs is None:
        return []
    if isinstance(blobs, bytes):
        blobs = [blobs]
    out: list[dict[str, Any]] = []
    for b in blobs:
        if not isinstance(b, bytes):
            continue
        rec = decode_record(b)
        if rec is not None:
            out.append(rec)
    return out
