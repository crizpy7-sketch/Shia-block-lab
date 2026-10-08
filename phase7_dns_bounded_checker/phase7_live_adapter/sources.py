"""Narrow chrony 4.5 sources CSV; identities are always private.

Grammar pinned to client.c process_cmd_sources()/print_report() and util.c at
chrony tag 4.5. CSV strings are unescaped, so ambiguous identifiers refuse.
"""
import ipaddress
import re

from .capture import need, CollectionError, OUTPUT_CAP

ROW_CAP = 64


def _unsigned(value, upper):
    need(re.fullmatch(r"(?:0|[1-9][0-9]{0,9})", value) is not None
         and int(value) <= upper, "SOURCES_NUMBER")
    return int(value)


def parse_sources(raw):
    need(type(raw) is bytes and 0 < len(raw) <= OUTPUT_CAP, "SOURCES_FORMAT")
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise CollectionError("SOURCES_FORMAT") from None
    need(text.endswith("\n") and "\r" not in text, "SOURCES_FORMAT")
    lines = text[:-1].split("\n")
    need(1 <= len(lines) <= ROW_CAP, "SOURCES_ROW_CAP")
    rows = []
    for line in lines:
        fields = line.split(",")
        need(len(fields) == 10 and fields[0] in {"^", "=", "#"}
             and fields[1] in {"*", "+", "-", "x", "~", "?"}, "SOURCES_SHAPE")
        ident = fields[2]
        if fields[0] == "#":
            need(re.fullmatch(r"[A-Za-z0-9_-]{1,4}", ident) is not None,
                 "SOURCE_IDENTITY_UNSUPPORTED")
        else:
            need(re.fullmatch(r"[0-9A-Fa-f:.]{2,45}", ident) is not None,
                 "SOURCE_IDENTITY_UNSUPPORTED")
            try:
                ipaddress.ip_address(ident)
            except ValueError:
                raise CollectionError("SOURCE_IDENTITY_UNSUPPORTED") from None
        _unsigned(fields[3], 65535)
        need(re.fullmatch(r"-?(?:0|[1-9][0-9]{0,4})", fields[4]) is not None
             and -32768 <= int(fields[4]) <= 32767, "SOURCES_NUMBER")
        need(re.fullmatch(r"[0-7]{1,3}", fields[5]) is not None
             and int(fields[5], 8) <= 255, "SOURCES_NUMBER")
        _unsigned(fields[6], 2**32 - 1)
        for scalar in fields[7:]:
            need(re.fullmatch(r"-?(?:0|[1-9][0-9]{0,3})\.[0-9]{9}", scalar) is not None,
                 "SOURCES_NUMBER")
        need(not fields[9].startswith("-"), "SOURCES_NUMBER")
        rows.append(tuple(fields))
    selected = [row for row in rows if row[1] == "*"]
    need(len(selected) == 1, "SELECTED_SOURCE_UNESTABLISHED")
    need((0 if selected[0][0] == "#" else 1) <= int(selected[0][3]) <= 15,
         "SELECTED_SOURCE_UNESTABLISHED")
    return {"rows": tuple(rows), "selected": selected[0]}


def match_tracking(first_raw, last_raw, parsed_sources):
    """Observed endpoint agreement only; neither atomicity nor continuity."""
    first = first_raw.decode("ascii").rstrip("\n").split(",")
    last = last_raw.decode("ascii").rstrip("\n").split(",")
    need(first[:2] == last[:2], "TRACKING_SOURCE_CHANGED")
    need(first[0] not in {"00000000", "7F7F0101"}
         and first[1] not in {"", "0.0.0.0", "::", "127.127.1.1", "LOCAL", "[UNSPEC]"},
         "LOCAL_OR_UNKNOWN_SOURCE")
    row = parsed_sources["selected"]
    if row[0] == "#":
        label = row[2]
        need(first[1] == label and first[0] == label.encode("ascii").ljust(4, b"\0").hex().upper(),
             "SOURCE_IDENTITY_MISMATCH")
        return "REFCLOCK_RENDERED_ID_AGREEMENT_ONLY"
    try:
        need(re.fullmatch(r"[0-9A-Fa-f:.]{2,45}", first[1]) is not None,
             "SOURCE_IDENTITY_MISMATCH")
        tracking_ip, selected_ip = ipaddress.ip_address(first[1]), ipaddress.ip_address(row[2])
    except ValueError:
        raise CollectionError("SOURCE_IDENTITY_MISMATCH") from None
    # IPv6 tracking reference-ID derivation is deliberately not inferred here.
    # Address equality is only a projection, not a full source identity proof.
    need(tracking_ip == selected_ip, "SOURCE_IDENTITY_MISMATCH")
    if tracking_ip.version == 4:
        need(first[0] == tracking_ip.packed.hex().upper(), "SOURCE_IDENTITY_MISMATCH")
    return "NTP_ADDRESS_AGREEMENT_ONLY"
