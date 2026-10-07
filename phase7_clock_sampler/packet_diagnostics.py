"""Pure retained timesyncd packet diagnostics; no runtime reads or alignment grant."""

import hashlib
import json
import re


MAX_REPLY_BYTES = 16384
MAX_RESULT_BYTES = 8192
UINT64_LIMIT = 1 << 64
PACKET_TYPE = "(uuuuittayttttbtt)"
MISSING_EVIDENCE = (
    "ACTUAL_RUNTIME_AND_PROVIDER_AUTHENTICATION",
    "COLLECTION_CLOCK_BRACKETS",
    "CURRENT_POST_CORRECTION_RESIDUAL",
    "APPLICABLE_CLIENT_TIMESTAMP_PRECISION",
    "REVIEWED_CORRECTION_AND_CONTINUITY_POLICY",
    "REVIEWED_RATE_ERROR_MODEL",
    "REQUIRED_INTERVAL_COVERAGE",
    "SECOND_RUNTIME_SAME_REFERENCE_EVIDENCE",
)


class _Refusal(Exception):
    pass


def _require(condition, code):
    if not condition:
        raise _Refusal(code)


def _result(code, *, context=None, components=None, quantization=None):
    return {
        "schema": 1,
        "record": "TIMESYNCD_PACKET_DIAGNOSTIC",
        "disposition": "CONDITIONAL_MODEL_ONLY",
        "status": "CONDITIONAL_MODEL_ONLY" if code == "OK" else "REFUSED",
        "code": code,
        "provenance": "SUPPLIED_UNVERIFIED",
        "context": context,
        "components": {} if components is None else components,
        "quantization": {} if quantization is None else quantization,
        "missing_evidence": list(MISSING_EVIDENCE),
        "control": "NONE",
        "gate_action": "NONE",
        "phase7": "BLOCKED",
        "alignment_established": False,
        "relative_alignment_established": False,
        "execution_authorized": False,
        "cleanup_proven": False,
        "valid_through": None,
    }


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "DUPLICATE_RESPONSE_KEY")
        result[key] = value
    return result


def _integer(text):
    # A D-Bus uint64 has at most twenty decimal digits. This cap also covers
    # the signed precision field without asking Python to parse huge integers.
    _require(len(text.lstrip("-")) <= 20, "INTEGER_TOKEN_CAP")
    return int(text)


def _reject_number(_text):
    raise _Refusal("NONINTEGER_JSON_NUMBER")


def _typed_property(raw, expected_type):
    _require(type(raw) is bytes and 0 < len(raw) <= MAX_REPLY_BYTES, "RESPONSE_CAP_OR_TYPE")
    try:
        reply = json.loads(raw.decode("utf-8", errors="strict"),
                           object_pairs_hook=_unique, parse_int=_integer,
                           parse_float=_reject_number, parse_constant=_reject_number)
    except _Refusal:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise _Refusal("RESPONSE_FORMAT") from None
    _require(type(reply) is dict and set(reply) == {"type", "data"}
             and reply["type"] == "v" and type(reply["data"]) is list
             and len(reply["data"]) == 1, "RESPONSE_SHAPE")
    variant = reply["data"][0]
    _require(type(variant) is dict and set(variant) == {"type", "data"}
             and variant["type"] == expected_type, "PROPERTY_TYPE")
    return variant["data"]


def _unsigned(value, bits):
    return type(value) is int and 0 <= value < (1 << bits)


def _packet_fields(message):
    _require(type(message) is list and len(message) == 15, "PACKET_SHAPE")
    for index in (0, 1, 2, 3, 5, 6, 8, 9, 10, 11, 13, 14):
        _require(_unsigned(message[index], 32 if index < 4 else 64), "PACKET_FIELD_TYPE")
    _require(type(message[4]) is int and -128 <= message[4] <= 127,
             "PRECISION_EXPONENT_UNSUPPORTED")
    _require(type(message[7]) is list and len(message[7]) == 4
             and all(_unsigned(value, 8) for value in message[7]), "REFERENCE_SHAPE")
    _require(type(message[12]) is bool, "IGNORED_FIELD_TYPE")
    _require(message[0] == 0 and message[1] in (3, 4) and message[2] == 4
             and 1 <= message[3] <= 15 and not message[12] and message[13] > 0,
             "SAMPLE_NOT_ACCEPTED")


def _evaluate(packet_before, packet_after, poll_before, poll_after, *,
              owner_before, owner_after, observed_utc_us, runtime_sha256):
    _require(type(observed_utc_us) is int and 0 < observed_utc_us < UINT64_LIMIT,
             "OBSERVED_UTC_TYPE")
    _require(type(runtime_sha256) is str
             and re.fullmatch(r"[0-9a-f]{64}", runtime_sha256) is not None,
             "RUNTIME_BINDING")
    for owner in (owner_before, owner_after):
        _require(type(owner) is str and len(owner) <= 255
                 and re.fullmatch(r":[0-9]+\.[0-9]+", owner) is not None,
                 "PROVIDER_OWNER")
    _require(owner_before == owner_after, "PROVIDER_CHANGED")
    for raw in (packet_before, packet_after, poll_before, poll_after):
        _require(type(raw) is bytes and 0 < len(raw) <= MAX_REPLY_BYTES,
                 "RESPONSE_CAP_OR_TYPE")
    _require(packet_before == packet_after, "PACKET_BYTES_CHANGED")
    _require(poll_before == poll_after, "POLL_BYTES_CHANGED")
    # Exact byte equality permits one parse of each pair. The digests bind those
    # supplied bytes, including insignificant JSON whitespace and any final LF.
    message = _typed_property(packet_before, PACKET_TYPE)
    poll = _typed_property(poll_before, "t")
    _packet_fields(message)
    _require(type(poll) is int and 0 < poll < UINT64_LIMIT, "POLL_INTERVAL_TYPE")
    t1, t2, t3, t4 = message[8:12]
    # systemd's timespec conversion can emit USEC_INFINITY on invalid/overflowed
    # time. It is not a finite timestamp and cannot support floor-error facts.
    _require(all(value < UINT64_LIMIT - 1 for value in (t1, t2, t3, t4)),
             "TIMESTAMP_INFINITY_UNSUPPORTED")
    _require(min(t1, t2, t3, t4) > 0 and t4 >= t1 and t3 >= t2
             and t4 - t1 >= t3 - t2, "TIMESTAMP_ORDER")
    offset_twice = (t2 - t1) + (t3 - t4)
    _require(abs(offset_twice) <= 6_000_000, "OFFSET_EXCEEDS_THREE_SECONDS")
    sample_age = observed_utc_us - t4
    _require(0 <= sample_age <= poll, "SAMPLE_STALE_OR_FUTURE")
    delay = (t4 - t1) - (t3 - t2)
    precision = message[4]
    if precision >= 0:
        precision_ceiling = 1_000_000 << precision
    else:
        denominator = 1 << -precision
        precision_ceiling = (1_000_000 + denominator - 1) // denominator
    context = {
        "runtime_sha256": runtime_sha256,
        "observed_utc_us": observed_utc_us,
        "provider_owner_sha256": hashlib.sha256(owner_before.encode("ascii")).hexdigest(),
        "packet_sha256": hashlib.sha256(packet_before).hexdigest(),
        "poll_sha256": hashlib.sha256(poll_before).hexdigest(),
        "reference_id_sha256": hashlib.sha256(bytes(message[7])).hexdigest(),
    }
    components = {
        "leap": message[0], "version": message[1], "mode": message[2],
        "stratum": message[3], "precision_exponent": precision,
        "root_delay_us": message[5], "root_dispersion_us": message[6],
        "root_distance_us": (message[5] + 1) // 2 + message[6],
        "offset_twice_us": offset_twice,
        "absolute_offset_ceiling_us": (abs(offset_twice) + 1) // 2,
        "round_trip_delay_us": delay,
        "half_round_trip_delay_ceiling_us": (delay + 1) // 2,
        "precision_ceiling_us": precision_ceiling,
        "sample_age_us": sample_age, "poll_us": poll,
        "packet_count": message[13], "jitter_us": message[14],
        "t1_us": t1, "t2_us": t2, "t3_us": t3, "t4_us": t4,
    }
    quantization = {
        "timestamp_export_error_exclusive_us": 1,
        "offset_export_error_ceiling_us": 1,
        "round_trip_export_error_ceiling_us": 2,
        "half_round_trip_export_error_ceiling_us": 1,
        "root_distance_export_error_ceiling_us": 2,
    }
    return _result("OK", context=context, components=components, quantization=quantization)


def evaluate(packet_before, packet_after, poll_before, poll_after, *,
             owner_before, owner_after, observed_utc_us, runtime_sha256):
    """Assess supplied exact replies without reads, time generation or policy grants.

    This pure function accepts no continuity/rate assumption and never creates
    a current-residual or future-validity envelope. Its successful result is a
    conditional pre-correction sample diagnostic, not an alignment decision.
    """
    try:
        result = _evaluate(packet_before, packet_after, poll_before, poll_after,
                           owner_before=owner_before, owner_after=owner_after,
                           observed_utc_us=observed_utc_us, runtime_sha256=runtime_sha256)
    except _Refusal as error:
        return _result(error.args[0])
    except Exception:
        # No dependency, raw reply, runtime identity or exception text is echoed.
        return _result("INPUT_REJECTED")
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    if len(encoded) + 1 > MAX_RESULT_BYTES:
        return _result("RESULT_CAP")
    return result
