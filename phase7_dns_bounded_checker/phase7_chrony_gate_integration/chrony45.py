"""Pure conditional chrony4.5 arithmetic; supplied fixtures never attest a clock."""
import hashlib
import json
import re


MAX_NS = (1 << 63) - 1
SECOND = 1_000_000_000
REF_EXPORT_NS = 1_000
REF_FUZZ_NS = SECOND
ROUNDING_TOLERANCE_NS = 1_000_000  # Retained kernel sampler's observation tolerance.
SCALAR_CAP_NS = 3_600 * SECOND
MODEL_KEYS = frozenset(("schema", "record", "basis", "runtime_sha256",
    "client_version", "daemon_semantics", "tracking_csv", "bracket",
    "kernel_before", "kernel_after", "source", "policy"))
POLICY_KEYS = frozenset(("valid_from_us", "valid_until_us", "source_accuracy_bound_ns",
    "rate_bound_ppb", "max_sample_age_ns", "continuity"))
BRACKET_KEYS = frozenset(("monotonic_before_ns", "realtime_before_ns",
    "realtime_after_ns", "monotonic_after_ns"))


class ModelError(ValueError):
    """Only implementation-owned fixed messages are raised."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def need(condition, code):
    if not condition:
        raise ModelError(code)


def keys(value, expected):
    return type(value) is dict and all(type(k) is str for k in value) and set(value) == expected


def integer(value, upper=MAX_NS):
    return type(value) is int and 0 <= value <= upper


def digest(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def literal(value, expected):
    return type(value) is str and value == expected


def ceil_div(n, d):
    return (n + d - 1) // d


def scalar_error(n):
    # Mandatory conservative reduced-precision Float + printed-unit expansion.
    # Pinned util.c a4c8288b38ca11b6e5a81076afcfbbd02d7540cb / client.c 7cfefba...
    return 1 + ceil_div(abs(n), 1 << 20)


def _scaled(text, digits):
    need(type(text) is str and re.fullmatch(
        r"-?(?:0|[1-9][0-9]{0,18})\." + r"[0-9]{" + str(digits) + "}", text)
        is not None, "CHRONY_NUMBER_INVALID")
    whole, fraction = text.lstrip("-").split(".")
    value = int(whole) * 10 ** digits + int(fraction)
    value = -value if text.startswith("-") else value
    need(-MAX_NS <= value <= MAX_NS, "CHRONY_NUMBER_INVALID")
    return value


def _tracking(raw):
    need(type(raw) is bytes and 0 < len(raw) <= 4096, "CHRONY_TRACKING_INVALID")
    try:
        text = raw.decode("ascii")
    except UnicodeError:
        raise ModelError("CHRONY_TRACKING_INVALID") from None
    need(text.endswith("\n") and text.count("\n") == 1 and "\r" not in text,
         "CHRONY_TRACKING_INVALID")
    fields = text[:-1].split(",")
    need(len(fields) == 14 and re.fullmatch(r"[0-9A-F]{8}", fields[0]) is not None
         and 1 <= len(fields[1]) <= 255 and all(32 <= ord(c) < 127 for c in fields[1]),
         "CHRONY_TRACKING_INVALID")
    need(re.fullmatch(r"(?:[1-9]|1[0-5])", fields[2]) is not None
         and fields[13] == "Normal", "CHRONY_UNSYNCHRONIZED")
    values = [_scaled(v, p) for v, p in zip(fields[3:13], (9, 9, 9, 9, 3, 3, 3, 9, 9, 1))]
    reference, correction, last, rms, frequency, residual, skew, delay, dispersion, update = values
    # Deliberately narrow supported finite ranges, not claims about this runner.
    # Timestamp cap also bounds binary64 fixed-nine-decimal export error.
    need(0 < reference < (1 << 32) * SECOND
         and abs(correction) <= SCALAR_CAP_NS and abs(last) <= SCALAR_CAP_NS
         and 0 <= rms <= SCALAR_CAP_NS and 0 <= delay <= SCALAR_CAP_NS
         and 0 <= dispersion <= SCALAR_CAP_NS and abs(frequency) <= 1_000_000_000
         and abs(residual) <= 1_000_000_000 and 0 <= skew <= 1_000_000_000
         and 0 < update <= 864_000, "CHRONY_SEMANTIC_RANGE")
    return fields, reference, correction, delay, dispersion


def evaluate_supplied(record, *, expected_runtime_sha256):
    """Return conditional interval arithmetic, never accepted live evidence.

    policy.rate_bound_ppb is explicitly supplied error growth per system-UTC
    coordinate interval, covering virtual error and correction changes. It is
    not inferred from chrony's frequency/skew. No-step/source continuity is a
    synthetic premise. Missing facts and capability-only projections refuse.
    """
    need(keys(record, MODEL_KEYS), "CHRONY_MODEL_MISSING_OR_INVALID")
    need(type(record["schema"]) is int and record["schema"] == 1
         and literal(record["record"], "SUPPLIED_CHRONY45_MODEL")
         and literal(record["basis"], "SYNTHETIC_FIXTURE"), "CHRONY_MODEL_MISSING_OR_INVALID")
    need(digest(expected_runtime_sha256) and digest(record["runtime_sha256"])
         and record["runtime_sha256"] == expected_runtime_sha256, "CHRONY_RUNTIME_MISMATCH")
    need(literal(record["client_version"], "4.5")
         and literal(record["daemon_semantics"], "CHRONYD_4_5_SUPPLIED_NOT_ATTESTED"),
         "CHRONY_DAEMON_SEMANTICS_UNESTABLISHED")
    fields, reference, correction, delay, dispersion = _tracking(record["tracking_csv"])
    source = record["source"]
    need(keys(source, {"kind", "reference_id", "address"})
         and literal(source["kind"], "SYNTHETIC_EXTERNAL_UTC_REFERENCE")
         and literal(source["reference_id"], fields[0])
         and literal(source["address"], fields[1])
         and fields[0] not in {"00000000", "7F7F0101"}
         and fields[1] not in {"0.0.0.0", "::", "127.127.1.1", "LOCAL", "[UNSPEC]"},
         "CHRONY_SOURCE_UNESTABLISHED")
    bracket = record["bracket"]
    need(keys(bracket, BRACKET_KEYS) and all(integer(v) for v in bracket.values()),
         "CHRONY_BRACKET_INVALID")
    m0, w0, w1, m1 = (bracket[k] for k in ("monotonic_before_ns", "realtime_before_ns",
                                         "realtime_after_ns", "monotonic_after_ns"))
    need(m0 <= m1 and w0 <= w1 and m1 - m0 < 40 * SECOND
         and w1 - w0 < 40 * SECOND, "CHRONY_BRACKET_INVALID")
    before, after = record["kernel_before"], record["kernel_after"]
    for kernel in (before, after):
        need(keys(kernel, {"state", "modes", "status"})
             and all(integer(v, 65535) for v in kernel.values())
             and kernel["state"] == 0 and kernel["modes"] == 0
             and kernel["status"] & 0x1E70 == 0, "CHRONY_KERNEL_REFUSED")
    need(before == after, "CHRONY_KERNEL_CHANGED")
    policy = record["policy"]
    need(keys(policy, POLICY_KEYS)
         and all(integer(policy[k]) for k in POLICY_KEYS - {"continuity"})
         and literal(policy["continuity"], "SYNTHETIC_NO_STEP_OR_SOURCE_CHANGE")
         and policy["valid_from_us"] < 10**18 and policy["valid_until_us"] < 10**18
         and policy["valid_from_us"] <= policy["valid_until_us"]
         and policy["rate_bound_ppb"] <= SECOND and policy["max_sample_age_ns"] > 0,
         "CHRONY_POLICY_UNESTABLISHED")
    low, high = policy["valid_from_us"] * 1000, policy["valid_until_us"] * 1000
    need(low <= w0 <= w1 <= high, "CHRONY_POLICY_INTERVAL")
    need(abs((w1 - w0) - (m1 - m0)) <= ROUNDING_TOLERANCE_NS
         + ceil_div(policy["rate_bound_ppb"] * (m1 - m0), SECOND),
         "CHRONY_CLOCK_DISCONTINUITY")
    correction_error = scalar_error(correction)
    ref_low, ref_high = reference - REF_EXPORT_NS, reference + REF_EXPORT_NS
    cooked_low, cooked_high = w0 + correction - correction_error, w1 + correction + correction_error
    need(ref_low <= cooked_high, "CHRONY_REFERENCE_FUTURE")
    age_upper = cooked_high - ref_low
    age_lower = max(0, cooked_low - ref_high - REF_FUZZ_NS)
    need(age_upper <= policy["max_sample_age_ns"], "CHRONY_SAMPLE_STALE")
    snapshot = (abs(correction) + correction_error + dispersion + scalar_error(dispersion)
                + ceil_div(delay + scalar_error(delay), 2))
    # Both spans are added conservatively; collection work is not free time.
    bracket_error = (w1 - w0) + (m1 - m0)
    # This covers retrospective native intervals as well as all future phase use.
    horizon = max(w1 - low, high - w0)
    drift = ceil_div(policy["rate_bound_ppb"] * horizon, SECOND)
    total = snapshot + bracket_error + policy["source_accuracy_bound_ns"] + drift
    need(total <= MAX_NS, "CHRONY_BOUND_RANGE")
    return {
        "status": "CONDITIONAL_MODEL_ONLY", "provenance": "SUPPLIED_UNVERIFIED",
        "basis": "SYNTHETIC_FIXTURE", "runtime_sha256": record["runtime_sha256"],
        "valid_from_us": policy["valid_from_us"], "valid_until_us": policy["valid_until_us"],
        "total_utc_error_bound_ns": str(total), "snapshot_upper_ns": str(snapshot),
        "observation_bracket_error_ns": str(bracket_error), "interval_growth_ns": str(drift),
        "source_accuracy_bound_ns": str(policy["source_accuracy_bound_ns"]),
        "sample_age_lower_ns": str(age_lower), "sample_age_upper_ns": str(age_upper),
        "source_classification": "SUPPLIED_SYNTHETIC_EXTERNAL_REFERENCE",
        "source_continuity": "SYNTHETIC_ASSUMPTION_NOT_PROVED",
        "alignment_established": False, "execution_authorized": False,
        "phase7_acceptance": "BLOCKED", "control_authority": "NONE",
    }


def supplied_pair(endpoint, runner, *, role, expected_left, expected_right):
    """Compose two conditional endpoint envelopes for the existing pure mapper."""
    expected = {"schema", "record", "basis", "role", "runtime_sha256", "valid_from_us",
                "valid_until_us", "total_utc_error_bound_ns"}
    need(keys(endpoint, expected) and type(endpoint["schema"]) is int and endpoint["schema"] == 1
         and literal(endpoint["record"], "SUPPLIED_ENDPOINT_ENVELOPE")
         and literal(endpoint["basis"], "SYNTHETIC_FIXTURE")
         and literal(endpoint["role"], role) and role in {"NATIVE", "COORDINATOR"}
         and digest(endpoint["runtime_sha256"]) and endpoint["runtime_sha256"] == expected_left
         and integer(endpoint["valid_from_us"], 10**18 - 1)
         and integer(endpoint["valid_until_us"], 10**18 - 1)
         and endpoint["valid_from_us"] <= endpoint["valid_until_us"]
         and integer(endpoint["total_utc_error_bound_ns"]), "ENDPOINT_ENVELOPE_UNESTABLISHED")
    runner_numbers = {"total_utc_error_bound_ns", "snapshot_upper_ns", "observation_bracket_error_ns",
        "interval_growth_ns", "source_accuracy_bound_ns", "sample_age_lower_ns", "sample_age_upper_ns"}
    runner_fixed = {"status": "CONDITIONAL_MODEL_ONLY", "provenance": "SUPPLIED_UNVERIFIED",
        "basis": "SYNTHETIC_FIXTURE", "source_classification": "SUPPLIED_SYNTHETIC_EXTERNAL_REFERENCE",
        "source_continuity": "SYNTHETIC_ASSUMPTION_NOT_PROVED", "alignment_established": False,
        "execution_authorized": False, "phase7_acceptance": "BLOCKED", "control_authority": "NONE"}
    need(keys(runner, runner_numbers | set(runner_fixed) | {
        "runtime_sha256", "valid_from_us", "valid_until_us"})
        and all(type(runner[k]) is type(v) and runner[k] == v for k, v in runner_fixed.items())
        and digest(expected_left) and digest(expected_right) and expected_left != expected_right
        and literal(runner["runtime_sha256"], expected_right)
        and integer(runner["valid_from_us"], 10**18 - 1)
        and integer(runner["valid_until_us"], 10**18 - 1)
        and runner["valid_from_us"] <= runner["valid_until_us"]
        and all(type(runner[k]) is str and re.fullmatch(r"(?:0|[1-9][0-9]{0,18})", runner[k])
                is not None and int(runner[k]) <= MAX_NS for k in runner_numbers),
        "CHRONY_RUNTIME_MISMATCH")
    need(int(runner["total_utc_error_bound_ns"]) == sum(int(runner[k]) for k in (
        "snapshot_upper_ns", "observation_bracket_error_ns", "interval_growth_ns",
        "source_accuracy_bound_ns")) and int(runner["sample_age_lower_ns"])
        <= int(runner["sample_age_upper_ns"]), "CHRONY_MODEL_INCONSISTENT")
    bound = ceil_div(endpoint["total_utc_error_bound_ns"] + int(runner["total_utc_error_bound_ns"]), 1000)
    need(bound <= 5_000_000, "CLOCK_ERROR_BOUND_EXCEEDED")
    start = max(endpoint["valid_from_us"], runner["valid_from_us"])
    finish = min(endpoint["valid_until_us"], runner["valid_until_us"])
    need(start <= finish, "CLOCK_INTERVAL_NOT_COVERED")
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    return {
        "schema": 1, "record": "SUPPLIED_CLOCK_ALIGNMENT", "basis": "FIXTURE",
        "left_role": role, "left_runtime_sha256": expected_left,
        "right_runtime_sha256": expected_right,
        "left_evidence_sha256": hashlib.sha256(canonical(endpoint)).hexdigest(),
        "right_evidence_sha256": hashlib.sha256(canonical(runner)).hexdigest(),
        "review_sha256": hashlib.sha256(b"OFFLINE_FIXTURE_NOT_REVIEW_OR_AUTHORITY").hexdigest(),
        "valid_from_us": start, "valid_until_us": finish, "total_error_bound_us": bound,
        "bound_scope": "TOTAL_OFFSET_AND_DRIFT",
    }
