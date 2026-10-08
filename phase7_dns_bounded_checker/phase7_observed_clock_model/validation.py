"""Pure revalidation of the frozen collector's private observation contract."""
import hashlib
import json
import stat

from phase7_chrony_gate_integration import chrony45 as arithmetic
from phase7_live_adapter import collector
from phase7_live_adapter.capture import CaptureResult, COMMAND_NS, PHASE_NS
from phase7_live_adapter.sources import parse_sources, match_tracking
from phase7_clock_sampler import sampler
from phase7_chrony_capability_probe import entry as probe


class ObservationModelError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def need(condition, code):
    if not condition:
        raise ObservationModelError(code)


def shape(value, fields):
    return arithmetic.keys(value, fields)


def private_binding(value):
    """Bounded type-preserving byte binding, not authenticity or public output."""
    remaining = [4096]

    def visit(item, depth=0):
        remaining[0] -= 1
        need(depth <= 10 and remaining[0] >= 0, "INPUT_SIZE_OR_TYPE")
        if item is None or type(item) is bool:
            return item
        if type(item) is int:
            need(-(2**63) <= item < 2**63, "INPUT_SIZE_OR_TYPE")
            return item
        if type(item) is str:
            need(len(item) <= 1024 and item.isascii(), "INPUT_SIZE_OR_TYPE")
            return item
        if type(item) is bytes:
            need(len(item) <= 4096, "INPUT_SIZE_OR_TYPE")
            return {"$bytes": item.hex()}
        if type(item) in (list, tuple):
            need(len(item) <= 64, "INPUT_SIZE_OR_TYPE")
            values = [visit(v, depth + 1) for v in item]
            return {"$tuple": values} if type(item) is tuple else values
        need(type(item) is dict and len(item) <= 64
             and all(type(k) is str and len(k) <= 64 and k.isascii() for k in item),
             "INPUT_SIZE_OR_TYPE")
        return {k: visit(item[k], depth + 1) for k in sorted(item)}

    encoded = json.dumps(visit(value), sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True, allow_nan=False).encode("ascii")
    need(len(encoded) <= 65536, "INPUT_SIZE_OR_TYPE")
    return hashlib.sha256(encoded).hexdigest()


def _kernel(record):
    try:
        checked = json.loads(sampler.serialize(record))
        need(checked == record and checked["status"] == "KERNEL_MODEL_OBSERVED"
             and checked["code"] == "OK", "KERNEL_INVALID")
        return checked
    except ObservationModelError:
        raise
    except Exception:
        raise ObservationModelError("KERNEL_INVALID") from None


def _client_identity(value):
    need(type(value) is tuple and len(value) == 4, "CLIENT_IDENTITY_INVALID")
    for index, entry in enumerate(value):
        need(type(entry) is tuple and len(entry) == 8
             and all(arithmetic.integer(v) for v in entry), "CLIENT_IDENTITY_INVALID")
        mode, uid = entry[2], entry[3]
        need(uid == 0 and mode & 0o022 == 0
             and (stat.S_ISDIR(mode) if index < 3 else stat.S_ISREG(mode) and mode & 0o111),
             "CLIENT_IDENTITY_INVALID")


def validate_observation(record, expected_runtime_sha256):
    """Check recorded consistency only. Does not read or attest a runtime."""
    binding = private_binding(record)
    expected = {"schema", "record", "runtime_sha256_supplied", "client_version", "captures",
        "kernel_before", "kernel_after", "source_projection", "client_path_identity",
        "owner_started_ns", "owner_deadline_ns", "required_reserve_ns"}
    need(shape(record, expected) and type(record["schema"]) is int and record["schema"] == 1
         and record["record"] == "PRIVATE_UNQUALIFIED_CHRONY_COLLECTION",
         "OBSERVATION_SCHEMA")
    need(arithmetic.digest(expected_runtime_sha256)
         and arithmetic.literal(record["runtime_sha256_supplied"], expected_runtime_sha256),
         "RUNTIME_MISMATCH")
    need(arithmetic.literal(record["client_version"], "4.5"), "CLIENT_VERSION_INVALID")
    start, deadline, reserve = (record[k] for k in (
        "owner_started_ns", "owner_deadline_ns", "required_reserve_ns"))
    need(all(arithmetic.integer(v) for v in (start, deadline, reserve))
         and deadline - start == PHASE_NS and reserve < PHASE_NS, "OWNER_INTERVAL_INVALID")
    _client_identity(record["client_path_identity"])
    captures = record["captures"]
    need(type(captures) is list and len(captures) == 4, "CAPTURE_INVALID")
    for item, kind in zip(captures, ("VERSION", "TRACKING", "SOURCES", "TRACKING")):
        need(shape(item, {"kind", "capture", "bracket", "stdout"})
             and arithmetic.literal(item["kind"], kind), "CAPTURE_INVALID")
        try:
            collector._bracket(item["bracket"])
            checked = collector._capture_result(CaptureResult(item["capture"], item["stdout"]),
                                                item["bracket"], kind)
            need(checked == item and item["capture"]["finished_monotonic_ns"]
                 - item["capture"]["started_monotonic_ns"] < COMMAND_NS, "CAPTURE_INVALID")
        except ObservationModelError:
            raise
        except Exception:
            raise ObservationModelError("CAPTURE_INVALID") from None
    try:
        need(probe.parse_version(captures[0]["stdout"]) == "4.5", "CLIENT_VERSION_INVALID")
    except ObservationModelError:
        raise
    except Exception:
        raise ObservationModelError("CLIENT_VERSION_INVALID") from None
    before, after = _kernel(record["kernel_before"]), _kernel(record["kernel_after"])
    need(before["samples"][-1]["kernel"]["status"] == after["samples"][0]["kernel"]["status"],
         "KERNEL_INVALID")

    def kernel_span(value):
        return {"monotonic_before_ns": value["samples"][0]["monotonic_before_ns"],
            "realtime_before_ns": value["samples"][0]["realtime_before_ns"],
            "realtime_after_ns": value["samples"][-1]["realtime_after_ns"],
            "monotonic_after_ns": value["samples"][-1]["monotonic_after_ns"]}

    stages = [captures[0]["bracket"], kernel_span(before), captures[1]["bracket"],
              captures[2]["bracket"], captures[3]["bracket"], kernel_span(after)]
    remaining = 4 * COMMAND_NS + 2 * sampler.MAX_DURATION_NS
    previous_m, previous_w = start, None
    for bracket in stages:
        m0, m1 = bracket["monotonic_before_ns"], bracket["monotonic_after_ns"]
        w0, w1 = bracket["realtime_before_ns"], bracket["realtime_after_ns"]
        need(previous_m <= m0 <= m1 < deadline
             and (previous_w is None or previous_w <= w0) and w0 <= w1,
             "COLLECTION_SEQUENCE_INVALID")
        need(deadline - m0 > reserve + remaining, "COLLECTION_RESERVE_INVALID")
        remaining -= COMMAND_NS  # Every retained stage's maximum is one second.
        need(deadline - m1 > reserve + remaining, "COLLECTION_RESERVE_INVALID")
        previous_m, previous_w = m1, w1
    span = {"monotonic_before_ns": stages[0]["monotonic_before_ns"],
            "realtime_before_ns": stages[0]["realtime_before_ns"],
            "realtime_after_ns": stages[-1]["realtime_after_ns"],
            "monotonic_after_ns": stages[-1]["monotonic_after_ns"]}
    try:
        collector._bracket(span)
    except Exception:
        raise ObservationModelError("COLLECTION_SEQUENCE_INVALID") from None
    try:
        sources = parse_sources(captures[2]["stdout"])
        need(sources == record["source_projection"], "SOURCE_PROJECTION_INVALID")
        classification = match_tracking(captures[1]["stdout"], captures[3]["stdout"], sources)
    except ObservationModelError:
        raise
    except Exception:
        raise ObservationModelError("SOURCE_PROJECTION_INVALID") from None
    return {"binding": binding, "captures": captures, "sources": sources,
            "span": span, "source_classification": classification}
