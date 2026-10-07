"""Injected clock/provider observation glue; no live defaults or alignment grant."""

from dataclasses import dataclass
import hashlib
import json
import re


OVERALL_BUDGET_NS = 15_000_000_000
MAX_OUTPUT_BYTES = 32768
MAX_NS = (1 << 63) - 1
WORKFLOW_REF = "crizpy7-sketch/Shia-block-lab/.github/workflows/phase7-clock-provider-capability.yml@refs/heads/main"
_FIXED_ASSOCIATION = {
    "GITHUB_REPOSITORY": "crizpy7-sketch/Shia-block-lab",
    "GITHUB_REPOSITORY_ID": "1316595124", "GITHUB_EVENT_NAME": "workflow_dispatch",
    "GITHUB_REF": "refs/heads/main", "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_JOB": "observe", "PHASE7_REPOSITORY_VISIBILITY": "public",
    "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64", "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
}
_SAMPLER_CODES = frozenset((
    "OK", "UNSUPPORTED_ABI", "LIBC_INTERFACE_UNAVAILABLE", "KERNEL_READ_FAILED",
    "CLOCK_READ_FAILED", "INVALID_CLOCK_VALUE", "INVALID_KERNEL_RECORD",
    "INVALID_KERNEL_VALUE", "NONZERO_MODES", "KERNEL_UNSYNCHRONIZED",
    "KERNEL_CLOCK_ERROR", "KERNEL_STATE_NOT_OK", "KERNEL_STATUS_REJECTED",
    "UNKNOWN_STATUS_BITS", "KERNEL_STATUS_CHANGED", "MONOTONIC_REVERSED",
    "REALTIME_REVERSED", "COLLECTION_DEADLINE_EXCEEDED",
    "KERNEL_TIME_OUTSIDE_BRACKET", "REALTIME_MONOTONIC_DIVERGENCE",
    "ARGUMENTS_NOT_ALLOWED", "OUTPUT_LIMIT_EXCEEDED", "INVALID_RESULT",
))
_COLLECTOR_CODES = frozenset((
    "OK", "DUPLICATE_RESPONSE_KEY", "INTEGER_TOKEN_CAP", "NONINTEGER_JSON_NUMBER",
    "RESPONSE_FORMAT", "RESPONSE_SHAPE", "PROVIDER_OWNER", "PROPERTY_TYPE",
    "PACKET_SHAPE", "PACKET_FIELD_TYPE", "PRECISION_FIELD_TYPE", "REFERENCE_SHAPE",
    "IGNORED_FIELD_TYPE", "POLL_INTERVAL_TYPE", "EXECUTOR_REPLY_SHAPE",
    "EXECUTOR_REPLY_FLAG_TYPE", "CLIENT_NOT_REAPED", "EXECUTOR_TIMED_OUT",
    "EXECUTOR_RETURN_CODE_TYPE", "RESPONSE_CAP_OR_TYPE", "PROVIDER_READ_FAILED",
    "STDERR_PRESENT", "EMPTY_RESPONSE", "MONOTONIC_READ_FAILED",
    "MONOTONIC_VALUE_TYPE", "MONOTONIC_REVERSED", "MONOTONIC_RANGE",
    "COLLECTION_DEADLINE", "EXECUTOR_FAILED", "CALL_DEADLINE", "RUNTIME_BINDING",
    "PACKET_BYTES_CHANGED", "POLL_BYTES_CHANGED", "PROVIDER_CHANGED",
    "PUBLIC_RESULT_CAP", "COLLECTION_FAILED",
))
_PACKET_CODES = frozenset((
    "OK", "DUPLICATE_RESPONSE_KEY", "INTEGER_TOKEN_CAP", "NONINTEGER_JSON_NUMBER",
    "RESPONSE_CAP_OR_TYPE", "RESPONSE_FORMAT", "RESPONSE_SHAPE", "PROPERTY_TYPE",
    "PACKET_SHAPE", "PACKET_FIELD_TYPE", "PRECISION_EXPONENT_UNSUPPORTED",
    "REFERENCE_SHAPE", "IGNORED_FIELD_TYPE", "SAMPLE_NOT_ACCEPTED",
    "OBSERVED_UTC_TYPE", "RUNTIME_BINDING", "PROVIDER_OWNER", "PROVIDER_CHANGED",
    "PACKET_BYTES_CHANGED", "POLL_BYTES_CHANGED", "POLL_INTERVAL_TYPE",
    "TIMESTAMP_ORDER", "TIMESTAMP_INFINITY_UNSUPPORTED", "OFFSET_EXCEEDS_THREE_SECONDS",
    "SAMPLE_STALE_OR_FUTURE", "INPUT_REJECTED", "RESULT_CAP",
))
_KERNEL_KEYS = frozenset((
    "state", "modes", "offset", "freq", "maxerror", "esterror", "status",
    "constant", "precision", "tolerance", "time_sec", "time_subsec", "tick",
    "ppsfreq", "jitter", "shift", "stabil", "jitcnt", "calcnt", "errcnt", "stbcnt", "tai",
))
_SAMPLE_INTS = frozenset((
    "offset_ns", "kernel_realtime_ns", "reported_maxerror_ns", "reported_esterror_ns",
    "reported_precision_ns", "monotonic_before_ns", "realtime_before_ns",
    "realtime_after_ns", "monotonic_after_ns",
))
_COMPONENTS = frozenset((
    "leap", "version", "mode", "stratum", "precision_exponent", "root_delay_us",
    "root_dispersion_us", "root_distance_us", "offset_twice_us",
    "absolute_offset_ceiling_us", "round_trip_delay_us",
    "half_round_trip_delay_ceiling_us", "precision_ceiling_us", "sample_age_us",
    "poll_us", "packet_count", "jitter_us", "t1_us", "t2_us", "t3_us", "t4_us",
))
_QUANTIZATION = frozenset((
    "timestamp_export_error_exclusive_us", "offset_export_error_ceiling_us",
    "round_trip_export_error_ceiling_us", "half_round_trip_export_error_ceiling_us",
    "root_distance_export_error_ceiling_us",
))


@dataclass(frozen=True, repr=False)
class RuntimeCheckResult:
    public: dict
    private: object

    def __repr__(self):
        return "<RuntimeCheckResult private>"


class _Stop(Exception):
    pass


def _require(condition, code="DEPENDENCY_RESULT_INVALID"):
    if not condition:
        raise _Stop(code)


def _hex(value, length):
    return type(value) is str and len(value) == length and re.fullmatch(r"[0-9a-f]+", value) is not None


def _keys(value, expected):
    return type(value) is dict and all(type(key) is str for key in value) and set(value) == expected


def _association(value):
    expected = set(_FIXED_ASSOCIATION) | {"GITHUB_SHA", "GITHUB_WORKFLOW_SHA", "GITHUB_RUN_ID"}
    _require(_keys(value, expected), "RUNTIME_ASSOCIATION_INVALID")
    _require(all(type(value[k]) is str and len(value[k]) <= 255 for k in expected),
             "RUNTIME_ASSOCIATION_INVALID")
    _require(all(value[k] == v for k, v in _FIXED_ASSOCIATION.items())
             and _hex(value["GITHUB_SHA"], 40)
             and value["GITHUB_WORKFLOW_SHA"] == value["GITHUB_SHA"]
             and re.fullmatch(r"[1-9][0-9]{0,19}", value["GITHUB_RUN_ID"]) is not None,
             "RUNTIME_ASSOCIATION_INVALID")
    copied = dict(value)
    encoded = json.dumps(copied, sort_keys=True, separators=(",", ":")).encode("ascii")
    return copied, hashlib.sha256(encoded).hexdigest()


def _sampler_result(value):
    fixed = {
        "schema": 1, "record": "LOCAL_CLOCK_MODEL_OBSERVATION", "disposition": "OBSERVATION_ONLY",
        "interface": "LIBC_ADJTIMEX_MODES_ZERO", "provenance": "UNVERIFIED_LOCAL_OBSERVATION",
        "collection_budget_ns": 1_000_000_000, "rounding_tolerance_ns": 1_000_000,
        "gate_action": "NONE", "phase7": "BLOCKED", "relative_alignment_established": False,
        "alignment_established": False, "execution_authorized": False,
        "cleanup_proven": False, "valid_through": None,
    }
    _require(_keys(value, set(fixed) | {"status", "code", "samples"}))
    _require(all(type(value[k]) is type(v) and value[k] == v for k, v in fixed.items()))
    _require(type(value["code"]) is str and value["code"] in _SAMPLER_CODES)
    _require(type(value["status"]) is str and value["status"] ==
             ("KERNEL_MODEL_OBSERVED" if value["code"] == "OK" else "REFUSED"))
    _require(type(value["samples"]) is list and len(value["samples"]) <= 2)
    samples = []
    sample_keys = _SAMPLE_INTS | {"kernel", "kernel_fraction_unit", "kernel_unsynchronized", "kernel_clock_error"}
    for sample in value["samples"]:
        _require(_keys(sample, sample_keys))
        raw = sample["kernel"]
        _require(_keys(raw, _KERNEL_KEYS)
                 and all(type(v) is int and -(1 << 63) <= v <= MAX_NS for v in raw.values()))
        _require(all(type(sample[k]) is int and -(1 << 63) <= sample[k] < (1 << 80) for k in _SAMPLE_INTS))
        _require(type(sample["kernel_fraction_unit"]) is str
                 and sample["kernel_fraction_unit"] in ("NANOSECONDS", "MICROSECONDS"))
        _require(type(sample["kernel_unsynchronized"]) is bool and type(sample["kernel_clock_error"]) is bool)
        samples.append(dict(sample, kernel=dict(raw)))
    if value["code"] == "OK":
        _require(len(samples) == 2 and all(s["kernel"]["state"] == 0
                 and s["kernel"]["modes"] == 0 and s["kernel"]["status"] & ~0xFFFF == 0
                 and s["kernel"]["status"] & 0x1E70 == 0 for s in samples))
    return dict(value, samples=samples)


def _collector_result(value):
    _require(type(value) is dict)
    code = value.get("code")
    _require(type(code) is str and code in _COLLECTOR_CODES)
    _require(type(value.get("status")) is str and value["status"] ==
             ("EXISTING_PROVIDER_BYTES_STABLE" if code == "OK" else "REFUSED"))
    attempted, completed = value.get("calls_attempted"), value.get("calls_completed")
    _require(type(attempted) is int and type(completed) is int and 0 <= completed <= attempted <= 6)
    _require(code != "OK" or attempted == completed == 6)
    return {"code": code, "status": value["status"], "calls_attempted": attempted, "calls_completed": completed}


def _packet_result(value, expected_context):
    _require(type(value) is dict)
    code = value.get("code")
    _require(type(code) is str and code in _PACKET_CODES)
    _require(type(value.get("status")) is str and value["status"] ==
             ("CONDITIONAL_MODEL_ONLY" if code == "OK" else "REFUSED"))
    projected = {"code": code, "status": value["status"], "components": {}, "quantization": {}}
    if code == "OK":
        context = value.get("context")
        _require(_keys(context, set(expected_context) | {"reference_id_sha256"}))
        _require(all(type(context[k]) is type(v) and context[k] == v for k, v in expected_context.items())
                 and _hex(context["reference_id_sha256"], 64))
        for name, keys, limit in (("components", _COMPONENTS, 1 << 160), ("quantization", _QUANTIZATION, 100)):
            data = value.get(name)
            _require(_keys(data, keys)
                     and all(type(v) is int and -limit < v < limit for v in data.values()))
            projected[name] = dict(data)
    return projected


class _Budget:
    def __init__(self, clock):
        self.clock, self.previous, self.deadline = clock, None, None
        self.failure_code, self.guard = None, None

    def read(self):
        try:
            _require(self.failure_code is None, self.failure_code)
            _require(self.guard is None or self.guard(), "EXECUTOR_CONTINUATION_UNSAFE")
            try:
                value = self.clock()
            except Exception:
                raise _Stop("MONOTONIC_READ_FAILED") from None
            _require(type(value) is int and 0 <= value <= MAX_NS, "MONOTONIC_VALUE_INVALID")
            _require(self.previous is None or value >= self.previous, "MONOTONIC_REVERSED")
            self.previous = value
            _require(self.deadline is None or value < self.deadline, "RUNTIME_DEADLINE")
            return value
        except _Stop as error:
            self.failure_code = error.args[0]
            raise


class _ExecutorProxy:
    def __init__(self, executor, budget):
        self.executor, self.budget, self.attempted, self.uncertain = executor, budget, 0, False

    def closed(self):
        try:
            return not self.uncertain and self.executor.client_closed is True
        except Exception:
            return False

    def run(self, argv, *, deadline_ns, cap):
        _require(self.closed() and self.attempted < 6, "EXECUTOR_CONTINUATION_UNSAFE")
        _require(self.budget.failure_code is None, self.budget.failure_code)
        _require(type(argv) is tuple and type(deadline_ns) is int and type(cap) is int and cap == 16384,
                 "EXECUTOR_ARGUMENT_INVALID")
        deadline = min(deadline_ns, self.budget.deadline)
        _require(self.budget.previous < deadline, "RUNTIME_DEADLINE")
        self.attempted += 1
        self.uncertain = True
        try:
            reply = self.executor.run(argv, deadline_ns=deadline, cap=cap)
        except Exception:
            raise _Stop("EXECUTOR_CONTINUATION_UNSAFE") from None
        if type(reply) is dict and reply.get("client_reaped") is True:
            try:
                self.uncertain = self.executor.client_closed is not True
            except Exception:
                pass
        return reply


def _retained(value, identity, before, after):
    _require(value is not None and type(value.runtime_sha256) is str and value.runtime_sha256 == identity)
    for owner in (value.owner_before, value.owner_after):
        _require(type(owner) is str and len(owner) <= 255
                 and re.fullmatch(r":[0-9]+\.[0-9]+", owner) is not None)
    _require(value.owner_before == value.owner_after)
    names = ("packet_before", "packet_after", "poll_before", "poll_after")
    raw = [getattr(value, name) for name in names]
    _require(all(type(x) is bytes and 0 < len(x) <= 16384 for x in raw)
             and raw[0] == raw[1] and raw[2] == raw[3])
    _require(all(type(x) is bytes and 0 < len(x) <= 16384 for x in
                 (value.owner_before_reply, value.owner_after_reply)))
    start, finish = value.started_monotonic_ns, value.finished_monotonic_ns
    _require(type(start) is int and type(finish) is int and before <= start <= finish <= after
             and finish - start < 10_000_000_000)
    _require(type(value.call_brackets) is tuple and len(value.call_brackets) == 6)
    previous = start
    for bracket in value.call_brackets:
        _require(type(bracket) is tuple and len(bracket) == 3 and all(type(x) is int for x in bracket))
        left, right, deadline = bracket
        _require(previous <= left <= right <= finish and right < deadline
                 and deadline == min(start + 10_000_000_000, left + 4_000_000_000))
        previous = right
    _require(previous == finish)
    digests = {name: hashlib.sha256(item).hexdigest() for name, item in zip(names, raw)}
    context = {"runtime_sha256": identity,
        "provider_owner_sha256": hashlib.sha256(value.owner_before.encode("ascii")).hexdigest(),
        "packet_sha256": digests["packet_before"], "poll_sha256": digests["poll_before"]}
    return raw, digests, context


def _wall(read):
    try:
        value = read()
    except Exception:
        raise _Stop("REALTIME_READ_FAILED") from None
    _require(type(value) is int and 0 <= value <= MAX_NS, "REALTIME_VALUE_INVALID")
    return value


def run_check(*, sampler, collector, executor, packet_evaluator, monotonic_ns,
              realtime_ns, runtime_association):
    """Observe through explicit dependencies only; caller owns external preemption."""
    public = {
        "schema": 1, "record": "CLOCK_PROVIDER_CAPABILITY_OBSERVATION",
        "status": "REFUSED", "code": "NOT_STARTED", "disposition": "OBSERVATION_ONLY",
        "provenance": "SUPPLIED_DEPENDENCIES_UNVERIFIED", "runtime_association": None,
        "runtime_association_sha256": None,
        "runtime_binding_kind": "GITHUB_JOB_ATTEMPT_ASSOCIATION_NOT_MACHINE_ATTESTATION",
        "kernel_before": None, "provider": None, "kernel_after": None,
        "packet_diagnostic": None, "collector_bracket": None, "private_evidence_digests": None,
        "overall_budget_ns": OVERALL_BUDGET_NS, "started_monotonic_ns": None,
        "finished_monotonic_ns": None, "calls_attempted": 0, "client_closed": None,
        "control_authority": "NONE", "gate_action": "NONE", "phase7_acceptance": "BLOCKED",
        "alignment_established": False, "relative_alignment_established": False,
        "execution_authorized": False, "cleanup_proven": False, "valid_through": None,
    }
    private, proxy, budget = None, None, _Budget(monotonic_ns)
    try:
        association, identity = _association(runtime_association)
        public.update(runtime_association=association, runtime_association_sha256=identity)
        start = budget.read()
        _require(start <= MAX_NS - OVERALL_BUDGET_NS, "MONOTONIC_VALUE_INVALID")
        budget.deadline = start + OVERALL_BUDGET_NS
        public["started_monotonic_ns"] = start
        public["kernel_before"] = _sampler_result(sampler())
        budget.read()
        before_code = public["kernel_before"]["code"]
        _require(before_code in ("OK", "KERNEL_UNSYNCHRONIZED"), "KERNEL_BEFORE_REFUSED")
        proxy = _ExecutorProxy(executor, budget)
        _require(proxy.closed(), "EXECUTOR_CONTINUATION_UNSAFE")
        budget.guard = proxy.closed
        m0 = budget.read()
        w0 = _wall(realtime_ns)
        collected = collector(proxy, budget.read, runtime_sha256=identity)
        _require(proxy.closed(), "EXECUTOR_CONTINUATION_UNSAFE")
        _require(budget.failure_code is None, budget.failure_code)
        public["provider"] = _collector_result(collected.public)
        _require(public["provider"]["calls_attempted"] == proxy.attempted)
        budget.read()
        w1 = _wall(realtime_ns)
        m1 = budget.read()
        _require(w1 >= w0, "REALTIME_REVERSED")
        public["collector_bracket"] = {
            "monotonic_before_ns": m0, "realtime_before_ns": w0,
            "realtime_after_ns": w1, "monotonic_after_ns": m1,
        }
        public["kernel_after"] = _sampler_result(sampler())
        budget.read()
        if public["provider"]["code"] == "OK":
            retained = collected.private
            raw, digests, context = _retained(retained, identity, m0, m1)
            public["private_evidence_digests"] = digests
            context["observed_utc_us"] = w1 // 1000
            diagnostic = packet_evaluator(*raw, owner_before=retained.owner_before,
                owner_after=retained.owner_after, observed_utc_us=w1 // 1000, runtime_sha256=identity)
            public["packet_diagnostic"] = _packet_result(diagnostic, context)
            private = retained
        public["finished_monotonic_ns"] = budget.read()
        if before_code != "OK" or public["kernel_after"]["code"] != "OK":
            public["code"] = "KERNEL_UNSYNCHRONIZED" if "KERNEL_UNSYNCHRONIZED" in (
                before_code, public["kernel_after"]["code"]) else "KERNEL_AFTER_REFUSED"
        elif public["provider"]["code"] != "OK":
            public["code"] = "PROVIDER_COLLECTION_REFUSED"
        elif public["packet_diagnostic"]["code"] != "OK":
            public["code"] = "PACKET_DIAGNOSTIC_REFUSED"
        else:
            public.update(code="OK", status="OBSERVATION_COMPLETE")
    except _Stop as error:
        public["code"] = error.args[0]
    except Exception:
        public["code"] = "DEPENDENCY_FAILED"
    if proxy is not None:
        public["calls_attempted"], public["client_closed"] = proxy.attempted, proxy.closed()
    if public["finished_monotonic_ns"] is None:
        public["finished_monotonic_ns"] = budget.previous
    encoded = (json.dumps(public, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    if len(encoded) > MAX_OUTPUT_BYTES:
        public = {"schema": 1, "record": "CLOCK_PROVIDER_CAPABILITY_OBSERVATION",
            "status": "REFUSED", "code": "PUBLIC_RESULT_CAP", "control_authority": "NONE",
            "disposition": "OBSERVATION_ONLY", "provenance": "SUPPLIED_DEPENDENCIES_UNVERIFIED",
            "gate_action": "NONE",
            "phase7_acceptance": "BLOCKED", "alignment_established": False,
            "relative_alignment_established": False, "execution_authorized": False,
            "cleanup_proven": False, "valid_through": None}
        private = None
    return RuntimeCheckResult(public, private)
