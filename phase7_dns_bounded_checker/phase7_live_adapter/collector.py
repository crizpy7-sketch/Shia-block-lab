"""Actual fixed local reader, prepared for later collection but not admission.

Only caller-supplied boundaries execute. ReadOnlyBoundary is the explicit real
boundary. Never pass a raw observation to the synthetic integration evaluator.
"""
from dataclasses import dataclass
import json
import re
import time

from phase7_chrony_capability_probe import entry as probe
from phase7_clock_sampler import sampler
from .capture import Budget, CaptureResult, CollectionError, PHASE_NS, OUTPUT_CAP, COMMAND_NS, capture, exact_ns, need
from .sources import parse_sources, match_tracking

PUBLIC_CAP = 8192
CAPTURE_KEYS = frozenset(("code", "returncode", "stdout_bytes", "stderr_bytes",
    "bytecounts_exact", "direct_child_reaped", "parent_pipes_closed", "pipe_eof_observed",
    "descendant_cleanup_proven", "containment_uncertain", "started_monotonic_ns",
    "finished_monotonic_ns"))


@dataclass(frozen=True, repr=False)
class CollectionResult:
    public: dict
    private: object

    def __repr__(self):
        return "<CollectionResult private unqualified observation>"


class ReadOnlyBoundary:
    """Direct client must already be allowed to access the fixed Unix socket.

Never escalates privilege or changes permissions. Import and construction do
not read the kernel; NativeAdapter initialization is deferred to kernel_read.
chronyc itself may create/remove its temporary local client socket.
"""
    monotonic_ns = staticmethod(time.monotonic_ns)
    time_ns = staticmethod(time.time_ns)

    def __init__(self):
        self._kernel = None

    def kernel_read(self):
        if self._kernel is None:
            self._kernel = sampler.NativeAdapter()
        return self._kernel()

    def binary_identity(self):
        return probe.binary_identity(probe.CHRONYC)

    def capture(self, kind, owner, required_reserve_ns):
        return capture(kind, owner=owner, clock=self, required_reserve_ns=required_reserve_ns)


def _public():
    return {"schema": 1, "record": "CHRONY_PRIVATE_COLLECTION_SUMMARY",
        "status": "REFUSED", "code": "NOT_STARTED",
        "provenance": "UNQUALIFIED_LOCAL_OBSERVATION",
        "runtime_association": "SUPPLIED_NOT_ATTESTED",
        "provider_invocations": 0, "kernel_reads_expected_on_success": 4,
        "kernel_code": None, "capture_code": None,
        "selected_source_classification": None, "source_continuity": "NOT_ESTABLISHED",
        "daemon_semantics": "NOT_ESTABLISHED", "source_policy": "NOT_ESTABLISHED",
        "direct_resource_closure_observed": False, "descendant_cleanup_proven": False,
        "alignment_established": False, "execution_authorized": False,
        "control_authority": "NONE", "phase7_acceptance": "BLOCKED",
        "admission_code": "LIVE_ADMISSION_UNIMPLEMENTED"}


def _bracket(raw):
    need(type(raw) is dict and set(raw) == {"monotonic_before_ns", "realtime_before_ns",
        "realtime_after_ns", "monotonic_after_ns"} and all(exact_ns(v) for v in raw.values()),
        "COLLECTION_BRACKET_INVALID")
    m0, w0, w1, m1 = (raw[k] for k in ("monotonic_before_ns", "realtime_before_ns",
        "realtime_after_ns", "monotonic_after_ns"))
    need(m0 <= m1 and w0 <= w1 and m1 - m0 < PHASE_NS and w1 - w0 < PHASE_NS,
         "COLLECTION_BRACKET_INVALID")
    # This is observed discontinuity detection, not a bound on unobserved steps.
    need(abs((w1 - w0) - (m1 - m0)) <= sampler.ROUNDING_TOLERANCE_NS,
         "OBSERVED_CLOCK_DISCONTINUITY")


def _capture_result(result, bracket, kind):
    need(type(result) is CaptureResult and type(result.meta) is dict
         and set(result.meta) == CAPTURE_KEYS and type(result.stdout) is bytes,
         "CAPTURE_SCHEMA")
    meta = result.meta
    need(type(meta["code"]) is str and meta["code"] == "OK"
         and type(meta["returncode"]) is int and meta["returncode"] == 0,
         "CAPTURE_REFUSED")
    for key in ("bytecounts_exact", "direct_child_reaped", "parent_pipes_closed", "pipe_eof_observed"):
        need(type(meta[key]) is bool and meta[key], "DIRECT_RESOURCE_CLOSURE_UNPROVEN")
    need(meta["descendant_cleanup_proven"] is False and meta["containment_uncertain"] is True,
         "LIFECYCLE_CLAIM_REFUSED")
    need(type(meta["stdout_bytes"]) is int and meta["stdout_bytes"] == len(result.stdout)
         and 0 < len(result.stdout) <= (512 if kind == "VERSION" else OUTPUT_CAP)
         and type(meta["stderr_bytes"]) is int and meta["stderr_bytes"] == 0,
         "CAPTURE_BYTECOUNTS")
    need(exact_ns(meta["started_monotonic_ns"]) and exact_ns(meta["finished_monotonic_ns"])
         and bracket["monotonic_before_ns"] <= meta["started_monotonic_ns"]
         <= meta["finished_monotonic_ns"] <= bracket["monotonic_after_ns"],
         "CAPTURE_BRACKET_MISMATCH")
    return {"kind": kind, "capture": dict(meta), "bracket": dict(bracket), "stdout": result.stdout}


def collect_private(*, owner, runtime_sha256, boundary, required_reserve_ns):
    """Collect fixed observations under one existing owner; never admit a gate.

runtime_sha256 is a supplied association label only. required_reserve_ns must
come from the unchanged downstream complete batch contract; equality refuses.
No valid-through interval, policy, endpoint envelope or alignment is fabricated.
"""
    public, private = _public(), None
    try:
        need(type(runtime_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", runtime_sha256)
             is not None, "RUNTIME_IDENTITY_INVALID")
        need(exact_ns(required_reserve_ns) and required_reserve_ns < PHASE_NS, "RESERVE_INVALID")
        budget = Budget(owner, boundary)
        remaining_collection_ns = 4 * COMMAND_NS + 2 * sampler.MAX_DURATION_NS

        def available(operation_ns=0):
            now = budget.check()
            need(budget.deadline_ns - now > required_reserve_ns + operation_ns,
                 "COLLECTION_RESERVE")
            return now

        available(remaining_collection_ns)
        identity = boundary.binary_identity()
        need(type(identity) is tuple and len(identity) > 0, "BINARY_IDENTITY_INVALID")
        available(remaining_collection_ns)
        captures = []

        def observe(kind):
            nonlocal remaining_collection_ns
            cap = COMMAND_NS
            m0 = available(remaining_collection_ns)
            w0 = boundary.time_ns()
            need(exact_ns(w0), "WALL_CLOCK_INVALID")
            public["provider_invocations"] += 1
            value = boundary.capture(kind, owner,
                required_reserve_ns + remaining_collection_ns - cap)
            w1 = boundary.time_ns()
            remaining_collection_ns -= cap
            m1 = available(remaining_collection_ns)
            capture_codes = {"OK", "COMMAND_REFUSED", "OWNER_INVALID", "OWNER_CHANGED",
                "MONOTONIC_INVALID", "PHASE_DEADLINE", "RESERVE_INVALID", "COLLECTION_RESERVE",
                "COMMAND_DEADLINE", "PIPE_UNAVAILABLE", "OUTPUT_CAP", "COMMAND_FAILED",
                "STDERR_PRESENT", "PROCESS_OR_CAPTURE_FAILED", "PHASE_OR_CLOCK_FAILED",
                "DIRECT_RESOURCE_CLOSURE_UNPROVEN", "COMMAND_CLOSURE_DEADLINE"}
            if (type(value) is CaptureResult and type(value.meta) is dict
                    and type(value.meta.get("code")) is str and value.meta["code"] in capture_codes):
                public["capture_code"] = value.meta["code"]
            bracket = {"monotonic_before_ns": m0, "realtime_before_ns": w0,
                       "realtime_after_ns": w1, "monotonic_after_ns": m1}
            _bracket(bracket)
            record = _capture_result(value, bracket, kind)
            captures.append(record)
            return value.stdout

        def kernel():
            nonlocal remaining_collection_ns
            available(remaining_collection_ns)
            result = sampler.collect(boundary.kernel_read, boundary)
            # Reuse the complete sampler serialization validation. This retains
            # full raw-record/ABI semantics, not a three-field kernel projection.
            checked = json.loads(sampler.serialize(result))
            remaining_collection_ns -= sampler.MAX_DURATION_NS
            available(remaining_collection_ns)
            if type(checked.get("code")) is str and checked["code"] in sampler.ERROR_CODES:
                public["kernel_code"] = checked["code"]
            need(checked["status"] == "KERNEL_MODEL_OBSERVED" and checked["code"] == "OK",
                 "KERNEL_OBSERVATION_REFUSED")
            return checked

        version_raw = observe("VERSION")
        version = probe.parse_version(version_raw)
        need(version == "4.5", "CLIENT_VERSION_UNSUPPORTED")
        before = kernel()
        first_raw = observe("TRACKING")
        first = probe.parse_tracking(first_raw, version)
        need(first["leap_report"] == "NORMAL" and 1 <= first["stratum"] <= 15,
             "TRACKING_UNSYNCHRONIZED")
        sources_raw = observe("SOURCES")
        sources = parse_sources(sources_raw)
        last_raw = observe("TRACKING")
        last = probe.parse_tracking(last_raw, version)
        need(last["leap_report"] == "NORMAL" and 1 <= last["stratum"] <= 15,
             "TRACKING_UNSYNCHRONIZED")
        classification = match_tracking(first_raw, last_raw, sources)
        after = kernel()
        need(before["samples"][-1]["kernel"]["status"] == after["samples"][0]["kernel"]["status"],
             "KERNEL_STATUS_CHANGED")
        # Cross-collection observed step check. No past/future interval claim.
        start, end = before["samples"][0], after["samples"][-1]
        _bracket({"monotonic_before_ns": start["monotonic_before_ns"],
                  "realtime_before_ns": start["realtime_before_ns"],
                  "realtime_after_ns": end["realtime_after_ns"],
                  "monotonic_after_ns": end["monotonic_after_ns"]})
        available()
        need(boundary.binary_identity() == identity, "CLIENT_BINARY_CHANGED")
        available()
        private = {"schema": 1, "record": "PRIVATE_UNQUALIFIED_CHRONY_COLLECTION",
            "runtime_sha256_supplied": runtime_sha256, "client_version": version,
            "captures": captures, "kernel_before": before, "kernel_after": after,
            "source_projection": sources, "client_path_identity": identity,
            "owner_started_ns": budget.started_ns, "owner_deadline_ns": budget.deadline_ns,
            "required_reserve_ns": required_reserve_ns}
        public.update(status="OBSERVATION_COMPLETE_UNQUALIFIED", code="COLLECTED_NOT_ADMITTED",
            selected_source_classification=classification, direct_resource_closure_observed=True)
        need(len(json.dumps(public, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True).encode("ascii")) <= PUBLIC_CAP, "PUBLIC_OUTPUT_CAP")
        available()
    except CollectionError as error:
        # Only fixed implementation codes may cross the public boundary. A
        # boundary can raise this type with hostile text, so allowlist it.
        allowed = {"OWNER_INVALID", "OWNER_CHANGED", "MONOTONIC_INVALID", "PHASE_DEADLINE",
            "RESERVE_INVALID", "COLLECTION_RESERVE", "RUNTIME_IDENTITY_INVALID",
            "BINARY_IDENTITY_INVALID", "WALL_CLOCK_INVALID", "COLLECTION_BRACKET_INVALID",
            "OBSERVED_CLOCK_DISCONTINUITY", "CAPTURE_SCHEMA", "CAPTURE_REFUSED",
            "DIRECT_RESOURCE_CLOSURE_UNPROVEN", "LIFECYCLE_CLAIM_REFUSED", "CAPTURE_BYTECOUNTS",
            "CAPTURE_BRACKET_MISMATCH", "CLIENT_VERSION_UNSUPPORTED", "KERNEL_OBSERVATION_REFUSED",
            "TRACKING_UNSYNCHRONIZED", "TRACKING_SOURCE_CHANGED", "LOCAL_OR_UNKNOWN_SOURCE",
            "SOURCE_IDENTITY_MISMATCH", "KERNEL_STATUS_CHANGED", "CLIENT_BINARY_CHANGED",
            "PUBLIC_OUTPUT_CAP", "SOURCES_FORMAT", "SOURCES_ROW_CAP", "SOURCES_NUMBER",
            "SOURCES_SHAPE", "SOURCE_IDENTITY_UNSUPPORTED", "SELECTED_SOURCE_UNESTABLISHED"}
        public.update(status="REFUSED", code=error.code if type(error.code) is str
                      and error.code in allowed else "DEPENDENCY_FAILED",
                      selected_source_classification=None, direct_resource_closure_observed=False)
        private = None
    except Exception:
        public.update(status="REFUSED", code="DEPENDENCY_FAILED",
                      selected_source_classification=None, direct_resource_closure_observed=False)
        private = None
    return CollectionResult(public=public, private=private)


def admit_live(_observation):
    """Deliberate closed boundary: no model conversion or transport callback."""
    result = _public()
    result.update(code="LIVE_ADMISSION_UNIMPLEMENTED")
    return CollectionResult(public=result, private=None)
