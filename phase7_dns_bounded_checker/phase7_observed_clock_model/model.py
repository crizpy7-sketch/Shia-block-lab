"""Conditional chrony arithmetic over actual-shaped, unqualified observations.

No callback, OS read, synthetic relabeling, mapper pair or live-admission path.
External policy assertions are model premises, never authenticated facts here.
"""
from dataclasses import dataclass
import json

from phase7_chrony_gate_integration import chrony45 as arithmetic
from .validation import ObservationModelError, need, shape, private_binding, validate_observation

POLICY_KEYS = {"schema", "record", "runtime_sha256", "valid_from_us", "valid_until_us",
               "source", "daemon", "limits", "continuity", "review_evidence_sha256"}
ERROR_CODES = frozenset({"INPUT_SIZE_OR_TYPE", "OBSERVATION_SCHEMA", "RUNTIME_MISMATCH",
    "CLIENT_VERSION_INVALID", "OWNER_INTERVAL_INVALID", "CLIENT_IDENTITY_INVALID", "CAPTURE_INVALID",
    "KERNEL_INVALID", "COLLECTION_SEQUENCE_INVALID", "COLLECTION_RESERVE_INVALID",
    "SOURCE_PROJECTION_INVALID", "POLICY_SCHEMA", "POLICY_RUNTIME_MISMATCH",
    "POLICY_SOURCE_MISMATCH", "POLICY_DAEMON_INVALID", "POLICY_LIMITS_INVALID",
    "POLICY_CONTINUITY_INVALID", "POLICY_INTERVAL_INVALID", "REQUEST_INTERVAL_INVALID",
    "RETROSPECTIVE_POLICY_REQUIRED", "CHRONY_TRACKING_INVALID", "CHRONY_NUMBER_INVALID",
    "CHRONY_UNSYNCHRONIZED", "CHRONY_SEMANTIC_RANGE", "CHRONY_REFERENCE_FUTURE",
    "CHRONY_SAMPLE_STALE", "CHRONY_BOUND_RANGE", "PUBLIC_OUTPUT_CAP"})


@dataclass(frozen=True, repr=False)
class ModelResult:
    public: dict
    private: object

    def __repr__(self):
        return "<ModelResult private conditional observation model>"


def _public():
    return {"schema": 1, "record": "CONDITIONAL_OBSERVED_CLOCK_MODEL", "status": "REFUSED",
        "code": "NOT_STARTED", "basis": "UNQUALIFIED_COLLECTION_WITH_EXTERNAL_POLICY_CLAIMS",
        "provenance": "COLLECTOR_RECORD_AND_POLICY_CLAIMS_NOT_AUTHENTICATED",
        "external_policy_verified": False, "daemon_association_verified": False,
        "source_truth_verified": False, "continuity_verified": False,
        "runtime_verified": False, "owner_containment_qualified": False,
        "alignment_established": False, "execution_authorized": False,
        "phase7_acceptance": "BLOCKED", "control_authority": "NONE",
        "source_classification": None, "retrospective_projection_required": None,
        "snapshots": [], "total_utc_error_bound_ns": None}


def _policy(policy, observed, runtime, low_us, high_us):
    binding = private_binding(policy)
    need(shape(policy, POLICY_KEYS) and type(policy["schema"]) is int and policy["schema"] == 1
         and arithmetic.literal(policy["record"], "EXPLICIT_CHRONY45_POLICY_CLAIMS")
         and arithmetic.digest(policy["review_evidence_sha256"]), "POLICY_SCHEMA")
    need(arithmetic.literal(policy["runtime_sha256"], runtime), "POLICY_RUNTIME_MISMATCH")
    need(arithmetic.integer(low_us, 10**18 - 1) and arithmetic.integer(high_us, 10**18 - 1)
         and low_us <= high_us, "REQUEST_INTERVAL_INVALID")
    need(arithmetic.integer(policy["valid_from_us"], 10**18 - 1)
         and arithmetic.integer(policy["valid_until_us"], 10**18 - 1)
         and policy["valid_from_us"] <= low_us <= high_us <= policy["valid_until_us"],
         "POLICY_INTERVAL_INVALID")
    low, high = low_us * 1000, high_us * 1000
    policy_low, policy_high = policy["valid_from_us"] * 1000, policy["valid_until_us"] * 1000
    need(policy_low <= observed["span"]["realtime_before_ns"]
         <= observed["span"]["realtime_after_ns"] <= policy_high, "POLICY_INTERVAL_INVALID")
    first, last = observed["captures"][1], observed["captures"][3]
    need(low <= first["bracket"]["realtime_before_ns"]
         and last["bracket"]["realtime_after_ns"] <= high
         and observed["span"]["realtime_after_ns"] <= high, "REQUEST_INTERVAL_INVALID")
    source = policy["source"]
    source_keys = {"mode", "reference_id", "address", "source_accuracy_bound_ns", "utc_basis"}
    need(shape(source, source_keys)
         and arithmetic.literal(source["mode"], observed["sources"]["selected"][0])
         and arithmetic.literal(source["utc_basis"], "UTC_ERROR_INCLUDES_TIMESCALE_CONVERSION")
         and arithmetic.integer(source["source_accuracy_bound_ns"]), "POLICY_SOURCE_MISMATCH")
    fields = first["stdout"].decode("ascii").rstrip("\n").split(",")
    need(arithmetic.literal(source["reference_id"], fields[0])
         and arithmetic.literal(source["address"], fields[1]), "POLICY_SOURCE_MISMATCH")
    daemon = policy["daemon"]
    need(shape(daemon, {"version", "runtime_sha256", "association_evidence_sha256",
                        "loaded_config_evidence_sha256"})
         and arithmetic.literal(daemon["version"], "4.5")
         and arithmetic.literal(daemon["runtime_sha256"], runtime)
         and arithmetic.digest(daemon["association_evidence_sha256"])
         and arithmetic.digest(daemon["loaded_config_evidence_sha256"]), "POLICY_DAEMON_INVALID")
    limits = policy["limits"]
    need(shape(limits, {"rate_bound_ppb", "max_sample_age_ns"})
         and arithmetic.integer(limits["rate_bound_ppb"], arithmetic.SECOND)
         and arithmetic.integer(limits["max_sample_age_ns"])
         and limits["max_sample_age_ns"] > 0, "POLICY_LIMITS_INVALID")
    continuity = policy["continuity"]
    need(shape(continuity, {"no_unaccounted_steps", "no_restart_or_source_change",
                            "allow_retrospective_projection"})
         and continuity["no_unaccounted_steps"] is True
         and continuity["no_restart_or_source_change"] is True
         and type(continuity["allow_retrospective_projection"]) is bool,
         "POLICY_CONTINUITY_INVALID")
    # Both reports are independently extended over the complete requested
    # interval. The later report also needs the explicit backward premise.
    retrospective = low < max(first["bracket"]["realtime_before_ns"],
                              last["bracket"]["realtime_before_ns"])
    need(not retrospective or continuity["allow_retrospective_projection"],
         "RETROSPECTIVE_POLICY_REQUIRED")
    return binding, low, high, retrospective


def _snapshot(capture, policy, low, high):
    # Retained strict 4.5 parser and export-error helpers; no call to the
    # synthetic evaluator and no synthesized SUPPLIED_CHRONY45_MODEL object.
    _, reference, correction, delay, dispersion = arithmetic._tracking(capture["stdout"])
    bracket = capture["bracket"]
    m0, w0, w1, m1 = (bracket[k] for k in ("monotonic_before_ns", "realtime_before_ns",
                                          "realtime_after_ns", "monotonic_after_ns"))
    correction_error = arithmetic.scalar_error(correction)
    ref_low = reference - arithmetic.REF_EXPORT_NS
    ref_high = reference + arithmetic.REF_EXPORT_NS
    cooked_low, cooked_high = w0 + correction - correction_error, w1 + correction + correction_error
    need(ref_low <= cooked_high, "CHRONY_REFERENCE_FUTURE")
    age_upper = cooked_high - ref_low
    age_lower = max(0, cooked_low - ref_high - arithmetic.REF_FUZZ_NS)
    need(age_upper <= policy["limits"]["max_sample_age_ns"], "CHRONY_SAMPLE_STALE")
    snapshot = (abs(correction) + correction_error + dispersion + arithmetic.scalar_error(dispersion)
                + arithmetic.ceil_div(delay + arithmetic.scalar_error(delay), 2))
    bracket_error = (w1 - w0) + (m1 - m0)
    horizon = max(w1 - low, high - w0)
    drift = arithmetic.ceil_div(policy["limits"]["rate_bound_ppb"] * horizon, arithmetic.SECOND)
    source_error = policy["source"]["source_accuracy_bound_ns"]
    total = snapshot + bracket_error + source_error + drift
    need(total <= arithmetic.MAX_NS, "CHRONY_BOUND_RANGE")
    return {"snapshot_upper_ns": str(snapshot), "observation_bracket_error_ns": str(bracket_error),
        "interval_growth_ns": str(drift), "source_accuracy_bound_ns": str(source_error),
        "sample_age_lower_ns": str(age_lower), "sample_age_upper_ns": str(age_upper),
        "total_utc_error_bound_ns": str(total)}


def evaluate_observation(record, *, expected_runtime_sha256, policy, valid_from_us, valid_until_us):
    """Evaluate explicit engineering assumptions over one validated record.

Policy evidence hashes bind supplied references only. Neither their presence,
this calculation nor the record's shape verifies the external policy's truth.
All requested backward/future applicability is conditional on the full stated
continuity and rate premises. There is no implicit freshness or source accuracy.
"""
    public, private = _public(), None
    try:
        observed = validate_observation(record, expected_runtime_sha256)
        policy_binding, low, high, retrospective = _policy(
            policy, observed, expected_runtime_sha256, valid_from_us, valid_until_us)
        snapshots = [_snapshot(observed["captures"][i], policy, low, high) for i in (1, 3)]
        total = max(int(item["total_utc_error_bound_ns"]) for item in snapshots)
        public.update(status="CONDITIONAL_MODEL_ONLY", code="CONDITIONAL_OBSERVATION_EVALUATED",
            source_classification=observed["source_classification"],
            retrospective_projection_required=retrospective,
            snapshots=snapshots, total_utc_error_bound_ns=str(total))
        need(len(json.dumps(public, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True).encode("ascii")) <= 8192, "PUBLIC_OUTPUT_CAP")
        private = {"schema": 1, "record": "PRIVATE_CONDITIONAL_OBSERVED_CLOCK_MODEL",
            "runtime_sha256_supplied": expected_runtime_sha256,
            "observation_sha256": observed["binding"], "policy_sha256": policy_binding,
            "review_evidence_sha256_supplied": policy["review_evidence_sha256"],
            "valid_from_us": valid_from_us, "valid_until_us": valid_until_us,
            "total_utc_error_bound_ns": total, "snapshots": snapshots,
            "basis": "UNQUALIFIED_COLLECTION_WITH_EXTERNAL_POLICY_CLAIMS",
            "alignment_established": False, "execution_authorized": False,
            "control_authority": "NONE", "phase7_acceptance": "BLOCKED"}
    except (ObservationModelError, arithmetic.ModelError) as error:
        public = _public()
        public["code"] = error.code if type(error.code) is str and error.code in ERROR_CODES else "MODEL_INPUT_FAILED"
    except Exception:
        public = _public()
        public["code"] = "MODEL_INPUT_FAILED"
    return ModelResult(public=public, private=private)
