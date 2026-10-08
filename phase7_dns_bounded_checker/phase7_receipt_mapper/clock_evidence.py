"""Pure structural validation of supplied clock envelopes; no attestation or IO."""

import hashlib
import json


_MAX_US = 10**18
_MAX_BOUND_US = 5_000_000
_HEX = frozenset("0123456789abcdef")
_KEYS = frozenset(
    {
        "schema",
        "record",
        "basis",
        "left_role",
        "left_runtime_sha256",
        "right_runtime_sha256",
        "left_evidence_sha256",
        "right_evidence_sha256",
        "review_sha256",
        "valid_from_us",
        "valid_until_us",
        "total_error_bound_us",
        "bound_scope",
    }
)
_DIGEST_KEYS = (
    "left_runtime_sha256",
    "right_runtime_sha256",
    "left_evidence_sha256",
    "right_evidence_sha256",
    "review_sha256",
)
_ERROR_CODES = frozenset(
    {
        "CLOCK_ALIGNMENT_UNESTABLISHED",
        "CLOCK_REQUEST_INVALID",
        "CLOCK_EVIDENCE_INVALID",
        "CLOCK_IDENTITY_MISMATCH",
        "CLOCK_INTERVAL_NOT_COVERED",
        "CLOCK_ERROR_BOUND_EXCEEDED",
    }
)


class ClockEvidenceError(ValueError):
    """A fixed, input-independent refusal code, safe for public projection."""

    def __init__(self, code):
        if type(code) is not str or len(code) > 40 or code not in _ERROR_CODES:
            code = "CLOCK_EVIDENCE_INVALID"
        self.code = code
        super().__init__(code)


def _digest(value):
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _microseconds(value):
    return type(value) is int and 0 <= value < _MAX_US


def _literal(value, choices):
    return type(value) is str and len(value) <= 32 and value in choices


def validate_pair(
    evidence, *, left_role, left_runtime, right_runtime, start_us, end_us
):
    """Validate supplied evidence for a left runtime against the actual runner.

    This validates structure, identity equality and claimed interval coverage.
    It cannot verify that a claimed observation, review or clock bound is true.
    No result grants live qualification, execution permission or gate authority.
    All input strings and containers must have their exact built-in types.
    """
    if evidence is None:
        raise ClockEvidenceError("CLOCK_ALIGNMENT_UNESTABLISHED")

    if (
        not _literal(left_role, ("NATIVE", "COORDINATOR"))
        or not _digest(left_runtime)
        or not _digest(right_runtime)
        or not _microseconds(start_us)
        or not _microseconds(end_us)
        or start_us > end_us
    ):
        raise ClockEvidenceError("CLOCK_REQUEST_INVALID")

    # Exact types and bounded key lengths prevent subclass hooks and oversized
    # strings from reaching hashing, comparisons or canonical serialization.
    if type(evidence) is not dict or len(evidence) != len(_KEYS):
        raise ClockEvidenceError("CLOCK_EVIDENCE_INVALID")
    if any(type(key) is not str or len(key) > 32 for key in evidence):
        raise ClockEvidenceError("CLOCK_EVIDENCE_INVALID")
    if frozenset(evidence) != _KEYS:
        raise ClockEvidenceError("CLOCK_EVIDENCE_INVALID")
    if (
        type(evidence["schema"]) is not int
        or evidence["schema"] != 1
        or not _literal(evidence["record"], ("SUPPLIED_CLOCK_ALIGNMENT",))
        or not _literal(evidence["basis"], ("FIXTURE", "REVIEWED_OBSERVATION"))
        or not _literal(evidence["left_role"], ("NATIVE", "COORDINATOR"))
        or not _literal(evidence["bound_scope"], ("TOTAL_OFFSET_AND_DRIFT",))
        or any(not _digest(evidence[key]) for key in _DIGEST_KEYS)
        or not _microseconds(evidence["valid_from_us"])
        or not _microseconds(evidence["valid_until_us"])
        or not _microseconds(evidence["total_error_bound_us"])
        or evidence["valid_from_us"] > evidence["valid_until_us"]
    ):
        raise ClockEvidenceError("CLOCK_EVIDENCE_INVALID")
    if evidence["total_error_bound_us"] > _MAX_BOUND_US:
        raise ClockEvidenceError("CLOCK_ERROR_BOUND_EXCEEDED")
    if (
        evidence["left_role"] != left_role
        or evidence["left_runtime_sha256"] != left_runtime
        or evidence["right_runtime_sha256"] != right_runtime
    ):
        raise ClockEvidenceError("CLOCK_IDENTITY_MISMATCH")
    if (
        evidence["valid_from_us"] > start_us
        or evidence["valid_until_us"] < end_us
    ):
        raise ClockEvidenceError("CLOCK_INTERVAL_NOT_COVERED")

    canonical = json.dumps(
        evidence, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return {
        "status": "STRUCTURALLY_VALID_SUPPLIED_ALIGNMENT",
        "basis": evidence["basis"],
        "provenance": "SUPPLIED_UNVERIFIED",
        "total_error_bound_us": evidence["total_error_bound_us"],
        "valid_from_us": evidence["valid_from_us"],
        "valid_until_us": evidence["valid_until_us"],
        "supplied_evidence_sha256": hashlib.sha256(canonical).hexdigest(),
    }
