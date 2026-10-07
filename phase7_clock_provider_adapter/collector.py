"""Injected existing-timesyncd reads; no production executor or alignment authority."""

from dataclasses import dataclass
import hashlib
import json
import re


TOTAL_BUDGET_NS = 10_000_000_000
CALL_BUDGET_NS = 4_000_000_000
RESPONSE_CAP = 16384
PUBLIC_CAP = 8192
MAX_MONOTONIC_NS = (1 << 63) - 1
UINT64_MAX = (1 << 64) - 1
CALL_PREFIX = (
    "/usr/bin/busctl", "--system", "--no-pager", "--auto-start=no",
    "--allow-interactive-authorization=no", "--timeout=3", "--json=short", "call",
)
OWNER_ARGS = (
    "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
    "GetNameOwner", "s", "org.freedesktop.timesync1",
)
PROPERTY_ARGS = (
    "/org/freedesktop/timesync1", "org.freedesktop.DBus.Properties", "Get", "ss",
    "org.freedesktop.timesync1.Manager",
)
PACKET_TYPE = "(uuuuittayttttbtt)"


@dataclass(frozen=True, repr=False)
class RetainedEvidence:
    owner_before_reply: bytes
    packet_before: bytes
    poll_before: bytes
    packet_after: bytes
    poll_after: bytes
    owner_after_reply: bytes
    owner_before: str
    owner_after: str
    runtime_sha256: str
    started_monotonic_ns: int
    finished_monotonic_ns: int
    call_brackets: tuple

    def __repr__(self):
        return "<RetainedEvidence private>"


@dataclass(frozen=True, repr=False)
class CollectionResult:
    public: dict
    private: object

    def __repr__(self):
        return "<CollectionResult private>"


class _Refusal(Exception):
    pass


def _require(condition, code):
    if not condition:
        raise _Refusal(code)


def _public(code, attempted, completed, evidence=None):
    return {
        "schema": 1,
        "record": "EXISTING_TIMESYNCD_COLLECTION",
        "disposition": "OBSERVATION_ONLY",
        "status": "EXISTING_PROVIDER_BYTES_STABLE" if code == "OK" else "REFUSED",
        "code": code,
        "provenance": "SUPPLIED_EXECUTOR_UNVERIFIED",
        "calls_attempted": attempted,
        "calls_completed": completed,
        "evidence": evidence,
        "total_budget_ns": TOTAL_BUDGET_NS,
        "call_budget_ns": CALL_BUDGET_NS,
        "response_cap_bytes": RESPONSE_CAP,
        "production_executor_verified": False,
        "kernel_synchronization_established": False,
        "missing_evidence": [
            "PRODUCTION_EXECUTOR_ENFORCEMENT", "ACTUAL_RUNTIME_BINDING",
            "SYNCHRONIZED_KERNEL_OBSERVATION", "UTC_COLLECTION_BRACKETS",
            "PACKET_DIAGNOSTIC", "CURRENT_POST_CORRECTION_RESIDUAL",
            "APPLICABLE_CONTINUITY_AND_RATE_POLICY", "RELATIVE_INTERVAL_COVERAGE",
        ],
        "control": "NONE", "gate_action": "NONE", "phase7": "BLOCKED",
        "alignment_established": False,
        "relative_alignment_established": False,
        "execution_authorized": False, "cleanup_proven": False,
        "valid_through": None,
    }


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "DUPLICATE_RESPONSE_KEY")
        result[key] = value
    return result


def _integer(text):
    _require(len(text.lstrip("-")) <= 20, "INTEGER_TOKEN_CAP")
    return int(text)


def _noninteger(_text):
    raise _Refusal("NONINTEGER_JSON_NUMBER")


def _json(raw):
    try:
        return json.loads(raw.decode("utf-8", errors="strict"),
                          object_pairs_hook=_unique, parse_int=_integer,
                          parse_float=_noninteger, parse_constant=_noninteger)
    except _Refusal:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise _Refusal("RESPONSE_FORMAT") from None


def _single(raw, kind):
    reply = _json(raw)
    _require(type(reply) is dict and set(reply) == {"type", "data"}
             and reply["type"] == kind and type(reply["data"]) is list
             and len(reply["data"]) == 1, "RESPONSE_SHAPE")
    return reply["data"][0]


def _owner(raw):
    value = _single(raw, "s")
    _require(type(value) is str and len(value) <= 255
             and re.fullmatch(r":[0-9]+\.[0-9]+", value) is not None,
             "PROVIDER_OWNER")
    return value


def _property(raw, kind):
    variant = _single(raw, "v")
    _require(type(variant) is dict and set(variant) == {"type", "data"}
             and variant["type"] == kind, "PROPERTY_TYPE")
    return variant["data"]


def _unsigned(value, bits):
    return type(value) is int and 0 <= value < (1 << bits)


def _packet(raw):
    value = _property(raw, PACKET_TYPE)
    _require(type(value) is list and len(value) == 15, "PACKET_SHAPE")
    for index in (0, 1, 2, 3, 5, 6, 8, 9, 10, 11, 13, 14):
        _require(_unsigned(value[index], 32 if index < 4 else 64), "PACKET_FIELD_TYPE")
    _require(type(value[4]) is int and -(1 << 31) <= value[4] < (1 << 31),
             "PRECISION_FIELD_TYPE")
    _require(type(value[7]) is list and len(value[7]) == 4
             and all(_unsigned(item, 8) for item in value[7]), "REFERENCE_SHAPE")
    _require(type(value[12]) is bool, "IGNORED_FIELD_TYPE")


def _poll(raw):
    value = _property(raw, "t")
    _require(type(value) is int and 0 < value <= UINT64_MAX, "POLL_INTERVAL_TYPE")


def _response(reply):
    _require(type(reply) is dict and set(reply) == {
        "returncode", "output", "error", "timed_out", "client_reaped",
    }, "EXECUTOR_REPLY_SHAPE")
    _require(type(reply["client_reaped"]) is bool and type(reply["timed_out"]) is bool,
             "EXECUTOR_REPLY_FLAG_TYPE")
    # A caller-supplied true flag is only an executor contract assertion. A
    # false assertion is still enough to prohibit any subsequent call.
    _require(reply["client_reaped"], "CLIENT_NOT_REAPED")
    _require(not reply["timed_out"], "EXECUTOR_TIMED_OUT")
    _require(type(reply["returncode"]) is int
             and -(1 << 31) <= reply["returncode"] < (1 << 31),
             "EXECUTOR_RETURN_CODE_TYPE")
    _require(type(reply["output"]) is bytes and type(reply["error"]) is bytes
             and len(reply["output"]) + len(reply["error"]) <= RESPONSE_CAP,
             "RESPONSE_CAP_OR_TYPE")
    _require(reply["returncode"] == 0, "PROVIDER_READ_FAILED")
    _require(not reply["error"], "STDERR_PRESENT")
    _require(bool(reply["output"]), "EMPTY_RESPONSE")
    return reply["output"]


class _Collection:
    def __init__(self, executor, monotonic_ns):
        self.executor = executor
        self.monotonic_ns = monotonic_ns
        self.attempted = 0
        self.completed = 0
        self.previous_ns = None
        self.started_ns = None
        self.deadline_ns = None
        self.brackets = []

    def read_clock(self):
        try:
            value = self.monotonic_ns()
        except Exception:
            raise _Refusal("MONOTONIC_READ_FAILED") from None
        _require(type(value) is int and 0 <= value <= MAX_MONOTONIC_NS,
                 "MONOTONIC_VALUE_TYPE")
        _require(self.previous_ns is None or value >= self.previous_ns,
                 "MONOTONIC_REVERSED")
        self.previous_ns = value
        return value

    def start(self):
        self.started_ns = self.read_clock()
        _require(self.started_ns <= MAX_MONOTONIC_NS - TOTAL_BUDGET_NS,
                 "MONOTONIC_RANGE")
        self.deadline_ns = self.started_ns + TOTAL_BUDGET_NS

    def call(self, args):
        before = self.read_clock()
        _require(before < self.deadline_ns, "COLLECTION_DEADLINE")
        deadline = min(self.deadline_ns, before + CALL_BUDGET_NS)
        self.attempted += 1
        try:
            reply = self.executor.run(CALL_PREFIX + args,
                                      deadline_ns=deadline, cap=RESPONSE_CAP)
        except Exception:
            raise _Refusal("EXECUTOR_FAILED") from None
        after = self.read_clock()
        _require(after < deadline, "CALL_DEADLINE")
        raw = _response(reply)
        self.completed += 1
        self.brackets.append((before, after, deadline))
        return raw


def _collect(state, runtime_sha256):
    _require(type(runtime_sha256) is str
             and re.fullmatch(r"[0-9a-f]{64}", runtime_sha256) is not None,
             "RUNTIME_BINDING")
    state.start()
    owner_before_reply = state.call(OWNER_ARGS)
    owner_before = _owner(owner_before_reply)
    packet_args = (owner_before,) + PROPERTY_ARGS + ("NTPMessage",)
    poll_args = (owner_before,) + PROPERTY_ARGS + ("PollIntervalUSec",)
    packet_before = state.call(packet_args)
    _packet(packet_before)
    poll_before = state.call(poll_args)
    _poll(poll_before)
    packet_after = state.call(packet_args)
    _packet(packet_after)
    _require(packet_before == packet_after, "PACKET_BYTES_CHANGED")
    poll_after = state.call(poll_args)
    _poll(poll_after)
    _require(poll_before == poll_after, "POLL_BYTES_CHANGED")
    owner_after_reply = state.call(OWNER_ARGS)
    owner_after = _owner(owner_after_reply)
    _require(owner_before == owner_after, "PROVIDER_CHANGED")
    retained = RetainedEvidence(
        owner_before_reply, packet_before, poll_before, packet_after, poll_after,
        owner_after_reply, owner_before, owner_after, runtime_sha256,
        state.started_ns, state.previous_ns, tuple(state.brackets),
    )
    evidence = {
        "runtime_sha256": runtime_sha256,
        "provider_owner_sha256": hashlib.sha256(owner_before.encode("ascii")).hexdigest(),
        "packet_sha256": hashlib.sha256(packet_before).hexdigest(),
        "poll_sha256": hashlib.sha256(poll_before).hexdigest(),
        "owner_before_reply_sha256": hashlib.sha256(owner_before_reply).hexdigest(),
        "owner_after_reply_sha256": hashlib.sha256(owner_after_reply).hexdigest(),
        "started_monotonic_ns": state.started_ns,
        "finished_monotonic_ns": state.previous_ns,
        "duration_ns": state.previous_ns - state.started_ns,
        "call_brackets": [dict(before_ns=before, after_ns=after, deadline_ns=deadline)
                          for before, after, deadline in state.brackets],
    }
    public = _public("OK", state.attempted, state.completed, evidence)
    _require(len(json.dumps(public, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True, allow_nan=False).encode("ascii")) + 1
             <= PUBLIC_CAP, "PUBLIC_RESULT_CAP")
    return CollectionResult(public, retained)


def collect(executor, monotonic_ns, *, runtime_sha256):
    """Call only injected dependencies, returning private bytes separately.

    No executor implementation or live clock default is supplied. A blocking or
    dishonest injected executor is not contained by this observer; production
    bounds and process cleanup require a separately reviewed owner/executor.
    """
    state = _Collection(executor, monotonic_ns)
    try:
        return _collect(state, runtime_sha256)
    except _Refusal as error:
        code = error.args[0]
    except Exception:
        code = "COLLECTION_FAILED"
    return CollectionResult(_public(code, state.attempted, state.completed), None)
