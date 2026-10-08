"""Bounded read-only Linux kernel clock-model observation; never gate evidence."""

import ctypes
import json
import platform
import sys
import time


MAX_DURATION_NS = 1_000_000_000
ROUNDING_TOLERANCE_NS = 1_000_000
MAX_OUTPUT_BYTES = 8192
MAX_SIGNED = (1 << 63) - 1
MIN_SIGNED = -(1 << 63)
MAX_MODEL_ERROR_US = 1_000_000_000_000
MAX_SCALED_PPM = 1_000_000 * 65536
STA_NANO = 0x2000
STA_UNSYNC = 0x0040
STA_CLOCKERR = 0x1000
KNOWN_STATUS_MASK = 0xFFFF
REJECT_STATUS_MASK = 0x0040 | 0x1000 | 0x0010 | 0x0020 | 0x0200 | 0x0400 | 0x0800

RAW_KEYS = (
    "state", "modes", "offset", "freq", "maxerror", "esterror", "status",
    "constant", "precision", "tolerance", "time_sec", "time_subsec", "tick",
    "ppsfreq", "jitter", "shift", "stabil", "jitcnt", "calcnt", "errcnt",
    "stbcnt", "tai",
)
ERROR_CODES = frozenset((
    "OK", "UNSUPPORTED_ABI", "LIBC_INTERFACE_UNAVAILABLE", "KERNEL_READ_FAILED",
    "CLOCK_READ_FAILED", "INVALID_CLOCK_VALUE", "INVALID_KERNEL_RECORD",
    "INVALID_KERNEL_VALUE", "NONZERO_MODES", "KERNEL_UNSYNCHRONIZED",
    "KERNEL_CLOCK_ERROR", "KERNEL_STATE_NOT_OK", "KERNEL_STATUS_REJECTED",
    "UNKNOWN_STATUS_BITS", "KERNEL_STATUS_CHANGED", "MONOTONIC_REVERSED",
    "REALTIME_REVERSED", "COLLECTION_DEADLINE_EXCEEDED",
    "KERNEL_TIME_OUTSIDE_BRACKET", "REALTIME_MONOTONIC_DIVERGENCE",
    "ARGUMENTS_NOT_ALLOWED", "OUTPUT_LIMIT_EXCEEDED", "INVALID_RESULT",
))


class ClockReadError(Exception):
    """Fixed diagnostic without exception text, paths, or environment content."""

    def __init__(self, code):
        self.code = code if type(code) is str and code in ERROR_CODES else "KERNEL_READ_FAILED"
        super().__init__(self.code)


class _Timeval(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_usec", ctypes.c_long)]


class _Timex(ctypes.Structure):
    _fields_ = [
        ("modes", ctypes.c_uint),
        ("offset", ctypes.c_long), ("freq", ctypes.c_long),
        ("maxerror", ctypes.c_long), ("esterror", ctypes.c_long),
        ("status", ctypes.c_int), ("constant", ctypes.c_long),
        ("precision", ctypes.c_long), ("tolerance", ctypes.c_long),
        ("time", _Timeval), ("tick", ctypes.c_long),
        ("ppsfreq", ctypes.c_long), ("jitter", ctypes.c_long),
        ("shift", ctypes.c_int), ("stabil", ctypes.c_long),
        ("jitcnt", ctypes.c_long), ("calcnt", ctypes.c_long),
        ("errcnt", ctypes.c_long), ("stbcnt", ctypes.c_long),
        ("tai", ctypes.c_int), ("reserved", ctypes.c_int * 11),
    ]


def _abi_supported():
    expected = {
        "modes": 0, "offset": 8, "freq": 16, "maxerror": 24, "esterror": 32,
        "status": 40, "constant": 48, "precision": 56, "tolerance": 64,
        "time": 72, "tick": 88, "ppsfreq": 96, "jitter": 104, "shift": 112,
        "stabil": 120, "jitcnt": 128, "calcnt": 136, "errcnt": 144,
        "stbcnt": 152, "tai": 160, "reserved": 164,
    }
    return (
        sys.platform == "linux" and platform.machine() == "x86_64"
        and sys.byteorder == "little"
        and ctypes.sizeof(ctypes.c_void_p) == 8
        and ctypes.sizeof(ctypes.c_long) == 8
        and ctypes.sizeof(ctypes.c_int) == 4
        and ctypes.sizeof(ctypes.c_uint) == 4
        and ctypes.sizeof(_Timeval) == 16
        and _Timeval.tv_sec.offset == 0 and _Timeval.tv_usec.offset == 8
        and ctypes.sizeof(_Timex) == 208 and ctypes.alignment(_Timex) == 8
        and all(getattr(_Timex, name).offset == offset for name, offset in expected.items())
    )


class NativeAdapter:
    """The only production kernel interface; modes cannot be supplied by callers."""

    def __init__(self):
        if not _abi_supported():
            raise ClockReadError("UNSUPPORTED_ABI")
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            # Presence of the GNU libc interface is checked without invoking it.
            getattr(libc, "gnu_get_libc_version")
            function = libc.adjtimex
            function.argtypes = [ctypes.POINTER(_Timex)]
            function.restype = ctypes.c_int
        except Exception:
            raise ClockReadError("LIBC_INTERFACE_UNAVAILABLE") from None
        self._libc = libc
        self._function = function

    def __call__(self):
        value = _Timex()  # All 208 bytes, including reserved storage, start at zero.
        value.modes = 0
        try:
            state = self._function(ctypes.byref(value))
        except Exception:
            raise ClockReadError("KERNEL_READ_FAILED") from None
        if type(state) is not int or state < 0:
            raise ClockReadError("KERNEL_READ_FAILED")
        result = {name: int(getattr(value, name)) for name in RAW_KEYS
                  if name not in ("state", "time_sec", "time_subsec")}
        result.update(state=state, time_sec=int(value.time.tv_sec),
                      time_subsec=int(value.time.tv_usec))
        return result


class SystemClock:
    monotonic_ns = staticmethod(time.monotonic_ns)
    time_ns = staticmethod(time.time_ns)


def _result(code, samples=()):
    return {
        "schema": 1,
        "record": "LOCAL_CLOCK_MODEL_OBSERVATION",
        "disposition": "OBSERVATION_ONLY",
        "status": "KERNEL_MODEL_OBSERVED" if code == "OK" else "REFUSED",
        "code": code,
        "interface": "LIBC_ADJTIMEX_MODES_ZERO",
        "provenance": "UNVERIFIED_LOCAL_OBSERVATION",
        "samples": list(samples),
        "collection_budget_ns": MAX_DURATION_NS,
        "rounding_tolerance_ns": ROUNDING_TOLERANCE_NS,
        "gate_action": "NONE",
        "phase7": "BLOCKED",
        "relative_alignment_established": False,
        "alignment_established": False,
        "execution_authorized": False,
        "cleanup_proven": False,
        "valid_through": None,
    }


def _clock_value(value):
    if type(value) is not int or not 0 <= value <= MAX_SIGNED:
        raise ClockReadError("INVALID_CLOCK_VALUE")
    return value


def _kernel_record(value):
    if type(value) is not dict or set(value) != set(RAW_KEYS):
        raise ClockReadError("INVALID_KERNEL_RECORD")
    if any(type(value[name]) is not int or not MIN_SIGNED <= value[name] <= MAX_SIGNED
           for name in RAW_KEYS):
        raise ClockReadError("INVALID_KERNEL_RECORD")
    raw = {name: value[name] for name in RAW_KEYS}
    if not (0 <= raw["state"] <= (1 << 31) - 1
            and 0 <= raw["modes"] <= (1 << 32) - 1
            and 0 <= raw["status"] <= (1 << 31) - 1):
        raise ClockReadError("INVALID_KERNEL_VALUE")
    if any(not 0 <= raw[name] <= MAX_MODEL_ERROR_US
           for name in ("maxerror", "esterror", "precision", "jitter")):
        raise ClockReadError("INVALID_KERNEL_VALUE")
    if not (0 <= raw["tolerance"] <= MAX_SCALED_PPM
            and -MAX_SCALED_PPM <= raw["freq"] <= MAX_SCALED_PPM
            and -MAX_SCALED_PPM <= raw["ppsfreq"] <= MAX_SCALED_PPM
            and 0 <= raw["stabil"] <= MAX_SCALED_PPM):
        raise ClockReadError("INVALID_KERNEL_VALUE")
    if any(raw[name] < 0 for name in ("constant", "tick", "shift", "jitcnt",
                                     "calcnt", "errcnt", "stbcnt", "tai", "time_sec")):
        raise ClockReadError("INVALID_KERNEL_VALUE")
    nano = bool(raw["status"] & STA_NANO)
    factor = 1 if nano else 1000
    if not 0 <= raw["time_subsec"] < (1_000_000_000 if nano else 1_000_000):
        raise ClockReadError("INVALID_KERNEL_VALUE")
    kernel_time = raw["time_sec"] * 1_000_000_000 + raw["time_subsec"] * factor
    offset = raw["offset"] * factor
    if not (0 <= kernel_time <= MAX_SIGNED and MIN_SIGNED <= offset <= MAX_SIGNED):
        raise ClockReadError("INVALID_KERNEL_VALUE")
    return {
        "kernel": raw,
        "offset_ns": offset,
        "kernel_realtime_ns": kernel_time,
        "kernel_fraction_unit": "NANOSECONDS" if nano else "MICROSECONDS",
        "reported_maxerror_ns": raw["maxerror"] * 1000,
        "reported_esterror_ns": raw["esterror"] * 1000,
        "reported_precision_ns": raw["precision"] * 1000,
        "kernel_unsynchronized": bool(raw["status"] & STA_UNSYNC),
        "kernel_clock_error": bool(raw["status"] & STA_CLOCKERR),
    }


def _interpret(samples):
    first, second = samples
    if second["monotonic_after_ns"] - first["monotonic_before_ns"] > MAX_DURATION_NS:
        return "COLLECTION_DEADLINE_EXCEEDED"
    if (first["monotonic_after_ns"] > second["monotonic_before_ns"]
            or any(s["monotonic_before_ns"] > s["monotonic_after_ns"] for s in samples)):
        return "MONOTONIC_REVERSED"
    if (first["realtime_after_ns"] > second["realtime_before_ns"]
            or any(s["realtime_before_ns"] > s["realtime_after_ns"] for s in samples)):
        return "REALTIME_REVERSED"
    for sample in samples:
        raw = sample["kernel"]
        if raw["modes"] != 0:
            return "NONZERO_MODES"
        if raw["status"] & ~KNOWN_STATUS_MASK:
            return "UNKNOWN_STATUS_BITS"
        if raw["status"] & STA_UNSYNC:
            return "KERNEL_UNSYNCHRONIZED"
        if raw["status"] & STA_CLOCKERR:
            return "KERNEL_CLOCK_ERROR"
        if raw["state"] != 0:
            return "KERNEL_STATE_NOT_OK"
        if raw["status"] & REJECT_STATUS_MASK:
            return "KERNEL_STATUS_REJECTED"
        resolution = 1 if raw["status"] & STA_NANO else 1000
        if not (sample["realtime_before_ns"] - resolution
                <= sample["kernel_realtime_ns"]
                <= sample["realtime_after_ns"] + resolution):
            return "KERNEL_TIME_OUTSIDE_BRACKET"
        wall_span = sample["realtime_after_ns"] - sample["realtime_before_ns"]
        mono_span = sample["monotonic_after_ns"] - sample["monotonic_before_ns"]
        if wall_span > mono_span + ROUNDING_TOLERANCE_NS:
            return "REALTIME_MONOTONIC_DIVERGENCE"
    if first["kernel"]["status"] != second["kernel"]["status"]:
        return "KERNEL_STATUS_CHANGED"
    intervals = [(s["realtime_before_ns"] - s["monotonic_after_ns"],
                  s["realtime_after_ns"] - s["monotonic_before_ns"]) for s in samples]
    if max(lo for lo, _ in intervals) > min(hi for _, hi in intervals) + ROUNDING_TOLERANCE_NS:
        return "REALTIME_MONOTONIC_DIVERGENCE"
    return "OK"


def collect(adapter, clock):
    """Observe two immediate reads through supplied dependencies; never certify truth."""
    samples = []
    for _ in range(2):
        try:
            m0 = _clock_value(clock.monotonic_ns())
            if samples:
                if m0 < samples[-1]["monotonic_after_ns"]:
                    return _result("MONOTONIC_REVERSED", samples)
                if m0 - samples[0]["monotonic_before_ns"] > MAX_DURATION_NS:
                    return _result("COLLECTION_DEADLINE_EXCEEDED", samples)
            w0 = _clock_value(clock.time_ns())
        except ClockReadError as error:
            return _result(error.code, samples)
        except Exception:
            return _result("CLOCK_READ_FAILED", samples)
        try:
            raw = adapter()
        except ClockReadError as error:
            return _result(error.code, samples)
        except Exception:
            return _result("KERNEL_READ_FAILED", samples)
        try:
            w1 = _clock_value(clock.time_ns())
            m1 = _clock_value(clock.monotonic_ns())
        except ClockReadError as error:
            return _result(error.code, samples)
        except Exception:
            return _result("CLOCK_READ_FAILED", samples)
        try:
            sample = _kernel_record(raw)
        except ClockReadError as error:
            return _result(error.code, samples)
        sample.update(monotonic_before_ns=m0, realtime_before_ns=w0,
                      realtime_after_ns=w1, monotonic_after_ns=m1)
        samples.append(sample)
        # A spent budget prevents beginning another kernel read. This is an
        # observed deadline, not preemption of a stalled function or scheduler.
        if m1 < m0:
            return _result("MONOTONIC_REVERSED", samples)
        if m1 - samples[0]["monotonic_before_ns"] > MAX_DURATION_NS:
            return _result("COLLECTION_DEADLINE_EXCEEDED", samples)
    return _result(_interpret(samples), samples)


def serialize(result):
    """Serialize collect's fixed schema; bound all emitted output, including errors."""
    template = _result("OK")
    invariant_keys = set(template) - {"status", "code", "samples"}
    if (type(result) is not dict or set(result) != set(template)
            or any(type(result[key]) is not type(template[key])
                   or result[key] != template[key] for key in invariant_keys)
            or type(result["code"]) is not str or result["code"] not in ERROR_CODES
            or type(result["status"]) is not str
            or result["status"] != ("KERNEL_MODEL_OBSERVED" if result["code"] == "OK" else "REFUSED")
            or type(result["samples"]) is not list or len(result["samples"]) > 2):
        result = _result("INVALID_RESULT")
    try:
        for sample in result["samples"]:
            if type(sample) is not dict or "kernel" not in sample:
                raise ClockReadError("INVALID_RESULT")
            expected = _kernel_record(sample["kernel"])
            for name in ("monotonic_before_ns", "realtime_before_ns",
                         "realtime_after_ns", "monotonic_after_ns"):
                expected[name] = _clock_value(sample[name])
            if (set(sample) != set(expected)
                    or any(type(sample[key]) is not type(expected[key])
                           or sample[key] != expected[key] for key in expected)):
                raise ClockReadError("INVALID_RESULT")
        if result["code"] == "OK" and (len(result["samples"]) != 2
                                         or _interpret(result["samples"]) != "OK"):
            raise ClockReadError("INVALID_RESULT")
    except Exception:
        result = _result("INVALID_RESULT")
    try:
        encoded = (json.dumps(result, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except Exception:
        encoded = (json.dumps(_result("INVALID_RESULT"), sort_keys=True,
                              separators=(",", ":")) + "\n").encode("ascii")
    if len(encoded) > MAX_OUTPUT_BYTES:
        encoded = (json.dumps(_result("OUTPUT_LIMIT_EXCEEDED"), sort_keys=True,
                              separators=(",", ":")) + "\n").encode("ascii")
    return encoded


encode_result = serialize


def collect_native():
    """Use the single fixed local interface and sanitize initialization failures."""
    try:
        return collect(NativeAdapter(), SystemClock())
    except ClockReadError as error:
        return _result(error.code)
    except Exception:
        return _result("KERNEL_READ_FAILED")


def main(argv=None):
    arguments = sys.argv[1:] if argv is None else argv
    if arguments:
        result = _result("ARGUMENTS_NOT_ALLOWED")
    else:
        result = collect_native()
    output = serialize(result)
    sys.stdout.buffer.write(output)
    return 0 if result["status"] == "KERNEL_MODEL_OBSERVED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
