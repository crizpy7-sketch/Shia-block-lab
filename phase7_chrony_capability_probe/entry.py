"""One fixed existing-chrony capability observation; no alignment or gate authority."""
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import time


WORKFLOW_REF = "crizpy7-sketch/Shia-block-lab/.github/workflows/phase7-chrony-capability.yml@refs/heads/main"
CHRONYC = "/usr/bin/chronyc"
TIMEOUT = "/usr/bin/timeout"
SUDO = "/usr/bin/sudo"
VERSION_ARGV = (TIMEOUT, "--signal=KILL", "2s", CHRONYC, "--version")
TRACKING_ARGV = (SUDO, "-n", "--", TIMEOUT, "--signal=TERM", "--kill-after=1s", "3s",
                 CHRONYC, "-n", "-c", "-h", "/run/chrony/chronyd.sock", "tracking")
OUTPUT_CAP = 4096
PUBLIC_CAP = 12288
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
LEAPS = {"Normal": "NORMAL", "Insert second": "INSERT_SECOND",
         "Delete second": "DELETE_SECOND", "Not synchronised": "NOT_SYNCHRONIZED",
         "Invalid": "INVALID"}


class Refusal(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refusal(code)


def association():
    approved = os.environ.get("PHASE7_APPROVED_COMMIT", "")
    require(re.fullmatch(r"[0-9a-f]{40}", approved) is not None, "APPROVED_COMMIT")
    fixed = {
        "GITHUB_REPOSITORY": "crizpy7-sketch/Shia-block-lab",
        "GITHUB_REPOSITORY_ID": "1316595124", "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": approved,
        "GITHUB_WORKFLOW_SHA": approved, "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
        "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "observe",
        "PHASE7_REPOSITORY_VISIBILITY": "public", "RUNNER_OS": "Linux", "RUNNER_ARCH": "X64",
    }
    require(all(os.environ.get(k) == v for k, v in fixed.items()), "JOB_ASSOCIATION")
    run = os.environ.get("GITHUB_RUN_ID", "")
    require(re.fullmatch(r"[1-9][0-9]{0,19}", run) is not None, "RUN_ID")
    return dict(fixed, GITHUB_RUN_ID=run)


def binary_identity(path):
    require(path in (CHRONYC, TIMEOUT, SUDO), "BINARY_PATH")
    identities = []
    for name in ("/", "/usr", "/usr/bin", path):
        try:
            value = os.lstat(name)
        except FileNotFoundError:
            raise Refusal("BINARY_UNAVAILABLE") from None
        except OSError:
            raise Refusal("BINARY_INSPECTION_FAILED") from None
        require(value.st_uid == 0 and not value.st_mode & 0o022, "BINARY_NOT_PROTECTED")
        require(stat.S_ISREG(value.st_mode) and value.st_mode & 0o111 if name == path
                else stat.S_ISDIR(value.st_mode), "BINARY_TYPE")
        identities.append((value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                           value.st_gid, value.st_size, value.st_mtime_ns, value.st_ctime_ns))
    return tuple(identities)


def parse_version(raw):
    require(type(raw) is bytes and 0 < len(raw) <= 512, "VERSION_FORMAT")
    # Only the finite numeric token is published; build/features text is dropped.
    match = re.fullmatch(rb"chronyc \(chrony\) version ([0-9]{1,3}\.[0-9]{1,3}(?:\.[0-9]{1,3})?"
                         rb"(?:-[A-Za-z0-9.+_-]{1,32})?) \([A-Za-z0-9+_ .-]{0,200}\)\n", raw)
    require(match is not None, "VERSION_FORMAT")
    return match.group(1).decode("ascii")


def _scaled(text, digits):
    # Chrony4.5 client.c emits fixed decimal fields, never exponent notation.
    require(re.fullmatch(r"-?(?:0|[1-9][0-9]{0,18})\." + r"[0-9]{" + str(digits) + r"}", text)
            is not None, "TRACKING_NUMBER")
    negative = text.startswith("-")
    whole, fraction = text.lstrip("-").split(".")
    value = int(whole) * (10 ** digits) + int(fraction)
    value = -value if negative else value
    require(-(1 << 63) < value < (1 << 63), "TRACKING_NUMBER_RANGE")
    return value


def parse_tracking(raw, version):
    require(type(raw) is bytes and 0 < len(raw) <= OUTPUT_CAP, "TRACKING_FORMAT")
    try:
        text = raw.decode("ascii", errors="strict")
    except UnicodeError:
        raise Refusal("TRACKING_FORMAT") from None
    require(text.endswith("\n") and text.count("\n") == 1 and "\r" not in text,
            "TRACKING_FORMAT")
    fields = text[:-1].split(",")
    require(len(fields) == 14 and re.fullmatch(r"[0-9A-F]{8}", fields[0]) is not None
            and 0 <= len(fields[1]) <= 255
            and all(32 <= ord(c) < 127 for c in fields[1]), "TRACKING_SHAPE")
    require(re.fullmatch(r"(?:0|[1-9][0-9]{0,4})", fields[2]) is not None
            and int(fields[2]) <= 65535, "TRACKING_STRATUM")
    require(fields[13] in LEAPS, "TRACKING_LEAP")
    names = ("reference_time_unix_ns", "system_correction_ns", "last_offset_ns", "rms_offset_ns",
             "frequency_milli_ppm", "residual_frequency_milli_ppm", "skew_milli_ppm",
             "root_delay_ns", "root_dispersion_ns", "update_interval_deciseconds")
    scales = (9, 9, 9, 9, 3, 3, 3, 9, 9, 1)
    numbers = dict(zip(names, (_scaled(value, scale) for value, scale in zip(fields[3:13], scales))))
    require(numbers["reference_time_unix_ns"] >= 0, "TRACKING_REFERENCE_TIME")
    # Every scaled integer stays lossless through JavaScript-based consumers.
    numbers = {name: str(value) for name, value in numbers.items()}
    return {
        "format": "CHRONYC_4_5_CSV_SHAPE", "source_contract_version_match": version == "4.5",
        "qualification": "FORMAT_ONLY_NOT_CLOCK_EVIDENCE", "leap_report": LEAPS[fields[13]],
        "stratum": int(fields[2]), "numbers": numbers,
        "source_identity_retained": False, "alignment_established": False,
    }


def capture(argv):
    """Bound parent memory/wait; inner root timeout contains the privileged command.

    Only direct Popen-child reaping and parent pipe closure are reported here.
    A timer's exit status cannot attest to every privileged descendant's cleanup.
    """
    require(argv in (VERSION_ARGV, TRACKING_ARGV), "COMMAND_NOT_ALLOWED")
    budget = 3_000_000_000 if argv == VERSION_ARGV else 6_000_000_000
    started = time.monotonic_ns()
    deadline, child, selector = started + budget, None, None
    output, error = bytearray(), bytearray()
    counts, capped, eof, code = [0, 0], False, False, "OK"
    reaped, closed, exitcode, killed = False, True, None, False
    try:
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=dict(ENV), close_fds=True,
                                 shell=False, start_new_session=False)
        selector = selectors.DefaultSelector()
        for index, pipe in enumerate((child.stdout, child.stderr)):
            require(pipe is not None, "PIPE_UNAVAILABLE")
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, index)
        while True:
            remaining = deadline - time.monotonic_ns()
            require(remaining > 0, "PARENT_DEADLINE")
            if not selector.get_map():
                eof = True
                status = child.poll()
                if status is not None:
                    exitcode = child.wait(timeout=0)
                    reaped = type(exitcode) is int
                    break
                try:
                    exitcode = child.wait(timeout=min(0.05, remaining / 1e9))
                    reaped = type(exitcode) is int
                    break
                except subprocess.TimeoutExpired:
                    continue
            for key, _ in selector.select(min(0.05, remaining / 1e9)):
                try:
                    chunk = os.read(key.fd, 1024)
                except (BlockingIOError, InterruptedError):
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                counts[key.data] = min(OUTPUT_CAP + 1, counts[key.data] + len(chunk))
                if capped or len(output) + len(error) + len(chunk) > OUTPUT_CAP:
                    capped = True
                    output.clear()
                    error.clear()
                else:
                    (output if key.data == 0 else error).extend(chunk)
        if capped:
            code = "OUTPUT_CAP"
        elif exitcode != 0:
            code = "COMMAND_TIMEOUT" if exitcode in (124, 137) else "COMMAND_FAILED"
        elif error:
            code = "STDERR_PRESENT"
        if time.monotonic_ns() >= deadline:
            code = "PARENT_DEADLINE"
    except Refusal as failure:
        code = failure.args[0]
    except Exception:
        code = "PROCESS_OR_CAPTURE_FAILED"
    finally:
        if selector is not None:
            try:
                selector.close()
            except Exception:
                closed = False
        if child is not None:
            if not reaped:
                try:
                    if child.poll() is None:
                        # This targets only our direct handle. It is never
                        # represented as proof a root-owned descendant died.
                        child.kill()
                        killed = True
                    exitcode = child.wait(timeout=0.5)
                    reaped = type(exitcode) is int
                except Exception:
                    reaped = False
            for pipe in (child.stdout, child.stderr):
                try:
                    if pipe is not None and not pipe.closed:
                        pipe.close()
                except Exception:
                    closed = False
        else:
            closed = False
    if not (reaped and closed):
        code = "PARENT_RESOURCE_CLOSURE_UNPROVEN"
    containment_uncertain = (not reaped or not closed or killed or not eof or exitcode in (124, 137)
                             or code in ("PARENT_DEADLINE", "PROCESS_OR_CAPTURE_FAILED"))
    try:
        finished = str(time.monotonic_ns())
    except Exception:
        # Preserve already-obtained resource evidence and the monitored-owner
        # requirement even when final timestamp collection itself fails.
        finished, code, containment_uncertain = None, "CLOCK_READ_FAILED", True
    public = {
        "code": code, "returncode": exitcode if type(exitcode) is int else None,
        "stdout_bytes": counts[0], "stderr_bytes": counts[1], "bytecounts_exact": not capped and eof,
        "direct_wrapper_reaped": reaped, "parent_pipes_closed": closed,
        "pipe_eof_observed": eof, "privileged_child_cleanup_proven": False,
        "containment_uncertain": containment_uncertain,
        "started_monotonic_ns": str(started), "finished_monotonic_ns": finished,
    }
    return public, bytes(output) if code == "OK" else b""


def observe():
    public = {
        "schema": 1, "record": "CHRONY_CAPABILITY_OBSERVATION", "status": "REFUSED",
        "code": "NOT_STARTED", "runtime_association": None, "approved_chronyc_available": None,
        "version": None, "version_probe": None,
        "tracking_probe": None, "tracking": None, "tracking_invocations_attempted": 0,
        "control_authority": "NONE", "phase7_acceptance": "BLOCKED",
        "alignment_established": False, "relative_alignment_established": False,
        "execution_authorized": False, "cleanup_proven": False,
    }
    try:
        public["runtime_association"] = association()
        public["approved_chronyc_available"] = False
        identity = binary_identity(CHRONYC)
        public["approved_chronyc_available"] = True
        timers = binary_identity(TIMEOUT)
        public["version_probe"], raw = capture(VERSION_ARGV)
        require(public["version_probe"]["code"] == "OK", "VERSION_PROBE_REFUSED")
        public["version"] = parse_version(raw)
        require(binary_identity(CHRONYC) == identity and binary_identity(TIMEOUT) == timers,
                "BINARY_CHANGED")
        binary_identity(SUDO)
        public["tracking_invocations_attempted"] = 1
        public["tracking_probe"], raw = capture(TRACKING_ARGV)
        require(public["tracking_probe"]["code"] == "OK", "TRACKING_PROBE_REFUSED")
        public["tracking"] = parse_tracking(raw, public["version"])
        public.update(status="OBSERVATION_COMPLETE", code="TRACKING_SHAPE_OBSERVED")
    except Refusal as failure:
        public["code"] = failure.args[0]
    except Exception:
        public["code"] = "OBSERVATION_FAILED"
    return public


def main():
    result = observe()
    raw = (json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("ascii")
    require(len(raw) <= PUBLIC_CAP, "PUBLIC_OUTPUT_CAP")
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()
    # An uncertain owner stays monitored by the externally required 20s timeout.
    # Its eventual group termination is containment, not a root-child receipt.
    if any(probe and probe["containment_uncertain"]
           for probe in (result["version_probe"], result["tracking_probe"])):
        while True:
            signal.pause()
    return 0 if result["status"] == "OBSERVATION_COMPLETE" else 2


if __name__ == "__main__":
    raise SystemExit(main())
