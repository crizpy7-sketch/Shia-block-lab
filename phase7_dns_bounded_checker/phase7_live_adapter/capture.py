"""Fixed direct-child capture inside a caller's already-running phase budget.

No sudo, shell, timeout process, alarm, provider activation, or network target.
The caller must provide actual external preemption; polling is not containment.
"""
from dataclasses import dataclass
import os
import selectors
import subprocess

PHASE_NS = 40_000_000_000
OUTPUT_CAP = 4096
COMMAND_NS = 1_000_000_000
CLEANUP_NS = 100_000_000
COMMANDS = {
    "VERSION": ("/usr/bin/chronyc", "--version"),
    "TRACKING": ("/usr/bin/chronyc", "-n", "-c", "-h", "/run/chrony/chronyd.sock", "tracking"),
    "SOURCES": ("/usr/bin/chronyc", "-n", "-c", "-h", "/run/chrony/chronyd.sock", "sources"),
}
ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}


class CollectionError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def need(condition, code):
    if not condition:
        raise CollectionError(code)


def exact_ns(value):
    return type(value) is int and 0 <= value < 2**63


class Budget:
    """Observe the original owner's fields without creating or renewing it."""
    def __init__(self, owner, clock):
        self.owner, self.clock = owner, clock
        self.started_ns, self.deadline_ns = owner.started_ns, owner.deadline_ns
        need(exact_ns(self.started_ns) and exact_ns(self.deadline_ns)
             and self.deadline_ns - self.started_ns == PHASE_NS, "OWNER_INVALID")
        self.previous = self.started_ns
        self.check()

    def check(self):
        need(type(self.owner.started_ns) is int and type(self.owner.deadline_ns) is int
             and self.owner.started_ns == self.started_ns
             and self.owner.deadline_ns == self.deadline_ns, "OWNER_CHANGED")
        now = self.clock.monotonic_ns()
        need(exact_ns(now) and now >= self.previous, "MONOTONIC_INVALID")
        self.previous = now
        need(now < self.deadline_ns, "PHASE_DEADLINE")
        return now


@dataclass(frozen=True, repr=False)
class CaptureResult:
    meta: dict
    stdout: bytes

    def __repr__(self):
        return "<CaptureResult private provider bytes>"


def capture(kind, *, owner, clock, required_reserve_ns):
    """Read one fixed command; every wait is capped by the original deadline.

Direct-child kill/reaping is best effort within remaining time. No statement
about other processes or privileged descendants follows from pipe EOF.
"""
    need(type(kind) is str and kind in COMMANDS, "COMMAND_REFUSED")
    budget = Budget(owner, clock)
    need(exact_ns(required_reserve_ns) and required_reserve_ns < PHASE_NS,
         "RESERVE_INVALID")
    started = budget.check()
    operation_ns = COMMAND_NS
    need(budget.deadline_ns - started > required_reserve_ns + operation_ns,
         "COLLECTION_RESERVE")
    limit = min(budget.deadline_ns - required_reserve_ns, started + operation_ns)
    read_limit = limit - CLEANUP_NS
    child = selector = None
    buffers, counts = [bytearray(), bytearray()], [0, 0]
    capped = eof = reaped = killed = False
    closed, code, exitcode, finished = True, "OK", None, started

    def remaining():
        now = budget.check()
        need(now < read_limit, "COMMAND_DEADLINE")
        return (read_limit - now) / 10**9

    try:
        remaining()
        child = subprocess.Popen(COMMANDS[kind], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
            env=dict(ENV), close_fds=True, start_new_session=False)
        remaining()
        selector = selectors.DefaultSelector()
        for index, pipe in enumerate((child.stdout, child.stderr)):
            need(pipe is not None, "PIPE_UNAVAILABLE")
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, index)
        while True:
            wait = min(0.02, remaining())
            if not selector.get_map():
                eof = True
                if child.poll() is not None:
                    exitcode = child.wait(timeout=0)
                    reaped = type(exitcode) is int
                    break
                try:
                    exitcode = child.wait(timeout=wait)
                    reaped = type(exitcode) is int
                    break
                except subprocess.TimeoutExpired:
                    continue
            for key, _ in selector.select(wait):
                remaining()
                try:
                    chunk = os.read(key.fd, 1024)
                except (BlockingIOError, InterruptedError):
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                counts[key.data] = min(OUTPUT_CAP + 1, counts[key.data] + len(chunk))
                if sum(len(v) for v in buffers) + len(chunk) > OUTPUT_CAP:
                    capped = True
                    buffers = [bytearray(), bytearray()]
                    raise CollectionError("OUTPUT_CAP")
                buffers[key.data].extend(chunk)
        remaining()
        need(exitcode == 0, "COMMAND_FAILED")
        need(not buffers[1], "STDERR_PRESENT")
    except CollectionError as error:
        code = error.code
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
                        child.kill()  # Our direct handle only, never a cleanup attestation.
                        killed = True
                    available = max(0, min(limit, budget.deadline_ns) - budget.check())
                    exitcode = child.wait(timeout=min(CLEANUP_NS / 10**9, available / 10**9))
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
        try:
            finished = budget.check()
            if finished >= limit:
                code = "COMMAND_CLOSURE_DEADLINE"
        except Exception:
            finished = None
            code = "PHASE_OR_CLOCK_FAILED"
    if not (reaped and closed):
        code = "DIRECT_RESOURCE_CLOSURE_UNPROVEN"
    meta = {
        "code": code, "returncode": exitcode if type(exitcode) is int else None,
        "stdout_bytes": counts[0], "stderr_bytes": counts[1],
        "bytecounts_exact": not capped and eof,
        "direct_child_reaped": reaped, "parent_pipes_closed": closed,
        "pipe_eof_observed": eof, "descendant_cleanup_proven": False,
        "containment_uncertain": True,
        "started_monotonic_ns": started, "finished_monotonic_ns": finished,
    }
    return CaptureResult(meta, bytes(buffers[0]) if code == "OK" else b"")
