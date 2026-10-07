"""Fixed existing-provider busctl executor; no CLI, service activation or gate authority."""

import os
import re
import selectors
import stat
import subprocess
import threading
import time


MAX_CAP = 16384
MAX_CALL_NS = 4_000_000_000
CLEANUP_RESERVE_NS = 500_000_000
MAX_MONOTONIC_NS = (1 << 63) - 1
READ_CHUNK = 4096
TOOL = "/usr/bin/busctl"
CALL_PREFIX = (
    TOOL, "--system", "--no-pager", "--auto-start=no",
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

# Public diagnostics are finite labels and counts, never child text or hashes.
# These observations do not verify service absence or establish clock alignment.
DIAGNOSTIC_CODES = frozenset((
    "OK", "ARGV_TYPE", "ARGV_GRAMMAR", "TOOL_OWNERSHIP", "TOOL_WRITABLE",
    "TOOL_PARENT_TYPE", "TOOL_PATH_CAP", "TOOL_ALIAS_CAP", "TOOL_ALIAS_TYPE",
    "TOOL_CHANGED", "TOOL_TYPE", "MONOTONIC_TYPE", "MONOTONIC_REVERSED",
    "PIPE_MISSING", "EXECUTOR_POISONED", "EXECUTOR_DEADLINE", "CHILD_STATUS_TYPE",
    "OUTPUT_CAP", "EXECUTOR_BUSY", "CAP_TYPE", "DEADLINE_TYPE", "DEADLINE_RANGE",
    "CHILD_NONZERO", "CHILD_STDERR", "EXECUTOR_FAILED", "CLIENT_CLEANUP_FAILED",
    "CLIENT_CLOSURE_UNPROVEN", "MONOTONIC_FAILED",
))
DIAGNOSTIC_PHASES = frozenset((
    "ENTRY", "VALIDATE", "TOOL_BIND", "SPAWN", "SUPERVISE", "CLEANUP", "FINAL_CHECK",
))
DIAGNOSTIC_STDERR_CLASSES = frozenset((
    "NOT_OBSERVED", "EMPTY", "UNCLASSIFIED",
    "TIMESYNC_NAME_HAS_NO_OWNER_REPORTED", "BUSCTL_SIGNATURE_ERROR_REPORTED",
))
_NO_OWNER_STDERR = (
    b"Call failed: Could not get owner of name 'org.freedesktop.timesync1': no such name\n"
)


def _diagnostic(code, phase, child_code, out, err, owner_query, client_closed):
    """Project complete supervised outputs without reflecting arbitrary bytes."""
    observed = (type(out) is bytes and type(err) is bytes
                and len(out) + len(err) <= MAX_CAP)
    stderr_class = "NOT_OBSERVED"
    if observed:
        stderr_class = "EMPTY" if not err else "UNCLASSIFIED"
        # Exact whole-message matching only. A textual report is not proof that
        # any service is absent; prefixes, suffixes and other targets do not match.
        if (type(child_code) is int and child_code != 0 and owner_query
                and not out and err == _NO_OWNER_STDERR):
            stderr_class = "TIMESYNC_NAME_HAS_NO_OWNER_REPORTED"
        elif (type(child_code) is int and child_code != 0 and not out
              and err in (b"Too few parameters for signature.\n",
                          b"Too many parameters for signature.\n")):
            stderr_class = "BUSCTL_SIGNATURE_ERROR_REPORTED"
    return {
        "schema": 1, "disposition": "DIAGNOSTIC_ONLY",
        "executor_code": code if type(code) is str and code in DIAGNOSTIC_CODES else "EXECUTOR_FAILED",
        "phase": phase if type(phase) is str and phase in DIAGNOSTIC_PHASES else "ENTRY",
        "child_returncode": child_code if type(child_code) is int and -(1 << 31) <= child_code < (1 << 31) else None,
        "stdout_bytes": len(out) if observed else None,
        "stderr_bytes": len(err) if observed else None,
        "stderr_class": stderr_class, "client_closed": client_closed is True,
    }


class _Failure(Exception):
    pass


def _require(condition, code):
    if not condition:
        raise _Failure(code)


def _validate_argv(argv):
    _require(type(argv) is tuple and len(argv) in (14, 15)
             and all(type(part) is str for part in argv), "ARGV_TYPE")
    _require(argv[:len(CALL_PREFIX)] == CALL_PREFIX, "ARGV_GRAMMAR")
    args = argv[len(CALL_PREFIX):]
    if args == OWNER_ARGS:
        return
    _require(len(args) == 7 and len(args[0]) <= 255
             and re.fullmatch(r":[0-9]+\.[0-9]+", args[0]) is not None
             and args[1:6] == PROPERTY_ARGS
             and args[6] in ("NTPMessage", "PollIntervalUSec"), "ARGV_GRAMMAR")


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _protected(info):
    _require(info.st_uid == 0, "TOOL_OWNERSHIP")
    _require(stat.S_ISLNK(info.st_mode) or not info.st_mode & 0o022, "TOOL_WRITABLE")


def _tool_identity():
    """Resolve every alias component while retaining protected-root node identities."""
    root = os.lstat("/")
    _protected(root)
    _require(stat.S_ISDIR(root.st_mode), "TOOL_PARENT_TYPE")
    nodes = [("/", _signature(root), None)]
    current = "/"
    pending = TOOL.split("/")[1:]
    links = 0
    steps = 0
    while pending:
        steps += 1
        _require(steps <= 128, "TOOL_PATH_CAP")
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            current = os.path.dirname(current)
            continue
        candidate = os.path.join(current, part)
        info = os.lstat(candidate)
        _protected(info)
        if stat.S_ISLNK(info.st_mode):
            links += 1
            _require(links <= 40, "TOOL_ALIAS_CAP")
            target = os.readlink(candidate)
            _require(type(target) is str and 0 < len(target) <= 4096 and "\0" not in target,
                     "TOOL_ALIAS_TYPE")
            _require(_signature(os.lstat(candidate)) == _signature(info), "TOOL_CHANGED")
            nodes.append((candidate, _signature(info), target))
            if target.startswith("/"):
                current = "/"
            pending = target.split("/") + pending
            continue
        nodes.append((candidate, _signature(info), None))
        if pending:
            _require(stat.S_ISDIR(info.st_mode), "TOOL_PARENT_TYPE")
        else:
            _require(stat.S_ISREG(info.st_mode) and bool(info.st_mode & 0o111), "TOOL_TYPE")
        current = candidate
    _require(current != "/" and nodes[-1][0] == current
             and stat.S_ISREG(nodes[-1][1][2]), "TOOL_TYPE")
    return tuple(nodes)


def _spawn(argv, env):
    return subprocess.Popen(
        argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=env, close_fds=True, shell=False, start_new_session=False,
    )


class BoundedExecutor:
    """Single owner, fixed command grammar; any failure permanently poisons reuse."""

    def __init__(self):
        self._lock = threading.Lock()
        self._poisoned = False
        self._active = None
        self._ownership_uncertain = False
        self._resource_uncertain = False
        self._selector = None
        self._identity = None
        self._last_ns = None
        self._last_diagnostic = None

    @property
    def last_diagnostic(self):
        """Snapshot of the last finished invocation; no raw child data is retained."""
        return None if self._last_diagnostic is None else dict(self._last_diagnostic)

    @property
    def poisoned(self):
        return self._poisoned

    @property
    def active(self):
        return self._active

    @property
    def client_closed(self):
        return (self._active is None and not self._ownership_uncertain
                and not self._resource_uncertain)

    @property
    def safe_to_continue(self):
        return not self._poisoned and self.client_closed

    def _now(self):
        value = time.monotonic_ns()
        _require(type(value) is int and 0 <= value <= MAX_MONOTONIC_NS, "MONOTONIC_TYPE")
        _require(self._last_ns is None or value >= self._last_ns, "MONOTONIC_REVERSED")
        self._last_ns = value
        return value

    def _failure_reply(self, code, cap, *, timed_out=False):
        safe_cap = cap if type(cap) is int and 1 <= cap <= MAX_CAP else MAX_CAP
        return {"returncode": -1, "output": b"", "error": code.encode("ascii")[:safe_cap],
                "timed_out": bool(timed_out), "client_reaped": bool(self.client_closed)}

    def _bind_tool(self):
        identity = _tool_identity()
        if self._identity is None:
            self._identity = identity
        _require(identity == self._identity, "TOOL_CHANGED")

    def _supervise(self, child, cap, work_deadline):
        out, err = bytearray(), bytearray()
        self._resource_uncertain = True
        self._selector = selectors.DefaultSelector()
        self._resource_uncertain = False
        for stream, name in ((child.stdout, "out"), (child.stderr, "err")):
            _require(stream is not None, "PIPE_MISSING")
            os.set_blocking(stream.fileno(), False)
            self._selector.register(stream, selectors.EVENT_READ, name)
        while True:
            _require(not self._poisoned, "EXECUTOR_POISONED")
            now = self._now()
            _require(now < work_deadline, "EXECUTOR_DEADLINE")
            interval = min(0.05, (work_deadline - now) / 1_000_000_000)
            if not self._selector.get_map():
                # Pipe EOF alone is not proof that the client has exited.
                try:
                    code = child.wait(timeout=interval)
                except subprocess.TimeoutExpired:
                    continue
                _require(type(code) is int and -(1 << 31) <= code < (1 << 31), "CHILD_STATUS_TYPE")
                _require(self._now() < work_deadline, "EXECUTOR_DEADLINE")
                return bytes(out), bytes(err), code
            events = self._selector.select(interval)
            _require(self._now() < work_deadline, "EXECUTOR_DEADLINE")
            for key, _mask in events:
                remaining = cap - len(out) - len(err)
                try:
                    chunk = os.read(key.fd, min(READ_CHUNK, remaining + 1))
                except (BlockingIOError, InterruptedError):
                    continue
                if not chunk:
                    self._selector.unregister(key.fileobj)
                    try:
                        key.fileobj.close()
                    except BaseException:
                        self._resource_uncertain = True
                        raise
                    continue
                _require(len(chunk) <= remaining, "OUTPUT_CAP")
                (out if key.data == "out" else err).extend(chunk)
            # A client exit does not imply EOF if an inherited pipe is held
            # elsewhere. Continue bounded draining; never claim descendant cleanup.
            code = child.poll()
            _require(code is None or (type(code) is int and -(1 << 31) <= code < (1 << 31)),
                     "CHILD_STATUS_TYPE")

    def _cleanup(self, deadline_ns):
        child = self._active
        reaped = child is None and not self._ownership_uncertain
        cleanup_ok = True
        if child is not None:
            # Ordinary cleanup stays inside the original budget. Already-late
            # construction/scheduling gets at most one separate 500 ms window.
            try:
                start = self._now()
                end = min(deadline_ns, start + CLEANUP_RESERVE_NS) if start < deadline_ns else start + CLEANUP_RESERVE_NS
            except BaseException:
                end = None
                cleanup_ok = False
            try:
                code = child.poll()
                known_exited = type(code) is int
            except BaseException:
                known_exited = False
                cleanup_ok = False
            if not known_exited:
                try:
                    child.kill()
                except ProcessLookupError:
                    pass
                except BaseException:
                    cleanup_ok = False
            try:
                remaining = 0.0 if end is None else max(0, end - self._now()) / 1_000_000_000
                code = child.wait(timeout=min(0.5, remaining))
                reaped = type(code) is int and -(1 << 31) <= code < (1 << 31)
                if not reaped:
                    cleanup_ok = False
            except BaseException:
                reaped = False
                cleanup_ok = False
        if self._selector is not None:
            try:
                self._selector.close()
                self._selector = None
            except BaseException:
                self._resource_uncertain = True
                cleanup_ok = False
        if child is not None:
            for name in ("stdin", "stdout", "stderr"):
                try:
                    stream = getattr(child, name, None)
                    if stream is not None and not stream.closed:
                        stream.close()
                except BaseException:
                    self._resource_uncertain = True
                    cleanup_ok = False
            if reaped and not self._resource_uncertain:
                self._active = None
        return cleanup_ok and reaped and self.client_closed

    def run(self, argv, *, deadline_ns, cap=MAX_CAP):
        if not self._lock.acquire(blocking=False):
            self._poisoned = True
            result = self._failure_reply("EXECUTOR_BUSY", cap)
            result["client_reaped"] = False
            self._last_diagnostic = _diagnostic(
                "EXECUTOR_BUSY", "ENTRY", None, None, None, False, False)
            return result
        if self._poisoned or not self.client_closed:
            result = self._failure_reply("EXECUTOR_POISONED", cap)
            self._last_diagnostic = _diagnostic(
                "EXECUTOR_POISONED", "ENTRY", None, None, None, False, self.client_closed)
            self._lock.release()
            return result
        failure = None
        timed_out = False
        remaining = None
        out, err, code = b"", b"", -1
        diagnostic_phase, diagnostic_child = "VALIDATE", None
        diagnostic_out, diagnostic_err, owner_query = None, None, False
        try:
            _validate_argv(argv)
            owner_query = argv == CALL_PREFIX + OWNER_ARGS
            _require(type(cap) is int and 1 <= cap <= MAX_CAP, "CAP_TYPE")
            _require(type(deadline_ns) is int and 0 < deadline_ns <= MAX_MONOTONIC_NS,
                     "DEADLINE_TYPE")
            self._last_ns = None
            remaining = deadline_ns - self._now()
            _require(CLEANUP_RESERVE_NS < remaining <= MAX_CALL_NS, "DEADLINE_RANGE")
            diagnostic_phase = "TOOL_BIND"
            self._bind_tool()
            _require(self._now() < deadline_ns - CLEANUP_RESERVE_NS, "EXECUTOR_DEADLINE")
            self._bind_tool()
            _require(not self._poisoned, "EXECUTOR_POISONED")
            _require(self._now() < deadline_ns - CLEANUP_RESERVE_NS, "EXECUTOR_DEADLINE")
            env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
            # If construction throws after creating a process, no returned
            # handle can prove ownership/closure. Preserve that uncertainty.
            self._ownership_uncertain = True
            diagnostic_phase = "SPAWN"
            self._active = _spawn(argv, env)
            self._ownership_uncertain = False
            diagnostic_phase = "SUPERVISE"
            out, err, code = self._supervise(self._active, cap, deadline_ns - CLEANUP_RESERVE_NS)
            diagnostic_out, diagnostic_err, diagnostic_child = out, err, code
            _require(code == 0, "CHILD_NONZERO")
            _require(not err, "CHILD_STDERR")
        except _Failure as error:
            failure = error.args[0]
            timed_out = (failure == "EXECUTOR_DEADLINE"
                         or (failure == "DEADLINE_RANGE" and remaining is not None
                             and remaining <= CLEANUP_RESERVE_NS))
        except BaseException:
            failure = "EXECUTOR_FAILED"
        finally:
            if self._active is not None or self._ownership_uncertain or self._selector is not None:
                if not self._cleanup(deadline_ns if type(deadline_ns) is int else 0):
                    if failure is None:
                        diagnostic_phase = "CLEANUP"
                    failure = "CLIENT_CLEANUP_FAILED" if self.client_closed else "CLIENT_CLOSURE_UNPROVEN"
            if failure is None:
                try:
                    diagnostic_phase = "FINAL_CHECK"
                    if self._now() >= deadline_ns:
                        failure, timed_out = "EXECUTOR_DEADLINE", True
                except BaseException:
                    failure = "MONOTONIC_FAILED"
            if failure is not None:
                self._poisoned = True
            self._last_diagnostic = _diagnostic(
                failure or "OK", diagnostic_phase, diagnostic_child, diagnostic_out,
                diagnostic_err, owner_query, self.client_closed)
            self._lock.release()
        if failure is not None:
            return self._failure_reply(failure, cap, timed_out=timed_out)
        return {"returncode": code, "output": out, "error": b"",
                "timed_out": False, "client_reaped": bool(self.client_closed)}
