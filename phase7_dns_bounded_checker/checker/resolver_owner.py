"""Linux-only owner for one fixed DNS child; importing never starts a child.

Acceptance requires EOF and waitpid proof inside the original operation budget.
The final 0.5s is reserved for SIGKILL and reaping, never additional lookup time.
OS scheduling can prevent timely cleanup: that remains DNS_CHILD_UNCLOSED, not
proof of closure. This module does not claim an unconditional realtime bound.
"""
import ctypes
import errno
import math
import os
from pathlib import Path
import select
import signal
import sys
import threading
import time

OUTPUT_CAP = 32
DISPOSAL_RESERVE = 0.5
POLL_SECONDS = 0.02
MAX_POLLS = 256
MAX_FDS = 256
MANAGED_SIGNALS = (signal.SIGALRM, signal.SIGINT, signal.SIGTERM)
CHILD_FILE = str(Path(__file__).resolve().with_name('resolver_child.py'))


def _descriptors():
    """Bounded snapshot; called with signals blocked and no other threads."""
    result = []
    with os.scandir('/proc/self/fd') as entries:
        for entry in entries:
            if len(result) >= MAX_FDS or not entry.name.isascii() or not entry.name.isdecimal():
                raise OSError('DNS_OWNER_UNAVAILABLE')
            descriptor = int(entry.name)
            if not 0 <= descriptor < 2**31:
                raise OSError('DNS_OWNER_UNAVAILABLE')
            result.append(descriptor)
    return tuple(result)


def _prepare_prctl():
    # Load libc before fork, not in a potentially interrupted child import.
    prctl = ctypes.CDLL(None, use_errno=True).prctl
    prctl.argtypes = (ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                     ctypes.c_ulong, ctypes.c_ulong)
    prctl.restype = ctypes.c_int
    return prctl


def _arm_parent_death(parent, prctl):
    # Parent may have died between fork and prctl; the second check closes that
    # race. Linux retains PDEATHSIG across this ordinary, non-setuid exec.
    if prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent:
        os._exit(126)


def _child_exec(parent, deadline):
    """Fixed production exec; mock only this seam for owned offline fixtures."""
    os.execve('/usr/bin/python3', ['/usr/bin/python3', '-I', '-S', '-B',
              CHILD_FILE, '--resolve-once', str(parent), repr(deadline)],
              {'LANG': 'C', 'LC_ALL': 'C'})


def _spawn(deadline):
    """Caller blocks managed signals until the returned PID is owned.

    There is no Popen constructor whose interrupted return could lose a PID.
    Fork/exec latency is counted and never renews the deadline.
    """
    parent = os.getpid()
    prctl = _prepare_prctl()
    read_fd = write_fd = null_fd = None
    try:
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        null_fd = os.open('/dev/null', os.O_RDWR | os.O_CLOEXEC)
        if min(read_fd, write_fd, null_fd) <= 2:
            raise OSError('DNS_OWNER_UNAVAILABLE')
        descriptors = _descriptors()
        if time.monotonic() >= deadline - DISPOSAL_RESERVE or any(
                item in signal.sigpending() for item in MANAGED_SIGNALS):
            raise OSError('DNS_OWNER_UNAVAILABLE')
        pid = os.fork()
        if pid == 0:
            try:
                _arm_parent_death(parent, prctl)
                os.setsid()
                os.dup2(null_fd, 0)
                os.dup2(write_fd, 1)
                os.dup2(null_fd, 2)
                for descriptor in descriptors:
                    if descriptor > 2:
                        try:
                            os.close(descriptor)
                        except OSError as failure:
                            # The snapshot's own directory FD is already shut.
                            # Every other failure aborts before exec below.
                            if failure.errno != errno.EBADF:
                                os._exit(126)
                for signum in MANAGED_SIGNALS:
                    signal.signal(signum, signal.SIG_DFL)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    os._exit(126)
                signal.setitimer(signal.ITIMER_REAL, remaining)
                signal.pthread_sigmask(signal.SIG_SETMASK, set())
                _child_exec(parent, deadline)
            except BaseException:
                pass
            os._exit(126)
        # A close failure must not turn into an exception which loses the PID.
        # Report it beside the PID so the owner disposes and refuses normally.
        setup_error = False
        for descriptor in (write_fd, null_fd):
            try:
                os.close(descriptor)
            except OSError:
                setup_error = True
        write_fd = null_fd = None
        # No raising Python handler can run until resolve_owned stores this PID.
        owned_read_fd = read_fd
        read_fd = None
        return pid, owned_read_fd, setup_error
    finally:
        for descriptor in (read_fd, write_fd, null_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _reap(pid):
    """(proved_closed, status, still_owned). ECHILD is not reaping evidence."""
    try:
        observed, status = os.waitpid(pid, os.WNOHANG)
    except OSError as failure:
        # With default SIGCHLD and one parent thread, only ECHILD removes our
        # claim. An interrupted/non-ECHILD wait must not abandon a live child.
        return False, None, failure.errno != errno.ECHILD
    if observed == pid:
        return True, status, False
    if observed == 0:
        return False, None, True
    return False, None, False


def _dispose(pid, deadline):
    """One kill, finite nonblocking reaping; no budget added on failure."""
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    for _ in range(MAX_POLLS):
        closed, status, owned = _reap(pid)
        if closed or not owned:
            return closed, status
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        select.select([], [], [], min(POLL_SECONDS, remaining))
    return False, None


def resolve_owned(deadline):
    """Return None or a fixed safe error; never return an address/child text.

    The caller supplies its already fixed monotonic deadline. No executable,
    hostname, environment, retries or arbitrary resolver result is caller input.
    """
    now = time.monotonic()
    if type(deadline) not in (int, float) or not math.isfinite(deadline):
        return 'DNS_OWNER_UNAVAILABLE'
    if deadline <= now:
        return 'DNS_TIMEOUT'
    if (sys.platform != 'linux' or threading.current_thread() is not threading.main_thread()
            or threading.active_count() != 1 or type(deadline) not in (int, float)
            or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
            or not 0 < deadline - now <= 3.0):
        return 'DNS_OWNER_UNAVAILABLE'
    pid = read_fd = old_mask = None
    old_handlers = {}
    closed, owned, status, eof = False, False, None, False
    cancellation = []
    output = bytearray()
    error = 'DNS_ERROR'

    def cancel(signum, _frame):
        # Do not interrupt ownership acquisition or disposal with an exception.
        # Only retain the first event, so repeated signals cannot grow memory.
        if not cancellation:
            cancellation.append(signum)

    try:
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
        if any(signum in old_mask for signum in MANAGED_SIGNALS):
            error = 'DNS_OWNER_UNAVAILABLE'
        else:
            for signum in MANAGED_SIGNALS:
                old_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, cancel)
            try:
                pid, read_fd, setup_error = _spawn(deadline)
            except OSError:
                error = 'DNS_OWNER_UNAVAILABLE'
                raise
            owned = True
            signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
            if setup_error:
                error = 'DNS_OWNER_UNAVAILABLE'
                raise OSError('DNS_OWNER_UNAVAILABLE')
            cutoff = deadline - DISPOSAL_RESERVE
            error = 'DNS_TIMEOUT'
            for _ in range(MAX_POLLS):
                if cancellation or time.monotonic() >= cutoff:
                    break
                try:
                    chunk = os.read(read_fd, OUTPUT_CAP + 1 - len(output))
                except BlockingIOError:
                    chunk = None
                if chunk == b'':
                    eof = True
                elif chunk is not None:
                    output.extend(chunk)
                    if len(output) > OUTPUT_CAP:
                        error = 'DNS_PROTOCOL_ERROR'
                        break
                if not closed:
                    closed, status, owned = _reap(pid)
                    if not closed and not owned:
                        error = 'DNS_CHILD_UNCLOSED'
                        break
                if closed and eof:
                    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
                        error = 'DNS_ERROR'
                    else:
                        error = {b'OK\n': None, b'MISMATCH\n': 'DNS_MISMATCH',
                                 b'ERROR\n': 'DNS_ERROR'}.get(bytes(output), 'DNS_PROTOCOL_ERROR')
                    break
                remaining = cutoff - time.monotonic()
                if remaining <= 0:
                    break
                # Empty read list after EOF prevents a permanently readable pipe
                # from busy-spinning while waiting for actual child exit.
                select.select([] if eof else [read_fd], [], [], min(POLL_SECONDS, remaining))
    except BaseException as failure:
        if isinstance(failure, (KeyboardInterrupt, SystemExit)):
            error = 'DNS_CANCELLED'
        elif error != 'DNS_OWNER_UNAVAILABLE':
            error = 'DNS_ERROR'
    finally:
        if pid is not None and not closed and owned:
            try:
                closed, status = _dispose(pid, deadline)
            except BaseException:
                closed = False
        if pid is not None and not closed:
            error = 'DNS_CHILD_UNCLOSED'
        if read_fd is not None:
            try:
                os.close(read_fd)
            except OSError:
                error = 'DNS_CHILD_UNCLOSED'
        # Restore after disposal, with managed signals blocked across all three
        # handler restorations. Pending interruption cannot lose a child handle.
        if old_mask is not None:
            try:
                signal.pthread_sigmask(signal.SIG_BLOCK, MANAGED_SIGNALS)
                for signum, handler in old_handlers.items():
                    signal.signal(signum, handler)
                signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
            except BaseException:
                error = 'DNS_CHILD_UNCLOSED' if pid is not None and not closed else 'DNS_OWNER_UNAVAILABLE'
    if error != 'DNS_CHILD_UNCLOSED':
        if cancellation:
            error = 'DNS_TIMEOUT' if cancellation[0] == signal.SIGALRM else 'DNS_CANCELLED'
        elif time.monotonic() >= deadline:
            error = 'DNS_TIMEOUT'
    return error
