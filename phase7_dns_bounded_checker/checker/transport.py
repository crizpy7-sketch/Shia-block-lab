"""Prepared fixed-destination transport. Import has no external side effects.

Not execution authority. A separately authorized entrypoint owns one 40-second
main-thread Unix alarm, and invokes only its contract's finite operation plan.
"""
import errno
import math
import signal
import socket
import ssl
import time

from checker.response import (BODY_CAP, HEADER_CAP, TOTAL_CAP, ERROR_CODES as PARSE_CODES,
                              ParseError, parse_response, scan_markers)
from checker.resolver_owner import resolve_owned

HOST = 'michel-pr20-377eb54-2-24-81-191.sslip.io'
IP = '2.24.81.191'
HTTPS_PATHS = ('/', '/asset.js', '/api/example', '/api/ready', '/authelia/')
PRIVATE_PORTS = (43120, 43121, 9091)
PHASE_SECONDS = 40.0
OP_SECONDS = 3.0
MAX_CONNECTIONS = 10
ERROR_CODES = frozenset({
    'DNS_MISMATCH', 'DNS_TIMEOUT', 'DNS_ERROR', 'DNS_REQUIRED', 'PHASE_TIMEOUT',
    'OP_TIMEOUT', 'TLS_ERROR', 'CONNECTION_REFUSED', 'NETWORK_UNREACHABLE',
    'NETWORK_ERROR', 'PEER_MISMATCH', 'REQUEST_LIMIT', 'REQUEST_INVALID',
    'ALARM_UNAVAILABLE', 'INTERNAL_ERROR', 'DNS_CHILD_UNCLOSED',
    'DNS_PROTOCOL_ERROR', 'DNS_OWNER_UNAVAILABLE', 'DNS_CANCELLED',
}) | frozenset('PARSE_' + code for code in PARSE_CODES)


class DeadlineError(TimeoutError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in (
            'PHASE_TIMEOUT', 'OP_TIMEOUT', 'ALARM_UNAVAILABLE') else 'ALARM_UNAVAILABLE'
        super().__init__(self.code)


class PhaseDeadline:
    """Exclusive SIGALRM owner: one 40s phase, nested 3s operation deadlines.

    The immutable nanosecond interval begins before signal setup. Setup,
    collection, transport and restoration all spend that original interval.
    No timer is borrowed and no deadline is renewed. Unix/Python signal delivery
    still requires real qualification, not inference from this source.
    """
    def __init__(self):
        self.active = False
        self.used = False
        self._bounds = None
        self._operation_deadline_ns = None
        self._last_ns = None
        self._failure_code = None
        self._handler_attempted = False
        self._timer_attempted = False
        self._closed = False
        self._restored = False
        self.previous_handler = None
        self.transport_claimed = False

    @property
    def started_ns(self):
        return None if self._bounds is None else self._bounds[0]

    @property
    def deadline_ns(self):
        return None if self._bounds is None else self._bounds[1]

    @property
    def deadline(self):
        return None if self._bounds is None else _seconds_at_most(self.deadline_ns)

    @property
    def operation_deadline_ns(self):
        return self._operation_deadline_ns

    @property
    def operation_deadline(self):
        value = self._operation_deadline_ns
        return None if value is None else _seconds_at_most(value)

    def _fail(self, code):
        # A caught phase alarm cannot turn into permission for more work.
        if self._failure_code is None or code == 'PHASE_TIMEOUT':
            self._failure_code = code
        raise DeadlineError(self._failure_code)

    def _now_ns(self):
        try:
            now = time.monotonic_ns()
        except (ValueError, OSError, AttributeError):
            self._fail('ALARM_UNAVAILABLE')
        if type(now) is not int or now < 0 or (self._last_ns is not None and now < self._last_ns):
            self._fail('ALARM_UNAVAILABLE')
        self._last_ns = now
        return now

    def _remaining_ns(self):
        if self._failure_code is not None:
            raise DeadlineError(self._failure_code)
        now = self._now_ns()
        if self.deadline_ns is None:
            self._fail('ALARM_UNAVAILABLE')
        if now >= self.deadline_ns:
            self._fail('PHASE_TIMEOUT')
        limit = self._operation_deadline_ns
        if limit is not None and now >= limit:
            # An ordinary operation timeout does not renew or consume the
            # remaining phase, and is not a sticky phase failure.
            raise DeadlineError('OP_TIMEOUT')
        return min(self.deadline_ns, self.deadline_ns if limit is None else limit) - now

    def _arm_original_bound(self):
        remaining_ns = self._remaining_ns()
        # Set before the syscall: a failing arm may have partially taken effect.
        self._timer_attempted = True
        try:
            signal.setitimer(signal.ITIMER_REAL, _seconds_at_most(remaining_ns))
        except BaseException as failure:
            if isinstance(failure, DeadlineError):
                raise
            if self._failure_code is None:
                self._failure_code = 'ALARM_UNAVAILABLE'
            if isinstance(failure, (ValueError, OSError, AttributeError)):
                raise DeadlineError('ALARM_UNAVAILABLE') from None
            raise
        self._remaining_ns()

    def _restore(self):
        if self._closed:
            return self._restored
        failed = False
        if self._timer_attempted:
            try:
                signal.setitimer(signal.ITIMER_REAL, 0.0)
            except BaseException:
                failed = True
        # Restoration is attempted even if disarming failed, or installation
        # raised before active became true. An existing foreign timer is never
        # disarmed: _timer_attempted is set only after both zero-timer checks.
        if self._handler_attempted:
            try:
                signal.signal(signal.SIGALRM, self.previous_handler)
            except BaseException:
                failed = True
        self.active = False
        self._operation_deadline_ns = None
        self._closed = True
        self._restored = not failed
        if failed and self._failure_code is None:
            self._failure_code = 'ALARM_UNAVAILABLE'
        return not failed

    def _alarm(self, _signum, _frame):
        now = self._now_ns()
        if self.deadline_ns is not None and now >= self.deadline_ns:
            self._fail('PHASE_TIMEOUT')
        if self._operation_deadline_ns is not None:
            raise DeadlineError('OP_TIMEOUT')
        # A premature/unexpected alarm while the phase owns SIGALRM must not
        # disappear if a collector catches its exception.
        self._fail('ALARM_UNAVAILABLE')

    def __enter__(self):
        if self.used or self._bounds is not None or self._closed:
            raise DeadlineError('ALARM_UNAVAILABLE')
        self.used = True
        try:
            started = self._now_ns()
            self._bounds = (started, started + 40_000_000_000)
            if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
                self._fail('ALARM_UNAVAILABLE')
            self.previous_handler = signal.getsignal(signal.SIGALRM)
            # signal.signal itself refuses non-main-thread use.
            self._handler_attempted = True
            signal.signal(signal.SIGALRM, self._alarm)
            if signal.getitimer(signal.ITIMER_REAL) != (0.0, 0.0):
                self._fail('ALARM_UNAVAILABLE')
            self.active = True
            self._arm_original_bound()
            return self
        except BaseException as failure:
            if self._failure_code is None:
                self._failure_code = 'ALARM_UNAVAILABLE'
            self._restore()
            if isinstance(failure, (ValueError, OSError, AttributeError)) and not isinstance(failure, DeadlineError):
                raise DeadlineError('ALARM_UNAVAILABLE') from None
            raise

    def __exit__(self, exc_type, _exc, _traceback):
        restored = self._restore()
        # Never replace an existing exception during restoration.
        if exc_type is not None:
            if self._failure_code is None:
                self._failure_code = 'ALARM_UNAVAILABLE'
            return False
        if not restored:
            self._fail('ALARM_UNAVAILABLE')
        self.check_closed()
        return False

    def check_closed(self):
        """Check restoration and the original cutoff without rearming or renewal."""
        if not self.used or not self._closed or self.active or not self._restored:
            self._fail('ALARM_UNAVAILABLE')
        self._remaining_ns()

    def remaining(self):
        if not self.active:
            raise DeadlineError('ALARM_UNAVAILABLE')
        return _seconds_at_most(self._remaining_ns())

    def operation(self):
        return _OperationDeadline(self)


def _seconds_at_most(value_ns):
    """Project an integer bound downward, never later than its exact ns value."""
    seconds = value_ns / 1_000_000_000
    numerator, denominator = seconds.as_integer_ratio()
    if numerator * 1_000_000_000 > value_ns * denominator:
        seconds = math.nextafter(seconds, -math.inf)
    return seconds


class _OperationDeadline:
    def __init__(self, owner):
        self.owner = owner
        self.used = False

    def __enter__(self):
        owner = self.owner
        if self.used:
            raise DeadlineError('ALARM_UNAVAILABLE')
        self.used = True
        owner.remaining()
        if owner.operation_deadline_ns is not None:
            raise DeadlineError('ALARM_UNAVAILABLE')
        owner._operation_deadline_ns = min(owner.deadline_ns, owner._now_ns() + 3_000_000_000)
        try:
            owner._arm_original_bound()
        except BaseException:
            owner._operation_deadline_ns = None
            if owner._failure_code is None:
                try:
                    owner._arm_original_bound()
                except BaseException:
                    if owner._failure_code is None:
                        owner._failure_code = 'ALARM_UNAVAILABLE'
            raise
        return owner

    def __exit__(self, exc_type, _exc, _traceback):
        owner = self.owner
        restoration_error = None
        expired_operation = False
        try:
            expired_operation = owner._now_ns() >= owner.operation_deadline_ns
            owner._operation_deadline_ns = None
            # This uses the original phase cutoff and includes rearming time.
            # An already expired phase is latched, never given a new allowance.
            owner._arm_original_bound()
        except BaseException as failure:
            owner._operation_deadline_ns = None
            restoration_error = failure
            if not isinstance(failure, DeadlineError) and owner._failure_code is None:
                owner._failure_code = 'ALARM_UNAVAILABLE'
        if exc_type is None:
            if restoration_error is not None:
                raise restoration_error
            if expired_operation:
                raise DeadlineError('OP_TIMEOUT')
        return False


class FixedTransport:
    """One DNS attempt; once-only fixed operations; no retries or redirects."""
    def __init__(self, owner):
        if type(owner) is not PhaseDeadline:
            raise DeadlineError('ALARM_UNAVAILABLE')
        if not owner.active or owner.transport_claimed:
            raise DeadlineError('ALARM_UNAVAILABLE')
        owner.transport_claimed = True
        self.owner = owner
        self.dns_used = False
        self.dns_ok = False
        self.used = set()
        self.connections = 0

    @staticmethod
    def _record(kind, path, port, accept, start, error=None, response=None, markers=None):
        elapsed = time.monotonic() - start
        if not math.isfinite(elapsed) or elapsed < 0:
            duration, error = 0, 'INTERNAL_ERROR'
        else:
            duration = round(elapsed * 1000)
        if error is not None and (type(error) is not str or error not in ERROR_CODES):
            error = 'INTERNAL_ERROR'
        return {'kind': kind, 'path': path, 'port': port, 'accept': accept,
                'error': error, 'response': response,
                'markers': [False] * 4 if markers is None else list(markers),
                'duration_ms': duration}

    def resolve(self):
        start = time.monotonic()
        if self.dns_used:
            return self._record('DNS', None, 0, 'NONE', start, 'REQUEST_LIMIT')
        self.dns_used = True
        error = None
        try:
            with self.owner.operation():
                # Includes spawn, lookup and disposal in the original budget.
                error = resolve_owned(min(self.owner.operation_deadline, start + OP_SECONDS))
                self.owner.remaining()
        except DeadlineError as failure:
            if error != 'DNS_CHILD_UNCLOSED':
                error = 'DNS_TIMEOUT' if failure.code == 'OP_TIMEOUT' else failure.code
        except (socket.gaierror, OSError):
            if error != 'DNS_CHILD_UNCLOSED':
                error = 'DNS_ERROR'
        # A resolver return followed by deadline expiry is not DNS approval.
        record = self._record('DNS', None, 0, 'NONE', start, error)
        if record['error'] is None and record['duration_ms'] >= 3000:
            record['error'] = 'DNS_TIMEOUT'
        self.dns_ok = record['error'] is None
        return record

    def _reserve(self, key):
        if key in self.used or self.connections >= MAX_CONNECTIONS:
            return 'REQUEST_LIMIT'
        self.used.add(key)
        self.connections += 1
        if not self.dns_ok:
            return 'DNS_REQUIRED'
        return None

    def _socket(self, port):
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            connection.settimeout(self.owner.remaining())
            connection.connect((IP, port))
            self.owner.remaining()
            peer = connection.getpeername()
            if peer[0] != IP or peer[1] != port:
                connection.close()
                raise _PeerError()
            return connection
        except BaseException:
            connection.close()
            raise

    @staticmethod
    def _network_error(failure):
        if isinstance(failure, DeadlineError):
            return failure.code
        if isinstance(failure, (socket.timeout, TimeoutError)):
            return 'OP_TIMEOUT'
        if isinstance(failure, ssl.SSLError):
            return 'TLS_ERROR'
        if isinstance(failure, _PeerError):
            return 'PEER_MISMATCH'
        if isinstance(failure, OSError):
            if failure.errno == errno.ECONNREFUSED:
                return 'CONNECTION_REFUSED'
            if failure.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN, errno.EHOSTDOWN):
                return 'NETWORK_UNREACHABLE'
        return 'NETWORK_ERROR'

    def tcp(self, port):
        start = time.monotonic()
        if type(port) is not int or port not in PRIVATE_PORTS + (443,):
            return self._record('TCP', None, 0, 'NONE', start, 'REQUEST_INVALID')
        error = self._reserve(('TCP', port))
        if error is None:
            try:
                with self.owner.operation():
                    with self._socket(port):
                        self.owner.remaining()
            except (DeadlineError, OSError, _PeerError) as failure:
                error = self._network_error(failure)
        return self._record('TCP', None, port, 'NONE', start, error)

    def https(self, path, accept='JSON'):
        if type(path) is not str or path not in HTTPS_PATHS or type(accept) is not str or not (
                (accept == 'JSON' and path in HTTPS_PATHS[:4]) or
                (accept == 'HTML' and path in ('/', '/authelia/'))):
            return self._record('HTTPS', None, 443, 'NONE', time.monotonic(), 'REQUEST_INVALID')
        return self._request('HTTPS', path, 443, accept)

    def http(self):
        return self._request('HTTP', '/api/ready', 80, 'JSON')

    def _request(self, kind, path, port, accept):
        start = time.monotonic()
        error = self._reserve((kind, path, accept))
        raw = bytearray()
        response = None
        if error is None:
            try:
                with self.owner.operation():
                    if kind == 'HTTPS':
                        # Explicit context does not consume SSLKEYLOGFILE as
                        # create_default_context may; no environment access.
                        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        context.check_hostname = True
                        context.verify_mode = ssl.CERT_REQUIRED
                        context.minimum_version = ssl.TLSVersion.TLSv1_2
                        context.load_default_certs()
                        self.owner.remaining()
                        with self._socket(port) as connection:
                            connection.settimeout(self.owner.remaining())
                            with context.wrap_socket(connection, server_hostname=HOST,
                                                     do_handshake_on_connect=False,
                                                     suppress_ragged_eofs=False) as secured:
                                secured.settimeout(self.owner.remaining())
                                secured.do_handshake()
                                self.owner.remaining()
                                if secured.getpeername() != (IP, port):
                                    raise _PeerError()
                                response = self._exchange(secured, path, accept, raw)
                    else:
                        with self._socket(port) as connection:
                            response = self._exchange(connection, path, accept, raw)
            except ParseError as failure:
                error = 'PARSE_' + failure.code
            except (DeadlineError, OSError, _PeerError) as failure:
                error = self._network_error(failure)
        markers = scan_markers(bytes(raw))
        # No success payload survives an expired/failed operation, but observed
        # positive markers remain even if later framing/TLS/EOF fails.
        if error is not None:
            response = None
        return self._record(kind, path, port, accept, start, error, response, markers)

    def _exchange(self, connection, path, accept, raw):
        chosen_accept = 'application/json' if accept == 'JSON' else 'text/html'
        request = ('GET ' + path + ' HTTP/1.1\r\nHost: ' + HOST +
                   '\r\nAccept: ' + chosen_accept + '\r\nCache-Control: no-cache'
                   '\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n').encode('ascii')
        connection.settimeout(self.owner.remaining())
        connection.sendall(request)
        self.owner.remaining()
        header_end = None
        # At least one byte per non-EOF read; allocation bounded independently
        # from time. Header/body limits are checked before extending raw.
        for _ in range(TOTAL_CAP + 1):
            capacity = (HEADER_CAP + 1 if header_end is None else
                        header_end + BODY_CAP + 1) - len(raw)
            if capacity <= 0:
                raise ParseError('HEADER_CAP' if header_end is None else 'BODY_CAP')
            connection.settimeout(self.owner.remaining())
            chunk = connection.recv(min(4096, capacity))
            self.owner.remaining()
            if not chunk:
                return parse_response(bytes(raw), eof=True)
            if len(chunk) > capacity:
                raise ParseError('TOTAL_CAP')
            raw.extend(chunk)
            if header_end is None:
                index = raw.find(b'\r\n\r\n')
                if index >= 0:
                    header_end = index + 4
                    if header_end > HEADER_CAP:
                        raise ParseError('HEADER_CAP')
            try:
                parse_response(bytes(raw), eof=False)
            except ParseError as failure:
                if failure.code != 'INCOMPLETE_HEADER':
                    raise
            # Even a full Content-Length response must reach clean EOF within
            # this same operation deadline; this detects retained extra bytes.
        raise ParseError('TOTAL_CAP')


class _PeerError(OSError):
    pass
