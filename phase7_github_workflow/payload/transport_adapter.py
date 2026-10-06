"""Finite synthetic IPC experiment. No gate decisions or production collector.

The trusted fixed child executes the exact bytes of the hash-bound adapter.
Source fixture timestamps are never replaced by transport clocks.
"""
from copy import deepcopy
import hashlib
import json
import math
import os
from pathlib import Path
import select
import struct
import subprocess
import sys
import time
import types

ADAPTER_SHA256 = '6d52fb2a32a0b81df30bc0d30c2ec820421c3048c990806c2af808d5eb83fae8'
HERE = Path(__file__).resolve().parent
CHILD_FILE = HERE / 'fake_child.py'
FRAME_CAP = 4096
BODY_CAP = FRAME_CAP - 4
FRAME_COUNT_CAP = 128
STREAM_BYTE_CAP = FRAME_CAP * FRAME_COUNT_CAP
RESULT_CAP = 4096
REPORT_CAP = 16384
READY_CAP = .4
TERM_GRACE = .05
REAP_CAP = .2
RESULT_WAIT_CAP = .2
EMERGENCY_CAP = 2.
_ACTIVE_OWNER = None  # One canonical module in the single-threaded test runner.
CASE_RECORDS = []
CASE_LABEL = None


def load_adapter():
    """Hash then compile the SAME bounded bytes; never reopen for execution."""
    packaged = HERE / 'dependencies' / 'event_adapter.py'
    path = packaged if packaged.exists() else HERE.parent / 'phase7_pressure_event_adapter' / 'event_adapter.py'
    with path.open('rb') as source:
        raw = source.read(65537)
    if len(raw) > 65536 or hashlib.sha256(raw).hexdigest() != ADAPTER_SHA256:
        raise ValueError('ADAPTER_HASH_MISMATCH')
    module = types.ModuleType('verified_fixture_adapter')
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module.Adapter


def _encode(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True,
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _pairs(items):
    value = {}
    if len(items) > 32:
        raise ValueError('JSON_OBJECT_CAP')
    for key, item in items:
        if key in value:
            raise ValueError('JSON_DUPLICATE_KEY')
        value[key] = item
    return value


def _number(text):
    if len(text) > 32:
        raise ValueError('JSON_NUMBER')
    value = float(text)
    if not math.isfinite(value):
        raise ValueError('JSON_NUMBER')
    return value


def _integer(text):
    if len(text.lstrip('-')) > 19:
        raise ValueError('JSON_INTEGER')
    value = int(text)
    if not -(2**63 - 1) <= value <= 2**63 - 1:
        raise ValueError('JSON_INTEGER')
    return value


def _constant(_):
    raise ValueError('JSON_CONSTANT')


def _tree(value, depth=0, count=None):
    count = [0] if count is None else count
    count[0] += 1
    if depth > 8 or count[0] > 1024:
        raise ValueError('JSON_TREE_CAP')
    if type(value) is dict:
        if len(value) > 32 or any(type(k) is not str or len(k) > 128 for k in value):
            raise ValueError('JSON_OBJECT_CAP')
        for item in value.values():
            _tree(item, depth + 1, count)
    elif type(value) is list:
        if len(value) > 32:
            raise ValueError('JSON_ARRAY_CAP')
        for item in value:
            _tree(item, depth + 1, count)
    elif type(value) is str:
        if len(value) > 128:
            raise ValueError('JSON_STRING_CAP')
    elif value is not None and type(value) not in (bool, int, float):
        raise ValueError('JSON_TYPE')
    elif type(value) in (int, float):
        if not -(2**63 - 1) <= value <= 2**63 - 1 or not math.isfinite(value):
            raise ValueError('JSON_NUMBER')


def strict_json(raw, cap=BODY_CAP):
    if type(cap) is not int or not 0 < cap <= BODY_CAP:
        raise ValueError('JSON_BYTE_CAP')
    if type(raw) is not bytes or not 0 < len(raw) <= cap:
        raise ValueError('JSON_BYTE_CAP')
    text = raw.decode('ascii')
    # Bound nesting before json.loads; braces inside strings are not nesting.
    depth = 0
    quoted = escaped = False
    for ch in text:
        if quoted:
            if escaped:
                escaped = False
            elif ch == '\\':
                escaped = True
            elif ch == '"':
                quoted = False
        elif ch == '"':
            quoted = True
        elif ch in '[{':
            depth += 1
            if depth > 8:
                raise ValueError('JSON_DEPTH')
        elif ch in ']}':
            depth -= 1
    value = json.loads(text, object_pairs_hook=_pairs, parse_int=_integer,
                       parse_float=_number, parse_constant=_constant)
    _tree(value)
    return value


def frame(transport_seq, event, *, padded=False):
    """Fixture setup only. Event schema validation remains the adapter's job."""
    if type(transport_seq) is not int or not 0 <= transport_seq < FRAME_COUNT_CAP:
        raise ValueError('TRANSPORT_SEQUENCE')
    if type(event) is not dict or type(padded) is not bool:
        raise ValueError('FRAME_INPUT')
    _tree(event)
    body = _encode({'transport_seq': transport_seq, 'event': event})
    if len(body) > BODY_CAP:
        raise ValueError('FRAME_CAP')
    if padded:
        body = body.ljust(BODY_CAP, b' ')
    return struct.pack('!I', len(body)) + body


class Decoder:
    """Bounded incremental byte-stream consumer, not an acknowledgement."""
    def __init__(self):
        self.adapter = load_adapter()(provenance='SYNTHETIC')
        self.buffer = bytearray()
        self.bytes_received = self.frames = self.expected = 0
        self.error = None
        self.finished = False

    def _fail(self, reason):
        if self.error is None:
            self.error = reason
        self.buffer.clear()
        self.adapter.drain(available=False)

    def feed(self, data):
        if self.finished:
            raise ValueError('DECODER_FINISHED')
        if self.error is not None:
            return None
        if type(data) is not bytes or not 0 < len(data) <= FRAME_CAP:
            self._fail('CHUNK_CAP'); return None
        self.bytes_received += len(data)
        if self.bytes_received > STREAM_BYTE_CAP:
            self._fail('STREAM_BYTE_CAP'); return None
        self.buffer.extend(data)  # At most 8191 bytes before complete frames drain.
        while len(self.buffer) >= 4:
            length = struct.unpack('!I', self.buffer[:4])[0]
            if not 0 < length <= BODY_CAP:
                self._fail('FRAME_LENGTH'); return None
            if len(self.buffer) < length + 4:
                break
            raw = bytes(self.buffer[4:length + 4])
            del self.buffer[:length + 4]
            if self.frames >= FRAME_COUNT_CAP:
                self._fail('FRAME_COUNT_CAP'); return None
            self.frames += 1
            try:
                item = strict_json(raw)
                if type(item) is not dict or set(item) != {'transport_seq', 'event'}:
                    raise ValueError('ENVELOPE')
                seq = item['transport_seq']
                if type(seq) is not int or not 0 <= seq < FRAME_COUNT_CAP or type(item['event']) is not dict:
                    raise ValueError('ENVELOPE')
            except (ValueError, UnicodeError, TypeError, RecursionError):
                self._fail('MALFORMED_FRAME'); return None
            if seq != self.expected:
                self._fail('TRANSPORT_SEQUENCE_LOSS'); return None
            self.expected += 1
            self.adapter.offer(item['event'])
            self.adapter.drain()
        return None

    def finish(self, *, input_eof=True):
        if self.finished:
            raise ValueError('DECODER_FINISHED')
        if type(input_eof) is not bool:
            raise ValueError('INPUT_EOF')
        self.finished = True
        if not input_eof:
            self._fail('INPUT_EOF_UNCONFIRMED')
        if self.buffer:
            self._fail('TRUNCATED_FRAME')
        if self.frames == 0 and self.error is None:
            self._fail('NO_FRAMES')
        adapter_raw = self.adapter.serialize()
        if len(adapter_raw) > 2048:
            raise ValueError('ADAPTER_OUTPUT_CAP')
        value = dict(schema=1, provenance='SYNTHETIC', input_eof=input_eof, transport_error=self.error,
                     frames=self.frames, bytes_received=self.bytes_received,
                     adapter=json.loads(adapter_raw))
        raw = _encode(value)
        if len(raw) > BODY_CAP:
            raise ValueError('RESULT_CAP')
        return struct.pack('!I', len(raw)) + raw


def result_value(raw):
    """Decode one bounded result; malformed bytes are never echoed."""
    if type(raw) is not bytes or not 4 < len(raw) <= RESULT_CAP:
        raise ValueError('RESULT_BYTES')
    length = struct.unpack('!I', raw[:4])[0]
    if length != len(raw) - 4:
        raise ValueError('RESULT_FRAME')
    value = strict_json(raw[4:])
    errors = {None, 'CHUNK_CAP', 'STREAM_BYTE_CAP', 'FRAME_LENGTH', 'FRAME_COUNT_CAP',
              'MALFORMED_FRAME', 'TRANSPORT_SEQUENCE_LOSS', 'TRUNCATED_FRAME', 'NO_FRAMES',
              'INPUT_EOF_UNCONFIRMED'}
    if (type(value) is not dict or set(value) != {'schema', 'provenance', 'input_eof', 'transport_error', 'frames', 'bytes_received', 'adapter'}
            or type(value['schema']) is not int or value['schema'] != 1
            or value['provenance'] != 'SYNTHETIC'
            or type(value['input_eof']) is not bool
            or value['transport_error'] not in errors
            or type(value['frames']) is not int or not 0 <= value['frames'] <= FRAME_COUNT_CAP
            or type(value['bytes_received']) is not int or not 0 <= value['bytes_received'] <= STREAM_BYTE_CAP + FRAME_CAP):
        raise ValueError('RESULT_SCHEMA')
    adapter = value['adapter']
    if (type(adapter) is not dict or len(_encode(adapter)) > 2048
            or adapter.get('provenance') != 'SYNTHETIC'
            or adapter.get('status') != 'DESCRIPTIVE_ONLY'
            or adapter.get('control_authority') != 'NONE'
            or adapter.get('gate_acceptance') != 'NOT_ASSESSED'
            or adapter.get('coverage_complete') is not False
            or type(adapter.get('rows')) is not list):
        raise ValueError('ADAPTER_RESULT_SCHEMA')
    return value


class Session:
    """Own at most two fixed fake children; optional evidence never controls stop."""
    def __init__(self, *, budget_s=2., child_ttl_s=5):
        global _ACTIVE_OWNER
        if _ACTIVE_OWNER is not None:
            raise RuntimeError('PRIOR_OWNER_NOT_DISPOSED')
        if type(budget_s) not in (int, float) or not 0 < budget_s <= 3:
            raise ValueError('BUDGET')
        if type(child_ttl_s) is not int or child_ttl_s not in (1, 5):
            raise ValueError('CHILD_TTL')
        self._deadline = time.monotonic() + budget_s
        self._ttl, self._label = child_ttl_s, CASE_LABEL
        self._children, self._setup, self._trace = {}, {}, []
        self._started = self._closed = False
        self._result = self._emergency = None
        self._input_read = self._input_write = self._result_read = self._result_write = None
        self._transport = dict(attempts=0, buffered=0, buffered_bytes=0, dropped_full=0, dropped_unavailable=0,
                               partial_unknown=0, dropped_expired=0, dropped_cap=0,
                               parent_loss=False, max_offer_elapsed_s=0., processing='UNKNOWN')
        try:
            self._input_read, self._input_write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
            self._result_read, self._result_write = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
            self.pipe_buf = min(os.fpathconf(fd, 'PC_PIPE_BUF') for fd in (self._input_write, self._result_write))
            if self.pipe_buf < FRAME_CAP:
                raise ValueError('PIPE_BUF_UNSUPPORTED')
        except BaseException:
            self._close_all()
            raise
        _ACTIVE_OWNER = self

    @property
    def deadline(self):
        return self._deadline

    def __enter__(self):
        return self

    def __exit__(self, *_):
        try:
            if self._result is None:
                self.stop()
        finally:
            self.emergency_cleanup()

    def _mark(self, event):
        if len(self._trace) < 40:
            self._trace.append(dict(event=event, mono_s=time.monotonic()))

    def _close(self, name):
        fd = getattr(self, name)
        setattr(self, name, None)
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    def _close_all(self):
        for name in ('_input_read', '_input_write', '_result_read', '_result_write'):
            self._close(name)

    def _spawn(self, role, mode):
        rfd, wfd = os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)
        began = time.monotonic()
        input_fd = self._input_read if role == 'collector' else -1
        output_fd = self._result_write if role == 'collector' else -1
        passed = (wfd, input_fd, output_fd) if role == 'collector' else (wfd,)
        try:
            child = subprocess.Popen([sys.executable, '-I', '-S', '-B', str(CHILD_FILE),
                mode, str(wfd), str(input_fd), str(output_fd), str(self._ttl)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                close_fds=True, pass_fds=passed, env={})
            self._children[role] = child  # Retain immediately, including partial startup.
            spawned = time.monotonic()
            os.close(wfd); wfd = None
            if role == 'collector':
                self._close('_input_read'); self._close('_result_write')
            remaining = max(0., min(READY_CAP, self.deadline - time.monotonic()))
            ready = bool(remaining and select.select([rfd], [], [], remaining)[0]
                         and os.read(rfd, 1) == b'R')
            self._setup[role] = dict(mode=mode, ready=ready, popen_elapsed_s=spawned-began,
                                     readiness_elapsed_s=time.monotonic()-spawned)
            return ready
        finally:
            for fd in (rfd, wfd):
                if fd is not None:
                    try:
                        os.close(fd)
                    except OSError:
                        pass

    def start(self, *, worker='cooperative', collector='normal'):
        if self._started or self._closed:
            raise ValueError('START_ONCE')
        if worker not in ('cooperative', 'ignore_term') or collector not in ('normal', 'stall', 'unavailable', 'no_ready', 'bad_result', 'oversize_result'):
            raise ValueError('MODE')
        self._started = True
        self._mark('SETUP_BEGIN')
        try:
            if time.monotonic() >= self.deadline:
                self._setup['status'] = 'DEADLINE_EXHAUSTED'; return
            if not self._spawn('worker', worker) or time.monotonic() >= self.deadline:
                self._setup['status'] = 'WORKER_NOT_READY'; return
            self._setup['status'] = 'READY' if self._spawn('collector', collector) else 'COLLECTOR_NOT_READY'
        except BaseException:
            self._setup['status'] = 'SETUP_EXCEPTION'
            self.stop()
            raise
        finally:
            self._mark('SETUP_END')

    def _drop(self, key):
        self._transport[key] = min(FRAME_COUNT_CAP + 1, self._transport[key] + 1)
        self._transport['parent_loss'] = True

    def offer(self, prepared):
        """At most one Python write, no application retry or output wait/read."""
        if self._closed:
            raise ValueError('SESSION_CLOSED')
        if type(prepared) is not bytes or not 0 < len(prepared) <= FRAME_CAP:
            self._drop('dropped_unavailable'); return None
        if self._transport['attempts'] == FRAME_COUNT_CAP:
            self._drop('dropped_cap'); return None
        self._transport['attempts'] += 1
        if self._setup.get('status') != 'READY' or self._input_write is None:
            self._drop('dropped_unavailable'); return None
        if time.monotonic() >= self.deadline:
            self._drop('dropped_expired'); return None
        began = time.monotonic()
        try:
            # No application retry; CPython may transparently retry EINTR.
            count = os.write(self._input_write, prepared)
            if count == len(prepared):
                self._transport['buffered'] += 1
                self._transport['buffered_bytes'] += count
            else:
                self._drop('partial_unknown')
        except BlockingIOError:
            self._drop('dropped_full')
        except OSError:
            self._drop('dropped_unavailable')
        finally:
            self._transport['max_offer_elapsed_s'] = max(self._transport['max_offer_elapsed_s'], time.monotonic()-began)
        return None

    def _term(self, role):
        child = self._children.get(role)
        if child is None:
            self._mark(role.upper() + '_NOT_CREATED'); return
        self._mark(role.upper() + '_TERM_ATTEMPT')
        try:
            child.terminate()
        except OSError:
            self._mark(role.upper() + '_TERM_UNCONFIRMED')

    def _settle(self, role):
        child = self._children.get(role)
        if child is None:
            return 'NOT_CREATED'
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            return 'UNKNOWN'
        self._mark(role.upper() + '_WAIT')
        try:
            child.wait(timeout=min(TERM_GRACE, remaining))
        except subprocess.TimeoutExpired:
            if time.monotonic() >= self.deadline:
                return 'UNKNOWN'
            self._mark(role.upper() + '_KILL_ATTEMPT')
            try:
                child.kill()
            except OSError:
                pass
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                return 'UNKNOWN'
            self._mark(role.upper() + '_REAP_WAIT')
            try:
                child.wait(timeout=min(REAP_CAP, remaining))
            except subprocess.TimeoutExpired:
                return 'UNKNOWN'
        return 'REAPED_WITHIN_DEADLINE' if time.monotonic() < self.deadline else 'UNKNOWN'

    def _capture(self):
        self._mark('RESULT_CAPTURE_BEGIN')
        end = min(self.deadline, time.monotonic() + RESULT_WAIT_CAP)
        raw = bytearray()
        while self._result_read is not None and time.monotonic() < end:
            if not select.select([self._result_read], [], [], max(0., end-time.monotonic()))[0]:
                return None, 'OUTPUT_UNAVAILABLE'
            try:
                chunk = os.read(self._result_read, RESULT_CAP + 1 - len(raw))
            except BlockingIOError:
                continue
            except OSError:
                return None, 'OUTPUT_READ_FAILED'
            if not chunk:
                if time.monotonic() >= self.deadline:
                    return None, 'OUTPUT_LATE'
                self._mark('RESULT_DECODE')
                try:
                    return result_value(bytes(raw)), None
                except (ValueError, TypeError, UnicodeError, RecursionError):
                    return None, 'OUTPUT_INVALID'
            raw.extend(chunk)
            if len(raw) > RESULT_CAP:
                return None, 'OUTPUT_OVERSIZED'
        return None, 'OUTPUT_UNAVAILABLE'

    def stop(self):
        if self._result is not None:
            return deepcopy(self._result)
        self._mark('CONTROL_STOP_SELECTED')
        # Even an expired budget permits this nonwaiting worker TERM attempt.
        self._term('worker')
        self._mark('INPUT_EOF_CLOSE')
        self._close('_input_write'); self._close('_input_read')
        self._closed = True
        worker = self._settle('worker')
        self._mark('WORKER_SETTLE_END')
        payload, reason = None, 'WORKER_CLOSURE_UNCONFIRMED'
        if worker == 'REAPED_WITHIN_DEADLINE' and time.monotonic() < self.deadline:
            payload, reason = self._capture()
        # EOF gave a normal collector a best-effort exit. Never wait for its
        # result before cancellation and settling of the controlled worker.
        if time.monotonic() < self.deadline:
            self._term('collector')
        collector = self._settle('collector')
        self._close_all()
        if self._transport['parent_loss']:
            payload, reason = None, 'PARENT_TRANSPORT_LOSS'
        elif payload is not None and (payload['input_eof'] is not True
                or payload['frames'] != self._transport['buffered']
                or payload['bytes_received'] != self._transport['buffered_bytes']):
            payload, reason = None, 'TRANSFER_COMPLETION_UNCONFIRMED'
        elif collector != 'REAPED_WITHIN_DEADLINE' or self._children.get('collector') is None or self._children['collector'].returncode != 0:
            payload, reason = None, 'COLLECTOR_CLOSURE_OR_EXIT_UNCONFIRMED'
        self._mark('STOP_END')
        assessed = time.monotonic()
        expired = assessed >= self.deadline
        if expired:
            payload, reason = None, 'ORIGINAL_DEADLINE_EXHAUSTED'
        self._result = dict(scope='LOCAL_SYNTHETIC_TRANSPORT_ONLY', control_decision='EXTERNAL_FIXED_STOP',
            original_deadline=self.deadline, terminal_assessment_mono_s=assessed, deadline_exhausted=expired,
            worker_closure=worker, collector_closure=collector,
            output_status='DESCRIPTIVE_RESULT' if payload is not None else 'UNKNOWN',
            output_reason=reason, child_result=payload, coverage_complete=False,
            safety_assessment='NOT_ASSESSED', adapter_sha256=ADAPTER_SHA256,
            verified_pipe_buf=self.pipe_buf, setup=deepcopy(self._setup),
            transport=deepcopy(self._transport), trace=deepcopy(self._trace),
            returncodes={role: child.returncode for role, child in self._children.items()})
        return deepcopy(self._result)

    def serialize(self):
        if self._result is None:
            raise ValueError('STOP_RESULT_REQUIRED')
        raw = _encode(self._result)
        if len(raw) <= REPORT_CAP:
            return raw
        return _encode(dict(output_status='UNKNOWN', output_reason='REPORT_CAP',
                            evidence_omitted=True, coverage_complete=False,
                            control_decision='EXTERNAL_FIXED_STOP', safety_assessment='NOT_ASSESSED',
                            worker_closure=self._result['worker_closure'], collector_closure=self._result['collector_closure'],
                            parent_loss=self._transport['parent_loss']))

    def inspection(self):
        return dict(setup=deepcopy(self._setup), transport=deepcopy(self._transport),
                    trace=deepcopy(self._trace), child_count=len(self._children),
                    returncodes={role: child.returncode for role, child in self._children.items()})

    def emergency_cleanup(self):
        """Separate disposal cannot upgrade the original cached stop evidence."""
        global _ACTIVE_OWNER
        if self._emergency is not None:
            if any(x != 'REAPED' for x in self._emergency['children'].values()):
                raise RuntimeError('EMERGENCY_CLOSURE_UNCONFIRMED')
            return deepcopy(self._emergency)
        self._close_all(); self._closed = True
        end = time.monotonic() + EMERGENCY_CAP
        report = dict(separate_test_teardown=True, children={})
        for role in ('worker', 'collector'):
            child = self._children.get(role)
            if child is not None and child.poll() is None:
                try:
                    child.kill()
                except OSError:
                    pass
        for role, child in self._children.items():
            try:
                child.wait(timeout=max(0., end-time.monotonic()))
                report['children'][role] = 'REAPED'
            except subprocess.TimeoutExpired:
                report['children'][role] = 'UNKNOWN'
        self._emergency = report
        if len(CASE_RECORDS) < 32:
            CASE_RECORDS.append(dict(fixture_test=self._label, modeled_stop=deepcopy(self._result), emergency=deepcopy(report)))
        if any(x != 'REAPED' for x in report['children'].values()):
            raise RuntimeError('EMERGENCY_CLOSURE_UNCONFIRMED')
        if _ACTIVE_OWNER is self:
            _ACTIVE_OWNER = None
        return deepcopy(report)
