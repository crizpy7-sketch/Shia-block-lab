"""Deterministic supplied-event model; no readers, clocks, callbacks or control.

The external control trace is not accepted or mutated by this model. offer and
drain return None, never an acknowledgement, stop decision, or gate permission.
PSI inputs are parsed numeric fixture assertions, not independently read bytes.
"""
from collections import deque
from copy import deepcopy
import json
import math
import re

QUEUE_CAP = 8
ROW_CAP = 32
EPOCH_CAP = 8
OUTPUT_CAP = 2048
MAX_INT = 2**63 - 1
FIELDS = {'kind', 'invocation', 'window', 'phase', 'epoch', 'seq',
          'source_mono_s', 'delivery_mono_s', 'data'}
KINDS = {'OPEN', 'CLOSE', 'SAMPLE_BEGIN', 'COUNTERS', 'COMPLETE', 'FAILED',
         'PSI', 'DECISION', 'LOSS'}
PHASE_GAP = {'ADMISSION': 2, 'RUNTIME': 3}
SAMPLE_CODES = {'MEMORY_FLOOR', 'MONITOR_LOSS', 'MONITOR_TIME', 'CLEANUP_DEADLINE',
    'DISK_RESERVE', 'DISK_ENVELOPE', 'EXISTING_SERVICE_DEGRADATION',
    'GATE_HEALTH_OR_OOM', 'NGINX_MEMORY_ALLOWANCE', 'SUSTAINED_CPU',
    'SUSTAINED_SWAP', 'NGINX_CPU_ALLOWANCE'}
WINDOW_CODES = {'ADMISSION_RETURNED', 'ADMISSION_SWAP', 'ADMISSION_MEMORY',
    'ADMISSION_DISK', 'ADMISSION_CPU', 'ADMISSION_EXISTING_SERVICE',
    'ADMISSION_CONTAINER_HEALTH', 'ADMISSION_OOM', 'ADMISSION_SAMPLE_WINDOW',
    'ADMISSION_SAMPLE_GAP'}
LIFECYCLE_CODES = SAMPLE_CODES | {'WORKER_COMPLETED', 'WORKER_EXITED',
    'WORKER_CHANNEL_CLOSED', 'WORKER_HEARTBEAT_LOSS', 'INTERRUPTED',
    'MONITOR_OR_STARTUP_LOSS', 'STARTUP_FAILED', 'STARTUP_TERMINAL_RESTORE_FAILED',
    'SUPERVISOR_TERMINAL_RESTORE_FAILED', 'CANCEL_ATTEMPTED', 'CLOSURE_CONFIRMED',
    'CLOSURE_UNCONFIRMED', 'CLEANUP_REPORTED', 'CLOSEOUT_REPORTED', 'UNKNOWN'}
STAGES = {'STOP', 'CANCEL', 'CLOSURE', 'CLEANUP', 'CLOSEOUT'}
CONDITIONS = SAMPLE_CODES | {'OOM'}


def _need(ok):
    if not ok:
        raise ValueError('INVALID_EVENT')


def _int(x):
    return type(x) is int and 0 <= x <= MAX_INT


def _time(x):
    return type(x) in (int, float) and 0 <= x < 1e12 and math.isfinite(x)


def _label(x):
    return type(x) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,32}', x) is not None


def _keys(data, keys):
    _need(type(data) is dict and set(data) == set(keys.split()))


def _validated(event):
    _need(type(event) is dict and set(event) == FIELDS)
    _need(type(event['kind']) is str and event['kind'] in KINDS)
    _need(_label(event['invocation']) and _label(event['window']))
    _need(event['epoch'] is None or _label(event['epoch']))
    _need(type(event['phase']) is str and event['phase'] in PHASE_GAP)
    _need(_int(event['seq']) and _time(event['delivery_mono_s']))
    source = event['source_mono_s']
    _need(source is None or _time(source) and source <= event['delivery_mono_s'])
    kind, d = event['kind'], event['data']
    if kind in {'OPEN', 'CLOSE'}:
        _keys(d, '')
    elif kind in {'SAMPLE_BEGIN', 'COMPLETE'}:
        _keys(d, 'sample_id'); _need(_int(d['sample_id']))
    elif kind == 'FAILED':
        _keys(d, 'sample_id stage'); _need(_int(d['sample_id']))
        _need(d['stage'] in ('BEFORE_COUNTERS', 'AFTER_COUNTERS'))
    elif kind == 'COUNTERS':
        _keys(d, 'sample_id previous_mono_s mono_s mem_available_bytes swap_in_pages swap_out_pages')
        _need(_int(d['sample_id']) and _time(d['mono_s']))
        _need(d['previous_mono_s'] is None or
              _time(d['previous_mono_s']) and d['previous_mono_s'] < d['mono_s'])
        _need(d['mono_s'] <= event['delivery_mono_s'])
        _need(source is None or source >= d['mono_s'])
        _need(all(d[k] is None or _int(d[k]) for k in
                  ('mem_available_bytes', 'swap_in_pages', 'swap_out_pages')))
    elif kind == 'PSI':
        _keys(d, 'some_total_us full_total_us read_before_mono_s read_after_mono_s payload_status payload_bytes')
        _need(d['payload_status'] in ('PARSED', 'ABSENT', 'MALFORMED', 'READ_FAILED', 'CLOCK_FAILED'))
        _need(d['payload_bytes'] is None or _int(d['payload_bytes']) and d['payload_bytes'] <= 4096)
        _need(all(d[k] is None or _int(d[k]) for k in ('some_total_us', 'full_total_us')))
        _need(all(d[k] is None or _time(d[k]) for k in ('read_before_mono_s', 'read_after_mono_s')))
        _need(all(d[k] is None or d[k] <= event['delivery_mono_s']
                  for k in ('read_before_mono_s', 'read_after_mono_s')))
        _need(source is None or d['read_after_mono_s'] is None or source >= d['read_after_mono_s'])
    elif kind == 'DECISION':
        _keys(d, 'scope target code conditions')
        _need(d['scope'] in ('SAMPLE', 'WINDOW', 'LIFECYCLE'))
        if d['scope'] == 'SAMPLE':
            _need(event['phase'] == 'RUNTIME' and _int(d['target']))
            _need(d['code'] is None or type(d['code']) is str and d['code'] in SAMPLE_CODES)
        elif d['scope'] == 'WINDOW':
            _need(event['phase'] == 'ADMISSION' and d['target'] == event['window'])
            _need(type(d['code']) is str and d['code'] in WINDOW_CODES)
        else:
            _need(type(d['target']) is str and d['target'] in STAGES)
            _need(type(d['code']) is str and d['code'] in LIFECYCLE_CODES)
        _need(type(d['conditions']) is list and len(d['conditions']) <= 8
              and all(type(x) is str and x in CONDITIONS for x in d['conditions'])
              and len(set(d['conditions'])) == len(d['conditions']))
    else:
        _keys(d, 'stream count')
        _need(d['stream'] in ('ALL', 'VM', 'PSI', 'DECISION'))
        _need(d['count'] is None or _int(d['count']) and d['count'] > 0)
    return deepcopy(event)


def _encode(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True,
                      allow_nan=False, ensure_ascii=True).encode('ascii')


def _fraction(microseconds, seconds):
    try:
        value = microseconds/(seconds*1e6)
        return value if math.isfinite(value) else None
    except ArithmeticError:
        return None


class Adapter:
    """Bounded abstract FIFO and consumer, with no real transport semantics.

    Queue loss, invalid offers and consumer unavailability install a sticky
    observation-state fence. This model does not attempt recovery after those
    boundaries. Scoped decisions can still be copied as supplied evidence.
    Epoch history is never evicted; capacity exhaustion is explicit unknown.
    """
    def __init__(self, *, provenance):
        _need(provenance in ('SYNTHETIC', 'RETAINED_PARTIAL_OBSERVATION'))
        self._provenance = provenance
        self._queue, self._rows = deque(), deque(maxlen=ROW_CAP)
        self._epochs, self._active = {}, None
        self._sample = self._psi = None
        self._delivery = None
        self._fenced = self._incomplete = False
        self._metrics = dict(offered=0, queue_dropped=0, invalid_dropped=0,
                             consumer_dropped=0, retained_evicted=0, consumed=0)

    def _bump(self, key, count=1):
        self._metrics[key] = min(MAX_INT, self._metrics[key] + count)

    def _fence(self):
        self._fenced = self._incomplete = True
        self._active = self._sample = self._psi = None

    def offer(self, event):
        self._bump('offered')
        if len(self._queue) == QUEUE_CAP:
            self._bump('queue_dropped'); self._fence(); return None
        try:
            checked = _validated(event)
        except Exception:
            self._bump('invalid_dropped'); self._fence(); return None
        self._queue.append(checked)
        return None

    def drain(self, *, available=True):
        _need(type(available) is bool)
        if not available:
            self._bump('consumer_dropped', len(self._queue))
            self._queue.clear(); self._fence(); return None
        while self._queue:  # At most QUEUE_CAP supplied items; no producer retry.
            e = self._queue.popleft()
            row = deepcopy(e)
            row.update(status='UNKNOWN', disposition=None,
                       vm_psi_association='UNESTABLISHED')
            self._consume(e, row)
            self._bump('consumed')
            self._bump('retained_evicted', int(len(self._rows) == ROW_CAP))
            if len(self._rows) == ROW_CAP:
                self._incomplete = True
            self._rows.append(row)
        return None

    def _consume(self, e, row):
        kind, d = e['kind'], e['data']
        key = tuple(e[k] for k in ('invocation', 'window', 'phase', 'epoch'))
        if self._delivery is not None and e['delivery_mono_s'] < self._delivery:
            self._fence()
            row['disposition'] = 'DELIVERY_ORDER_INVALID'; return
        self._delivery = e['delivery_mono_s']
        if self._fenced:
            row['disposition'] = 'OBSERVATION_STATE_UNKNOWN_AFTER_LOSS'
            if kind == 'DECISION':
                row['status'] = 'SUPPLIED_DECISION_UNVERIFIED_CONTEXT'
            return
        if kind == 'OPEN':
            if key in self._epochs or self._active is not None or e['seq'] != 0:
                self._fence()
                row['disposition'] = 'EPOCH_REOPEN_OR_TRANSITION_INVALID'; return
            if len(self._epochs) == EPOCH_CAP:
                self._fence(); row['disposition'] = 'EPOCH_HISTORY_EXHAUSTED'; return
            self._epochs[key] = {'closed': False, 'seq': {'EPOCH': 0}, 'time': {}, 'vm_mono': None}
            self._active = key
            self._sample = self._psi = None
            row.update(status='DESCRIPTIVE_EVENT', disposition='EPOCH_OPENED'); return
        state = self._epochs.get(key)
        if state is None:
            self._fence()
            row['disposition'] = 'UNKNOWN_EPOCH'; return
        if state['closed'] and kind != 'DECISION':
            row['disposition'] = 'LATE_AFTER_CLOSE'; self._incomplete = True; return
        stream = ('VM' if kind in {'SAMPLE_BEGIN', 'COUNTERS', 'COMPLETE', 'FAILED'}
                  else 'EPOCH' if kind == 'CLOSE' else kind)
        previous_seq = state['seq'].get(stream)
        previous_time = state['time'].get(stream)
        if previous_seq is not None and e['seq'] <= previous_seq:
            self._fence()
            row['disposition'] = 'REORDERED_OR_DUPLICATE_SOURCE'; return
        gap = e['seq'] != (0 if previous_seq is None else previous_seq + 1)
        if previous_time is not None and (e['source_mono_s'] is None or
                                         e['source_mono_s'] < previous_time):
            gap = True
        state['seq'][stream] = e['seq']
        state['time'][stream] = e['source_mono_s']
        row['source_gap'] = gap
        if gap:
            self._fence()
            row['disposition'] = 'SOURCE_GAP'
            if kind == 'DECISION':
                row['status'] = 'SUPPLIED_DECISION_UNVERIFIED_CONTEXT'
            return
        if kind == 'LOSS':
            self._fence()
            row['disposition'] = 'KNOWN_LOSS' if d['count'] is not None else 'UNKNOWN_LOSS'
        elif kind == 'CLOSE':
            state['closed'] = True
            self._active = self._sample = self._psi = None
            row.update(status='DESCRIPTIVE_EVENT', disposition='EPOCH_CLOSED')
        elif kind == 'DECISION':
            row.update(status='SUPPLIED_DECISION', disposition='COPIED_SCOPE_ONLY' if not gap else 'SOURCE_GAP')
        elif kind == 'PSI':
            self._pressure(e, row, gap)
        elif kind == 'SAMPLE_BEGIN':
            if self._sample is not None:
                self._psi = None; self._incomplete = True
                row['disposition'] = 'PRIOR_SAMPLE_TERMINAL_MISSING'
            self._sample = {'sample_id': d['sample_id'], 'vm': None}
            row['status'] = 'DESCRIPTIVE_EVENT'
            row['disposition'] = row['disposition'] or 'SAMPLE_STARTED'
        elif self._sample is None or self._sample['sample_id'] != d['sample_id']:
            self._sample = self._psi = None; self._incomplete = True
            row['disposition'] = 'MISSING_SAMPLE_ATTEMPT'
        elif kind == 'COUNTERS':
            if self._sample['vm'] is not None:
                self._sample = self._psi = None; self._incomplete = True
                row['disposition'] = 'DUPLICATE_COUNTERS'; return
            previous_vm = state['vm_mono']
            row['vm_interval_status'] = 'BASELINE_UNKNOWN' if d['previous_mono_s'] is None else 'SUPPLIED'
            if previous_vm is not None and (d['previous_mono_s'] != previous_vm or d['mono_s'] <= previous_vm):
                row['vm_interval_status'] = 'GAP_OR_REORDERED'
                self._psi = None; self._incomplete = True
            state['vm_mono'] = d['mono_s']
            self._sample['vm'] = deepcopy(d)
            row.update(status='DESCRIPTIVE_EVENT', disposition='COUNTERS_ONLY')
        else:
            vm = self._sample['vm']
            if kind == 'COMPLETE' and vm is not None:
                row.update(status='DESCRIPTIVE_EVENT', disposition='COMPLETE', vm=deepcopy(vm))
            elif kind == 'FAILED' and (d['stage'] == 'AFTER_COUNTERS') == (vm is not None):
                row.update(status='DESCRIPTIVE_EVENT', disposition='FAILED_'+d['stage'], vm=deepcopy(vm))
                self._psi = None
            else:
                self._psi = None; self._incomplete = True
                row['disposition'] = 'COMPLETION_OR_FAILURE_UNVERIFIED'
            self._sample = None

    def _pressure(self, e, row, gap):
        d, old = e['data'], self._psi
        self._psi = None
        row.update(pressure_status='UNKNOWN', delta_us=None, elapsed_seconds=None,
                   stall_fraction_bounds=None, atomicity='NOT_ATTESTED',
                   parse_provenance='SUPPLIED_NUMERIC_FIXTURE_ASSERTION')
        some, full = d['some_total_us'], d['full_total_us']
        before, after = d['read_before_mono_s'], d['read_after_mono_s']
        if (d['payload_status'] != 'PARSED' or not d['payload_bytes'] or some is None or full is None
                or before is None or after is None or e['source_mono_s'] is None):
            row['disposition'] = 'PRESSURE_UNAVAILABLE'; return
        if full > some or after < before or after-before > PHASE_GAP[e['phase']]:
            row['disposition'] = 'INVALID_PRESSURE_OR_READ_BOUNDS'; return
        if e['epoch'] is None:
            row['disposition'] = 'EPOCH_IDENTITY_UNKNOWN'; return
        self._psi = deepcopy(d)
        if gap or old is None:
            row['disposition'] = 'SOURCE_GAP' if gap else 'NO_PAIRED_BASELINE'; return
        lower, upper = before-old['read_after_mono_s'], after-old['read_before_mono_s']
        delta = {'some': some-old['some_total_us'], 'full': full-old['full_total_us']}
        if lower <= 0 or upper > PHASE_GAP[e['phase']]:
            self._psi = None; row['disposition'] = 'INVALID_OR_GAPPED_PSI_INTERVAL'; return
        if min(delta.values()) < 0 or delta['full'] > delta['some']:
            self._psi = None; row['disposition'] = 'RESET_OR_INVALID_COUNTER_DELTA'; return
        row.update(status='DESCRIPTIVE_EVENT', disposition='PSI_DELTA',
                   pressure_status='DESCRIPTIVE_DELTA', delta_us=delta,
                   elapsed_seconds=[lower, upper],
                   stall_fraction_bounds={k:[_fraction(v,upper), _fraction(v,lower)] for k,v in delta.items()})

    def serialize(self):
        rows = list(self._rows)
        value = dict(schema=1, provenance=self._provenance, status='DESCRIPTIVE_ONLY',
                     control_authority='NONE', gate_acceptance='NOT_ASSESSED',
                     coverage_complete=False, observation_state_unknown=self._fenced,
                     known_discontinuity=self._incomplete, queue_pending=len(self._queue),
                     metrics=dict(self._metrics), output_dropped_rows=0, rows=rows)
        try:
            while True:
                raw = _encode(value)
                _need(type(raw) is bytes)
                if len(raw) <= OUTPUT_CAP:
                    return raw
                _need(bool(rows))
                rows.pop(0); value['output_dropped_rows'] += 1
                value['known_discontinuity'] = True
        except Exception:
            return (b'{"status":"UNKNOWN","reason":"SERIALIZATION_FAILED",'
                    b'"control_authority":"NONE","gate_acceptance":"NOT_ASSESSED",'
                    b'"coverage_complete":false,"evidence_omitted":true,"rows":[]}')
