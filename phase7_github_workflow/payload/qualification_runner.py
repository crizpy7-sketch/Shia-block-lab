"""Prepared six-case synthetic qualification; execution needs separate authority.

This program is the constrained workload, not its external Docker supervisor.
Only the six fixed cases below may create children. JSONL writes are bounded
observations, not durable receipts, VM-disposal evidence, or gate acceptance.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import time
import types

HERE = Path(__file__).resolve().parent
SOURCES = {
    'transport_adapter.py': '15f1709aeda2734cd0e1b514d25311c022d630a84330c8b017e7fbc2363b6fd4',
    'fake_child.py': 'ed9d43d3f1a05cad6479a6500e08e0aaab44876ac34ff3e4ef92243ccfb27b8d',
    'dependencies/event_adapter.py': '6d52fb2a32a0b81df30bc0d30c2ec820421c3048c990806c2af808d5eb83fae8',
}
CASE_NAMES = ('NORMAL_VM', 'NORMAL_PSI', 'MALFORMED_RESULT',
              'OVERSIZED_RESULT', 'FULL_PIPE_IGNORED_TERM', 'EXPIRED_DEADLINE')
CASE_CAP = 16384  # Combined JSONL records for one case, including newlines.
TOTAL_CAP = 262144
CHILD_CAP = 12
SESSION_SECONDS = 2.0


def scope():
    return dict(schema=1, provenance='SYNTHETIC', scope='SIX_CASE_QUALIFICATION',
                historical_first_run_closure='UNKNOWN', gate_acceptance='NOT_ASSESSED',
                outer_environment_disposal='EXTERNAL_EVIDENCE_REQUIRED',
                durable_delivery='NOT_ESTABLISHED')


class ReportingFailure(Exception):
    pass


class CheckFailure(Exception):
    def __init__(self, code):
        self.code = code  # Only fixed literals supplied by this file.


def need(condition, code):
    if not condition:
        raise CheckFailure(code)


def failure(error):
    if type(error) is CheckFailure:
        return error.code
    if isinstance(error, ReportingFailure):
        return 'REPORTING_FAILED'
    if isinstance(error, KeyboardInterrupt):
        return 'INTERRUPTED'
    if isinstance(error, SystemExit):
        return 'UNEXPECTED_EXIT'
    if isinstance(error, AssertionError):
        return 'ASSERTION'
    return 'EXCEPTION'  # Never stringify exceptions, payloads or tracebacks.


class Output:
    """One Python write per record; no application retry or flush/ack wait."""
    def __init__(self):
        self.total = 0
        self.per_case = {name: 0 for name in CASE_NAMES}
        self.failed = False

    def emit(self, kind, *, case=None, **fields):
        if self.failed:
            raise ReportingFailure()
        try:
            record = dict(scope(), record=kind, case=case,
                          observed_mono_s=time.monotonic(), **fields)
            raw = json.dumps(record, separators=(',', ':'), sort_keys=True,
                             ensure_ascii=True, allow_nan=False).encode('ascii') + b'\n'
            if (len(raw) > CASE_CAP or self.total + len(raw) > TOTAL_CAP
                    or case is not None and self.per_case[case] + len(raw) > CASE_CAP):
                raise ReportingFailure()
            # Account attempted bytes even if only a prefix is retained.
            self.total += len(raw)
            if case is not None:
                self.per_case[case] += len(raw)
            if os.write(1, raw) != len(raw):
                raise ReportingFailure()
        except BaseException:
            self.failed = True
            raise ReportingFailure() from None


def load_transport():
    """Read/hash bounded source, then execute the same transport bytes.

    The external immutable mount binds the child's later pathname opens.
    No unverified source or old suite is imported by this entrypoint.
    """
    raw_sources = {}
    for relative, digest in SOURCES.items():
        path = HERE / relative
        need(not path.is_symlink(), 'SOURCE_SYMLINK')
        with path.open('rb') as source:
            raw = source.read(65537)
        need(len(raw) <= 65536 and hashlib.sha256(raw).hexdigest() == digest,
             'SOURCE_HASH_MISMATCH')
        raw_sources[relative] = raw
    module = types.ModuleType('transport_adapter')
    module.__file__ = str(HERE / 'transport_adapter.py')
    need('transport_adapter' not in sys.modules, 'PRELOADED_TRANSPORT')
    sys.modules['transport_adapter'] = module
    exec(compile(raw_sources['transport_adapter.py'], module.__file__, 'exec'), module.__dict__)
    need((module.READY_CAP, module.TERM_GRACE, module.REAP_CAP,
          module.RESULT_WAIT_CAP, module.EMERGENCY_CAP) == (.4, .05, .2, .2, 2.),
         'SUBORDINATE_BOUND_MISMATCH')
    return module


def event(kind='OPEN', seq=0, at=10.0, data=None):
    return dict(kind=kind, invocation='qualification', window='run', phase='RUNTIME',
                epoch='epoch1', seq=seq, source_mono_s=at, delivery_mono_s=at,
                data={} if data is None else data)


def prepare(h, case):
    """All packet encoding occurs before the original Session clock starts."""
    items = [event()]
    if case == 'NORMAL_VM':
        items += [event('SAMPLE_BEGIN', 0, 10.1, {'sample_id': 0}),
                  event('COUNTERS', 1, 10.2, dict(sample_id=0, previous_mono_s=9.2,
                        mono_s=10.2, mem_available_bytes=100000,
                        swap_in_pages=3, swap_out_pages=0)),
                  event('COMPLETE', 2, 10.3, {'sample_id': 0})]
    elif case == 'NORMAL_PSI':
        for seq, before, some, full in ((0, 10.1, 100, 20), (1, 11.1, 130, 25)):
            items.append(event('PSI', seq, before + .1, dict(some_total_us=some,
                full_total_us=full, read_before_mono_s=before,
                read_after_mono_s=before + .1, payload_status='PARSED', payload_bytes=100)))
    elif case == 'FULL_PIPE_IGNORED_TERM':
        items = [event() for _ in range(h.FRAME_COUNT_CAP)]
    elif case == 'EXPIRED_DEADLINE':
        items = []
    packets = [h.frame(i, item, padded=case == 'FULL_PIPE_IGNORED_TERM')
               for i, item in enumerate(items)]
    need(len(packets) <= 128 and all(len(x) <= 4096 for x in packets)
         and sum(map(len, packets)) <= 524288, 'INPUT_BOUND')
    return items, packets


def identities(session):
    # Original Popen objects remain owned by Session. These copied PID values
    # are container-local observations, never authority for later PID lookup.
    return {role: dict(pid=child.pid, returncode=child.returncode,
                       identity_scope='ORIGINAL_POPEN_CONTAINER_LOCAL_PID')
            for role, child in session._children.items()}


def check_order(result):
    names = [item['event'] for item in result['trace']]
    need('CONTROL_STOP_SELECTED' in names and 'WORKER_TERM_ATTEMPT' in names,
         'WORKER_TERM_MISSING')
    term = names.index('WORKER_TERM_ATTEMPT')
    need(names.index('CONTROL_STOP_SELECTED') < term < names.index('INPUT_EOF_CLOSE'),
         'CANCELLATION_ORDER')
    if 'RESULT_CAPTURE_BEGIN' in names:
        need(names.index('WORKER_SETTLE_END') < names.index('RESULT_CAPTURE_BEGIN'),
             'CAPTURE_BEFORE_WORKER_SETTLED')
    need(all(term < i for i, name in enumerate(names)
             if name.startswith(('COLLECTOR_', 'RESULT_'))), 'OBSERVER_BEFORE_TERM')
    return names


def check_case(h, case, result, supplied, packets):
    names = check_order(result)
    need(result['coverage_complete'] is False and result['safety_assessment'] == 'NOT_ASSESSED',
         'AUTHORITY_CHANGED')
    if case == 'EXPIRED_DEADLINE':
        need(result['deadline_exhausted'] is True and result['worker_closure'] == 'UNKNOWN'
             and result['collector_closure'] == 'UNKNOWN', 'EXPIRED_CLOSURE_UPGRADED')
        need('RESULT_CAPTURE_BEGIN' not in names and result['child_result'] is None
             and result['output_reason'] == 'ORIGINAL_DEADLINE_EXHAUSTED', 'EXPIRED_OUTPUT_ACCEPTED')
        return
    need(all(result[key] == 'REAPED_WITHIN_DEADLINE'
             for key in ('worker_closure', 'collector_closure'))
         and result['deadline_exhausted'] is False, 'ORIGINAL_CLOSURE_UNCONFIRMED')
    if case in ('MALFORMED_RESULT', 'OVERSIZED_RESULT'):
        expected = 'OUTPUT_INVALID' if case == 'MALFORMED_RESULT' else 'OUTPUT_OVERSIZED'
        # Preserve another rejection as actual evidence, but do not count it
        # as qualification of the intended oversize condition or retry it.
        need(result['output_status'] == 'UNKNOWN' and result['child_result'] is None,
             'INVALID_OUTPUT_ACCEPTED')
        need(result['output_reason'] == expected, 'EXPECTED_REJECTION_NOT_OBSERVED')
        return
    if case == 'FULL_PIPE_IGNORED_TERM':
        t = result['transport']
        need(t['attempts'] == 128 and t['dropped_full'] > 0 and t['parent_loss'] is True,
             'FINITE_FULL_PIPE_NOT_OBSERVED')
        need(result['output_status'] == 'UNKNOWN' and result['child_result'] is None
             and result['output_reason'] == 'PARENT_TRANSPORT_LOSS'
             and t['processing'] == 'UNKNOWN', 'LOSS_NOT_STICKY')
        need(names.index('WORKER_KILL_ATTEMPT') < names.index('RESULT_CAPTURE_BEGIN'),
             'KILL_NOT_BEFORE_CAPTURE')
        need(result['returncodes'] == {'worker': -signal.SIGKILL, 'collector': -signal.SIGKILL},
             'IGNORED_TERM_EXIT_UNEXPECTED')
        return
    need(result['output_status'] == 'DESCRIPTIVE_RESULT', 'NORMAL_OUTPUT_UNAVAILABLE')
    child = result['child_result']
    need(child['input_eof'] is True and child['transport_error'] is None
         and child['frames'] == len(packets) and child['bytes_received'] == sum(map(len, packets)),
         'TRANSFER_COMPLETION_MISMATCH')
    need(result['transport']['buffered'] == len(packets)
         and result['transport']['parent_loss'] is False, 'NORMAL_TRANSFER_LOSS')
    adapter = child['adapter']
    need(adapter['control_authority'] == 'NONE' and adapter['gate_acceptance'] == 'NOT_ASSESSED'
         and adapter['coverage_complete'] is False, 'ADAPTER_AUTHORITY_CHANGED')
    if case == 'NORMAL_VM':
        rows = [row for row in adapter['rows'] if row['disposition'] == 'COMPLETE']
        need(len(rows) == 1, 'VM_COMPLETION_MISSING')
        row = rows[0]
        need(row['vm'] == supplied[2]['data'] and row['source_mono_s'] == 10.3
             and row['delivery_mono_s'] == 10.3 and 'selected_legacy_reason' not in row,
             'VM_SOURCE_CHANGED')
    else:
        row = adapter['rows'][-1]
        need(row['pressure_status'] == 'DESCRIPTIVE_DELTA'
             and row['delta_us'] == {'some': 30, 'full': 5}
             and row['data'] == supplied[-1]['data'], 'PSI_DELTA_OR_SOURCE_CHANGED')
        need(abs(row['elapsed_seconds'][0] - .9) < 1e-9
             and abs(row['elapsed_seconds'][1] - 1.1) < 1e-9
             and row['vm_psi_association'] == 'UNESTABLISHED'
             and row['atomicity'] == 'NOT_ATTESTED', 'PSI_ASSOCIATION_OR_BOUNDS_CHANGED')


def run_case(h, output, case, total_children):
    session = None
    result = emergency = None
    primary = cleanup_failure = reporting_failure = None
    stop_attempted = False
    observed_children = {}
    setup = None
    emergency_began = emergency_ended = None
    try:
        need(h._ACTIVE_OWNER is None and total_children <= CHILD_CAP - 2, 'OWNER_OR_CHILD_BUDGET')
        supplied, packets = prepare(h, case)
        output.emit('CASE_INTENT', case=case, fixture_budget_seconds=SESSION_SECONDS,
                    planned_children=2, planned_frames=len(packets),
                    prepared_stream_sha256=hashlib.sha256(b''.join(packets)).hexdigest())
        h.CASE_LABEL = case
        session = h.Session(budget_s=SESSION_SECONDS, child_ttl_s=5)
        output.emit('SESSION_CREATED', case=case, original_deadline=session.deadline)
        worker = 'ignore_term' if case in ('FULL_PIPE_IGNORED_TERM', 'EXPIRED_DEADLINE') else 'cooperative'
        collector = {'MALFORMED_RESULT': 'bad_result', 'OVERSIZED_RESULT': 'oversize_result',
                     'FULL_PIPE_IGNORED_TERM': 'stall', 'EXPIRED_DEADLINE': 'stall'}.get(case, 'normal')
        session.start(worker=worker, collector=collector)
        observed_children = identities(session)
        setup = session.inspection()['setup']
        output.emit('OWNED_CHILDREN', case=case, original_deadline=session.deadline,
                    children=observed_children, setup=setup,
                    identity_snapshot_point='AFTER_SETUP_BEFORE_OFFERS')
        need(setup.get('status') == 'READY' and len(observed_children) == 2, 'SETUP_NOT_READY')
        for packet in packets:
            session.offer(packet)
        if case == 'EXPIRED_DEADLINE':
            # Deliberately expire this SAME original two-second deadline.
            time.sleep(max(0.0, session.deadline - time.monotonic()) + .01)
        stop_attempted = True
        result = session.stop()
        check_case(h, case, result, supplied, packets)
    except BaseException as error:
        primary = failure(error)
    finally:
        if session is not None:
            observed_children = identities(session)
            # Capture primary first. Later cleanup failures cannot replace it.
            # start() itself attempts stop on SETUP_EXCEPTION. Do not retry
            # a stop that already raised; use any cached evidence, then the
            # separately bounded emergency teardown of the same handles.
            internal_stop_attempted = session._setup.get('status') == 'SETUP_EXCEPTION'
            if result is None and session._result is not None:
                result = session._result
            if result is None and not stop_attempted and not internal_stop_attempted:
                try:
                    stop_attempted = True
                    result = session.stop()
                except BaseException:
                    cleanup_failure = 'STOP_EXCEPTION'
            elif result is None:
                cleanup_failure = 'STOP_EXCEPTION'
            emergency_began = time.monotonic()
            try:
                emergency = session.emergency_cleanup()  # Exactly one separate attempt.
            except BaseException:
                cleanup_failure = cleanup_failure or 'EMERGENCY_EXCEPTION'
                emergency = session._emergency  # May retain partial closure facts.
            emergency_ended = time.monotonic()
            observed_children = identities(session)
            if (emergency is None or set(emergency['children']) != set(observed_children)
                    or any(value != 'REAPED' for value in emergency['children'].values())
                    or h._ACTIVE_OWNER is not None):
                cleanup_failure = cleanup_failure or 'EMERGENCY_CLOSURE_UNCONFIRMED'
            if result is not None:
                try:
                    need(session.stop() == result, 'STOP_EVIDENCE_CHANGED_AFTER_EMERGENCY')
                except BaseException:
                    cleanup_failure = cleanup_failure or 'STOP_EVIDENCE_CHANGED_AFTER_EMERGENCY'
    total_children += len(observed_children)
    if total_children > CHILD_CAP:
        primary = primary or 'TOTAL_CHILD_BOUND'
    retained_stop = None
    if result is not None:
        try:
            # Reuse the frozen bounded report; its overflow fallback remains
            # explicit UNKNOWN rather than manufacturing complete evidence.
            raw_stop = session.serialize()
            need(len(raw_stop) <= h.REPORT_CAP, 'STOP_REPORT_CAP')
            retained_stop = json.loads(raw_stop)
            need(retained_stop.get('evidence_omitted') is not True, 'STOP_EVIDENCE_OMITTED')
        except BaseException:
            reporting_failure = 'STOP_SERIALIZATION_FAILED_OR_OMITTED'
    completed = (primary is None and cleanup_failure is None and reporting_failure is None
                 and session is not None)
    output.emit('CASE_RESULT', case=case, assertions='MET' if completed else 'NOT_MET',
                primary_failure=primary, cleanup_failure=cleanup_failure,
                reporting_failure=reporting_failure, original_stop=retained_stop, emergency=emergency,
                emergency_observation_bounds=[emergency_began, emergency_ended],
                children=observed_children, fixture_children_total=total_children,
                child_self_expiry='BACKUP_ONLY_NOT_CLOSURE_PROOF')
    return completed, total_children


def main():
    output = Output()
    completed = children = 0
    try:
        need(len(sys.argv) == 1, 'NO_ARGUMENTS_ALLOWED')
        output.emit('RUN_INTENT', case_order=list(CASE_NAMES), source_sha256=SOURCES,
                    fixture_child_cap=CHILD_CAP, original_session_seconds=SESSION_SECONDS,
                    external_watchdog='REQUIRED_25_SECONDS_PLUS_5_SECONDS_DISPOSAL_OBSERVATION')
        h = load_transport()
        for case in CASE_NAMES:
            ok, children = run_case(h, output, case, children)
            if not ok:
                break  # No further children after failure or uncertain cleanup.
            completed += 1
        output.emit('RUN_RESULT', completed_cases=completed, fixture_children_total=children,
                    assertions='MET' if completed == 6 else 'NOT_MET',
                    qualification_acceptance='EXTERNAL_REVIEW_REQUIRED',
                    owner_registry_empty=h._ACTIVE_OWNER is None,
                    exported_bytes_before_this_record=output.total)
        return 0 if completed == 6 and children == 12 and h._ACTIVE_OWNER is None else 1
    except BaseException as error:
        # Case cleanup occurs in run_case before reporting failures escape.
        # A failed output descriptor gets no retries or replacement success.
        if not output.failed:
            try:
                output.emit('RUN_FAILURE', failure=failure(error), completed_cases=completed,
                            fixture_children_total=children, assertions='NOT_MET')
            except BaseException:
                pass
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
