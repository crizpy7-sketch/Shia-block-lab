"""Fixed sudo monitor; actual observations and explicit policy, never admission."""
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time

from phase7_chrony_capability_probe import entry as probe
from phase7_observed_clock_model import model
from phase7_observed_clock_model.validation import private_binding, _client_identity
from . import collector, monitor_facts
from .capture import Budget, CaptureResult, CollectionError, COMMAND_NS, CLEANUP_NS, PHASE_NS, ENV, exact_ns, need
from .sources import parse_sources, match_tracking

MODE = 'NONINTERACTIVE_SUDO_MONITOR'
COLLECTION_NS = 6 * COMMAND_NS
FACTS_HELPER = str(Path(__file__).resolve().with_name('monitor_facts.py'))
PREFIX = ('/usr/bin/sudo', '-n', '--', '/usr/bin/timeout', '--signal=TERM', '--kill-after=0.1s')
COMMANDS = {'VERSION': ('/usr/bin/chronyc', '--version'),
    'TRACKING': PREFIX + ('0.7s', '/usr/bin/chronyc', '-n', '-c', '-h', '/run/chrony/chronyd.sock', 'tracking'),
    'SOURCES': PREFIX + ('0.7s', '/usr/bin/chronyc', '-n', '-c', '-h', '/run/chrony/chronyd.sock', 'sources'),
    'FACTS': PREFIX + ('0.8s', '/usr/bin/python3', '-I', '-S', '-B', FACTS_HELPER)}
DIGEST = re.compile(r'[0-9a-f]{64}')


def needs_deadline_hold(*, reaped, eof, closed, parent_killed, returncode):
    return not (reaped and eof and closed) or parent_killed or returncode in (124, 137)


def _hold_until_deadline(child, deadline_ns, clock, *, _sleep=None):
    """Retain original ownership to its bound; a missing handle stays unknown."""
    sleeper = time.sleep if _sleep is None else _sleep
    while True:
        now = clock.monotonic_ns()
        if now >= deadline_ns:
            return
        try:
            if child.poll() is not None:
                child.wait(timeout=0)
        except Exception:
            pass
        sleeper(min(0.02, (deadline_ns - now) / 10**9))


def _capture_frame(kind, *, owner, clock, required_reserve_ns, _popen=None, _selector=None, _sleep=None):
    """Fixed tuples only; direct wrapper closure does not attest root descendants."""
    need(kind in COMMANDS, 'COMMAND_REFUSED')
    budget = Budget(owner, clock)
    need(exact_ns(required_reserve_ns), 'RESERVE_INVALID')
    started = budget.check()
    need(budget.deadline_ns - started > required_reserve_ns + COMMAND_NS, 'COLLECTION_RESERVE')
    limit = started + COMMAND_NS
    child = selector = None
    buffers, counts = [bytearray(), bytearray()], [0, 0]
    code, reaped, closed, eof, capped, exitcode, finished = 'OK', False, True, False, False, None, started
    parent_killed = False

    def remaining():
        now = budget.check()
        need(now < limit - CLEANUP_NS, 'COMMAND_DEADLINE')
        return (limit - CLEANUP_NS - now) / 10**9

    try:
        remaining()
        create = subprocess.Popen if _popen is None else _popen
        child = create(COMMANDS[kind], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, shell=False, env=dict(ENV), close_fds=True, start_new_session=False)
        selector = selectors.DefaultSelector() if _selector is None else _selector()
        for index, pipe in enumerate((child.stdout, child.stderr)):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, index)
        while True:
            wait = min(0.02, remaining())
            if not selector.get_map():
                eof = True
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
                counts[key.data] = min(4097, counts[key.data] + len(chunk))
                if sum(map(len, buffers)) + len(chunk) > 4096:
                    capped = True
                    buffers = [bytearray(), bytearray()]
                    raise CollectionError('OUTPUT_CAP')
                buffers[key.data].extend(chunk)
        remaining()
        need(exitcode == 0, 'COMMAND_FAILED')
        need(not buffers[1], 'STDERR_PRESENT')
    except CollectionError as error:
        code = error.code
    except Exception:
        code = 'PROCESS_OR_CAPTURE_FAILED'
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
                        parent_killed = True
                        child.kill()
                    left = max(0, limit - budget.check())
                    exitcode = child.wait(timeout=min(CLEANUP_NS, left) / 10**9)
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
        if needs_deadline_hold(reaped=reaped, eof=eof, closed=closed,
                parent_killed=parent_killed, returncode=exitcode):
            _hold_until_deadline(child, budget.deadline_ns, clock, _sleep=_sleep)
        try:
            finished = budget.check()
            if finished >= limit:
                code = 'COMMAND_CLOSURE_DEADLINE'
        except Exception:
            finished, code = None, 'PHASE_OR_CLOCK_FAILED'
    if not (reaped and closed):
        code = 'DIRECT_RESOURCE_CLOSURE_UNPROVEN'
    return CaptureResult({'code': code, 'returncode': exitcode,
        'stdout_bytes': counts[0], 'stderr_bytes': counts[1], 'bytecounts_exact': not capped and eof,
        'direct_child_reaped': reaped, 'parent_pipes_closed': closed, 'pipe_eof_observed': eof,
        'descendant_cleanup_proven': False, 'containment_uncertain': True,
        'started_monotonic_ns': started, 'finished_monotonic_ns': finished},
        bytes(buffers[0]) if code == 'OK' else b'')


def _capture(kind, *, owner, clock, required_reserve_ns):
    return _capture_frame(kind, owner=owner, clock=clock, required_reserve_ns=required_reserve_ns)


class FixedMonitorBoundary:
    monotonic_ns = staticmethod(time.monotonic_ns)
    time_ns = staticmethod(time.time_ns)

    def namespace_identity(self):
        value = os.readlink('/proc/self/ns/time')
        need(re.fullmatch(r'time:\[[0-9]{1,20}\]', value) is not None
             and os.readlink('/proc/self/ns/time_for_children') == value, 'MONITOR_NAMESPACE_INVALID')
        return value

    def binary_identity(self):
        return tuple(probe.binary_identity(path) for path in (probe.CHRONYC, probe.SUDO, probe.TIMEOUT))

    def capture(self, kind, owner, required_reserve_ns):
        return _capture(kind, owner=owner, clock=self, required_reserve_ns=required_reserve_ns)


def _public():
    return {'schema': 1, 'record': 'ORDINARY_CHRONY_MONITOR_SUMMARY', 'status': 'REFUSED',
        'code': 'NOT_STARTED', 'provider_mode': MODE, 'provider_invocations': 0,
        'kernel_reads': 0, 'kernel_utc_authority_claimed': False,
        'provenance': 'ACTUAL_LOCAL_MONITOR_WITH_UNVERIFIED_OPERATING_PREMISES',
        'direct_resource_closure_observed': False, 'descendant_cleanup_proven': False,
        'loaded_config_verified': False, 'source_truth_verified': False,
        'alignment_established': False, 'execution_authorized': False,
        'control_authority': 'NONE', 'phase7_acceptance': 'BLOCKED'}


def _facts(capture):
    def pairs(items):
        need(len(items) == len(dict(items)), 'MONITOR_FACTS_INVALID')
        return dict(items)
    try:
        need(type(capture['stdout']) is bytes and capture['stdout'].isascii(), 'MONITOR_FACTS_INVALID')
        value = monitor_facts.validate(json.loads(capture['stdout'], object_pairs_hook=pairs))
    except Exception:
        raise CollectionError('MONITOR_FACTS_INVALID') from None
    return value


def collect_private(*, owner, runtime_sha256, boundary=None, required_reserve_ns):
    public, private = _public(), None
    boundary = FixedMonitorBoundary() if boundary is None else boundary
    try:
        need(type(runtime_sha256) is str and DIGEST.fullmatch(runtime_sha256) is not None, 'RUNTIME_IDENTITY_INVALID')
        need(exact_ns(required_reserve_ns) and required_reserve_ns < PHASE_NS, 'RESERVE_INVALID')
        budget, remaining = Budget(owner, boundary), COLLECTION_NS
        need(budget.deadline_ns - budget.check() > required_reserve_ns + remaining, 'COLLECTION_RESERVE')
        identity = boundary.binary_identity()
        namespace = boundary.namespace_identity()
        captures, metadata, sequence = [], [], []

        def observe(kind):
            nonlocal remaining
            m0 = budget.check()
            need(budget.deadline_ns - m0 > required_reserve_ns + remaining, 'COLLECTION_RESERVE')
            w0 = boundary.time_ns()
            public['provider_invocations'] += 1
            value = boundary.capture(kind, owner, required_reserve_ns + remaining - COMMAND_NS)
            w1, m1 = boundary.time_ns(), budget.check()
            remaining -= COMMAND_NS
            need(budget.deadline_ns - m1 > required_reserve_ns + remaining, 'COLLECTION_RESERVE')
            bracket = {'monotonic_before_ns': m0, 'realtime_before_ns': w0,
                'realtime_after_ns': w1, 'monotonic_after_ns': m1}
            collector._bracket(bracket)
            record = collector._capture_result(value, bracket, kind)
            sequence.append(record)
            (metadata if kind == 'FACTS' else captures).append(record)
            return record

        version = probe.parse_version(observe('VERSION')['stdout'])
        need(version == '4.5', 'CLIENT_VERSION_UNSUPPORTED')
        before = _facts(observe('FACTS'))
        first = observe('TRACKING')
        sources = parse_sources(observe('SOURCES')['stdout'])
        last = observe('TRACKING')
        classification = match_tracking(first['stdout'], last['stdout'], sources)
        for capture in (first, last):
            tracking = probe.parse_tracking(capture['stdout'], version)
            need(tracking['leap_report'] == 'NORMAL' and 1 <= tracking['stratum'] <= 15, 'TRACKING_UNSYNCHRONIZED')
        after = _facts(observe('FACTS'))
        need(before == after, 'MONITOR_DAEMON_OR_CONFIG_CHANGED')
        need(boundary.binary_identity() == identity, 'CLIENT_BINARY_CHANGED')
        need(boundary.namespace_identity() == namespace == before['time_namespace'], 'MONITOR_NAMESPACE_INVALID')
        span = dict(sequence[0]['bracket'])
        span.update(realtime_after_ns=sequence[-1]['bracket']['realtime_after_ns'],
                    monotonic_after_ns=sequence[-1]['bracket']['monotonic_after_ns'])
        collector._bracket(span)
        private = {'schema': 1, 'record': 'PRIVATE_ORDINARY_CHRONY_MONITOR', 'provider_mode': MODE,
            'runtime_sha256_supplied': runtime_sha256, 'client_version': version, 'captures': captures,
            'metadata_captures': metadata, 'facts': before, 'source_projection': sources,
            'client_path_identity': identity, 'time_namespace': namespace, 'owner_started_ns': budget.started_ns,
            'owner_deadline_ns': budget.deadline_ns, 'required_reserve_ns': required_reserve_ns}
        public.update(status='OBSERVATION_COMPLETE_UNQUALIFIED', code='MONITORED_NOT_ADMITTED',
                      direct_resource_closure_observed=True)
        need(budget.deadline_ns - budget.check() > required_reserve_ns, 'COLLECTION_RESERVE')
    except Exception:
        public.update(status='REFUSED', code='MONITOR_COLLECTION_REFUSED', direct_resource_closure_observed=False)
        private = None
    return collector.CollectionResult(public, private)


def validate_observation(record, runtime):
    binding = private_binding(record)
    keys = {'schema', 'record', 'provider_mode', 'runtime_sha256_supplied', 'client_version', 'captures',
        'metadata_captures', 'facts', 'source_projection', 'client_path_identity', 'time_namespace', 'owner_started_ns',
        'owner_deadline_ns', 'required_reserve_ns'}
    need(type(record) is dict and set(record) == keys and type(record['schema']) is int and record['schema'] == 1
         and record['record'] == 'PRIVATE_ORDINARY_CHRONY_MONITOR' and record['provider_mode'] == MODE
         and record['runtime_sha256_supplied'] == runtime and record['client_version'] == '4.5', 'MONITOR_RECORD_INVALID')
    need(exact_ns(record['owner_started_ns']) and exact_ns(record['owner_deadline_ns'])
         and record['owner_deadline_ns'] - record['owner_started_ns'] == PHASE_NS
         and exact_ns(record['required_reserve_ns']) and record['required_reserve_ns'] < PHASE_NS, 'MONITOR_RECORD_INVALID')
    identity = record['client_path_identity']
    need(type(identity) is tuple and len(identity) == 3, 'MONITOR_RECORD_INVALID')
    for group in identity:
        _client_identity(group)
    captures, metadata = record['captures'], record['metadata_captures']
    need(type(captures) is list and len(captures) == 4 and type(metadata) is list and len(metadata) == 2, 'MONITOR_RECORD_INVALID')
    sequence = [captures[0], metadata[0], *captures[1:], metadata[1]]
    previous = record['owner_started_ns']
    for index, (item, kind) in enumerate(zip(sequence, ('VERSION', 'FACTS', 'TRACKING', 'SOURCES', 'TRACKING', 'FACTS'))):
        need(type(item) is dict and set(item) == {'kind', 'capture', 'bracket', 'stdout'} and item['kind'] == kind, 'MONITOR_RECORD_INVALID')
        collector._bracket(item['bracket'])
        collector._capture_result(CaptureResult(item['capture'], item['stdout']), item['bracket'], kind)
        bracket = item['bracket']
        need(previous <= bracket['monotonic_before_ns'] <= bracket['monotonic_after_ns'] < record['owner_deadline_ns']
             and bracket['monotonic_after_ns'] - bracket['monotonic_before_ns'] < COMMAND_NS
             and record['owner_deadline_ns'] - bracket['monotonic_before_ns'] > record['required_reserve_ns'] + (6 - index) * COMMAND_NS
             and record['owner_deadline_ns'] - bracket['monotonic_after_ns'] > record['required_reserve_ns'] + (5 - index) * COMMAND_NS, 'MONITOR_RECORD_INVALID')
        previous = bracket['monotonic_after_ns']
    need(probe.parse_version(captures[0]['stdout']) == '4.5', 'MONITOR_RECORD_INVALID')
    sources = parse_sources(captures[2]['stdout'])
    classification = match_tracking(captures[1]['stdout'], captures[3]['stdout'], sources)
    need(sources == record['source_projection'] and _facts(metadata[0]) == _facts(metadata[1]) == record['facts'], 'MONITOR_RECORD_INVALID')
    need(type(record['time_namespace']) is str and record['time_namespace'] == record['facts']['time_namespace'], 'MONITOR_NAMESPACE_INVALID')
    span = dict(sequence[0]['bracket'])
    span.update(realtime_after_ns=sequence[-1]['bracket']['realtime_after_ns'], monotonic_after_ns=sequence[-1]['bracket']['monotonic_after_ns'])
    collector._bracket(span)
    return {'captures': captures, 'sources': sources, 'source_classification': classification,
            'span': span, 'binding': binding, 'facts': record['facts']}


def validate_profile(profile):
    keys = {'schema', 'record', 'provider_mode', 'profile_id', 'valid_from_us', 'valid_until_us',
        'config', 'source_accuracy_bound_ns', 'limits', 'continuity', 'review_evidence_sha256'}
    need(type(profile) is dict and set(profile) == keys and type(profile['schema']) is int and profile['schema'] == 1
         and all(type(profile[key]) is str for key in ('record', 'provider_mode', 'profile_id'))
         and profile['record'] == 'ORDINARY_CHRONY_MONITOR_OPERATING_PROFILE'
         and profile['provider_mode'] == MODE and profile['profile_id'] == 'CANONICAL_NOBLE_CHRONY45_HYPERV_PHC', 'MONITOR_PROFILE_INVALID')
    need(all(type(profile[key]) is int and 0 <= profile[key] < 10**18 for key in ('valid_from_us', 'valid_until_us'))
         and profile['valid_from_us'] <= profile['valid_until_us'] and type(profile['review_evidence_sha256']) is str
         and DIGEST.fullmatch(profile['review_evidence_sha256']) is not None, 'MONITOR_PROFILE_INVALID')
    config = profile['config']
    need(type(config) is dict and set(config) == {'loaded_config_equivalence_assumed', 'no_config_edits_assumed'}
         and all(value is True for value in config.values()), 'MONITOR_PROFILE_MISMATCH')
    need(type(profile['continuity']) is dict and set(profile['continuity']) == {'no_unaccounted_steps',
         'no_restart_or_source_change', 'allow_retrospective_projection'}
         and all(value is True for value in profile['continuity'].values()), 'MONITOR_PROFILE_INVALID')
    need(type(profile['source_accuracy_bound_ns']) is int and profile['source_accuracy_bound_ns'] == 1_000_000_000
         and type(profile['limits']) is dict and profile['limits'] == {'rate_bound_ppb': 1_000_000, 'max_sample_age_ns': 16_000_000_000}
         and all(type(value) is int for value in profile['limits'].values()), 'MONITOR_PROFILE_INVALID')
    return profile


def materialize_policy(profile, observed, runtime, low, high):
    validate_profile(profile)
    facts = observed['facts']
    refclocks = facts['configuration']['refclocks']
    need(len(refclocks) == 1 and refclocks[0][0] == 'PHC'
         and refclocks[0][1] in ('/dev/ptp_hyperv', facts['hyperv']['resolved']), 'MONITOR_PROFILE_MISMATCH')
    options = refclocks[0][2:]
    need(len(options) % 2 == 0 and len(set(options[::2])) == len(options[::2]), 'MONITOR_PROFILE_MISMATCH')
    options = dict(zip(options[::2], options[1::2]))
    need(set(options) <= {'poll', 'dpoll', 'offset', 'refid', 'precision'} and options.get('poll') == '3'
         and options.get('dpoll') == '-2' and options.get('offset', '0') in ('0', '0.0'), 'MONITOR_PROFILE_MISMATCH')
    label = options.get('refid', 'PHC0')
    need(re.fullmatch(r'[A-Za-z0-9_-]{1,4}', label) is not None and observed['sources']['selected'][:3] == ('#', '*', label)
         and observed['sources']['selected'][4] == '3' and int(observed['sources']['selected'][6]) <= 16, 'MONITOR_PROFILE_MISMATCH')
    for capture in (observed['captures'][1], observed['captures'][3]):
        numbers = probe.parse_tracking(capture['stdout'], '4.5')['numbers']
        need(all(abs(int(numbers[key])) <= 100_000_000 for key in ('system_correction_ns', 'last_offset_ns',
             'rms_offset_ns', 'root_delay_ns', 'root_dispersion_ns')), 'MONITOR_PROFILE_MISMATCH')
        need(all(abs(int(numbers[key])) <= 1_000_000 for key in ('frequency_milli_ppm',
             'residual_frequency_milli_ppm', 'skew_milli_ppm')), 'MONITOR_PROFILE_MISMATCH')
    first = observed['captures'][1]['stdout'].decode('ascii').rstrip('\n').split(',')
    policy = {key: profile[key] for key in ('schema', 'valid_from_us', 'valid_until_us',
              'limits', 'continuity', 'review_evidence_sha256')}
    policy.update(record='EXPLICIT_CHRONY45_POLICY_CLAIMS', runtime_sha256=runtime,
        source={'mode': '#', 'reference_id': first[0], 'address': first[1],
            'source_accuracy_bound_ns': 1_000_000_000, 'utc_basis': 'UTC_ERROR_INCLUDES_TIMESCALE_CONVERSION'},
        daemon={'version': '4.5', 'runtime_sha256': runtime,
            'association_evidence_sha256': private_binding(facts),
            'loaded_config_evidence_sha256': facts['config_sha256']})
    model._policy(policy, observed, runtime, low, high)
    return policy


def evaluate_observation(record, *, expected_runtime_sha256, profile, valid_from_us, valid_until_us):
    public, private = model._public(), None
    basis = 'ACTUAL_CHRONY_MONITOR_WITH_EXPLICIT_OPERATING_POLICY'
    public.update(basis=basis, provenance='MONITOR_OBSERVATION_AND_EXTERNAL_PREMISES_NOT_AUTHENTICATED',
                  kernel_utc_authority_claimed=False, provider_mode=MODE)
    try:
        observed = validate_observation(record, expected_runtime_sha256)
        policy = materialize_policy(profile, observed, expected_runtime_sha256, valid_from_us, valid_until_us)
        policy_hash, low, high, retrospective = model._policy(policy, observed, expected_runtime_sha256, valid_from_us, valid_until_us)
        snapshots = [model._snapshot(observed['captures'][index], policy, low, high) for index in (1, 3)]
        total = max(int(item['total_utc_error_bound_ns']) for item in snapshots)
        public.update(status='CONDITIONAL_MODEL_ONLY', code='CONDITIONAL_OBSERVATION_EVALUATED',
            source_classification=observed['source_classification'], retrospective_projection_required=retrospective,
            snapshots=snapshots, total_utc_error_bound_ns=str(total))
        private = {'schema': 1, 'record': 'PRIVATE_CONDITIONAL_OBSERVED_CLOCK_MODEL',
            'runtime_sha256_supplied': expected_runtime_sha256, 'observation_sha256': observed['binding'],
            'policy_sha256': policy_hash, 'review_evidence_sha256_supplied': profile['review_evidence_sha256'],
            'valid_from_us': valid_from_us, 'valid_until_us': valid_until_us,
            'total_utc_error_bound_ns': total, 'snapshots': snapshots, 'basis': basis,
            'alignment_established': False, 'execution_authorized': False, 'control_authority': 'NONE', 'phase7_acceptance': 'BLOCKED'}
    except Exception:
        public.update(status='REFUSED', code='MONITOR_MODEL_REFUSED')
    return model.ModelResult(public, private)
