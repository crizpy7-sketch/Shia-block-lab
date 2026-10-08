"""Synthetic monitor boundaries only; root runs under its provider guards."""
import copy
import hashlib
import json
import stat
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from phase7_live_adapter import monitor, monitor_facts
from phase7_live_adapter.capture import CaptureResult, CollectionError

NOW = 1_800_000_000
RUNTIME = 'a' * 64


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def facts_fixture():
    configuration = {'files': [[monitor_facts.CONFIG, 200, 'b' * 64]],
        'directories': [[path, True] for path in sorted(monitor_facts.DIRECTORIES)],
        'configured_sources': [],
        'refclocks': [['PHC', '/dev/ptp_hyperv', 'poll', '3', 'dpoll', '-2', 'offset', '0']]}
    return {'schema': 1, 'record': 'ORDINARY_CHRONY_MONITOR_FACTS',
        'boot_id': '01234567-89ab-cdef-0123-456789abcdef', 'pid': 42, 'start_ticks': 12345, 'time_namespace': 'time:[12345]',
        'uids': [113] * 4, 'daemon_exe': {'path': monitor_facts.DAEMON, 'device': 1,
            'inode': 2, 'bytes': 1000, 'sha256': 'c' * 64, 'package_md5_match': True},
        'hyperv': {'resolved': '/dev/ptp0', 'clock_name': 'hyperv', 'device': 123,
            'process_open_match': True}, 'package_version': '4.5-1ubuntu4.4',
        'command_line_sha256': 'd' * 64, 'configuration': configuration,
        'config_sha256': hashlib.sha256(monitor_facts.canonical(configuration)).hexdigest(),
        'loaded_config_verified': False, 'source_truth_verified': False,
        'kernel_utc_authority_claimed': False}


def profile_fixture():
    return {'schema': 1, 'record': 'ORDINARY_CHRONY_MONITOR_OPERATING_PROFILE',
        'provider_mode': monitor.MODE, 'profile_id': 'CANONICAL_NOBLE_CHRONY45_HYPERV_PHC',
        'valid_from_us': (NOW - 1) * 10**6, 'valid_until_us': (NOW + 60) * 10**6,
        'source_accuracy_bound_ns': 1_000_000_000,
        'limits': {'rate_bound_ppb': 1_000_000, 'max_sample_age_ns': 16_000_000_000},
        'config': {'loaded_config_equivalence_assumed': True, 'no_config_edits_assumed': True},
        'continuity': {'no_unaccounted_steps': True, 'no_restart_or_source_change': True,
            'allow_retrospective_projection': True}, 'review_evidence_sha256': 'e' * 64}


class Clock:
    def __init__(self):
        self.mono = 1_000_000_000
        self.step = 0
    def monotonic_ns(self):
        self.mono += 1000
        return self.mono
    def time_ns(self):
        return NOW * 10**9 + self.mono - 1_000_000_000 + self.step


class Owner:
    def __init__(self, clock):
        self.clock, self.started_ns = clock, clock.mono
        self.deadline_ns = self.started_ns + 40 * 10**9
        self.active = False
    def __enter__(self):
        self.active = True
        return self
    def remaining(self):
        if not self.active or self.clock.mono >= self.deadline_ns:
            raise RuntimeError('owner failed')
        return (self.deadline_ns - self.clock.mono) / 10**9
    def __exit__(self, *args):
        self.active = False
    def check_closed(self):
        if self.active or self.clock.mono >= self.deadline_ns:
            raise RuntimeError('owner failed')


class Boundary:
    def __init__(self, clock, *, facts_change=None, source_label='PHC0', failure_kind=None):
        self.clock, self.commands, self.kernel_calls = clock, [], 0
        self.facts_calls = 0
        self.facts_change, self.source_label, self.failure_kind = facts_change, source_label, failure_kind
    def monotonic_ns(self): return self.clock.monotonic_ns()
    def time_ns(self): return self.clock.time_ns()
    def namespace_identity(self): return 'time:[12345]'
    def binary_identity(self):
        group = tuple((1, 2, (stat.S_IFDIR | 0o755) if index < 3 else (stat.S_IFREG | 0o755),
                       0, 0, 100, 1, 1) for index in range(4))
        return (group, group, group)
    def capture(self, kind, owner, required_reserve_ns):
        self.commands.append((kind, id(owner), required_reserve_ns))
        start = self.monotonic_ns()
        if kind == 'VERSION':
            raw = b'chronyc (chrony) version 4.5 (+READLINE)\n'
        elif kind == 'FACTS':
            self.facts_calls += 1
            facts = facts_fixture()
            if self.facts_change:
                self.facts_change(facts, self.facts_calls)
                facts['config_sha256'] = hashlib.sha256(monitor_facts.canonical(facts['configuration'])).hexdigest()
            raw = (canonical(facts) + '\n').encode('ascii')
        elif kind == 'SOURCES':
            raw = ('#,*,%s,0,3,377,1,0.000000000,0.000000000,0.001000000\n' % self.source_label).encode('ascii')
        else:
            raw = (f'50484330,PHC0,1,{NOW-1}.000000000,0.000000000,0.000000000,'
                   '0.000000000,0.000,0.000,0.000,0.001000000,0.001000000,1.0,Normal\n').encode('ascii')
        failed = kind == self.failure_kind
        if failed:
            raw = b''
        end = self.monotonic_ns()
        return CaptureResult({'code': 'COMMAND_FAILED' if failed else 'OK', 'returncode': 1 if failed else 0,
            'stdout_bytes': len(raw), 'stderr_bytes': 0, 'bytecounts_exact': True,
            'direct_child_reaped': True, 'parent_pipes_closed': True, 'pipe_eof_observed': True,
            'descendant_cleanup_proven': False, 'containment_uncertain': True,
            'started_monotonic_ns': start, 'finished_monotonic_ns': end}, raw)


def collection_fixture(**changes):
    clock = Clock()
    boundary = Boundary(clock, **changes)
    owner = Owner(clock)
    with owner:
        result = monitor.collect_private(owner=owner, runtime_sha256=RUNTIME,
            boundary=boundary, required_reserve_ns=33 * 10**9)
    return result, boundary, owner


def evaluate(record, profile=None):
    profile = profile_fixture() if profile is None else profile
    return monitor.evaluate_observation(record, expected_runtime_sha256=RUNTIME, profile=profile,
        valid_from_us=profile['valid_from_us'], valid_until_us=profile['valid_until_us'])


def facts(): return facts_fixture()


def profile(low, high):
    value = profile_fixture()
    value.update(valid_from_us=low, valid_until_us=high)
    return value


class MonitorChecks(unittest.TestCase):
    def test_actual_shaped_collection_and_conditional_arithmetic(self):
        collected, boundary, owner = collection_fixture()
        self.assertIsNotNone(collected.private, collected.public)
        self.assertEqual([item[0] for item in boundary.commands],
            ['VERSION', 'FACTS', 'TRACKING', 'SOURCES', 'TRACKING', 'FACTS'])
        self.assertTrue(all(item[1] == id(owner) for item in boundary.commands))
        self.assertEqual(boundary.kernel_calls, 0)
        self.assertEqual(collected.private['record'], 'PRIVATE_ORDINARY_CHRONY_MONITOR')
        result = evaluate(collected.private)
        self.assertIsNotNone(result.private, result.public)
        self.assertEqual(result.public['status'], 'CONDITIONAL_MODEL_ONLY')
        self.assertLess(int(result.public['total_utc_error_bound_ns']), 5 * 10**9)
        self.assertFalse(result.public['kernel_utc_authority_claimed'])
        self.assertFalse(result.public['alignment_established'])
        self.assertEqual(result.public['phase7_acceptance'], 'BLOCKED')
        self.assertNotIn('PHC0', canonical(result.public))
        self.assertFalse(collected.public['descendant_cleanup_proven'])
    def test_metadata_pid_config_and_device_changes_refuse(self):
        changes = (lambda facts: facts.__setitem__('pid', 43),
            lambda facts: facts['configuration']['files'][0].__setitem__(2, 'f' * 64),
            lambda facts: facts['hyperv'].__setitem__('resolved', '/dev/ptp1'))
        for change in changes:
            with self.subTest(change=change):
                result, _, _ = collection_fixture(facts_change=lambda facts, count: change(facts) if count == 2 else None)
                self.assertIsNone(result.private)
                self.assertFalse(result.public['direct_resource_closure_observed'])
    def test_source_mismatch_refuses(self):
        result, _, _ = collection_fixture(source_label='PTP0')
        self.assertIsNone(result.private)
    def test_unsupported_sudo_or_helper_failure_refuses(self):
        result, boundary, _ = collection_fixture(failure_kind='FACTS')
        self.assertIsNone(result.private)
        self.assertEqual([item[0] for item in boundary.commands], ['VERSION', 'FACTS'])
    def test_full_login_reserve_exhaustion_before_capture(self):
        clock, boundary = Clock(), None
        owner = Owner(clock)
        clock.mono += 2 * 10**9
        boundary = Boundary(clock)
        with owner:
            result = monitor.collect_private(owner=owner, runtime_sha256=RUNTIME,
                boundary=boundary, required_reserve_ns=33 * 10**9)
        self.assertIsNone(result.private)
        self.assertEqual(boundary.commands, [])
    def test_profile_requires_exact_types_and_explicit_premises(self):
        mutations = (lambda profile: profile['limits'].__setitem__('rate_bound_ppb', 1000000.0),
            lambda profile: profile.__setitem__('source_accuracy_bound_ns', 2 * 10**9),
            lambda profile: profile['config'].__setitem__('loaded_config_equivalence_assumed', False),
            lambda profile: profile['continuity'].__setitem__('allow_retrospective_projection', False))
        for mutate in mutations:
            profile = profile_fixture()
            mutate(profile)
            with self.assertRaises(CollectionError): monitor.validate_profile(profile)
    def test_actual_unsupported_config_is_not_materialized(self):
        def change(facts, count):
            facts['configuration']['refclocks'][0][-1] = '1'
        collected, _, _ = collection_fixture(facts_change=change)
        self.assertIsNotNone(collected.private)
        self.assertIsNone(evaluate(collected.private).private)
    def test_record_tampering_refuses_arithmetic(self):
        collected, _, _ = collection_fixture()
        for mutate in (lambda record: record['facts'].__setitem__('pid', 43),
                       lambda record: record['captures'][1]['capture'].__setitem__('descendant_cleanup_proven', True),
                       lambda record: record.__setitem__('owner_deadline_ns', record['owner_deadline_ns'] + 1)):
            record = copy.deepcopy(collected.private)
            mutate(record)
            self.assertIsNone(evaluate(record).private)
    def test_exact_daemon_argv_grammar(self):
        for args in ([], ['-F', '1'], ['-F1', '-f', monitor_facts.CONFIG]):
            raw = ('\0'.join([monitor_facts.DAEMON, *args]) + '\0').encode('ascii')
            self.assertTrue(monitor_facts.validate_command_line(raw))
        for args in (['-x'], ['-q'], ['-F', '2'], ['-f', '/tmp/chrony.conf'],
                     ['server 192.0.2.1'], ['-F1', '-F1'], ['--', 'refclock PHC /dev/ptp0']):
            raw = ('\0'.join([monitor_facts.DAEMON, *args]) + '\0').encode('ascii')
            with self.assertRaises(monitor_facts.FactsError): monitor_facts.validate_command_line(raw)
    def test_uncertain_capture_holds_original_handle_to_deadline(self):
        clean = dict(reaped=True, eof=True, closed=True, parent_killed=False, returncode=1)
        self.assertFalse(monitor.needs_deadline_hold(**clean))
        for field, value in (('reaped', False), ('eof', False), ('closed', False),
                             ('parent_killed', True), ('returncode', 124), ('returncode', 137)):
            changed = dict(clean)
            changed[field] = value
            self.assertTrue(monitor.needs_deadline_hold(**changed))
        class Child:
            calls = 0
            def poll(self): self.calls += 1; return 1
            def wait(self, timeout): return 1
        clock, child = Clock(), Child()
        deadline = clock.mono + 40 * 10**9
        delays = []
        def advance(delay):
            self.assertLessEqual(delay, 0.02)
            delays.append(delay)
            clock.mono += max(1, int(delay * 10**9))
        monitor._hold_until_deadline(child, deadline, clock, _sleep=advance)
        self.assertGreaterEqual(clock.mono, deadline)
        self.assertGreater(child.calls, 1)
        self.assertTrue(delays)
    def test_capture_frame_clean_denial_vs_timeout_ownership(self):
        for returncode, held in ((1, False), (124, True), (137, True), (None, True)):
            with self.subTest(returncode=returncode):
                class Pipe:
                    def __init__(self, descriptor): self.descriptor, self.closed = descriptor, False
                    def fileno(self): return self.descriptor
                    def close(self): self.closed = True
                class Child:
                    def __init__(self):
                        self.stdout, self.stderr, self.polls, self.kills = Pipe(101), Pipe(102), 0, 0
                    def poll(self): self.polls += 1; return -9 if self.kills else returncode
                    def wait(self, timeout):
                        if returncode is None and not self.kills:
                            clock.mono += 100_000_000
                            raise subprocess.TimeoutExpired('fixed-mock-child', timeout)
                        return -9 if self.kills else returncode
                    def kill(self): self.kills += 1
                class Selector:
                    def __init__(self): self.keys = {}
                    def register(self, pipe, events, data):
                        self.keys[pipe.fileno()] = SimpleNamespace(fd=pipe.fileno(), fileobj=pipe, data=data)
                    def unregister(self, pipe): self.keys.pop(pipe.fileno())
                    def get_map(self): return self.keys
                    def select(self, wait): return [(key, 1) for key in list(self.keys.values())]
                    def close(self): pass
                clock, child, launches, sleeps = Clock(), Child(), [], []
                owner = Owner(clock)
                def launch(argv, **kwargs): launches.append((argv, kwargs)); return child
                def advance(delay): sleeps.append(delay); clock.mono += max(1, int(delay * 10**9))
                with patch.object(monitor.os, 'set_blocking', return_value=None), patch.object(monitor.os, 'read', return_value=b''):
                    with owner:
                        result = monitor._capture_frame('FACTS', owner=owner, clock=clock,
                            required_reserve_ns=33 * 10**9, _popen=launch, _selector=Selector, _sleep=advance)
                self.assertEqual(len(launches), 1)
                self.assertEqual(launches[0][0], monitor.COMMANDS['FACTS'])
                self.assertFalse(launches[0][1]['shell'])
                self.assertTrue(result.meta['direct_child_reaped'])
                self.assertTrue(result.meta['parent_pipes_closed'])
                self.assertTrue(result.meta['pipe_eof_observed'])
                self.assertFalse(result.meta['descendant_cleanup_proven'])
                self.assertEqual(bool(sleeps), held)
                self.assertEqual(clock.mono >= owner.deadline_ns, held)
                self.assertEqual(owner.deadline_ns, owner.started_ns + 40 * 10**9)
                self.assertEqual(child.kills, int(returncode is None))
                self.assertEqual(result.meta['code'], 'PHASE_OR_CLOCK_FAILED' if held else 'COMMAND_FAILED')

    def test_spawn_failure_without_handle_holds_original_deadline(self):
        clock, attempts, delays = Clock(), [], []
        owner = Owner(clock)
        def failed_spawn(argv, **kwargs):
            attempts.append(argv)
            raise RuntimeError('synthetic-spawn-uncertainty')
        def advance(delay):
            self.assertLessEqual(delay, 0.02)
            delays.append(delay)
            clock.mono += max(1, int(delay * 10**9))
        with owner:
            result = monitor._capture_frame('FACTS', owner=owner, clock=clock,
                required_reserve_ns=33 * 10**9, _popen=failed_spawn, _sleep=advance)
        self.assertEqual(attempts, [monitor.COMMANDS['FACTS']])
        self.assertTrue(delays)
        self.assertGreaterEqual(clock.mono, owner.deadline_ns)
        self.assertEqual(owner.deadline_ns, owner.started_ns + 40 * 10**9)
        self.assertFalse(result.meta['direct_child_reaped'])
        self.assertFalse(result.meta['parent_pipes_closed'])
        self.assertFalse(result.meta['descendant_cleanup_proven'])
        self.assertEqual(result.meta['code'], 'DIRECT_RESOURCE_CLOSURE_UNPROVEN')
