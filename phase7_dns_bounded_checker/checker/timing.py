"""Conditional same-owner timing context; no provider, clock or network defaults.

Reuses observed collection arithmetic and pair validation without private R1
delivery. Supplied review/policy identities associate claims; they attest none.
"""
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re

from checker import contract
from phase7_live_adapter import collector
from phase7_observed_clock_model import model
from phase7_observed_clock_model.validation import private_binding
from phase7_receipt_mapper.clock_evidence import validate_pair


CONTEXT_CAP = 16384
PHASE_NS = 40_000_000_000
COLLECTION_NS = 6_000_000_000
OP_NS = 3_000_000_000
US = 1_000_000
CONTEXT_KEYS = frozenset(('schema', 'record', 'request_sha256', 'expected_commit',
    'observation_lower_us', 'native_endpoint', 'coordinator_endpoint', 'runner_policy'))
ENDPOINT_KEYS = frozenset(('schema', 'record', 'basis', 'role', 'runtime_sha256',
    'evidence_sha256', 'review_sha256', 'valid_from_us', 'valid_until_us',
    'total_utc_error_bound_ns'))
ASSOCIATION_KEYS = contract.ENV_KEYS | frozenset((
    'GITHUB_JOB', 'PHASE7_REPOSITORY_VISIBILITY', 'RUNNER_OS', 'RUNNER_ARCH'))
SAFE_CODES = frozenset(('TIMING_CONTEXT_INVALID', 'TIMING_REQUEST_MISMATCH',
    'TIMING_COMMIT_MISMATCH', 'TIMING_JOB_INVALID', 'TIMING_PHASE_INVALID',
    'TIMING_POLICY_INVALID', 'TIMING_ENDPOINT_INVALID', 'TIMING_INTERVAL_INVALID',
    'TIMING_CONTEXT_STALE', 'TIMING_OWNER_INVALID', 'TIMING_OWNER_CHANGED',
    'TIMING_MONOTONIC_INVALID', 'TIMING_PHASE_DEADLINE', 'TIMING_WALL_INVALID',
    'TIMING_CLOCK_DISCONTINUITY', 'TIMING_RESERVE', 'TIMING_COLLECTION_REFUSED',
    'TIMING_COLLECTION_NOT_CURRENT', 'TIMING_MODEL_REFUSED', 'TIMING_PAIR_REFUSED'))


class TimingError(ValueError):
    def __init__(self, code):
        self.code = code if type(code) is str and code in SAFE_CODES else 'TIMING_CONTEXT_INVALID'
        super().__init__(self.code)


def _need(value, code):
    if not value:
        raise TimingError(code)


def _integer(value, upper=2**63):
    return type(value) is int and 0 <= value < upper


def _digest(value, size=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{%d}' % size, value) is not None


def _keys(value, expected):
    return type(value) is dict and set(value) == expected


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'),
                      ensure_ascii=True, allow_nan=False).encode('ascii')


def _hash(raw):
    return hashlib.sha256(raw).hexdigest()


def _unique(items):
    result = {}
    for key, value in items:
        _need(key not in result, 'TIMING_CONTEXT_INVALID')
        result[key] = value
    return result


def _number(token):
    _need(re.fullmatch(r'(?:0|[1-9][0-9]{0,18})', token) is not None,
          'TIMING_CONTEXT_INVALID')
    value = int(token)
    _need(_integer(value), 'TIMING_CONTEXT_INVALID')
    return value


def _not_number(_):
    raise TimingError('TIMING_CONTEXT_INVALID')


def _load(raw):
    _need(type(raw) is bytes and 0 < len(raw) <= CONTEXT_CAP and raw.isascii(),
          'TIMING_CONTEXT_INVALID')
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_int=_number,
                           parse_float=_not_number, parse_constant=_not_number)
        remaining = [2048]
        def visit(item, depth=0):
            remaining[0] -= 1
            _need(depth <= 10 and remaining[0] >= 0, 'TIMING_CONTEXT_INVALID')
            if item is None or type(item) is bool or _integer(item):
                return
            if type(item) is str:
                _need(len(item) <= 1024 and item.isascii(), 'TIMING_CONTEXT_INVALID')
                return
            _need(type(item) is dict and len(item) <= 32, 'TIMING_CONTEXT_INVALID')
            for key, child in item.items():
                _need(type(key) is str and len(key) <= 64 and key.isascii(),
                      'TIMING_CONTEXT_INVALID')
                visit(child, depth + 1)
        visit(value)
        _need(len(_canonical(value)) <= CONTEXT_CAP, 'TIMING_CONTEXT_INVALID')
        return value
    except TimingError:
        raise
    except (ValueError, TypeError, RecursionError, OverflowError, UnicodeError):
        raise TimingError('TIMING_CONTEXT_INVALID') from None


def runtime_identity(env, approved_commit):
    """Hash actual selected job fields; no environment lookup or attestation."""
    _need(type(env) is dict, 'TIMING_JOB_INVALID')
    selected = {key: env.get(key) for key in ASSOCIATION_KEYS}
    _need(all(type(v) is str and 0 < len(v) <= 256 and v.isascii()
              for v in selected.values()), 'TIMING_JOB_INVALID')
    fixed = {'GITHUB_REPOSITORY': contract.REPOSITORY, 'GITHUB_REPOSITORY_ID': '1316595124',
        'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
        'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_WORKFLOW_REF': contract.WORKFLOW_REF,
        'GITHUB_JOB': 'observe', 'PHASE7_REPOSITORY_VISIBILITY': 'public',
        'RUNNER_OS': 'Linux', 'RUNNER_ARCH': 'X64'}
    _need(all(selected[k] == v for k, v in fixed.items()) and _digest(approved_commit, 40)
          and selected['GITHUB_SHA'] == approved_commit == selected['GITHUB_WORKFLOW_SHA']
          and re.fullmatch(r'[1-9][0-9]{0,19}', selected['GITHUB_RUN_ID']) is not None,
          'TIMING_JOB_INVALID')
    return _hash(_canonical(selected))


def _endpoint(value, role, runtime):
    _need(_keys(value, ENDPOINT_KEYS) and type(value['schema']) is int and value['schema'] == 1
          and value['record'] == 'REVIEWED_CONDITIONAL_ENDPOINT'
          and value['basis'] == 'EXPLICIT_OPERATING_POLICY' and value['role'] == role
          and all(_digest(value[k]) for k in ('runtime_sha256', 'evidence_sha256', 'review_sha256'))
          and value['runtime_sha256'] != runtime
          and _integer(value['valid_from_us'], 10**18)
          and _integer(value['valid_until_us'], 10**18)
          and value['valid_from_us'] <= value['valid_until_us']
          and _integer(value['total_utc_error_bound_ns'])
          and value['total_utc_error_bound_ns'] <= 5_000_000_000,
          'TIMING_ENDPOINT_INVALID')


def _policy_template(value):
    _need(_keys(value, model.POLICY_KEYS) and type(value['schema']) is int and value['schema'] == 1
          and value['record'] == 'EXPLICIT_CHRONY45_POLICY_CLAIMS'
          and value['runtime_sha256'] == 'CURRENT_JOB'
          and _digest(value['review_evidence_sha256'])
          and _integer(value['valid_from_us'], 10**18)
          and _integer(value['valid_until_us'], 10**18)
          and value['valid_from_us'] <= value['valid_until_us'], 'TIMING_POLICY_INVALID')
    source, daemon, limits, continuity = (value[k] for k in ('source', 'daemon', 'limits', 'continuity'))
    _need(_keys(source, {'mode', 'reference_id', 'address', 'source_accuracy_bound_ns', 'utc_basis'})
          and source['mode'] in ('^', '=', '#') and type(source['reference_id']) is str
          and re.fullmatch('[0-9A-F]{8}', source['reference_id']) is not None
          and type(source['address']) is str and 0 < len(source['address']) <= 255
          and source['reference_id'] not in ('00000000', '7F7F0101')
          and source['address'] not in ('0.0.0.0', '::', '127.127.1.1', 'LOCAL', '[UNSPEC]')
          and source['utc_basis'] == 'UTC_ERROR_INCLUDES_TIMESCALE_CONVERSION'
          and _integer(source['source_accuracy_bound_ns']), 'TIMING_POLICY_INVALID')
    if source['mode'] == '#':
        _need(re.fullmatch(r'[A-Za-z0-9_-]{1,4}', source['address']) is not None
              and source['reference_id'] == source['address'].encode('ascii').ljust(4, b'\0').hex().upper(),
              'TIMING_POLICY_INVALID')
    else:
        _need(re.fullmatch(r'[0-9A-Fa-f:.]{2,45}', source['address']) is not None,
              'TIMING_POLICY_INVALID')
        try:
            address = ipaddress.ip_address(source['address'])
        except ValueError:
            raise TimingError('TIMING_POLICY_INVALID') from None
        if address.version == 4:
            _need(source['reference_id'] == address.packed.hex().upper(), 'TIMING_POLICY_INVALID')
        # The retained source parser does not infer an IPv6 reference-ID hash.
    _need(_keys(daemon, {'version', 'runtime_sha256', 'association_evidence_sha256', 'loaded_config_evidence_sha256'})
          and daemon['version'] == '4.5' and daemon['runtime_sha256'] == 'CURRENT_JOB'
          and _digest(daemon['association_evidence_sha256'])
          and _digest(daemon['loaded_config_evidence_sha256']), 'TIMING_POLICY_INVALID')
    _need(_keys(limits, {'rate_bound_ppb', 'max_sample_age_ns'})
          and _integer(limits['rate_bound_ppb'], 1_000_000_001)
          and _integer(limits['max_sample_age_ns']) and limits['max_sample_age_ns'] > 0,
          'TIMING_POLICY_INVALID')
    _need(_keys(continuity, {'no_unaccounted_steps', 'no_restart_or_source_change', 'allow_retrospective_projection'})
          and all(continuity[k] is True for k in continuity), 'TIMING_POLICY_INVALID')


def _validate_context(snapshot, request, runtime, approved_commit):
    _need(_keys(snapshot, CONTEXT_KEYS) and type(snapshot['schema']) is int
          and snapshot['schema'] == 1 and snapshot['record'] == 'ORDINARY_CHECKER_TIMING_CONTEXT',
          'TIMING_CONTEXT_INVALID')
    _need(request['phase'] in ('CLOSED', 'LOGIN', 'CLOSEOUT'), 'TIMING_PHASE_INVALID')
    _need(_digest(snapshot['expected_commit'], 40) and snapshot['expected_commit'] == approved_commit,
          'TIMING_COMMIT_MISMATCH')
    _need(_digest(snapshot['request_sha256']) and snapshot['request_sha256'] == _hash(_canonical(request))
          and type(snapshot['observation_lower_us']) is int
          and snapshot['observation_lower_us'] == request['observed_epoch'] * US,
          'TIMING_REQUEST_MISMATCH')
    _endpoint(snapshot['native_endpoint'], 'NATIVE', runtime)
    _need((snapshot['coordinator_endpoint'] is None) == (request['phase'] != 'CLOSEOUT'),
          'TIMING_ENDPOINT_INVALID')
    if snapshot['coordinator_endpoint'] is not None:
        _endpoint(snapshot['coordinator_endpoint'], 'COORDINATOR', runtime)
    _policy_template(snapshot['runner_policy'])


def parse_context(raw, request_context, env, approved_commit):
    """Parse <=16KiB ASCII context; bind its eight-field request and actual job."""
    try:
        snapshot = _load(raw)
        runtime = runtime_identity(env, approved_commit)
        _need(type(request_context) is dict, 'TIMING_REQUEST_MISMATCH')
        request = {key: request_context[key] for key in contract.INPUT_KEYS}
        checked = contract.validate(_canonical(request).decode('ascii'),
            {key: env.get(key) for key in contract.ENV_KEYS}, request_context['validation_epoch'])
        _need(checked == request_context and request_context['github_sha'] == approved_commit,
              'TIMING_REQUEST_MISMATCH')
        _validate_context(snapshot, request, runtime, approved_commit)
        return snapshot, runtime
    except TimingError:
        raise
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise TimingError('TIMING_CONTEXT_INVALID') from None


class Clock:
    """Borrow immutable bounds; collection, target work and closure share them."""
    def __init__(self, owner, monotonic_ns, time_ns):
        self.owner, self.monotonic_ns, self.time_ns = owner, monotonic_ns, time_ns
        self.start, self.deadline = owner.started_ns, owner.deadline_ns
        _need(_integer(self.start) and _integer(self.deadline)
              and self.deadline - self.start == PHASE_NS, 'TIMING_OWNER_INVALID')
        self.previous, self.wall_start = self.start, None
        self.check()

    def check(self, *, active=True):
        _need(type(self.owner.started_ns) is int and type(self.owner.deadline_ns) is int
              and self.owner.started_ns == self.start and self.owner.deadline_ns == self.deadline,
              'TIMING_OWNER_CHANGED')
        now = self.monotonic_ns()
        _need(_integer(now) and now >= self.previous, 'TIMING_MONOTONIC_INVALID')
        self.previous = now
        _need(now < self.deadline, 'TIMING_PHASE_DEADLINE')
        if active:
            self.owner.remaining()
        return now

    def wall(self, *, active=True):
        before = self.check(active=active)
        value = self.time_ns()
        after = self.check(active=active)
        _need(_integer(value), 'TIMING_WALL_INVALID')
        if self.wall_start is None:
            self.wall_start = (value, before, after)
        else:
            wall0, mono0, mono1 = self.wall_start
            _need(before - mono1 - 5_000_000_000 <= value - wall0
                  <= after - mono0 + 5_000_000_000, 'TIMING_CLOCK_DISCONTINUITY')
        return value // 1000

    def reserve(self, required_ns):
        _need(_integer(required_ns) and self.deadline - self.check() > required_ns, 'TIMING_RESERVE')


@dataclass(frozen=True, repr=False)
class Prepared:
    context_raw: bytes
    policy_raw: bytes
    request_raw: bytes
    runtime_sha256: str
    owner_started_ns: int
    owner_deadline_ns: int
    started_us: int
    coverage_lower_us: int
    horizon_us: int


def prepare(owner, snapshot, runtime, request_context, *, monotonic_ns, time_ns):
    """Freeze private claims and the initial horizon before provider or network."""
    _need(_digest(runtime), 'TIMING_JOB_INVALID')
    context_raw = _canonical(snapshot)
    snapshot = _load(context_raw)
    request = {key: request_context[key] for key in contract.INPUT_KEYS}
    _validate_context(snapshot, request, runtime, request_context['github_sha'])
    clock = Clock(owner, monotonic_ns, time_ns)
    started = clock.wall()
    horizon = started + PHASE_NS // 1000
    lower = min(started, snapshot['observation_lower_us'])
    _need(request['observed_epoch'] * US <= started + 5 * US
          and started + 45 * US < request['expires_epoch'] * US, 'TIMING_CONTEXT_STALE')
    reserve = 85 if request['phase'] == 'CLOSEOUT' else 1705
    _need(started + reserve * US < request['deadline_epoch'] * US, 'TIMING_CONTEXT_STALE')
    policy = snapshot['runner_policy']
    for endpoint in (snapshot['native_endpoint'], snapshot['coordinator_endpoint'], policy):
        if endpoint is not None:
            _need(endpoint['valid_from_us'] <= lower <= horizon <= endpoint['valid_until_us'],
                  'TIMING_INTERVAL_INVALID')
    policy['runtime_sha256'] = runtime
    policy['daemon']['runtime_sha256'] = runtime
    prepared = Prepared(context_raw, _canonical(policy), _canonical(request), runtime,
        clock.start, clock.deadline, started, lower, horizon)
    clock.check()
    return clock, prepared


def _owner(clock, prepared):
    _need(type(prepared) is Prepared and clock.start == prepared.owner_started_ns
          and clock.deadline == prepared.owner_deadline_ns, 'TIMING_OWNER_CHANGED')


def _pair(endpoint, observed, prepared):
    right = observed.private
    low = max(endpoint['valid_from_us'], right['valid_from_us'])
    high = min(endpoint['valid_until_us'], right['valid_until_us'])
    total = (endpoint['total_utc_error_bound_ns'] + right['total_utc_error_bound_ns'] + 999) // 1000
    _need(low <= prepared.coverage_lower_us <= prepared.horizon_us <= high
          and total <= 5_000_000 and right['runtime_sha256_supplied'] == prepared.runtime_sha256,
          'TIMING_PAIR_REFUSED')
    left_hash, right_hash = _hash(_canonical(endpoint)), private_binding(right)
    review = _hash(_canonical({'left_review': endpoint['review_sha256'],
        'right_review': right['review_evidence_sha256_supplied'], 'left_envelope': left_hash,
        'right_model': right_hash, 'basis': 'CONDITIONAL_CLAIMS_NOT_QUALIFIED_ALIGNMENT'}))
    return {'schema': 1, 'record': 'SUPPLIED_CLOCK_ALIGNMENT', 'basis': 'REVIEWED_OBSERVATION',
        'left_role': endpoint['role'], 'left_runtime_sha256': endpoint['runtime_sha256'],
        'right_runtime_sha256': prepared.runtime_sha256, 'left_evidence_sha256': left_hash,
        'right_evidence_sha256': right_hash, 'review_sha256': review, 'valid_from_us': low,
        'valid_until_us': high, 'total_error_bound_us': total, 'bound_scope': 'TOTAL_OFFSET_AND_DRIFT'}


@dataclass(frozen=True, repr=False)
class Evaluation:
    native_pair_raw: bytes
    coordinator_pair_raw: bytes | None
    owner_started_ns: int
    owner_deadline_ns: int
    started_us: int
    coverage_lower_us: int
    horizon_us: int
    context_sha256: str

    @property
    def summary(self):
        pairs = [json.loads(raw) for raw in (self.native_pair_raw, self.coordinator_pair_raw) if raw is not None]
        result = initial_summary()
        result.update(status='CONDITIONAL_OBSERVED_TIMING', code='CONDITIONAL_TIMING_EVALUATED',
                      collection_calls=1)
        result.update({'pair_bounds_us': [p['total_error_bound_us'] for p in pairs],
            'original_owner_started_ns': self.owner_started_ns,
            'original_owner_deadline_ns': self.owner_deadline_ns, 'original_wall_start_us': self.started_us,
            'coverage_lower_us': self.coverage_lower_us, 'original_horizon_us': self.horizon_us})
        return public_summary(result)


def initial_summary():
    return {'schema': 1, 'record': 'ORDINARY_CHECKER_CONDITIONAL_TIMING',
        'status': 'REFUSED', 'code': 'NOT_STARTED', 'provider_access_mode': 'DIRECT_SOCKET_ONLY',
        'runtime_association': 'ACTUAL_JOB_FIELDS_NOT_ATTESTATION', 'policy_truth_verified': False,
        'runtime_attested': False, 'alignment_established': False, 'execution_authorized': False,
        'phase7_acceptance': 'BLOCKED', 'phase_budget_ns': PHASE_NS,
        'collection_calls': 0, 'transport_created': False, 'pair_bounds_us': [],
        'original_owner_started_ns': None, 'original_owner_deadline_ns': None,
        'original_wall_start_us': None, 'coverage_lower_us': None, 'original_horizon_us': None}


def public_summary(value):
    """Exact fixed public projection; no provider, policy or evidence contents."""
    template = initial_summary()
    intervals = ('original_owner_started_ns', 'original_owner_deadline_ns',
                 'original_wall_start_us', 'coverage_lower_us', 'original_horizon_us')
    variable = {'status', 'code', 'collection_calls', 'transport_created', 'pair_bounds_us', *intervals}
    _need(_keys(value, set(template)), 'TIMING_CONTEXT_INVALID')
    _need(all(type(value[k]) is type(template[k]) and value[k] == template[k]
              for k in set(template) - variable), 'TIMING_CONTEXT_INVALID')
    _need(type(value['status']) is str and value['status'] in ('REFUSED', 'CONDITIONAL_OBSERVED_TIMING')
          and type(value['code']) is str and value['code'] in SAFE_CODES | {
              'NOT_STARTED', 'DEPENDENCY_FAILED', 'CONDITIONAL_TIMING_EVALUATED'}
          and type(value['collection_calls']) is int and value['collection_calls'] in (0, 1)
          and type(value['transport_created']) is bool and type(value['pair_bounds_us']) is list
          and len(value['pair_bounds_us']) <= 2
          and all(_integer(v, 5_000_001) for v in value['pair_bounds_us']), 'TIMING_CONTEXT_INVALID')
    populated = any(value[k] is not None for k in intervals)
    if populated:
        _need(all(_integer(value[k]) for k in intervals)
              and value['original_owner_deadline_ns'] - value['original_owner_started_ns'] == PHASE_NS
              and value['original_horizon_us'] - value['original_wall_start_us'] == PHASE_NS // 1000
              and value['coverage_lower_us'] <= value['original_wall_start_us']
              and value['collection_calls'] == 1 and len(value['pair_bounds_us']) in (1, 2),
              'TIMING_CONTEXT_INVALID')
    else:
        _need(not value['pair_bounds_us'] and not value['transport_created'], 'TIMING_CONTEXT_INVALID')
    if value['status'] == 'CONDITIONAL_OBSERVED_TIMING':
        _need(populated and value['code'] == 'CONDITIONAL_TIMING_EVALUATED', 'TIMING_CONTEXT_INVALID')
    if value['transport_created']:
        _need(populated and value['collection_calls'] == 1, 'TIMING_CONTEXT_INVALID')
    return {k: list(value[k]) if k == 'pair_bounds_us' else value[k] for k in sorted(template)}


def evaluate(collected, clock, prepared, *, collection_start_ns, collection_end_ns):
    """Evaluate one same-run actual-shaped collection, never a fixture model."""
    _owner(clock, prepared)
    try:
        _need(type(collected) is collector.CollectionResult
              and collected.public.get('status') == 'OBSERVATION_COMPLETE_UNQUALIFIED'
              and type(collected.private) is dict, 'TIMING_COLLECTION_REFUSED')
        _need(_integer(collection_start_ns) and _integer(collection_end_ns)
              and prepared.owner_started_ns <= collection_start_ns <= collection_end_ns < prepared.owner_deadline_ns,
              'TIMING_COLLECTION_NOT_CURRENT')
        record = collected.private
        first, last = record['captures'][0]['bracket'], record['kernel_after']['samples'][-1]
        now_us = clock.wall()
        _need(record['owner_started_ns'] == prepared.owner_started_ns
              and record['owner_deadline_ns'] == prepared.owner_deadline_ns
              and collection_start_ns <= first['monotonic_before_ns'] <= last['monotonic_after_ns'] <= collection_end_ns
              and prepared.started_us * 1000 <= first['realtime_before_ns']
              and last['realtime_after_ns'] < (now_us + 1) * 1000, 'TIMING_COLLECTION_NOT_CURRENT')
        policy = json.loads(prepared.policy_raw)
        observed = model.evaluate_observation(record, expected_runtime_sha256=prepared.runtime_sha256,
            policy=policy, valid_from_us=prepared.coverage_lower_us, valid_until_us=prepared.horizon_us)
        _need(type(observed) is model.ModelResult and observed.public.get('status') == 'CONDITIONAL_MODEL_ONLY'
              and type(observed.private) is dict and observed.private['policy_sha256'] == private_binding(policy),
              'TIMING_MODEL_REFUSED')
        context = json.loads(prepared.context_raw)
        native = _pair(context['native_endpoint'], observed, prepared)
        coordinator = None if context['coordinator_endpoint'] is None else _pair(context['coordinator_endpoint'], observed, prepared)
        result = Evaluation(_canonical(native), None if coordinator is None else _canonical(coordinator),
            prepared.owner_started_ns, prepared.owner_deadline_ns, prepared.started_us,
            prepared.coverage_lower_us, prepared.horizon_us, _hash(prepared.context_raw))
        fresh(clock, prepared, result)
        return result
    except TimingError:
        raise
    except (ValueError, TypeError, KeyError, IndexError, RecursionError, OverflowError):
        raise TimingError('TIMING_MODEL_REFUSED') from None


def fresh(clock, prepared, evaluated, *, active=True):
    """Check current coverage without changing the original plan or horizon."""
    _owner(clock, prepared)
    _need(type(evaluated) is Evaluation and evaluated.context_sha256 == _hash(prepared.context_raw)
          and (evaluated.owner_started_ns, evaluated.owner_deadline_ns, evaluated.started_us,
               evaluated.coverage_lower_us, evaluated.horizon_us) ==
              (prepared.owner_started_ns, prepared.owner_deadline_ns, prepared.started_us,
               prepared.coverage_lower_us, prepared.horizon_us), 'TIMING_PAIR_REFUSED')
    now_us = clock.wall(active=active)
    context, request = json.loads(prepared.context_raw), json.loads(prepared.request_raw)
    _need(now_us + 5 * US < request['expires_epoch'] * US, 'TIMING_CONTEXT_STALE')
    reserve = 45 if request['phase'] == 'CLOSEOUT' else 1665
    _need(now_us + reserve * US < request['deadline_epoch'] * US, 'TIMING_CONTEXT_STALE')
    try:
        for raw, endpoint, role in ((evaluated.native_pair_raw, context['native_endpoint'], 'NATIVE'),
                (evaluated.coordinator_pair_raw, context['coordinator_endpoint'], 'COORDINATOR')):
            if raw is not None:
                validate_pair(json.loads(raw), left_role=role, left_runtime=endpoint['runtime_sha256'],
                    right_runtime=prepared.runtime_sha256, start_us=prepared.coverage_lower_us,
                    end_us=max(prepared.horizon_us, now_us))
    except (ValueError, TypeError, KeyError):
        raise TimingError('TIMING_PAIR_REFUSED') from None
    clock.check(active=active)
    return now_us
