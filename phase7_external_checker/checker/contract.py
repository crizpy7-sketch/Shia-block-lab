"""Pure fixed external-observer contract and normalized interpretation.

No clock, environment, filesystem, process or network reads occur here. Public
input fields associate observations; they are not authenticated phase authority.
"""
import json
import math
import re

HOST = 'michel-pr20-377eb54-2-24-81-191.sslip.io'
IP = '2.24.81.191'
ORIGIN = 'https://' + HOST
LOGIN_URL = ORIGIN + '/authelia/'
NATIVE_GATE_BINDING = 'b042dd5d1bba6e150a53ae1cf66271a14b6ce9bdff9111e7b35c20d197741945'
REPOSITORY = 'crizpy7-sketch/Shia-block-lab'
WORKFLOW_REF = REPOSITORY + '/.github/workflows/phase7-external-check.yml@refs/heads/main'
PHASES = ('ROUTE', 'CLOSED', 'LOGIN', 'CLOSEOUT')
PROTECTED_PATHS = ('/', '/asset.js', '/api/example', '/api/ready')
PRIVATE_PORTS = (43120, 43121, 9091)
INPUT_KEYS = frozenset(('schema', 'phase', 'invocation', 'package_sha256',
    'receipt_sha256', 'observed_epoch', 'expires_epoch', 'deadline_epoch'))
ENV_KEYS = frozenset(('GITHUB_REPOSITORY_ID', 'GITHUB_REPOSITORY', 'GITHUB_EVENT_NAME',
    'GITHUB_REF', 'GITHUB_RUN_ATTEMPT', 'GITHUB_RUN_ID', 'GITHUB_SHA',
    'GITHUB_WORKFLOW_REF', 'GITHUB_WORKFLOW_SHA'))
OP_KEYS = frozenset(('kind', 'path', 'port', 'accept'))
RESPONSE_KEYS = frozenset(('status', 'private', 'no_store', 'location', 'age',
                           'markers', 'complete'))
OBSERVATION_KEYS = OP_KEYS | {'error', 'response', 'markers', 'duration_ms'}
RESULT_KEYS = OP_KEYS | {'outcome', 'reason', 'positive_https_control',
                        'exposure_observed', 'expectation_met'}
PARSER_ERRORS = frozenset(('INPUT_TYPE', 'TOTAL_CAP', 'HEADER_CAP', 'INCOMPLETE_HEADER',
    'EARLY_EOF', 'BAD_LINE_ENDING', 'STATUS_LINE', 'HEADER_COUNT', 'HEADER_FORMAT',
    'HEADER_CONTROL', 'DUPLICATE_HEADER', 'AMBIGUOUS_FRAMING',
    'UNSUPPORTED_TRANSFER_ENCODING', 'UNSUPPORTED_CONTENT_ENCODING', 'CONTENT_LENGTH',
    'BODY_CAP', 'EXTRA_DATA', 'BODY_FORBIDDEN', 'INTERIM_UNSUPPORTED'))
TRANSPORT_ERRORS = frozenset(('DNS_MISMATCH', 'DNS_TIMEOUT', 'DNS_ERROR', 'DNS_REQUIRED',
    'PHASE_TIMEOUT', 'OP_TIMEOUT', 'TLS_ERROR', 'CONNECTION_REFUSED',
    'NETWORK_UNREACHABLE', 'NETWORK_ERROR', 'PEER_MISMATCH', 'REQUEST_LIMIT',
    'REQUEST_INVALID', 'ALARM_UNAVAILABLE', 'INTERNAL_ERROR')) | frozenset(
        'PARSE_' + code for code in PARSER_ERRORS)
RESULT_REASONS = frozenset(('PROTECTED_MARKER_OBSERVED', 'ROUTE_TCP_CONNECTED',
    'PRIVATE_PORT_OPEN', 'PRIVATE_PORT_REFUSED', 'NO_POSITIVE_HTTPS_CONTROL',
    'TRANSPORT_UNVERIFIED', 'RESPONSE_INCOMPLETE', 'CACHE_UNVERIFIED',
    'UNEXPECTED_HTTP_STATUS', 'UNEXPECTED_LOCATION', 'EXPECTED_RESPONSE',
    'CLOSEOUT_ENDPOINT_OBSERVED'))


class ContractError(ValueError):
    """Fixed safe code only; never include rejected input or remote text."""
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _need(ok, code):
    if not ok:
        raise ContractError(code)


def _keys(value, expected):
    return (type(value) is dict and len(value) == len(expected)
            and all(type(k) is str and len(k) <= 64 for k in value)
            and set(value) == expected)


def _enum(value, choices):
    return type(value) is str and len(value) <= 64 and value in choices


def _hex(value, length):
    return (type(value) is str and len(value) == length
            and re.fullmatch('[0-9a-f]+', value) is not None)


def _epoch(value):
    return type(value) is int and 0 <= value < 10**12


def _clock(value):
    return (type(value) in (int, float) and 0 <= value < 10**12
            and math.isfinite(value))


def _unique(pairs):
    result = {}
    for key, value in pairs:
        _need(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def _json_integer(value):
    _need(len(value) <= 12 and value.isascii() and value.isdecimal(), 'JSON_INTEGER')
    return int(value)


def _not_number(_):
    raise ContractError('JSON_NUMBER')


def validate(raw, env, now):
    """Validate supplied ASCII input and exact filtered GitHub context.

    now is a caller-supplied UTC reading. Five seconds is an uncertainty margin,
    not synchronization proof. Caller must revalidate at completion and check
    separately reviewed code/public-run eligibility; no authority is created.
    """
    _need(type(raw) is str and 0 < len(raw) <= 2048 and raw.isascii(), 'INPUT_SIZE_OR_ASCII')
    _need(_clock(now), 'CLOCK_VALUE')
    try:
        value = json.loads(raw, object_pairs_hook=_unique, parse_int=_json_integer,
                           parse_float=_not_number, parse_constant=_not_number)
    except ContractError:
        raise
    except (ValueError, RecursionError):
        raise ContractError('JSON_INVALID') from None
    _need(_keys(value, INPUT_KEYS), 'INPUT_SCHEMA')
    _need(type(value['schema']) is int and value['schema'] == 1, 'SCHEMA_VERSION')
    _need(_enum(value['phase'], PHASES), 'PHASE')
    phase = value['phase']
    _need(_hex(value['package_sha256'], 64), 'PACKAGE_HASH')
    if phase == 'ROUTE':
        _need(value['invocation'] is None and value['receipt_sha256'] is None
              and value['deadline_epoch'] is None, 'ROUTE_CORRELATION')
        _need(value['package_sha256'] == NATIVE_GATE_BINDING, 'ROUTE_PACKAGE_BINDING')
    else:
        _need(_hex(value['invocation'], 32) and _hex(value['receipt_sha256'], 64),
              'NATIVE_CORRELATION')
        _need(_epoch(value['deadline_epoch']), 'NATIVE_DEADLINE')
    observed, expires = value['observed_epoch'], value['expires_epoch']
    _need(_epoch(observed) and _epoch(expires), 'EPOCH_TYPE')
    _need(observed <= now + 5, 'OBSERVATION_FUTURE')
    _need(observed <= expires <= observed + 120, 'VALIDITY_WINDOW')
    _need(now + 5 < expires, 'OBSERVATION_STALE')
    if phase in ('CLOSED', 'LOGIN'):
        _need(now + 5 + 40 + 120 + 1500 < value['deadline_epoch'], 'BROWSER_TIME_RESERVE')
    elif phase == 'CLOSEOUT':
        _need(now + 5 + 40 < value['deadline_epoch'], 'FINISH_TIME_RESERVE')
    _need(_keys(env, ENV_KEYS), 'GITHUB_ENV_SCHEMA')
    _need(all(type(v) is str and 0 < len(v) <= 256 and v.isascii() for v in env.values()),
          'GITHUB_ENV_VALUE')
    expected = {'GITHUB_REPOSITORY_ID': '1316595124', 'GITHUB_REPOSITORY': REPOSITORY,
                'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
                'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_WORKFLOW_REF': WORKFLOW_REF}
    _need(all(env[k] == v for k, v in expected.items()), 'GITHUB_CONTEXT_MISMATCH')
    _need(re.fullmatch('[0-9]{1,20}', env['GITHUB_RUN_ID']) is not None, 'GITHUB_RUN_ID')
    _need(_hex(env['GITHUB_SHA'], 40) and env['GITHUB_WORKFLOW_SHA'] == env['GITHUB_SHA'],
          'GITHUB_SOURCE_BINDING')
    return dict(value, native_gate_binding=NATIVE_GATE_BINDING,
                github_run_id=env['GITHUB_RUN_ID'], github_sha=env['GITHUB_SHA'],
                validation_epoch=now, association_only=True, control_authority='NONE',
                op_count=len(operations(phase)))


def operations(phase):
    """Exact target operations after one separately bounded successful DNS check."""
    _need(_enum(phase, PHASES), 'PHASE')
    if phase == 'ROUTE':
        return ({'kind': 'TCP', 'path': None, 'port': 443, 'accept': 'NONE'},)
    plan = [{'kind': 'HTTPS', 'path': path, 'port': 443, 'accept': 'JSON'}
            for path in PROTECTED_PATHS]
    if phase == 'LOGIN':
        plan.extend(({'kind': 'HTTPS', 'path': '/', 'port': 443, 'accept': 'HTML'},
                     {'kind': 'HTTPS', 'path': '/authelia/', 'port': 443, 'accept': 'HTML'}))
    plan.append({'kind': 'HTTP', 'path': '/api/ready', 'port': 80, 'accept': 'JSON'})
    plan.extend({'kind': 'TCP', 'path': None, 'port': port, 'accept': 'NONE'}
                for port in PRIVATE_PORTS)
    return tuple(plan)


def _op(value):
    return (_keys(value, OP_KEYS) and _enum(value['kind'], ('HTTPS', 'HTTP', 'TCP'))
            and (value['path'] is None or _enum(value['path'], PROTECTED_PATHS + ('/authelia/',)))
            and type(value['port']) is int and value['port'] in (443, 80) + PRIVATE_PORTS
            and _enum(value['accept'], ('JSON', 'HTML', 'NONE')))


def _markers(value):
    return type(value) is list and len(value) == 4 and all(type(v) is bool for v in value)


def _response(value):
    return (_keys(value, RESPONSE_KEYS) and type(value['status']) is int
            and 100 <= value['status'] <= 599
            and all(type(value[k]) is bool for k in ('private', 'no_store', 'complete'))
            and _enum(value['location'], ('ABSENT', 'EXACT_LOGIN', 'OTHER'))
            and _enum(value['age'], ('ABSENT', 'ZERO', 'OTHER'))
            and _markers(value['markers']))


def interpret(phase, operation, observation, positive_https_control=False):
    """Interpret one normalized fixed operation; no raw HTTP text is accepted.

    positive_https_control is prior same-phase complete verified HTTPS evidence,
    not backend health. Transport owns certificate/peer/deadline enforcement.
    CLOSEOUT always remains OBSERVED_ONLY, even on exposure or incomplete data.
    """
    _need(_enum(phase, PHASES) and _op(operation), 'OPERATION_SCHEMA')
    _need(operation in operations(phase), 'OPERATION_NOT_PLANNED')
    _need(type(positive_https_control) is bool, 'CONTROL_TYPE')
    _need(_keys(observation, OBSERVATION_KEYS), 'OBSERVATION_SCHEMA')
    _need(_op({k: observation[k] for k in OP_KEYS})
          and all(observation[k] == operation[k] for k in OP_KEYS), 'OBSERVATION_OPERATION')
    _need(observation['error'] is None or _enum(observation['error'], TRANSPORT_ERRORS),
          'OBSERVATION_ERROR')
    _need(type(observation['duration_ms']) is int and 0 <= observation['duration_ms'] <= 40000,
          'OBSERVATION_DURATION')
    _need(_markers(observation['markers']), 'OBSERVATION_MARKERS')
    response = observation['response']
    _need(response is None or _response(response), 'RESPONSE_SCHEMA')
    _need(operation['kind'] != 'TCP' or response is None, 'TCP_RESPONSE_FORBIDDEN')
    error = observation['error']
    exposure = any(observation['markers']) or (response is not None and any(response['markers']))
    timely = observation['duration_ms'] <= 3000
    https_positive = (operation['kind'] == 'HTTPS' and error is None
                      and response is not None and response['complete'] and timely)
    result = dict(operation, outcome='INCONCLUSIVE', reason='TRANSPORT_UNVERIFIED',
                  positive_https_control=https_positive, exposure_observed=exposure,
                  expectation_met=False)
    if exposure:
        result.update(outcome='FAIL', reason='PROTECTED_MARKER_OBSERVED')
    elif not timely:
        pass  # Late operation remains inconclusive, regardless of claimed error=None.
    elif operation['kind'] == 'TCP':
        if error is None:
            if phase == 'ROUTE':
                result.update(outcome='ROUTE_CONNECTED', reason='ROUTE_TCP_CONNECTED',
                              expectation_met=True)
            else:
                result.update(outcome='FAIL', reason='PRIVATE_PORT_OPEN', exposure_observed=True)
        elif error == 'CONNECTION_REFUSED':
            if phase != 'ROUTE' and positive_https_control:
                result.update(outcome='EXPECTED', reason='PRIVATE_PORT_REFUSED', expectation_met=True)
            else:
                result['reason'] = 'NO_POSITIVE_HTTPS_CONTROL'
    elif error is None and response is not None:
        if not response['complete']:
            result['reason'] = 'RESPONSE_INCOMPLETE'
        elif phase == 'CLOSEOUT':
            result['reason'] = 'CLOSEOUT_ENDPOINT_OBSERVED'
        else:
            cache = response['private'] and response['no_store'] and response['age'] in ('ABSENT', 'ZERO')
            if operation['kind'] == 'HTTP':
                expected_status, expected_location = 404, 'ABSENT'
            elif phase == 'CLOSED':
                expected_status, expected_location = 503, 'ABSENT'
            elif operation['accept'] == 'JSON':
                expected_status, expected_location = 401, 'ABSENT'
            elif operation['path'] == '/':
                expected_status, expected_location = 302, 'EXACT_LOGIN'
            else:
                expected_status, expected_location = 200, 'ABSENT'
            if response['status'] != expected_status:
                result.update(outcome='FAIL', reason='UNEXPECTED_HTTP_STATUS')
            elif response['location'] != expected_location:
                result.update(outcome='FAIL', reason='UNEXPECTED_LOCATION')
            elif not cache:
                result['reason'] = 'CACHE_UNVERIFIED'
            else:
                result.update(outcome='EXPECTED', reason='EXPECTED_RESPONSE', expectation_met=True)
    if phase == 'CLOSEOUT':
        result.update(outcome='OBSERVED_ONLY', expectation_met=False)
    return result


def summarize(phase, results):
    """Bounded ordered phase summary; neither result nor inputs grant gate PASS."""
    plan = operations(phase)
    _need(type(results) in (list, tuple) and len(results) <= len(plan), 'RESULTS_SCHEMA')
    for index, item in enumerate(results):
        _need(_keys(item, RESULT_KEYS), 'RESULT_SCHEMA')
        _need(_op({k: item[k] for k in OP_KEYS})
              and all(item[k] == plan[index][k] for k in OP_KEYS), 'RESULT_ORDER')
        _need(_enum(item['outcome'], ('EXPECTED', 'FAIL', 'INCONCLUSIVE', 'OBSERVED_ONLY',
                                      'ROUTE_CONNECTED'))
              and _enum(item['reason'], RESULT_REASONS), 'RESULT_VALUE')
        _need(all(type(item[k]) is bool for k in
                  ('positive_https_control', 'exposure_observed', 'expectation_met')), 'RESULT_FLAG')
        _need(item['expectation_met'] == (item['outcome'] in ('EXPECTED', 'ROUTE_CONNECTED')),
              'RESULT_CONTRADICTION')
        _need(not item['positive_https_control'] or item['kind'] == 'HTTPS', 'RESULT_CONTROL')
        _need((item['outcome'] != 'ROUTE_CONNECTED' or phase == 'ROUTE')
              and (phase != 'CLOSEOUT' or item['outcome'] == 'OBSERVED_ONLY'), 'RESULT_PHASE')
    complete = len(results) == len(plan)
    exposure = any(item['exposure_observed'] for item in results)
    if phase == 'CLOSEOUT':
        outcome = 'OBSERVED_ONLY'
    elif exposure or any(item['outcome'] == 'FAIL' for item in results):
        outcome = 'FAIL'
    elif complete and all(item['expectation_met'] and item['outcome'] in
                          ('EXPECTED', 'ROUTE_CONNECTED') for item in results):
        outcome = 'ROUTE_CAPABILITY_OBSERVED' if phase == 'ROUTE' else 'EXPECTED_PHASE_OBSERVATIONS'
    else:
        outcome = 'INCONCLUSIVE'
    return {'phase': phase, 'outcome': outcome, 'planned_operations': len(plan),
            'completed_operations': len(results), 'missing_operations': len(plan) - len(results),
            'exposure_observed': exposure, 'positive_https_control': any(
                item['positive_https_control'] for item in results),
            'association_only': True, 'control_authority': 'NONE',
            'cleanup_proven': False, 'gate_acceptance': 'NOT_ASSESSED'}
