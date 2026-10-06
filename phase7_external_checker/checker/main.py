"""Single manual phase; public bounded evidence, never a native gate command."""
import datetime
import json
import math
import os
from pathlib import Path
import re
import sys
import time

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from checker import contract, transport

GITHUB_KEYS = ('GITHUB_REPOSITORY', 'GITHUB_REPOSITORY_ID', 'GITHUB_EVENT_NAME',
               'GITHUB_REF', 'GITHUB_SHA', 'GITHUB_WORKFLOW_REF',
               'GITHUB_WORKFLOW_SHA', 'GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT')
ASSOCIATION_KEYS = ('schema', 'phase', 'invocation', 'package_sha256',
                    'receipt_sha256', 'observed_epoch', 'expires_epoch', 'deadline_epoch')
OUTPUT_CAP = 32768
RESULT_CODES = {'ROUTE_CAPABILITY_OBSERVED', 'EXPECTED_PHASE_OBSERVATIONS', 'OBSERVED_ONLY',
                'REFUSED', 'INCONCLUSIVE', 'EXPOSURE', 'FAIL'}


def public_observation(value):
    """Reconstruct the exact safe fields; reject unexpected normalization."""
    keys = {'kind', 'path', 'port', 'accept', 'error', 'response', 'markers', 'duration_ms'}
    if type(value) is not dict or set(value) != keys:
        raise ValueError('NORMALIZATION_INVALID')
    if type(value['kind']) is not str or value['kind'] not in {'DNS', 'HTTPS', 'HTTP', 'TCP'}:
        raise ValueError('NORMALIZATION_INVALID')
    if value['path'] is not None and (type(value['path']) is not str or value['path'] not in {'/', '/asset.js', '/api/example', '/api/ready', '/authelia/'}):
        raise ValueError('NORMALIZATION_INVALID')
    if type(value['port']) is not int or value['port'] not in {0, 80, 443, 43120, 43121, 9091}:
        raise ValueError('NORMALIZATION_INVALID')
    if type(value['accept']) is not str or value['accept'] not in {'NONE', 'JSON', 'HTML'}:
        raise ValueError('NORMALIZATION_INVALID')
    if value['error'] is not None and (type(value['error']) is not str or value['error'] not in transport.ERROR_CODES):
        raise ValueError('NORMALIZATION_INVALID')
    if type(value['duration_ms']) is not int or not 0 <= value['duration_ms'] <= 60000:
        raise ValueError('NORMALIZATION_INVALID')
    markers = value['markers']
    if type(markers) is not list or len(markers) != 4 or any(type(x) is not bool for x in markers):
        raise ValueError('NORMALIZATION_INVALID')
    response = value['response']
    if response is not None:
        if type(response) is not dict or set(response) != {'status', 'private', 'no_store', 'location', 'markers', 'complete', 'age'}:
            raise ValueError('NORMALIZATION_INVALID')
        if type(response['status']) is not int or not 100 <= response['status'] <= 599:
            raise ValueError('NORMALIZATION_INVALID')
        if any(type(response[x]) is not bool for x in ('private', 'no_store', 'complete')):
            raise ValueError('NORMALIZATION_INVALID')
        if (type(response['location']) is not str or response['location'] not in {'ABSENT', 'EXACT_LOGIN', 'OTHER'}
                or type(response['age']) is not str or response['age'] not in {'ABSENT', 'ZERO', 'OTHER'}):
            raise ValueError('NORMALIZATION_INVALID')
        if (type(response['markers']) is not list or len(response['markers']) != 4
                or response['markers'] != markers or any(type(x) is not bool for x in response['markers'])):
            raise ValueError('NORMALIZATION_INVALID')
        response = {key: list(response[key]) if key == 'markers' else response[key] for key in sorted(response)}
    return {key: response if key == 'response' else list(markers) if key == 'markers' else value[key]
            for key in sorted(keys)}


def encode_record(context, observations, outcome, started_epoch, elapsed_ms):
    if type(outcome) is not str or outcome not in RESULT_CODES or type(observations) is not list or len(observations) > 11:
        raise ValueError('OUTPUT_INVALID')
    if type(started_epoch) not in (int, float) or not math.isfinite(started_epoch):
        raise ValueError('OUTPUT_INVALID')
    if type(elapsed_ms) is not int or not 0 <= elapsed_ms <= 60000:
        raise ValueError('OUTPUT_INVALID')
    association = None
    github = None
    if context is not None:
        # Revalidate the public projection even for direct fixture/helper calls.
        association = {key: context[key] for key in ASSOCIATION_KEYS}
        supplied_env = {'GITHUB_REPOSITORY': contract.REPOSITORY, 'GITHUB_REPOSITORY_ID': '1316595124',
                        'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_REF': 'refs/heads/main',
                        'GITHUB_SHA': context['github_sha'], 'GITHUB_WORKFLOW_SHA': context['github_sha'],
                        'GITHUB_WORKFLOW_REF': contract.WORKFLOW_REF,
                        'GITHUB_RUN_ID': context['github_run_id'], 'GITHUB_RUN_ATTEMPT': '1'}
        checked = contract.validate(json.dumps(association), supplied_env, context['validation_epoch'])
        if context['op_count'] != checked['op_count']:
            raise ValueError('OUTPUT_INVALID')
        github = {'commit': checked['github_sha'], 'run_id': checked['github_run_id'], 'run_attempt': 1}
    record = {'record': 'PHASE7_EXTERNAL_OBSERVATION', 'schema': 1,
              'outcome': outcome, 'association': association, 'github': github,
              'association_is_operator_supplied': True,
              'native_gate_binding': contract.NATIVE_GATE_BINDING,
              'observed_utc': datetime.datetime.fromtimestamp(started_epoch, datetime.timezone.utc).isoformat(),
              'elapsed_ms': elapsed_ms,
              'observations': [public_observation(value) for value in observations],
              'protected_marker_observed': any(any(value['markers']) for value in observations),
              'private_port_open': any(value['kind'] == 'TCP' and value['port'] in contract.PRIVATE_PORTS
                                       and value['error'] is None for value in observations),
              'planned_target_operations': None if context is None else context['op_count'],
              'completed_target_operations': sum(value['kind'] != 'DNS' for value in observations),
              'cleanup_proven': False, 'control_authority': 'NONE',
              'phase7_acceptance': 'BLOCKED'}
    encoded = json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n'
    if len(encoded.encode('ascii')) > OUTPUT_CAP:
        raise ValueError('OUTPUT_CAP')
    return encoded


def run_once(raw, environ):
    """Return one record and exit status. Does not print or issue next phases."""
    started = time.time()
    monotonic_start = time.monotonic()
    observations = []
    context = None
    outcome = 'REFUSED'
    try:
        env = {key: environ.get(key) for key in GITHUB_KEYS}
        approved = environ.get('PHASE7_APPROVED_COMMIT', '')
        if not re.fullmatch('[0-9a-f]{40}', approved) or approved != env['GITHUB_SHA']:
            raise ValueError('COMMIT_REFUSED')
        if environ.get('PHASE7_REPOSITORY_VISIBILITY') != 'public':
            raise ValueError('VISIBILITY_REFUSED')
        context = contract.validate(raw, env, started)

        def fresh():
            utc = time.time()
            elapsed = time.monotonic() - monotonic_start
            if not math.isfinite(elapsed) or elapsed < 0 or abs((utc - started) - elapsed) > 5:
                raise contract.ContractError('CLOCK_DISCONTINUITY')
            contract.validate(raw, env, utc)

        with transport.PhaseDeadline() as owner:
            connection = transport.FixedTransport(owner)
            # Refuse again after interpreter/setup delay, before DNS/network.
            fresh()
            dns = connection.resolve()
            observations.append(public_observation(dns))
            if dns['error'] is not None:
                outcome = 'INCONCLUSIVE'
            else:
                evaluations = []
                positive_https = False
                for operation in contract.operations(context['phase']):
                    fresh()
                    if operation['kind'] == 'HTTPS':
                        value = connection.https(operation['path'], operation['accept'])
                    elif operation['kind'] == 'HTTP':
                        value = connection.http()
                    else:
                        value = connection.tcp(operation['port'])
                    value = public_observation(value)
                    observations.append(value)
                    evaluation = contract.interpret(context['phase'], operation, value,
                                                    positive_https_control=positive_https)
                    evaluations.append(evaluation)
                    if evaluation['positive_https_control']:
                        positive_https = True
                fresh()
                outcome = contract.summarize(context['phase'], evaluations)['outcome']
    except contract.ContractError:
        outcome = 'REFUSED' if not observations else 'INCONCLUSIVE'
    except Exception:
        # Neither response bytes, input text nor exception messages are public.
        outcome = 'INCONCLUSIVE' if observations else 'REFUSED'
    if context is not None and context['phase'] != 'CLOSEOUT' and any(
            any(value['markers']) or (value['kind'] == 'TCP' and value['port'] in contract.PRIVATE_PORTS
                                       and value['error'] is None) for value in observations):
        outcome = 'FAIL'
    elapsed = int((time.monotonic() - monotonic_start) * 1000)
    try:
        encoded = encode_record(context, observations, outcome, started, elapsed)
    except Exception:
        encoded = '{"record":"PHASE7_EXTERNAL_OBSERVATION","outcome":"REFUSED","reason":"OUTPUT_INVALID","phase7_acceptance":"BLOCKED"}\n'
        outcome = 'REFUSED'
    return encoded, (0 if outcome in {'ROUTE_CAPABILITY_OBSERVED', 'EXPECTED_PHASE_OBSERVATIONS', 'OBSERVED_ONLY'} else 1)


def main():
    output, code = run_once(os.environ.get('PHASE7_REQUEST', ''), dict(os.environ))
    sys.stdout.write(output)
    sys.stdout.flush()
    return code


if __name__ == '__main__':
    raise SystemExit(main())
