"""Focused offline ordinary timing tests. Every provider/transport is synthetic."""
import copy
import hashlib
import json
import stat
import unittest
from unittest.mock import patch
from checker import contract, main, timing
from phase7_live_adapter import monitor
from test_monitor import Boundary, profile

NOW = 1_800_000_000
COMMIT = 'a' * 40


def canonical(x):
    return json.dumps(x, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


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
        self.clock = clock
        self.started_ns = clock.mono
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


class Transport:
    def __init__(self, owner, phase, calls, clock, step=False):
        self.owner, self.phase, self.calls, self.clock, self.step = owner, phase, calls, clock, step
        calls.append(('CREATE', id(owner)))
    def observation(self, kind, path, port, accept, error=None):
        self.calls.append((kind, path, port, accept))
        if self.step: self.clock.step = 6 * 10**9
        response = None
        if kind in ('HTTPS','HTTP'):
            status = 404 if kind == 'HTTP' else 503 if self.phase == 'CLOSED' else 401
            location = 'ABSENT'
            if accept == 'HTML': status, location = (302, 'EXACT_LOGIN') if path == '/' else (200, 'ABSENT')
            response = {'status':status,'private':True,'no_store':True,'location':location,
                        'markers':[False]*4,'complete':True,'age':'ABSENT'}
        return {'kind':kind,'path':path,'port':port,'accept':accept,'error':error,
                'response':response,'markers':[False]*4,'duration_ms':1}
    def resolve(self): return self.observation('DNS',None,0,'NONE')
    def https(self,path,accept): return self.observation('HTTPS',path,443,accept)
    def http(self): return self.observation('HTTP','/api/ready',80,'JSON')
    def tcp(self,port): return self.observation('TCP',None,port,'NONE','CONNECTION_REFUSED')


def inputs(phase='CLOSED'):
    env = {'GITHUB_REPOSITORY':contract.REPOSITORY,'GITHUB_REPOSITORY_ID':'1316595124',
        'GITHUB_EVENT_NAME':'workflow_dispatch','GITHUB_REF':'refs/heads/main','GITHUB_SHA':COMMIT,
        'GITHUB_WORKFLOW_SHA':COMMIT,'GITHUB_WORKFLOW_REF':contract.WORKFLOW_REF,
        'GITHUB_RUN_ID':'12345','GITHUB_RUN_ATTEMPT':'1','GITHUB_JOB':'observe',
        'PHASE7_REPOSITORY_VISIBILITY':'public','RUNNER_OS':'Linux','RUNNER_ARCH':'X64',
        'PHASE7_APPROVED_COMMIT':COMMIT}
    request = {'schema':1,'phase':phase,'invocation':'b'*32,'package_sha256':'c'*64,
        'receipt_sha256':'d'*64,'observed_epoch':NOW-1,'expires_epoch':NOW+119,
        'deadline_epoch':NOW+4000}
    low, high = (NOW-1)*10**6, (NOW+60)*10**6
    def endpoint(role, runtime):
        return {'schema':1,'record':'REVIEWED_CONDITIONAL_ENDPOINT','basis':'EXPLICIT_OPERATING_POLICY',
            'role':role,'runtime_sha256':runtime,'evidence_sha256':'e'*64,'review_sha256':'f'*64,
            'valid_from_us':low,'valid_until_us':high,'total_utc_error_bound_ns':100_000_000}
    operating_profile = profile(low, high)
    context = {'schema':2,'record':'ORDINARY_CHRONY_TIMING_CONTEXT',
        'request_sha256':hashlib.sha256(canonical(request).encode()).hexdigest(),
        'expected_commit':COMMIT,'observation_lower_us':low,
        'native_endpoint':endpoint('NATIVE','4'*64),
        'coordinator_endpoint':endpoint('COORDINATOR','5'*64) if phase == 'CLOSEOUT' else None,
        'runner_profile':operating_profile}
    return request, env, context


class TimingChecks(unittest.TestCase):
    def run_case(self, phase='CLOSED', change=None, clock_change=None, step=False, boundary_change=None):
        request,env,context = inputs(phase)
        if change: change(request,env,context)
        clock = Clock()
        if clock_change: clock_change(clock)
        boundary, calls, owners = Boundary(clock), [], []
        if boundary_change: boundary_change(boundary)
        def factory():
            owner=Owner(clock); owners.append(owner); return owner
        def transport(owner): return Transport(owner,phase,calls,clock,step)
        with patch.object(main.time,'time',return_value=NOW), patch.object(main.time,'monotonic',return_value=1.0):
            result, code = main.run_once(canonical(request), env, timing_raw=canonical(context),
                _owner_factory=factory,_boundary=boundary,_transport_factory=transport,
                _monotonic_ns=clock.monotonic_ns,_time_ns=clock.time_ns)
        return json.loads(result),code,boundary,calls,owners
    def test_same_owner_closed_login_closeout(self):
        for phase in ('CLOSED','LOGIN','CLOSEOUT'):
            with self.subTest(phase=phase):
                record,code,boundary,calls,owners=self.run_case(phase)
                self.assertEqual(code,0,record)
                self.assertEqual(len(owners),1)
                self.assertEqual([x[0] for x in boundary.commands],['VERSION','FACTS','TRACKING','SOURCES','TRACKING','FACTS'])
                self.assertEqual(boundary.kernel_calls,0)
                self.assertTrue(all(x[1]==id(owners[0]) for x in boundary.commands))
                self.assertEqual(calls[0],('CREATE',id(owners[0])))
                self.assertEqual(len(calls)-2,len(contract.operations(phase)))
                self.assertFalse(record['same_run_timing']['alignment_established'])
                self.assertEqual(record['phase7_acceptance'],'BLOCKED')
                self.assertNotIn('PHC0',canonical(record))
    def test_missing_timing(self):
        record,code,boundary,calls,_=self.run_case(change=lambda r,e,c:c.clear())
        self.assertEqual(record['outcome'],'REFUSED'); self.assertEqual(boundary.commands,[]); self.assertEqual(calls,[])
    def test_stale_policy_before_collection(self):
        def change(r,e,c): c['runner_profile']['valid_until_us']=NOW*10**6
        record,code,boundary,calls,_=self.run_case(change=change)
        self.assertEqual(code,1); self.assertEqual(boundary.commands,[]); self.assertEqual(calls,[])
    def test_changed_commit_and_receipt_binding(self):
        for field in ('expected_commit','request_sha256'):
            record,code,boundary,calls,_=self.run_case(change=lambda r,e,c:c.__setitem__(field,'0'*len(c[field])))
            self.assertEqual(code,1); self.assertEqual(boundary.commands,[]); self.assertEqual(calls,[])
    def test_unsupported_runtime(self):
        record,code,boundary,calls,_=self.run_case(change=lambda r,e,c:e.__setitem__('RUNNER_ARCH','ARM64'))
        self.assertEqual(code,1); self.assertEqual(boundary.commands,[]); self.assertEqual(calls,[])
    def test_login_original_reserve_exhausted(self):
        def late(boundary):
            original=boundary.binary_identity
            def identity(): boundary.clock.mono += 2*10**9; return original()
            boundary.binary_identity=identity
        record,code,boundary,calls,owners=self.run_case('LOGIN',boundary_change=late)
        self.assertEqual(code,1); self.assertEqual(calls,[]); self.assertEqual(len(owners),1)
    def test_actual_profile_mismatch_before_dns(self):
        def mismatch(boundary):
            boundary.facts_change = lambda facts,count: facts['configuration']['refclocks'][0].__setitem__(-1,'1')
        record,code,boundary,calls,_=self.run_case(boundary_change=mismatch)
        self.assertEqual(code,1); self.assertEqual(len(boundary.commands),6); self.assertEqual(calls,[])
    def test_invalid_profile_before_collection(self):
        def change(r,e,c): c['runner_profile']['limits']['rate_bound_ppb'] = 999999
        record,code,boundary,calls,_=self.run_case(change=change)
        self.assertEqual(code,1); self.assertEqual(record['same_run_timing']['code'],'TIMING_POLICY_INVALID')
        self.assertEqual(boundary.commands,[]); self.assertEqual(calls,[])
    def test_closeout_requires_coordinator(self):
        record,code,boundary,calls,_=self.run_case('CLOSEOUT',change=lambda r,e,c:c.__setitem__('coordinator_endpoint',None))
        self.assertEqual(code,1); self.assertEqual(boundary.commands,[]); self.assertEqual(calls,[])
    def test_over_five_second_bound(self):
        record,code,boundary,calls,_=self.run_case(change=lambda r,e,c:c['native_endpoint'].__setitem__('total_utc_error_bound_ns',5*10**9))
        self.assertEqual(code,1); self.assertEqual(calls,[])
    def test_step_stops_after_dns(self):
        record,code,boundary,calls,_=self.run_case(step=True)
        self.assertEqual(code,1); self.assertEqual(record['outcome'],'INCONCLUSIVE')
        self.assertEqual(len(calls),2)
    def test_parser_rejects_ambiguous_or_large_json(self):
        request,env,ctx=inputs()
        checked=contract.validate(canonical(request),{k:env[k] for k in main.GITHUB_KEYS},NOW)
        for raw in ('{}'*9000,'{"schema":1,"schema":1}','{"schema":1.0}','{"schema":NaN}','{"x":"é"}'):
            with self.subTest(raw=raw[:30]):
                with self.assertRaises(timing.TimingError): timing.parse_context(raw.encode('utf8'),checked,env,COMMIT)
