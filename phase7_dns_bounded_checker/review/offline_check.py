"""One focused offline check. Guards installed before candidate imports."""
import contextlib
import ctypes
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import unittest
from unittest.mock import patch

TEST_ROOT=Path(__file__).resolve().parent
ROOT=TEST_ROOT.parent if TEST_ROOT.name == 'review' else TEST_ROOT
started=time.monotonic_ns()
source={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
        for p in ROOT.rglob('*.py')}
counters=dict.fromkeys(('network','process','thread','write','real_provider','signal'),0)

def blocked(kind):
    def call(*args,**kwargs):
        counters[kind]+=1
        raise RuntimeError('OFFLINE_BOUNDARY_REFUSED')
    return call

audit_active=True

def audit(event,args):
    if not audit_active: return
    kind=None
    if event.startswith('socket.') and event not in ('socket.__new__',): kind='network'
    elif event in ('subprocess.Popen','os.system','os.posix_spawn','os.fork'): kind='process'
    elif event == 'open':
        mode=args[1]; flags=args[2]
        if (type(mode) is str and any(x in mode for x in 'wax+')) or (type(flags) is int and flags & 0o1103): kind='write'
    elif event in ('os.remove','os.rename','os.mkdir','os.rmdir','os.chmod','os.chown','os.truncate'): kind='write'
    if kind: blocked(kind)()

sys.addaudithook(audit)
sys.path.insert(0,str(ROOT))
sys.path.insert(0,str(TEST_ROOT))
with contextlib.ExitStack() as stack:
    for obj,name,kind in ((socket,'socket','network'),(socket,'getaddrinfo','network'),
                          (subprocess,'Popen','process'),(threading.Thread,'start','thread'),
                          (ctypes,'CDLL','real_provider'),(signal,'signal','signal'),(signal,'setitimer','signal')):
        stack.enter_context(patch.object(obj,name,blocked(kind)))
    from phase7_clock_sampler import sampler
    from phase7_live_adapter import collector, monitor, monitor_facts
    from phase7_chrony_capability_probe import entry as probe
    for obj,name in ((sampler,'NativeAdapter'),(collector.ReadOnlyBoundary,'kernel_read'),
                     (collector.ReadOnlyBoundary,'capture'),(collector.ReadOnlyBoundary,'binary_identity'),
                     (probe,'capture'),(monitor,'_capture'),
                     (monitor.FixedMonitorBoundary,'capture'),
                     (monitor.FixedMonitorBoundary,'binary_identity'),
                     (monitor.FixedMonitorBoundary,'namespace_identity'),
                     (monitor_facts,'collect_facts')):
        stack.enter_context(patch.object(obj,name,blocked('real_provider')))
    suite=unittest.TestSuite()
    for name in ('test_timing', 'test_monitor'):
        spec=importlib.util.spec_from_file_location(name,TEST_ROOT/(name+'.py'))
        module=importlib.util.module_from_spec(spec)
        sys.modules[name]=module
        spec.loader.exec_module(module)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
    logs=io.StringIO()
    result=unittest.TextTestRunner(stream=logs,verbosity=2).run(suite)
    after={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
           for p in ROOT.rglob('*.py')}
audit_active=False
passed=result.wasSuccessful() and source==after and not any(counters.values())
report={'record':'ORDINARY_TIMING_OFFLINE_CHECK','schema':1,'test_mode':'SYNTHETIC_BOUNDARIES_ONLY',
    'passed':passed,'tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
    'skips':len(result.skipped),'guard_counters':counters,'source_unchanged':source==after,
    'source_sha256':source,'elapsed_ns':time.monotonic_ns()-started,'test_log':logs.getvalue(),
    'actual_runner_clock_observed':False,'target_network_observed':False,'workflow_dispatched':False,
    'phase7_acceptance':'BLOCKED'}
print(json.dumps(report,sort_keys=True,indent=2))
raise SystemExit(0 if passed else 1)
