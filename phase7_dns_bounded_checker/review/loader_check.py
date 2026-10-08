"""Offline workflow-loader check; execve is replaced, candidate never starts."""
import ast
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
from unittest.mock import patch

TEST_ROOT=Path(__file__).resolve().parent
ROOT=TEST_ROOT.parent if TEST_ROOT.name == 'review' else TEST_ROOT
WORKFLOW_ROOT=ROOT if (ROOT/'.github').is_dir() else ROOT.parent
workflow=WORKFLOW_ROOT/'.github/workflows/phase7-dns-bounded-check.yml'
raw=workflow.read_text()
code=raw.split("python3 -I -S -B - <<'PY'\n",1)[1].rsplit('          PY',1)[0]
code='\n'.join(line[10:] for line in code.splitlines())
compiled=compile(ast.parse(code),'reviewed_workflow_loader','exec')
manifest=json.loads((ROOT/'manifest.json').read_text())
original_cwd=Path.cwd()
checks=[]
real_calls={'network':0,'process':0,'thread':0}

def block(kind):
    def call(*args,**kwargs):
        real_calls[kind]+=1
        raise RuntimeError('REAL_BOUNDARY_REFUSED')
    return call

with tempfile.TemporaryDirectory(prefix='ordinary_loader_',dir=original_cwd) as stage:
    stage=Path(stage)
    for case in ('valid','bad_manifest','changed_module','extra_python','symlink_source','oversized_input'):
        project=stage/case; target=project/'phase7_dns_bounded_checker'
        target.mkdir(parents=True)
        for name in manifest['files']:
            dest=target/name; dest.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT/name,dest)
        shutil.copyfile(ROOT/'manifest.json',target/'manifest.json')
        if case=='bad_manifest': (target/'manifest.json').write_text('{}')
        elif case=='changed_module': (target/'checker/main.py').write_text('# altered\n')
        elif case=='extra_python': (target/'checker/extra.py').write_text('# unexpected\n')
        elif case=='symlink_source':
            p=target/'checker/main.py'; p.unlink(); p.symlink_to(ROOT/'checker/main.py')
        launch=[]
        def fake_execve(executable,args,env):
            launch.append({'executable':executable,'args':args,'env_keys':sorted(env),
                           'timing_bytes':len(env['PHASE7_TIMING_CONTEXT'])})
        env={'PHASE7_APPROVED_COMMIT':'a'*40,'GITHUB_SHA':'a'*40,
             'PHASE7_REQUEST':'{}','PHASE7_TIMING_CONTEXT':'x'*16385 if case=='oversized_input' else '{}',
             'UNRELATED_SECRET':'must_be_removed'}
        refused=False
        os.chdir(project)
        try:
            with patch.dict(os.environ,env,clear=True), patch.object(os,'execve',fake_execve), \
                 patch.object(socket,'socket',block('network')), patch.object(socket,'getaddrinfo',block('network')), \
                 patch.object(subprocess,'Popen',block('process')), patch.object(threading.Thread,'start',block('thread')):
                try: exec(compiled,{'__name__':'offline_workflow_loader'})
                except SystemExit as error: refused=(str(error)=='PHASE7_SOURCE_BINDING_REFUSED')
        finally: os.chdir(original_cwd)
        expected=case=='valid'
        passed=(len(launch)==1 and not refused and 'UNRELATED_SECRET' not in launch[0]['env_keys']) if expected else (not launch and refused)
        checks.append({'case':case,'passed':passed,'stub_launches':len(launch),'refused':refused})
report={'record':'ORDINARY_WORKFLOW_LOADER_OFFLINE_CHECK','checks':checks,
    'passed':all(x['passed'] for x in checks) and not any(real_calls.values()),
    'workflow_sha256':hashlib.sha256(workflow.read_bytes()).hexdigest(),
    'manifest_sha256':hashlib.sha256((ROOT/'manifest.json').read_bytes()).hexdigest(),
    'real_boundary_calls':real_calls,'candidate_imported':False,'candidate_started':False,
    'publication_performed':False,'workflow_dispatched':False,'phase7_acceptance':'BLOCKED'}
print(json.dumps(report,indent=2,sort_keys=True))
raise SystemExit(0 if report['passed'] else 1)
