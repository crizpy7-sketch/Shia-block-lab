"""Exact-source entry point for one separately authorized provider capability job."""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import sys
import time
import types


WORKFLOW_REF = "crizpy7-sketch/Shia-block-lab/.github/workflows/phase7-clock-provider-capability.yml@refs/heads/main"
RECORD_CAP = 49152
# Filled from final reviewed bytes before the proposal is frozen.
BINDINGS = {'sampler': {'path': 'phase7_clock_sampler/sampler.py', 'bytes': 15177, 'sha256': '3305111d412ce1726282ee8cf8322b975cb252c15287bf57b8075f2c552ec385'}, 'collector': {'path': 'phase7_clock_provider_adapter/collector.py', 'bytes': 10912, 'sha256': 'c3d339660fc5b1e37d798b6311f6b3cf1dffb0aa9989b39ca4bc1ebdc16b0043'}, 'packet': {'path': 'phase7_clock_sampler/packet_diagnostics.py', 'bytes': 8829, 'sha256': '0fdced77934530894fa52e5040e1c9674bcdfc714780bda3367b829bc7d43070'}, 'executor': {'path': 'phase7_clock_provider_executor/executor.py', 'bytes': 13135, 'sha256': 'de768988612b757adf1d3cf6a9e3ac9938770ead30dfb90e22b46231c6cdcf3d'}, 'runtime': {'path': 'phase7_clock_provider_executor/runtime_check.py', 'bytes': 18609, 'sha256': 'a3d7b039922d8c7e4d967b7e07e3f6ee36834631b36e51777246adab894a3853'}}


class Refusal(Exception):
    pass


def _require(condition, code):
    if not condition:
        raise Refusal(code)


def _association():
    approved = os.environ.get("PHASE7_APPROVED_COMMIT", "")
    _require(re.fullmatch(r"[0-9a-f]{40}", approved) is not None, "APPROVED_COMMIT")
    fixed = {
        "GITHUB_REPOSITORY": "crizpy7-sketch/Shia-block-lab",
        "GITHUB_REPOSITORY_ID": "1316595124",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": approved,
        "GITHUB_WORKFLOW_SHA": approved,
        "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_JOB": "observe",
        "PHASE7_REPOSITORY_VISIBILITY": "public",
        "RUNNER_OS": "Linux",
        "RUNNER_ARCH": "X64",
    }
    _require(all(os.environ.get(key) == value for key, value in fixed.items()), "JOB_ASSOCIATION")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    _require(re.fullmatch(r"[1-9][0-9]{0,19}", run_id) is not None, "RUN_ID")
    return dict(fixed, GITHUB_RUN_ID=run_id)


def _sources():
    _require(set(BINDINGS) == {"sampler", "collector", "packet", "executor", "runtime"}, "SOURCE_BINDINGS")
    result = {}
    for label, binding in BINDINGS.items():
        path = Path(binding["path"])
        _require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 65536, "SOURCE_FILE")
        raw = path.read_bytes()
        _require(len(raw) == binding["bytes"] and hashlib.sha256(raw).hexdigest() == binding["sha256"], "SOURCE_DIGEST")
        result[label] = raw
    return result


def _module(label, raw):
    name = "phase7_provider_bound_" + label
    module = types.ModuleType(name)
    module.__file__ = "<reviewed-provider-" + label + ">"
    sys.modules[name] = module
    exec(compile(raw, module.__file__, "exec"), module.__dict__)
    return module


def main():
    executor = None
    try:
        association = _association()
        sources = _sources()
        os.environ.clear()
        os.environ.update(PATH="/usr/bin:/bin", LANG="C", LC_ALL="C")
        modules = {label: _module(label, raw) for label, raw in sources.items()}
        executor = modules["executor"].BoundedExecutor()
        result = modules["runtime"].run_check(
            sampler=modules["sampler"].collect_native,
            collector=modules["collector"].collect,
            executor=executor,
            packet_evaluator=modules["packet"].evaluate,
            monotonic_ns=time.monotonic_ns,
            realtime_ns=time.time_ns,
            runtime_association=association,
        )
        # Raw provider replies remain only in the private result in this process.
        record = {
            "schema": 1,
            "record": "CLOCK_PROVIDER_CAPABILITY_JOB",
            "source_bindings": BINDINGS,
            "runtime_observation": result.public,
            "control_authority": "NONE",
            "relative_alignment_established": False,
            "phase7_acceptance": "BLOCKED",
        }
        output = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
        _require(len(output) <= RECORD_CAP, "PUBLIC_OUTPUT_CAP")
        sys.stdout.buffer.write(output)
        sys.stdout.buffer.flush()
        return 2 if result.public["status"] == "REFUSED" else 0
    except Refusal as error:
        code = error.args[0]
    except Exception:
        code = "JOB_COLLECTION_FAILED"
    finally:
        if executor is not None:
            try:
                closed = executor.client_closed is True
            except BaseException:
                closed = False
            if not closed:
                # Keep the monitored wrapper in the timeout process group.
                # Normal-mode `timeout --signal=KILL 20s` is required externally.
                # A group kill is containment, never a client-reaped receipt.
                try:
                    print('{"record":"CLOCK_PROVIDER_OWNER_RESIDUAL","status":"REFUSED","client_closed":false,"control_authority":"NONE","phase7_acceptance":"BLOCKED"}', flush=True)
                finally:
                    while True:
                        signal.pause()
    print(json.dumps({"record": "CLOCK_PROVIDER_CAPABILITY_JOB", "status": "REFUSED", "code": code,
                      "control_authority": "NONE", "relative_alignment_established": False,
                      "phase7_acceptance": "BLOCKED"}, sort_keys=True, separators=(",", ":")))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
