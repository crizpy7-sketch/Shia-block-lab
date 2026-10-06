#!/usr/bin/env python3
"""One unpublished, manually dispatched qualification run; never a retry tool.

Only this file's main entry point launches Docker helpers. Import/compile is inert.
The Docker daemon is a separate owner: killing a timed-out CLI is NOT container
termination. Only the original full container ID may be inspected or removed.
"""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time


DOCKER = "/usr/bin/docker"
MEMORY = 268435456
PIDS = 32
SCRATCH = 16777216
EXPORT_LIMIT = 262144
DATA_LIMIT = 196608  # Includes base64/JSON overhead, leaves control-record room.
SETUP_SECONDS = 30.0
PULL_SECONDS = 45.0
WORKLOAD_SECONDS = 25.0
DISPOSAL_SECONDS = 5.0
HELPER_LIMIT = 10
PREFLIGHT_LIMIT = 8192
CANCEL_SIGNAL = None
META_KEYS = (
    "GITHUB_REPOSITORY", "GITHUB_REPOSITORY_ID", "GITHUB_REF", "GITHUB_SHA",
    "GITHUB_WORKFLOW_REF", "GITHUB_WORKFLOW_SHA", "GITHUB_RUN_ID",
    "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "GITHUB_EVENT_NAME",
    "ImageOS", "ImageVersion",
)


class Refusal(Exception):
    pass


def request_cancel(number, _frame):
    global CANCEL_SIGNAL
    CANCEL_SIGNAL = number


class Transcript:
    """Bounded, nonblocking stdout; log backpressure never postpones disposal."""

    def __init__(self):
        self.fd = sys.stdout.fileno()
        os.set_blocking(self.fd, False)
        self.queue = bytearray()
        self.total = 0
        self.data_total = 0
        self.failed = False
        self.overflow = False

    def emit(self, record, data=False, **fields):
        value = {"record": record, "monotonic": time.monotonic(), **fields}
        encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        if self.total + len(encoded) > EXPORT_LIMIT or (
            data and self.data_total + len(encoded) > DATA_LIMIT
        ):
            self.overflow = True
            return False
        self.total += len(encoded)
        if data:
            self.data_total += len(encoded)
        self.queue.extend(encoded)
        self.flush()
        return not self.failed

    def flush(self):
        if self.failed or not self.queue:
            return
        try:
            count = os.write(self.fd, self.queue)
            del self.queue[:count]
        except BlockingIOError:
            pass
        except OSError:
            self.failed = True

    def stream(self, source, payload):
        return self.emit("CONTAINER_STREAM", data=True, stream=source,
                         encoding="base64", bytes=len(payload),
                         value=base64.b64encode(payload).decode("ascii"))


class Helper:
    """Owns exactly one Popen handle, never a discovered or reconstructed PID."""

    def __init__(self, owner, stage, args, deadline, stream=False, interactive=False, output_limit=65536):
        if owner.helper_count >= HELPER_LIMIT or time.monotonic() >= deadline:
            raise Refusal("HELPER_BUDGET_EXHAUSTED")
        if CANCEL_SIGNAL is not None and not owner.disposing:
            raise Refusal("OWNER_CANCELLED_BEFORE_HELPER")
        owner.helper_count += 1
        self.owner = owner
        self.stage = stage
        self.deadline = deadline
        self.stream = stream
        self.output_limit = output_limit
        self.outputs = {"stdout": bytearray(), "stderr": bytearray()}
        self.first_line = bytearray()
        self.preflight = None
        self.preflight_error = False
        self.exceeded = False
        self.timed_out = False
        self.killed = False
        self.reaped = False
        self.reported = None
        self.selector = None
        self.proc = subprocess.Popen(
            [DOCKER, *args], stdin=subprocess.PIPE if interactive else subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "LANG": "C", "DOCKER_CONFIG": owner.config_dir},
            cwd="/", close_fds=True,
        )
        # Register ownership before any fallible selector/descriptor setup. Even
        # a partially initialized helper must be killed/reaped by this same owner.
        owner.helpers.append(self)
        self.selector = selectors.DefaultSelector()
        for name, pipe in (("stdout", self.proc.stdout), ("stderr", self.proc.stderr)):
            os.set_blocking(pipe.fileno(), False)
            self.selector.register(pipe, selectors.EVENT_READ, name)
        if interactive:
            os.set_blocking(self.proc.stdin.fileno(), False)
        owner.out.emit("DOCKER_HELPER_STARTED", stage=stage, helper_number=owner.helper_count,
                       pid=self.proc.pid, deadline_monotonic=deadline)

    def tick(self):
        # At most sixteen small reads per tick; a full pipe cannot starve deadlines.
        try:
            ready = self.selector.select(0)[:2] if self.selector is not None else []
        except OSError:
            ready = []
            self.exceeded = True
        for key, _ in ready:
            for _ in range(8):
                try:
                    chunk = os.read(key.fileobj.fileno(), 1024)
                except BlockingIOError:
                    break
                except OSError:
                    chunk = b""
                    self.exceeded = True
                if not chunk:
                    self.selector.unregister(key.fileobj)
                    key.fileobj.close()
                    break
                name = key.data
                if self.stream:
                    if not self.owner.out.stream(name, chunk):
                        self.exceeded = True
                    if name == "stdout" and self.preflight is None and not self.preflight_error:
                        self.first_line.extend(chunk)
                        if b"\n" in self.first_line:
                            line = bytes(self.first_line).split(b"\n", 1)[0]
                            if len(line) > PREFLIGHT_LIMIT:
                                self.preflight_error = True
                            else:
                                try:
                                    value = json.loads(line)
                                    if (isinstance(value, dict)
                                            and value.get("record") == "PHASE7_CONTAINER_PREFLIGHT"
                                            and value.get("status") == "PASS"):
                                        self.preflight = value
                                    else:
                                        self.preflight_error = True
                                except (ValueError, UnicodeError):
                                    self.preflight_error = True
                            self.first_line.clear()
                        elif len(self.first_line) > PREFLIGHT_LIMIT:
                            self.preflight_error = True
                            self.first_line.clear()
                elif sum(map(len, self.outputs.values())) + len(chunk) <= self.output_limit:
                    self.outputs[name].extend(chunk)
                else:
                    self.exceeded = True
        code = self.proc.poll()  # waitpid on the original owned handle only.
        if code is not None:
            self.reaped = True
        self.owner.out.flush()
        return code

    def drained(self):
        return self.selector is None or not self.selector.get_map()

    def kill_cli(self):
        if self.proc.poll() is None:
            self.proc.kill()
            self.killed = True
        # A CLI kill is deliberately not described as a daemon/container stop.

    def report(self):
        observation = (self.proc.poll(), self.reaped, self.killed, self.timed_out, self.exceeded)
        if self.reported == observation:
            return
        self.reported = observation
        self.owner.out.emit("DOCKER_HELPER_OBSERVATION", stage=self.stage,
                            pid=self.proc.pid, returncode=self.proc.poll(),
                            reaped=self.reaped, cli_killed=self.killed,
                            timed_out=self.timed_out, output_overflow=self.exceeded,
                            daemon_termination_implied=False)

    def close(self):
        if self.selector is not None:
            self.selector.close()
        for pipe in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            if pipe is not None and not pipe.closed:
                pipe.close()


class Owner:
    def __init__(self, out, config_dir):
        self.out = out
        self.config_dir = config_dir
        self.helpers = []
        self.helper_count = 0
        self.container_id = None
        self.start_attempted = False
        self.attached = None
        self.waiter = None
        self.released = False
        self.workload_deadline = None
        self.disposing = False

    def command(self, stage, args, deadline, output_limit=65536):
        helper = Helper(self, stage, args, deadline, output_limit=output_limit)
        while time.monotonic() < deadline:
            code = helper.tick()
            if time.monotonic() >= deadline:
                helper.timed_out = True
                break
            if CANCEL_SIGNAL is not None and not self.disposing:
                break
            if helper.exceeded:
                break
            if code is not None and helper.drained():
                helper.report()
                return helper
            time.sleep(0.01)
        helper.timed_out = time.monotonic() >= deadline
        helper.kill_cli()
        # Reaping is attempted later inside the existing disposal deadline.
        helper.tick()
        helper.report()
        return helper

    def object(self, stage, args, deadline):
        helper = self.command(stage, args, deadline)
        if helper.timed_out or helper.exceeded or helper.proc.returncode != 0:
            self.out.emit("DOCKER_OPERATION_UNPROVEN", stage=stage,
                          error=bytes(helper.outputs["stderr"][:2048]).decode("utf-8", "replace"))
            raise Refusal(stage + "_FAILED")
        try:
            value = json.loads(helper.outputs["stdout"])
        except (ValueError, UnicodeError) as exc:
            raise Refusal(stage + "_INVALID_JSON") from exc
        if not isinstance(value, dict):
            raise Refusal(stage + "_INVALID_OBJECT")
        return value

    def inspect_state(self, stage, deadline):
        value = self.object(stage, ["container", "inspect", "--format", "{{json .State}}", self.container_id], deadline)
        retained = {key: value.get(key) for key in (
            "Status", "Running", "Paused", "Restarting", "OOMKilled", "Dead",
            "Pid", "ExitCode", "Error", "StartedAt", "FinishedAt",
        )}
        if len(str(retained.get("Error"))) > 2048:
            retained["Error"] = "STATE_ERROR_TOO_LARGE"
        self.out.emit("CONTAINER_STATE", stage=stage, container_id=self.container_id, state=retained)
        return retained


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def load_binding(bundle):
    raw = (bundle / "contract.json").read_bytes()
    require(len(raw) <= 65536, "CONTRACT_TOO_LARGE")
    contract = json.loads(raw)
    require(isinstance(contract, dict), "CONTRACT_INVALID")
    require(re.fullmatch(r"docker\.io/library/python@sha256:[0-9a-f]{64}",
                         str(contract.get("image_digest", ""))), "IMAGE_DIGEST_INVALID")
    metadata = {key: os.environ.get(key, "") for key in META_KEYS}
    require(all(len(value) <= 512 for value in metadata.values()), "METADATA_TOO_LARGE")
    for env_key, contract_key in (
        ("GITHUB_REPOSITORY", "repository"), ("GITHUB_REPOSITORY_ID", "repository_id"),
        ("GITHUB_REF", "expected_ref"), ("GITHUB_WORKFLOW_REF", "workflow_ref"),
    ):
        require(metadata[env_key] == str(contract[contract_key]), "BINDING_MISMATCH_" + env_key)
    require(metadata["GITHUB_EVENT_NAME"] == "workflow_dispatch", "MANUAL_EVENT_REQUIRED")
    require(os.environ.get("PHASE7_REPOSITORY_VISIBILITY") == "public", "PUBLIC_REPOSITORY_REQUIRED")
    require(metadata["GITHUB_RUN_ATTEMPT"] == "1", "RERUN_REFUSED")
    require(re.fullmatch(r"[0-9]{1,20}", metadata["GITHUB_RUN_ID"]), "RUN_ID_INVALID")
    require(re.fullmatch(r"[0-9a-f]{40}", metadata["GITHUB_SHA"]), "COMMIT_INVALID")
    require(re.fullmatch(r"[0-9a-f]{40}", metadata["GITHUB_WORKFLOW_SHA"]), "WORKFLOW_COMMIT_INVALID")
    require(os.environ.get("PHASE7_APPROVED_COMMIT") == metadata["GITHUB_SHA"]
            == metadata["GITHUB_WORKFLOW_SHA"], "EXACT_REVIEWED_COMMIT_REQUIRED")
    require(metadata["ImageOS"] == "ubuntu24", "STANDARD_UBUNTU24_IMAGE_REQUIRED")
    payload = bundle / "payload"
    require(payload.is_dir() and not payload.is_symlink(), "PAYLOAD_DIRECTORY_INVALID")
    expected = contract["source_sha256"]
    require(isinstance(expected, dict) and 1 <= len(expected) <= 32, "SOURCE_BINDING_INVALID")
    observed = {}
    for path in sorted(payload.rglob("*")):
        require(not path.is_symlink(), "PAYLOAD_SYMLINK_REFUSED")
        if path.is_dir():
            continue
        require(path.is_file(), "PAYLOAD_SPECIAL_FILE_REFUSED")
        relative = path.relative_to(payload).as_posix()
        require(relative in expected, "UNBOUND_PAYLOAD_FILE")
        content = path.read_bytes()
        require(len(content) <= 1048576, "PAYLOAD_FILE_TOO_LARGE")
        observed[relative] = hashlib.sha256(content).hexdigest()
    require(observed == expected, "PAYLOAD_HASH_MISMATCH")
    require("container_preflight.py" in observed and "qualification_runner.py" in observed
            and "manifest.json" in observed, "REQUIRED_PAYLOAD_MISSING")
    return contract, metadata, payload, hashlib.sha256(raw).hexdigest()


def check_configuration(value, owner, image, payload, name, labels):
    require(value.get("Id") == owner.container_id, "CONTAINER_ID_MISMATCH")
    require(value.get("Name") == "/" + name, "CONTAINER_NAME_MISMATCH")
    config = value["Config"]
    host = value["HostConfig"]
    require(config.get("Image") == image, "CONTAINER_IMAGE_MISMATCH")
    require(config.get("User") == "65534:65534", "CONTAINER_USER_MISMATCH")
    require(config.get("Entrypoint") == ["/usr/local/bin/python3"], "ENTRYPOINT_MISMATCH")
    require(config.get("Cmd") == ["-I", "-S", "-B", "/payload/container_preflight.py"], "COMMAND_MISMATCH")
    require(config.get("WorkingDir") == "/payload", "WORKDIR_MISMATCH")
    require(config.get("OpenStdin") is True and config.get("Tty") is False, "STDIN_MODE_MISMATCH")
    require(config.get("Labels") == labels, "CONTAINER_LABELS_MISMATCH")
    require(not config.get("Volumes") and not config.get("ExposedPorts"), "IMAGE_VOLUMES_OR_PORTS_REFUSED")
    for key, wanted in (
        ("Memory", MEMORY), ("MemorySwap", MEMORY), ("NanoCpus", 1000000000),
        ("PidsLimit", PIDS), ("ReadonlyRootfs", True), ("Privileged", False),
        ("NetworkMode", "none"), ("IpcMode", "none"), ("AutoRemove", False),
        ("CgroupnsMode", "private"),
    ):
        require(host.get(key) == wanted, "CONFIG_MISMATCH_" + key)
    require(host.get("CapDrop") == ["ALL"] and not host.get("CapAdd"), "CAPABILITY_MISMATCH")
    require(host.get("SecurityOpt") == ["no-new-privileges"], "SECURITY_OPTION_MISMATCH")
    require(host.get("LogConfig") == {"Type": "none", "Config": {}}, "LOGGING_MISMATCH")
    require(host.get("RestartPolicy") == {"Name": "no", "MaximumRetryCount": 0}, "RESTART_POLICY_MISMATCH")
    require(host.get("PidMode") == "" and host.get("UTSMode") == "", "HOST_NAMESPACE_REFUSED")
    require(not host.get("PortBindings") and not host.get("Devices")
            and not host.get("DeviceRequests") and not host.get("Binds"), "EXTRA_HOST_ACCESS_REFUSED")
    require(host.get("Tmpfs") == {"/tmp": "rw,noexec,nosuid,nodev,size=16777216,uid=65534,gid=65534,mode=0700"},
            "TMPFS_CONFIGURATION_MISMATCH")
    mounts = value.get("Mounts", [])
    require(len(mounts) == 1, "EXTRA_MOUNT_REFUSED")
    mount = mounts[0]
    require(mount.get("Type") == "bind" and mount.get("Source") == str(payload)
            and mount.get("Destination") == "/payload" and mount.get("RW") is False,
            "PAYLOAD_MOUNT_MISMATCH")
    require(value.get("State", {}).get("Status") == "created"
            and value.get("State", {}).get("Running") is False, "PRESTART_STATE_MISMATCH")
    owner.out.emit("CONTAINER_CONFIG_VERIFIED", container_id=owner.container_id,
                   image=image, image_id=value.get("Image"), cpu=1, memory_bytes=MEMORY,
                   memory_swap_bytes=MEMORY, pids=PIDS, writable_scratch_bytes=SCRATCH,
                   root_read_only=True, network="none", ipc="none", user="65534:65534",
                   payload_mount_read_only=True, log_driver="none", automatic_removal=False)


def prepare(owner, contract, payload, temp):
    require(CANCEL_SIGNAL is None, "OWNER_CANCELLED_BEFORE_PREPARATION")
    image = contract["image_digest"]
    pull_deadline = time.monotonic() + PULL_SECONDS
    owner.out.emit("IMAGE_PULL_START", image=image, deadline_monotonic=pull_deadline)
    pull = owner.command("image_pull", ["pull", "--platform", "linux/amd64", image],
                         pull_deadline, output_limit=16384)
    owner.out.emit("IMAGE_PULL_OBSERVED", data=True, cli_exit=pull.proc.returncode,
                   timed_out=pull.timed_out, output_overflow=pull.exceeded,
                   encoding="base64", stdout=base64.b64encode(pull.outputs["stdout"]).decode("ascii"),
                   stderr=base64.b64encode(pull.outputs["stderr"]).decode("ascii"),
                   cli_timeout_does_not_prove_daemon_operation_cancelled=True)
    require(pull.proc.returncode == 0 and not pull.timed_out and not pull.exceeded, "IMAGE_PULL_UNPROVEN")
    require(CANCEL_SIGNAL is None and not owner.out.failed and not owner.out.overflow,
            "OWNER_CANCELLED_OR_RETENTION_FAILED")
    setup_deadline = time.monotonic() + SETUP_SECONDS
    image_data = owner.object("image_inspect", ["image", "inspect", "--format", "{{json .}}", image], setup_deadline)
    image_config = image_data.get("Config") or {}
    require(image_data.get("Os") == "linux" and image_data.get("Architecture") == "amd64", "IMAGE_PLATFORM_MISMATCH")
    require(not image_config.get("Volumes") and not image_config.get("Entrypoint")
            and not image_config.get("ExposedPorts") and not image_config.get("Healthcheck"),
            "IMAGE_AUTOMATIC_BEHAVIOR_REFUSED")
    # Exact labels avoid inheritance of unreviewed image metadata.
    require(not image_config.get("Labels"), "IMAGE_LABELS_REFUSED")
    run_id = os.environ["GITHUB_RUN_ID"]
    name = "phase7-qualification-" + run_id + "-1"
    labels = {"phase7.run_id": run_id, "phase7.attempt": "1", "phase7.scope": "transport-qualification"}
    cidfile = Path(temp) / "original.cid"
    args = [
        "create", "--name", name, "--cidfile", str(cidfile), "--interactive",
        "--pull", "never", "--platform", "linux/amd64", "--cpus", "1",
        "--memory", str(MEMORY), "--memory-swap", str(MEMORY), "--pids-limit", str(PIDS),
        "--read-only", "--network", "none", "--ipc", "none", "--cgroupns", "private",
        "--user", "65534:65534",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--log-driver", "none",
        "--restart", "no", "--workdir", "/payload", "--hostname", "phase7-qualification",
        "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16777216,uid=65534,gid=65534,mode=0700",
        "--mount", "type=bind,src=" + str(payload) + ",dst=/payload,readonly",
        "--entrypoint", "/usr/local/bin/python3",
    ]
    for key, value in labels.items():
        args.extend(["--label", key + "=" + value])
    args.extend([image, "-I", "-S", "-B", "/payload/container_preflight.py"])
    created = owner.command("create", args, setup_deadline)
    # A CID written by this original create is retained even if CLI acknowledgement failed.
    if cidfile.is_file() and not cidfile.is_symlink():
        identity = cidfile.read_bytes()
        if len(identity) <= 65:
            candidate = identity.decode("ascii", "replace").strip()
            if re.fullmatch(r"[0-9a-f]{64}", candidate):
                owner.container_id = candidate
                owner.out.emit("ORIGINAL_CONTAINER_BOUND", container_id=candidate, source="original_create_cidfile")
    require(owner.container_id is not None, "CREATE_IDENTITY_UNKNOWN")
    require(created.proc.returncode == 0 and not created.timed_out and not created.exceeded,
            "CREATE_ACKNOWLEDGEMENT_UNPROVEN")
    require(CANCEL_SIGNAL is None and not owner.out.failed and not owner.out.overflow,
            "OWNER_CANCELLED_OR_RETENTION_FAILED")
    require(bytes(created.outputs["stdout"]).decode("ascii", "replace").strip() == owner.container_id,
            "CREATE_IDENTITY_DISAGREEMENT")
    value = owner.object("config_inspect", ["container", "inspect", "--format", "{{json .}}", owner.container_id], setup_deadline)
    check_configuration(value, owner, image, payload, name, labels)


def workload(owner):
    require(CANCEL_SIGNAL is None, "OWNER_CANCELLED_BEFORE_START")
    owner.workload_deadline = time.monotonic() + WORKLOAD_SECONDS
    owner.out.emit("WORKLOAD_START_ATTEMPT", container_id=owner.container_id,
                   original_deadline_monotonic=owner.workload_deadline,
                   disposal_allowance_seconds=DISPOSAL_SECONDS)
    owner.start_attempted = True
    owner.attached = Helper(owner, "start_attach", ["start", "--attach", "--interactive", owner.container_id],
                            owner.workload_deadline, stream=True, interactive=True)
    release_recorded = False
    while time.monotonic() < owner.workload_deadline:
        require(CANCEL_SIGNAL is None, "OWNER_CANCELLED_DURING_WORKLOAD")
        attached_rc = owner.attached.tick()
        wait_rc = owner.waiter.tick() if owner.waiter is not None else None
        if (owner.out.failed or owner.out.overflow or owner.attached.exceeded
                or owner.attached.preflight_error or (owner.waiter is not None and owner.waiter.exceeded)):
            raise Refusal("STREAM_OR_PREFLIGHT_FAILURE")
        if owner.attached.preflight is not None and not owner.released:
            # Before this point the container might still be merely 'created':
            # docker wait could then return immediately without observing its run.
            if owner.waiter is None:
                owner.waiter = Helper(owner, "wait", ["wait", owner.container_id], owner.workload_deadline)
            if not release_recorded:
                owner.out.emit("PREFLIGHT_OBSERVED_RELEASE_INTENT", container_id=owner.container_id)
                release_recorded = True
            owner.out.flush()
            if not owner.out.queue and not owner.out.failed:
                require(time.monotonic() < owner.workload_deadline and CANCEL_SIGNAL is None,
                        "RELEASE_DEADLINE_OR_CANCELLATION")
                token = b"PHASE7_RELEASE\n"
                try:
                    written = os.write(owner.attached.proc.stdin.fileno(), token)
                except (BlockingIOError, BrokenPipeError, OSError) as exc:
                    raise Refusal("RELEASE_DELIVERY_FAILED") from exc
                require(written == len(token), "RELEASE_DELIVERY_PARTIAL")
                owner.released = True
                owner.attached.proc.stdin.close()
                release_observed = time.monotonic()
                owner.out.emit("FIXTURE_RELEASE_DELIVERED", container_id=owner.container_id,
                               observed_monotonic=release_observed,
                               before_original_deadline=release_observed < owner.workload_deadline)
                require(release_observed < owner.workload_deadline and CANCEL_SIGNAL is None,
                        "LATE_OR_CANCELLED_RELEASE_OBSERVATION")
        if attached_rc is not None and owner.waiter is None:
            raise Refusal("CONTAINER_EXITED_BEFORE_PREFLIGHT")
        if attached_rc is not None and wait_rc is not None:
            # Drain already-written bytes without extending the original deadline.
            if owner.attached.drained() and owner.waiter.drained():
                terminal_observed = time.monotonic()
                require(terminal_observed < owner.workload_deadline and CANCEL_SIGNAL is None,
                        "LATE_OR_CANCELLED_TERMINAL_OBSERVATION")
                owner.attached.report()
                owner.waiter.report()
                wait_raw = bytes(owner.waiter.outputs["stdout"]).strip()
                require(re.fullmatch(rb"[0-9]{1,3}", wait_raw), "DOCKER_WAIT_RESULT_MISSING")
                code = int(wait_raw)
                require(code <= 255, "DOCKER_WAIT_RESULT_INVALID")
                owner.out.emit("DOCKER_WAIT_ACKNOWLEDGED", container_id=owner.container_id,
                               container_exit_code=code, wait_cli_exit=wait_rc,
                               attached_cli_exit=attached_rc,
                               observed_monotonic=terminal_observed,
                               observed_before_original_deadline=True)
                require(owner.released and attached_rc == 0 and wait_rc == 0 and code == 0,
                        "WORKLOAD_NONZERO_OR_UNRELEASED")
                require(time.monotonic() < owner.workload_deadline and CANCEL_SIGNAL is None,
                        "LATE_OR_CANCELLED_TERMINAL_ACCEPTANCE")
                return True
        time.sleep(0.01)
    raise Refusal("ORIGINAL_WORKLOAD_DEADLINE_EXPIRED")


def disposal(owner):
    owner.disposing = True
    deadline = time.monotonic() + DISPOSAL_SECONDS
    owner.out.emit("DISPOSAL_OBSERVATION_STARTED", container_id=owner.container_id,
                   deadline_monotonic=deadline, extends_workload_deadline=False)
    result = {"container_id": owner.container_id, "stopped_observed": False,
              "removal_acknowledged": False, "status": "UNKNOWN", "state": None}
    if owner.container_id is not None:
        state = None
        try:
            # Allocate inside the original five seconds; no operation gets a new budget.
            state = owner.inspect_state("state_inspect", min(deadline, time.monotonic() + 1.0))
        except (Refusal, OSError, ValueError, KeyError) as exc:
            owner.out.emit("DISPOSAL_STATE_UNKNOWN", reason=type(exc).__name__, detail=str(exc)[:256])
        try:
            result["state"] = state
            stopped = state is not None and state.get("Running") is False and state.get("Status") in ("created", "exited", "dead")
            if not stopped:
                killed = owner.command("kill", ["kill", "--signal", "KILL", owner.container_id],
                                       min(deadline, time.monotonic() + 1.0))
                owner.out.emit("CONTAINER_KILL_ACKNOWLEDGEMENT", container_id=owner.container_id,
                               cli_exit=killed.proc.returncode, timed_out=killed.timed_out,
                               termination_proven_by_acknowledgement_alone=False)
                state = owner.inspect_state("final_state_inspect", min(deadline, time.monotonic() + 1.0))
                result["state"] = state
                stopped = state.get("Running") is False and state.get("Status") in ("exited", "dead")
            result["stopped_observed"] = stopped
            if stopped:
                removed = owner.command("remove", ["rm", owner.container_id],
                                        min(deadline, time.monotonic() + 1.0))
                acknowledged = (removed.proc.returncode == 0 and not removed.timed_out
                                and not removed.exceeded and bytes(removed.outputs["stdout"]).strip()
                                == owner.container_id.encode("ascii"))
                result["removal_acknowledged"] = acknowledged
                if acknowledged:
                    result["status"] = "ORIGINAL_CONTAINER_STOPPED_AND_REMOVAL_ACKNOWLEDGED"
        except (Refusal, OSError, ValueError, KeyError) as exc:
            owner.out.emit("DISPOSAL_INCOMPLETE", reason=type(exc).__name__, detail=str(exc)[:256])
    # Settle only the original CLI handles, inside the same deadline. No process scan.
    for helper in owner.helpers:
        if helper.proc.poll() is None:
            try:
                helper.kill_cli()
            except OSError:
                pass
    while time.monotonic() < deadline:
        pending = False
        for helper in owner.helpers:
            helper.tick()
            pending |= helper.proc.poll() is None
        if not pending:
            break
        time.sleep(0.01)
    for helper in owner.helpers:
        helper.tick()
        helper.report()
    result["docker_helpers_launched"] = owner.helper_count
    result["all_original_cli_handles_reaped"] = all(helper.reaped for helper in owner.helpers)
    result["observed_monotonic"] = time.monotonic()
    result["disposal_deadline_monotonic"] = deadline
    if result["observed_monotonic"] > deadline:
        # Timing does not get upgraded by a late response or later CLI exit.
        result["status"] = "UNKNOWN_DISPOSAL_OBSERVATION_DEADLINE_EXCEEDED"
    owner.out.emit("DISPOSAL_RESULT", **result)
    return result


def main():
    signal.signal(signal.SIGTERM, request_cancel)
    signal.signal(signal.SIGINT, request_cancel)
    out = Transcript()
    bundle = Path(__file__).resolve().parent
    owner = None
    failure = None
    functional = False
    cleanup = {"status": "NOT_STARTED", "removal_acknowledged": False}
    runner_temp = Path(os.environ.get("RUNNER_TEMP", ""))
    if not runner_temp.is_absolute() or not runner_temp.is_dir() or runner_temp.is_symlink():
        out.emit("OWNER_FAILURE", reason="FRESH_RUNNER_TEMP_REQUIRED")
        return 1
    with tempfile.TemporaryDirectory(prefix="phase7-owner-", dir=str(runner_temp)) as temp:
        config_dir = str(Path(temp) / "docker-config")
        Path(config_dir).mkdir(mode=0o700)
        owner = Owner(out, config_dir)
        try:
            contract, metadata, payload, contract_hash = load_binding(bundle)
            require(Path(DOCKER).is_file() and os.access(DOCKER, os.X_OK), "DOCKER_UNAVAILABLE")
            out.emit("OWNER_BINDING", metadata=metadata, contract_sha256=contract_hash,
                     host_supervisor_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                     pull_seconds=PULL_SECONDS, setup_seconds=SETUP_SECONDS, workload_seconds=WORKLOAD_SECONDS,
                     separate_disposal_seconds=DISPOSAL_SECONDS, export_limit_bytes=EXPORT_LIMIT,
                     docker_helper_limit=HELPER_LIMIT, attempts=1)
            require(not out.failed and not out.queue, "EXTERNAL_START_RECORD_NOT_DELIVERED")
            prepare(owner, contract, payload, temp)
            functional = workload(owner)
        except (Refusal, OSError, ValueError, KeyError, TypeError) as exc:
            failure = str(exc)[:512]
            out.emit("OWNER_FAILURE", reason=type(exc).__name__, detail=failure,
                     original_workload_deadline=owner.workload_deadline)
        finally:
            cleanup = disposal(owner)
            for helper in owner.helpers:
                helper.close()
        state = cleanup.get("state") or {}
        success = (functional and failure is None and owner.released
                   and CANCEL_SIGNAL is None
                   and cleanup.get("status") == "ORIGINAL_CONTAINER_STOPPED_AND_REMOVAL_ACKNOWLEDGED"
                   and cleanup.get("all_original_cli_handles_reaped") is True
                   and state.get("ExitCode") == 0 and state.get("OOMKilled") is False
                   and not out.failed and not out.overflow)
        out.emit("OWNER_TERMINAL", status="PASS" if success else "FAIL_OR_UNKNOWN",
                 workload_completed_before_deadline=functional,
                 failure=failure, disposal=cleanup.get("status"),
                 fixture_release_delivered=owner.released,
                 cancellation_signal=CANCEL_SIGNAL,
                 historical_unknown_unchanged=True, phase7_acceptance="BLOCKED",
                 transcript_bytes_before_terminal=out.total)
        # Log flushing has its own short finite interval; it cannot extend workload/disposal.
        flush_deadline = time.monotonic() + 1.0
        while out.queue and not out.failed and time.monotonic() < flush_deadline:
            out.flush()
            if out.queue:
                time.sleep(0.01)
        return 0 if success and not out.queue and not out.failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
