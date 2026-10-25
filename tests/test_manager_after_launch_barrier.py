"""Controlled stdlib-only IPC children; these do not qualify a native tuple."""

import hashlib
import importlib.util
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SUPERVISOR = ROOT / "src/vllm_hust_ext/process_supervisor.py"
ADMIN = ROOT / "experiments/formal_campaign/h3_manager_after_launch.py"


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


admin = module(ADMIN, "phase_admin")


@pytest.fixture
def harness():
    processes = []
    with tempfile.TemporaryDirectory(prefix="mp-") as directory:
        yield Path(directory), processes
        for process in processes:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
        report = os.environ.get("ECPA_MANAGER_PHASE_TEST_REPORT")
        if report:
            with Path(report).open("a") as stream:
                stream.write(
                    json.dumps(
                        {
                            "classification": "CONTROLLED_STDLIB_CHILD_TEST_ONLY",
                            "processes": [
                                {
                                    "pid": p.pid,
                                    "returncode": p.returncode,
                                    "known_epochs": getattr(p, "_known_epochs", []),
                                    "fault_timing": getattr(p, "_fault_timing", None),
                                    "remaining_known_pids": [
                                        k["pid"]
                                        for k in getattr(p, "_known_epochs", [])
                                        if Path(f"/proc/{k['pid']}").exists()
                                    ],
                                }
                                for p in processes
                            ],
                        }
                    )
                    + "\n"
                )


def start(harness, *, enabled=True, binding=True, extra_argument=None):
    directory, processes = harness
    ref = admin.declare(
        directory / "phase",
        start_id="manager-crash-after-launch-r1-ecpa",
        deadline_ns=time.monotonic_ns() + 5_000_000_000,
        nonce="a" * 64,
    )
    ref = ref.reference()
    config = json.loads(Path(ref["path"]).read_bytes())
    env = os.environ.copy()
    for key in (
        "VLLM_ECPA_PLAN_ID",
        "VLLM_ECPA_LAUNCH_ID",
        "ECPA_SEMANTIC_EXECUTION_PLAN_ID",
        "ECPA_SEMANTIC_CONTROLLER_INSTANCE",
        "ECPA_SEMANTIC_CANDIDATE_GENERATION",
        "ECPA_SEMANTIC_MEMBERSHIP_EPOCH",
    ):
        env.pop(key, None)
    native = dict(
        VLLM_ECPA_PLAN_ID="fixture-native",
        VLLM_ECPA_LAUNCH_ID="fixture-launch",
        ECPA_SEMANTIC_EXECUTION_PLAN_ID="fixture-semantic",
        ECPA_SEMANTIC_CONTROLLER_INSTANCE="fixture-controller",
        ECPA_SEMANTIC_CANDIDATE_GENERATION="1",
        ECPA_SEMANTIC_MEMBERSHIP_EPOCH="1",
    )
    if binding:
        env.update(native)
    if enabled:
        env[admin.ENV] = ref["path"]
    command = [sys.executable, "-c", "import time;time.sleep(.3)"]
    if extra_argument is not None:
        command.append(extra_argument)
    script = (
        "import importlib.util,os,sys;"
        f"s=importlib.util.spec_from_file_location('supervisor',{str(SUPERVISOR)!r});"
        "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
        f"sys.exit(m.supervise({command!r},env=os.environ,shutdown_grace_seconds=.2))"
    )
    log = (directory / "manager.log").open("wb")
    try:
        process = subprocess.Popen(
            [sys.executable, "-c", script],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finally:
        log.close()
    process._known_epochs = [admin.kernel(process.pid)]
    processes.append(process)
    return process, config, native


def connect(process, config):
    path = Path(config["socket_path"])
    deadline = time.monotonic() + 3
    while not path.exists():
        assert process.poll() is None
        assert time.monotonic() < deadline
        time.sleep(0.005)
    connection = admin._connect_private_manager(
        path, admin.kernel(process.pid), config["deadline_ns"]
    )
    children = (
        Path(f"/proc/{process.pid}/task/{process.pid}/children").read_text().split()
    )
    process._known_epochs.extend(admin.kernel(int(pid)) for pid in children)
    return connection


def test_real_popen_source_event_and_release(harness):
    process, config, native = start(harness)
    manager = admin.kernel(process.pid)
    with connect(process, config) as connection:
        request = dict(
            schema=admin.SCHEMA,
            operation="hold-after-launch",
            start_id=config["start_id"],
            nonce=config["nonce"],
            expected_manager=manager,
            expected_native=native,
        )
        raw = admin.canonical(request) + b"\n"
        connection.sendall(raw)
        event = admin._read(connection, config["deadline_ns"])
        assert event["manager"] == manager
        assert event["child"] == admin.kernel(event["child"]["pid"])
        assert event["request_sha256"] == hashlib.sha256(raw).hexdigest()
        assert (
            event["source"]["sha256"]
            == hashlib.sha256(SUPERVISOR.read_bytes()).hexdigest()
        )
        assert event["model_request_id"] is None
        assert event["commit_proved"] is event["native_completion_proved"] is False
        assert (
            event["child_popen_ns"]
            <= event["observed_monotonic_ns"]
            < time.monotonic_ns()
        )
        connection.sendall(
            admin.canonical(
                dict(
                    schema=admin.SCHEMA,
                    operation="release",
                    nonce=config["nonce"],
                    event_sha256=admin.sha(admin.canonical(event)),
                )
            )
            + b"\n"
        )
    assert process.wait(timeout=3) == 0
    assert not Path(f"/proc/{event['child']['pid']}").exists()


def test_wrong_challenge_rejected_not_a_phase_success(harness):
    process, config, native = start(harness)
    with connect(process, config) as connection:
        request = dict(
            schema=admin.SCHEMA,
            operation="hold-after-launch",
            start_id=config["start_id"],
            nonce="b" * 64,
            expected_manager=admin.kernel(process.pid),
            expected_native=native,
        )
        connection.sendall(admin.canonical(request) + b"\n")
        assert connection.recv(65536) == b""
    assert process.wait(timeout=3) != 0
    assert b"challenge differs" in (harness[0] / "manager.log").read_bytes()


def test_original_signal_cancels_barrier_and_reaps_owned_child(harness):
    process, config, _ = start(harness)
    with connect(process, config):
        fd = os.pidfd_open(process.pid)
        try:
            signal.pidfd_send_signal(fd, signal.SIGTERM)
        finally:
            os.close(fd)
        assert process.wait(timeout=3) == 128 + signal.SIGTERM


def test_missing_native_context_fails_closed(harness):
    process, config, _ = start(harness, binding=False)
    assert process.wait(timeout=3) != 0
    assert not Path(config["socket_path"]).exists()
    assert (
        b"actual validated Manager native/semantic binding"
        in (harness[0] / "manager.log").read_bytes()
    )


def test_disabled_default_does_not_require_native_context(harness):
    process, config, _ = start(harness, enabled=False, binding=False)
    assert process.wait(timeout=3) == 0
    assert not Path(config["socket_path"]).exists()


def test_actual_pidfd_fault_on_held_owned_manager_and_orphan_cleanup(harness):
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    previous = ctypes.c_int()
    assert libc.prctl(37, ctypes.byref(previous), 0, 0, 0) == 0
    assert libc.prctl(36, 1, 0, 0, 0) == 0
    process = None
    try:
        process, config, native = start(harness)
        manager = admin.kernel(process.pid)
        with connect(process, config) as connection:
            request = dict(
                schema=admin.SCHEMA,
                operation="hold-after-launch",
                start_id=config["start_id"],
                nonce=config["nonce"],
                expected_manager=manager,
                expected_native=native,
            )
            connection.sendall(admin.canonical(request) + b"\n")
            event = admin._read(connection, config["deadline_ns"])
            with pytest.raises(TimeoutError, match="before fault"):
                admin._kill_held_manager(manager, time.monotonic_ns() - 1)
            assert process.poll() is None
            timing = admin._kill_held_manager(manager, config["deadline_ns"])
            process._fault_timing = timing
            assert (
                timing["fault_before_ns"]
                <= timing["fault_sent_ns"]
                < timing["death_observed_ns"]
            )
            assert (
                timing["recovery_deadline_ns"] - timing["fault_before_ns"]
                == 30_000_000_000
            )
        assert process.wait(timeout=3) == -signal.SIGKILL
        # The orphan is an actual retained child kernel, not a guessed PID.
        assert event["child"] in process._known_epochs
    finally:
        try:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=3)
                for child in getattr(process, "_known_epochs", [])[1:]:
                    try:
                        waited, _ = os.waitpid(child["pid"], os.WNOHANG)
                    except ChildProcessError:
                        continue
                    if waited == 0:
                        fd = os.pidfd_open(child["pid"])
                        try:
                            raw = Path(f"/proc/{child['pid']}/stat").read_text()
                            fields = raw.rsplit(")", 1)[1].split()
                            assert int(fields[19]) == child["start_ticks"]
                            assert int(fields[3]) == child["session"]
                            if fields[0] != "Z":
                                with suppress(ProcessLookupError):
                                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                        finally:
                            os.close(fd)
                        os.waitpid(child["pid"], 0)
                    assert not Path(f"/proc/{child['pid']}").exists()
        finally:
            assert libc.prctl(36, previous.value, 0, 0, 0) == 0


def test_oversized_real_source_event_is_not_truncated_into_proof(harness):
    process, config, native = start(harness, extra_argument="x" * 65000)
    with connect(process, config) as connection:
        request = dict(
            schema=admin.SCHEMA,
            operation="hold-after-launch",
            start_id=config["start_id"],
            nonce=config["nonce"],
            expected_manager=admin.kernel(process.pid),
            expected_native=native,
        )
        connection.sendall(admin.canonical(request) + b"\n")
        assert connection.recv(65536) == b""
    assert process.wait(timeout=3) != 0
    assert b"exceeds original frame bound" in (harness[0] / "manager.log").read_bytes()
