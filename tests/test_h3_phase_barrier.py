"""Live native SQLite prepare qualification; never formal model evidence."""

from __future__ import annotations

import contextlib
import copy
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from experiments.formal_campaign.h3_phase_barrier import identity, wait_native_prepare

ROOT = Path(__file__).resolve().parents[1]


def wait_file(path: Path, process: subprocess.Popen) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        assert process.poll() is None
        if path.exists():
            return
        time.sleep(0.02)
    raise TimeoutError(str(path))


def test_real_native_prepare_kill_recovery_and_replay_rejection(tmp_path: Path):
    env = os.environ | {"PYTHONPATH": str(ROOT / "src") + ":" + str(ROOT)}
    grant = {
        "holder": "nonformal-cpu-test",
        "fencing_token": 1,
        "expires_at": int(time.time()) + 60,
    }
    spec = {
        "root": str(tmp_path / "manager"),
        "authority_socket": str(tmp_path / "authority.sock"),
        "grant": grant,
        "launch_id": "cpu-test-only",
        "candidate": {"generation": 1},
        "predecessor": {"generation": 0},
        "evidence_identity_sha256": "sha256:" + "a" * 64,
    }
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(spec))
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    proxy_cmd = [
        sys.executable,
        str(ROOT / "experiments/exposure_gate/loopback_traffic.py"),
        "--socket",
        spec["authority_socket"],
        "--journal",
        str(tmp_path / "authority.jsonl"),
        "--listen-port",
        "0",
        "--predecessor-port",
        str(port),
        "--candidate-port",
        str(port),
        "--predecessor-snapshot",
        '{"generation":0}',
        "--grant-holder",
        grant["holder"],
        "--grant-token",
        "1",
        "--grant-expires-at",
        str(grant["expires_at"]),
    ]
    command = [
        sys.executable,
        str(ROOT / "experiments/formal_campaign/h3_native_prepare.py"),
        "launch",
        "--spec",
        str(spec_path),
    ]
    children = []
    with (tmp_path / "raw.log").open("wb") as log:
        try:
            proxy = subprocess.Popen(
                proxy_cmd, env=env, stdout=log, stderr=log, start_new_session=True
            )
            children.append(proxy)
            wait_file(Path(spec["authority_socket"]), proxy)
            launched = time.monotonic_ns()
            manager = subprocess.Popen(
                command, env=env, stdout=log, stderr=log, start_new_session=True
            )
            children.append(manager)
            config = {
                "protocol": "ecpa-native-close-prepare-barrier/v1",
                "barrier_path": str(tmp_path / "manager/prepare-barrier.json"),
                "journal_path": str(tmp_path / "manager/gate.sqlite"),
                "timeout_s": 10,
            }
            wait_file(Path(config["barrier_path"]), manager)
            state_cmd = command.copy()
            state_cmd[2] = "state"
            state = json.loads(subprocess.check_output(state_cmd, env=env))
            kwargs = {
                "target": identity(manager.pid),
                "launcher_pid": manager.pid,
                "launch_id": spec["launch_id"],
                "launched_ns": launched,
                "state_before": state,
            }
            proof = wait_native_prepare(config, **kwargs)
            assert proof["native_rows"][-1]["kind"] == "intent"
            for wrong in (
                {"launch_id": "replayed"},
                {"launched_ns": time.monotonic_ns()},
            ):
                with pytest.raises(ValueError, match="stale or replayed"):
                    wait_native_prepare(config, **(kwargs | wrong))
            changed = copy.deepcopy(state)
            changed["route"]["generation"] = 1
            with pytest.raises(ValueError, match="predecessor"):
                wait_native_prepare(config, **(kwargs | {"state_before": changed}))
            barrier_path = Path(config["barrier_path"])
            original_barrier = barrier_path.read_text()
            for field, value in [
                ("schema", "health-ready"),
                ("native_rows_sha256", "sha256:" + "f" * 64),
                ("intent_operation_id", "replayed-intent"),
            ]:
                mutated = json.loads(original_barrier)
                mutated[field] = value
                barrier_path.write_text(json.dumps(mutated))
                with pytest.raises(ValueError):
                    wait_native_prepare(config, **kwargs)
            barrier_path.write_text(original_barrier)
            manager.kill()
            manager.wait(timeout=5)
            assert manager.returncode == -signal.SIGKILL
            restarted = subprocess.Popen(
                command, env=env, stdout=log, stderr=log, start_new_session=True
            )
            children.append(restarted)
            wait_file(tmp_path / "manager/recovery.json", restarted)
            recovered = json.loads((tmp_path / "manager/recovery.json").read_text())
            assert recovered["rollback_classification"] == "RESTORED_STRONG"
            assert recovered["actual_route"]["generation"] == 0
            assert recovered["manager"]["pid"] != manager.pid
        finally:
            for child in reversed(children):
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)


def test_cleanup_reclaims_children_after_launcher_killed(tmp_path: Path):
    import importlib.util

    module_spec = importlib.util.spec_from_file_location(
        "h3_owned_cleanup", ROOT / "experiments/formal_campaign/run_h3.py"
    )
    assert module_spec and module_spec.loader
    previous = sys.path[:]
    sys.path.insert(0, str(ROOT / "experiments/formal_campaign"))
    try:
        module = importlib.util.module_from_spec(module_spec)
        module_spec.loader.exec_module(module)
    finally:
        sys.path[:] = previous
    child_file = tmp_path / "child.pid"
    code = (
        "import subprocess,sys,time; from pathlib import Path; "
        "c=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); "
        "Path(sys.argv[1]).write_text(str(c.pid)); time.sleep(60)"
    )
    parent = subprocess.Popen(
        [sys.executable, "-c", code, str(child_file)], start_new_session=True
    )
    owner = module.process_identity(parent.pid)
    try:
        wait_file(child_file, parent)
        child = int(child_file.read_text())
        parent.kill()
        parent.wait(timeout=5)
        assert identity(child)["session"] == parent.pid
        module.terminate_owned_session(parent, owner)
        with pytest.raises((ValueError, FileNotFoundError)):
            identity(child)
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(parent.pid, signal.SIGKILL)
        parent.wait(timeout=5)
