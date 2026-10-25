from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from experiments.formal_campaign import h3_worker_relaunch as runner
from tests.test_h3_worker_relaunch import campaign
from vllm_hust_ext.runtime_evidence import _EVIDENCE_ENVIRONMENT, launch_environment
from vllm_hust_ext.runtime_phase_handoff import (
    PROTOCOL,
    accept_native_binding,
    bind_receiver,
    manager_source_digests,
    process_identity,
)

ROOT = Path(__file__).resolve().parents[1]
MANAGER = ROOT / "tests/fixtures/h3_native_manager_fixture.py"


def test_legacy_entrypoint_environment_remains_exactly_five_fields():
    assert _EVIDENCE_ENVIRONMENT == (
        "VLLM_ECPA_EVIDENCE_SINK",
        "VLLM_ECPA_EVIDENCE_STRICT",
        "VLLM_ECPA_PLAN_ID",
        "VLLM_ECPA_LAUNCH_ID",
        "VLLM_HUST_EXT_EVIDENCE_PATH",
    )


def native_campaign(tmp_path):
    c = campaign(tmp_path)
    arm = c["arms"][2]
    arm.pop("plan_id")
    arm.update(
        binding_protocol=PROTOCOL,
        manager_source_sha256=manager_source_digests(),
        argv=[sys.executable, str(MANAGER), "@native_phase_socket@"],
        env={
            "PYTHONPATH": str(ROOT / "src") + os.pathsep + str(ROOT),
            "XDG_CONFIG_HOME": str(tmp_path / "config"),
        },
        phases=[{"handoff_path": str(tmp_path / f"phase{i}.sock")} for i in range(2)],
    )
    arm["sources"][0].update(path=str(MANAGER), sha256=runner.sha(MANAGER))
    return c


def test_complete_native_cli_mint_handoff_supervise_kill_relaunch(tmp_path):
    tmp_path.chmod(0o700)
    c = native_campaign(tmp_path)
    result = runner.run_arm(c, "ecpa", tmp_path / "out")
    assert result["passed"], result
    receipts = [
        json.loads((tmp_path / f"out/phase{i}.native-binding.json").read_text())
        for i in range(2)
    ]
    envs = [r["environment"] for r in receipts]
    assert envs[0]["VLLM_ECPA_PLAN_ID"] == envs[1]["VLLM_ECPA_PLAN_ID"]
    assert envs[0]["VLLM_ECPA_LAUNCH_ID"] != envs[1]["VLLM_ECPA_LAUNCH_ID"]
    assert (
        envs[0]["VLLM_HUST_EXT_EVIDENCE_PATH"] != envs[1]["VLLM_HUST_EXT_EVIDENCE_PATH"]
    )
    targets = [e for e in result["events"] if e["kind"] == "worker-observed"]
    assert all(len(e["ownership_sessions"]) == 2 for e in targets)
    assert all(
        e["raw"]["launch_id"] == env["VLLM_ECPA_LAUNCH_ID"]
        for e, env in zip(targets, envs, strict=True)
    )
    assert result["classification"] == "CPU_PREFLIGHT_ONLY"
    assert result["cleanup_errors"] == [] and result["formal_result"] is False
    assert not any(runner.live(s) for e in targets for s in e["ownership_sessions"])
    assert not any(tmp_path.glob("*.sock"))


@pytest.mark.parametrize("variable", _EVIDENCE_ENVIRONMENT)
def test_native_reserved_environment_ownership_rejection_unchanged(
    monkeypatch, variable
):
    monkeypatch.setenv(variable, "caller cannot choose native binding")
    with pytest.raises(ValueError, match="owns runtime evidence"):
        launch_environment(())


def test_changed_source_rejects_before_supervised_worker_start(tmp_path):
    tmp_path.chmod(0o700)
    c = native_campaign(tmp_path)
    c["arms"][2]["manager_source_sha256"]["runtime_evidence.py"] = "0" * 64
    result = runner.run_arm(c, "ecpa", tmp_path / "out")
    assert not result["passed"]
    assert "source/identity binding differs" in result["failure"]
    assert not any(e["kind"] == "worker-observed" for e in result["events"])
    assert result["cleanup_errors"] == []


def test_native_phase_cannot_supply_external_ids_or_reserved_env(tmp_path):
    c = native_campaign(tmp_path)
    c["arms"][2]["phases"][0]["launch_id"] = "external-mint"
    with pytest.raises(ValueError, match="never IDs"):
        runner.validate(c)
    c = native_campaign(tmp_path)
    c["arms"][2]["env"]["VLLM_ECPA_PLAN_ID"] = "0" * 64
    with pytest.raises(ValueError, match="Manager-owned"):
        runner.validate(c)


def test_unowned_publisher_pid_rejected(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "peer.sock"
    listener = bind_receiver(path, 2)
    launched = time.time_ns()
    outsider = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import socket,sys,time; s=socket.socket(socket.AF_UNIX); "
            "s.connect(sys.argv[1]);time.sleep(2)",
            str(path),
        ]
    )
    try:
        with pytest.raises(ValueError, match="not the owned Manager"):
            accept_native_binding(
                listener,
                path,
                process_identity(os.getpid()),
                launched,
                manager_source_digests(),
            )
    finally:
        listener.close()
        path.unlink()
        outsider.terminate()
        outsider.wait(timeout=3)


def test_private_directory_and_cli_help_contract(tmp_path):
    tmp_path.chmod(0o755)
    with pytest.raises(ValueError, match="private and owned"):
        bind_receiver(tmp_path / "public.sock", 1)
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from vllm_hust_ext.cli import main; main(sys.argv[1:])",
            "run",
            "--help",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "--phase-binding-socket" in result.stdout


def test_message_identity_must_match_actual_native_publisher(tmp_path):
    tmp_path.chmod(0o700)
    c = native_campaign(tmp_path)
    c["arms"][2]["env"]["FIXTURE_BAD_PUBLISHER"] = "1"
    result = runner.run_arm(c, "ecpa", tmp_path / "out")
    assert not result["passed"]
    assert "source/identity binding differs" in result["failure"]
    assert result["cleanup_errors"] == []
    assert not any(e["kind"] == "worker-observed" for e in result["events"])
    assert (tmp_path / "out/phase0.handoff-unvalidated.json").exists()


def test_manager_rejects_wrong_ack_before_supervision(tmp_path):
    tmp_path.chmod(0o700)
    path = tmp_path / "ack.sock"
    listener = bind_receiver(path, 3)
    environment = {
        "PYTHONPATH": str(ROOT / "src") + os.pathsep + str(ROOT),
        "XDG_CONFIG_HOME": str(tmp_path / "config"),
    }
    manager = subprocess.Popen(
        [sys.executable, str(MANAGER), str(path)],
        env=environment,
        start_new_session=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(3)
            message = b""
            while not message.endswith(b"\n"):
                message += connection.recv(4096)
            environment = json.loads(message)["environment"]
            connection.sendall(
                json.dumps({"schema": PROTOCOL, "binding_sha256": "0" * 64}).encode()
                + b"\n"
            )
        _, error = manager.communicate(timeout=3)
        assert manager.returncode != 0
        assert b"acknowledgement" in error
        assert Path(environment["VLLM_HUST_EXT_EVIDENCE_PATH"]).read_bytes() == b""
    finally:
        listener.close()
        path.unlink()
        if manager.poll() is None:
            manager.kill()
            manager.wait(timeout=3)
