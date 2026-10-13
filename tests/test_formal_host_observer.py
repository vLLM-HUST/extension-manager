import argparse
from pathlib import Path

import pytest
from test_formal_process_snapshot import EXECUTION, SLOTS, receipt
from test_host_observer import BINDING, host_event

from vllm_hust_ext.ecpa_model import canonical_bytes
from vllm_hust_ext.formal_host_observer import FormalObserverError, observe
from vllm_hust_ext.formal_process_snapshot import make_transition


def _capture() -> dict[str, object]:
    return {
        "schema": "ecpa-formal-observer-capture/v1",
        "phase": "observer-captured",
        "scenario": "partial-worker-coverage",
        **EXECUTION,
        "invocation_id": "launch:one:4:challenge",
        "sequence": 4,
        "challenge": "challenge",
    }


def _inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> argparse.Namespace:
    event_dir = (tmp_path / "events").resolve()
    event_dir.mkdir(mode=0o700)
    raw = host_event()
    (event_dir / "worker.jsonl").write_bytes(raw + b"\n")
    transition = make_transition(SLOTS, EXECUTION, [receipt(raw)], frozen_at_ns=1)
    snapshot = (tmp_path / "snapshot.json").resolve()
    snapshot.write_bytes(canonical_bytes(transition) + b"\n")
    snapshot.chmod(0o400)
    metadata = event_dir.stat()
    environment = {
        "ECPA_PLAN_ID": EXECUTION["plan_id"],
        "ECPA_LAUNCH_ID": EXECUTION["launch_id"],
        "ECPA_CONTROLLER_INSTANCE": EXECUTION["controller_instance"],
        "ECPA_OBSERVER_SOURCE_ROLE": "host-observer",
        "ECPA_PROCESS_SNAPSHOT_PATH": str(snapshot),
        "ECPA_SUT_PID": "12345",
        "ECPA_EXPECTED_CONTRACT": "manager-controlled-activation",
    }
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    frozen = transition["processes"][0]

    def identity(pid: int) -> dict[str, object]:
        if pid == 12345:
            return {
                "pid": pid,
                "start_ticks": 999,
                "argv": ["vllm", "serve", "--enable-ecpa-manager"],
            }
        assert pid == frozen["pid"]
        return {
            "pid": pid,
            "start_ticks": frozen["start_ticks"],
            "argv": ["worker", "--rank", "0"],
        }

    monkeypatch.setattr("vllm_hust_ext.formal_host_observer._linux_identity", identity)
    return argparse.Namespace(
        event_dir=str(event_dir),
        device=metadata.st_dev,
        inode=metadata.st_ino,
        entry_point_group=BINDING.group,
        entry_point_name=BINDING.name,
        entry_point_value=BINDING.value,
    )


def test_observer_derives_activation_invocation_and_dynamic_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = _inputs(tmp_path, monkeypatch)
    result = observe(args, _capture())
    events = {row["event"]: row for row in result["events"]}

    assert events["activation-path"]["value"] == "manager-controlled-activation"
    assert events["effective-claim"]["value"] is False
    assert events["plugin-invoked"]["value"] is True
    assert events["coverage"]["value"] == 1.0
    process = events["plugin-invoked"]["effect_process_identities"][0]
    assert process["process_epoch"] == 7
    assert process["assignment_source"] == "host"
    assert process["argv"] == ["worker", "--rank", "0"]
    assert all(row["source_role"] == "host-observer" for row in result["events"])
    assert all("causal_ack" not in row for row in result["events"])


def test_observer_rejects_execution_or_live_process_identity_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = _inputs(tmp_path, monkeypatch)
    changed = _capture()
    changed["launch_id"] = "launch:replayed"
    with pytest.raises(FormalObserverError, match="execution identity"):
        observe(args, changed)

    monkeypatch.setattr(
        "vllm_hust_ext.formal_host_observer._linux_identity",
        lambda pid: {
            "pid": pid,
            "start_ticks": 999,
            "argv": ["vllm", "--enable-ecpa-manager"],
        },
    )
    with pytest.raises(FormalObserverError, match="frozen identity"):
        observe(args, _capture())


def test_observer_rejects_wrong_journal_directory_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    args = _inputs(tmp_path, monkeypatch)
    args.inode += 1
    with pytest.raises(RuntimeError, match="identity changed"):
        observe(args, _capture())
