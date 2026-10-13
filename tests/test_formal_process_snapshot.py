"""Synthetic host bytes exercise identity mechanics, not formal H1 qualification."""

import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from test_host_observer import PLAN, event_id, host_event

from vllm_hust_ext.formal_process_snapshot import (
    derive_snapshot,
    make_transition,
    validate_runner_snapshots,
    validate_slots,
    validate_transition,
)

sys.path.insert(0, str(Path("experiments/false_effective").resolve()))
import runner  # noqa: E402

SLOTS = [{"host": "host-a", "role": "worker", "ordinal": 0}]
EXECUTION = {
    "plan_id": PLAN.plan_id,
    "launch_id": "launch:one",
    "controller_instance": "controller:one",
}


def receipt(raw):
    return {
        "raw_base64": base64.b64encode(raw).decode(),
        "raw_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
    }


def mutated(raw, change):
    value = json.loads(raw)
    change(value)
    value["event_id"] = event_id(value)
    return json.dumps(value, separators=(",", ":")).encode()


def test_transition_reconstructs_exact_host_epoch_and_rejects_offline_edits():
    raw = host_event(epoch=148591475053783)
    transition = make_transition(SLOTS, EXECUTION, [receipt(raw)], frozen_at_ns=100)
    rows = validate_transition(transition, SLOTS, EXECUTION)
    assert rows[0]["process_epoch"] == 148591475053783
    assert rows[0]["pid"] == os.getpid()
    assert rows[0]["start_ticks"] > 0
    for field in ("processes_digest", "logical_slots_digest", "execution_identity"):
        changed = copy.deepcopy(transition)
        changed[field] = "tampered"
        with pytest.raises(ValueError, match="differs"):
            validate_transition(changed, SLOTS, EXECUTION)
    with pytest.raises(ValueError, match="prelaunch epochs"):
        validate_slots([{**SLOTS[0], "process_epoch": 7}])


@pytest.mark.parametrize(
    "kind",
    [
        "missing",
        "replay",
        "replacement",
        "cross-launch",
        "wrong-authority",
        "wrong-ticks",
        "duplicate-pid",
        "wrong-digest",
    ],
)
def test_snapshot_rejects_incomplete_or_ambiguous_identity(kind):
    raw = host_event()
    receipts = [receipt(raw)]
    slots = SLOTS
    if kind == "missing":
        receipts = []
    elif kind == "replay":
        receipts *= 2
    elif kind == "replacement":
        receipts.append(
            receipt(mutated(raw, lambda v: v["process"].update(process_epoch=8)))
        )
    elif kind == "cross-launch":
        receipts = [receipt(host_event(launch_id="launch:old"))]
    elif kind == "wrong-authority":
        receipts = [receipt(host_event(assignment_source="environment"))]
    elif kind == "wrong-ticks":
        receipts = [
            receipt(
                mutated(
                    raw,
                    lambda v: v["process"].update(start_identity="pid:1:start_ticks:0"),
                )
            )
        ]
    elif kind == "duplicate-pid":
        slots = [*SLOTS, {**SLOTS[0], "ordinal": 1}]
        receipts.append(receipt(mutated(raw, lambda v: v["process"].update(ordinal=1))))
    elif kind == "wrong-digest":
        receipts[0]["raw_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        derive_snapshot(slots, EXECUTION, receipts)


def test_live_process_freeze_and_missing_deadline(tmp_path):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    root = (tmp_path / "events").resolve()
    root.mkdir(mode=0o700)
    info = root.stat()
    context = {"host_event_dir": str(root), "device": info.st_dev, "inode": info.st_ino}
    try:
        # Use the real Linux start identity with generated test host bytes.
        raw = host_event(pid=child.pid, epoch=912345)
        (root / "worker.jsonl").write_bytes(raw + b"\n")
        transition = runner.freeze_formal_processes(context, EXECUTION, SLOTS, child, 1)
        assert transition["processes"][0]["pid"] == child.pid
        assert transition["processes"][0]["process_epoch"] == 912345
        validate_transition(transition, SLOTS, EXECUTION)
        (root / "worker.jsonl").unlink()
        started = time.monotonic()
        with pytest.raises(ValueError, match="freeze deadline"):
            runner.freeze_formal_processes(context, EXECUTION, SLOTS, child, 0.1)
        assert time.monotonic() - started < 1
    finally:
        child.terminate()
        child.wait(timeout=2)


def test_offline_runner_binds_both_snapshots_and_transition_times():
    transition = make_transition(
        SLOTS, EXECUTION, [receipt(host_event())], frozen_at_ns=100
    )
    identity = {
        "required_process_slots": SLOTS,
        "required_processes": [
            {k: row[k] for k in ("host", "role", "ordinal", "process_epoch")}
            for row in transition["processes"]
        ],
    }
    command = {
        "execution_identity": EXECUTION,
        "process_transition": transition,
        "prelaunch_snapshot": {
            "schema": "ecpa-formal-logical-snapshot/v1",
            "execution_identity": EXECUTION,
            "logical_slots": SLOTS,
            "logical_slots_digest": transition["logical_slots_digest"],
            "prepared_at_ns": 10,
        },
        "monotonic_start_ns": 20,
        "phase_bounds": {"service-ready": [110, 120]},
    }
    assert validate_runner_snapshots(identity, command) == transition["processes"]
    for field, value in (
        ("prepared_at_ns", 30),
        ("logical_slots_digest", "forged"),
        ("logical_slots", [{**SLOTS[0], "ordinal": 1}]),
    ):
        changed = copy.deepcopy(command)
        changed["prelaunch_snapshot"][field] = value
        with pytest.raises(ValueError):
            validate_runner_snapshots(identity, changed)
    changed = copy.deepcopy(command)
    changed["phase_bounds"]["service-ready"][0] = 99
    with pytest.raises(ValueError, match="outside"):
        validate_runner_snapshots(identity, changed)
    changed_identity = copy.deepcopy(identity)
    changed_identity["required_processes"][0]["process_epoch"] += 1
    with pytest.raises(ValueError, match="epochs differ"):
        validate_runner_snapshots(changed_identity, command)
