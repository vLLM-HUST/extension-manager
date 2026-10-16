"""Protocol/owned-CPU tests only; no accelerator or model qualification."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from experiments.formal_campaign.h3_cell_dispatch import (
    cell_policy, validate_cell_execution, validate_raw_kind,
)
from experiments.formal_campaign.h3_worker_recovery import validate_carrier

ROOT = Path(__file__).resolve().parents[1]


def worker_campaign():
    # These are explicit CPU protocol fixtures, never registered deployment IDs.
    arms = ["vanilla-vllm-entry-points", "manual-integration", "ecpa"]
    starts = {}
    payload = {"model": "cpu-protocol-fixture"}
    oracle = {"text_equals": "fixture"}
    for repetition in (1, 2, 3):
        for arm in arms:
            sid = f"worker-crash-r{repetition}-{arm}"
            starts[sid] = {"client_window": {
                "schema": "ecpa-h3-client-window-spec/v1", "start_id": sid,
                "request_url": "http://127.0.0.1:8187/v1/completions",
                "payload": payload, "response_expectation": oracle,
                "request_count": 60, "concurrency": 8, "interval_s": .2,
                "timeout_s": 10, "dispatch_slack_s": .5,
                "retry_policy": "single-attempt-no-retry",
            }}
    return {"cell_id": "worker-crash", "fault": {"target_role": "worker"}, "probe": {"request_count": 60, "request_timeout_s": 10, "request_payload": payload,
            "response_expectation": oracle}, "cell_execution": {
        "kind": "worker-recovery", "source": {
            "repository_path": "experiments/formal_campaign/h3_worker_recovery.py",
            "sha256": "sha256:" + "0" * 64},
        "command": [sys.executable, str(ROOT / "experiments/formal_campaign/h3_worker_recovery.py")],
        "recovery_action": "bounded-operator-full-relaunch", "starts": starts,
    }}


def test_exact_original_matrix_dispatch_no_name_substring_fallback():
    protocol = json.loads((ROOT / "experiments/formal_campaign/protocol.json").read_text())
    cells = protocol["h3"]["required_cells"]
    assert len(cells) * len(protocol["arms"]) * len(protocol["schedule"]) == 225
    assert len(protocol["h4"]["required_cells"]) * 9 == 36
    assert {cell_policy(c) for c in cells} == {
        "native-prepare", "worker-recovery", "pre-serving-rejection", "unimplemented-actuator"}
    assert cell_policy("manager-crash-before-prepare") == "unimplemented-actuator"
    with pytest.raises(ValueError, match="original matrix"):
        cell_policy("arbitrary-prepare-fixture")


@pytest.mark.parametrize("cell", ["worker-crash", "worker-replacement", "observer-loss",
    "unsupported-plugin-below-range", "unsupported-plugin-above-range", "unsupported-api-protocol-capability"])
def test_no_carrier_rejected_before_any_launch(cell):
    with pytest.raises(ValueError, match="carrier"):
        validate_cell_execution({"cell_id": cell}, arm="ecpa", launching=True)
    with pytest.raises(ValueError, match="raw carrier|inapplicable"):
        validate_raw_kind({"cell_id": cell}, {"schema": "ecpa-h3-raw-recovery/v2"})


def test_worker_positive_structural_branch_preserves_nine_original_starts():
    campaign = worker_campaign()
    assert validate_cell_execution(campaign) == "worker-recovery"
    assert validate_raw_kind(campaign, {"schema": "ecpa-h3-worker-raw-recovery/v1"}) == "worker-recovery"
    del campaign["cell_execution"]["starts"]["worker-crash-r3-ecpa"]
    with pytest.raises(Exception):
        validate_carrier(campaign)


@pytest.mark.parametrize("field,value", [("request_count", 2), ("concurrency", 1),
    ("timeout_s", 240), ("interval_s", 1)])
def test_serial_cached_producer_cannot_replace_original_client(field, value):
    campaign = worker_campaign()
    campaign["cell_execution"]["starts"]["worker-crash-r1-ecpa"]["client_window"][field] = value
    with pytest.raises(ValueError, match="workload changed"):
        validate_carrier(campaign)


def test_current_unpublished_or_wrong_carrier_source_cannot_launch():
    campaign = worker_campaign()
    with pytest.raises(ValueError, match="source bytes"):
        validate_carrier(campaign, check_sources=True)


def test_native_prepare_only_runs_own_applicable_protocol():
    campaign = {"cell_id": "manager-crash-after-prepare", "arms": [
        {"id": "manual-integration", "phase_barrier": {"support": "supported"}}]}
    with pytest.raises(ValueError, match="baseline"):
        validate_cell_execution(campaign, arm="manual-integration", launching=True)


def test_real_owned_cpu_epoch_capture_then_graceful_exit():
    # A fresh owned child publishes its own actual kernel epoch and exits when
    # stdin closes. No PID guesses, signals, accelerator imports or model runs.
    script = """import json,os,pathlib,sys
fields=pathlib.Path('/proc/self/stat').read_text().rsplit(')',1)[1].split()
print(json.dumps({'pid':os.getpid(),'start_ticks':int(fields[19]),'boot_id':pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),'session':int(fields[3])}),flush=True)
sys.stdin.read()
"""
    with subprocess.Popen([sys.executable, "-c", script], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, text=True, start_new_session=True) as child:
        observed = json.loads(child.stdout.readline())
        fields = Path(f"/proc/{child.pid}/stat").read_text().rsplit(")", 1)[1].split()
        assert observed["pid"] == child.pid and observed["session"] == child.pid
        assert observed["start_ticks"] == int(fields[19])
        child.stdin.close()
        assert child.wait(timeout=5) == 0
    assert not Path(f"/proc/{observed['pid']}").exists()


def test_actual_worker_must_descend_from_its_exact_api_parent():
    from experiments.formal_campaign.h3_worker_recovery import (
        capture_parent_worker_ancestry, verify_parent_worker_ancestry,
    )
    import copy
    # Two independent Host-shaped process trees under the same adapter (pytest).
    # Each owns a fresh child. All processes exit by stdin EOF, without signals.
    host_source = """import json,os,pathlib,subprocess,sys
child=subprocess.Popen([sys.executable,'-c','import sys; sys.stdin.read()'],stdin=subprocess.PIPE)
print(json.dumps({'parent':os.getpid(),'worker':child.pid}),flush=True)
sys.stdin.read()
child.stdin.close()
assert child.wait(timeout=5)==0
"""
    hosts = [subprocess.Popen([sys.executable, "-c", host_source], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, text=True, start_new_session=True)
             for _ in range(2)]
    try:
        rows = [json.loads(h.stdout.readline()) for h in hosts]
        def kernel(pid):
            fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            return {"pid": pid, "start_ticks": int(fields[19]), "session": int(fields[3]),
                    "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
                    "launch_id": "same-label-is-not-ancestry"}
        parent_a, parent_b = [kernel(r["parent"]) for r in rows]
        worker_a, worker_b = [kernel(r["worker"]) for r in rows]
        # Both phases use this same live observation function in the runner.
        for parent, worker in ((parent_a, worker_a), (parent_b, worker_b)):
            chain = capture_parent_worker_ancestry(parent, worker)
            phase = {"parent": parent, "worker": worker, "parent_worker_ancestry": chain}
            verify_parent_worker_ancestry(phase)
            corrupted = copy.deepcopy(phase)
            corrupted["parent_worker_ancestry"][-1]["ppid"] = worker["pid"]
            with pytest.raises(ValueError, match="ancestry edge"):
                verify_parent_worker_ancestry(corrupted)
        # Old checks admitted both workers as adapter descendants with the same
        # launch label; the actual PPID join must reject either cross-Host swap.
        for parent, wrong_worker in ((parent_a, worker_b), (parent_b, worker_a)):
            with pytest.raises(ValueError, match="API-parent subtree"):
                capture_parent_worker_ancestry(parent, wrong_worker)
    finally:
        for host in hosts:
            host.stdin.close()
        for host in hosts:
            assert host.wait(timeout=5) == 0
