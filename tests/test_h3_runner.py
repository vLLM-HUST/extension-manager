ÚznÛéºÉ¢Šwèfrom __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "experiments/formal_campaign/run_h3.py"
ANALYZER = ROOT / "experiments/formal_campaign/analyze.py"
SERVER = ROOT / "tests/fixtures/h3_http_server.py"


def sha(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def test_runner_executes_bound_process_crash_and_recovery(tmp_path: Path) -> None:
    port = free_port()
    pid_file = tmp_path / "target.pid"
    state = tmp_path / "state.py"
    predecessor = "sha256:" + "a" * 64
    evidence = "sha256:" + "b" * 64
    state.write_text(
        "import json\n"
        f"print(json.dumps({{'predecessor_digest': '{predecessor}', "
        f"'evidence_identity_sha256': '{evidence}', "
        "'final_route': 'predecessor', 'functional_correctness': True, "
        "'rollback_classification': 'automatic-restoration'}))\n"
    )
    cleanup_probe = tmp_path / "cleanup.py"
    cleanup_probe.write_text(
        "import json\n"
        "print(json.dumps({'processes_reclaimed': True, "
        "'ports_reclaimed': True, 'devices_reclaimed': True}))\n"
    )
    identity = {
        "manager_commit": "1" * 40,
        "host_commit": "2" * 40,
        "accelerator_commit": "3" * 40,
        "plugin_commits": {"mod": "4" * 40},
        "provider_versions": {"ascend": "9.1.0"},
        "model_digest": "sha256:" + "5" * 64,
        "workload_digest": "sha256:" + "6" * 64,
        "hardware": "test-only-cpu",
        "topology": "single-process-test",
        "warm_state": "cold",
        "container_digest": "sha256:" + "7" * 64,
    }
    launch = [
        sys.executable,
        str(SERVER),
        "--port",
        str(port),
        "--pid-file",
        str(pid_file),
    ]
    arms = [
        {"id": arm, "launch_command": launch, "fault_target_pid_file": str(pid_file)}
        for arm in ("vanilla-vllm-entry-points", "manual-integration", "ecpa")
    ]
    campaign = {
        "schema": "ecpa-h3-exact-stack-cell-campaign/v1",
        "campaign_id": "H3-transactional-recovery-v1",
        "cell_id": "manager-crash-after-prepare",
        "evidence_class": "formal-real",
        "arms": arms,
        "fixed_identity": identity,
        "fault": {
            "id": "kill-manager",
            "signal": "SIGKILL",
            "target_role": "manager",
            "target_exit_timeout_s": 5,
        },
        "objective": {
            "max_recovery_ms": 5000,
            "max_lost_requests": 0,
            "max_duplicated_requests": 0,
            "max_operator_actions": 0,
            "expected_final_route": "predecessor",
            "allowed_rollback_classifications": ["automatic-restoration"],
        },
        "probe": {
            "health_url": f"http://127.0.0.1:{port}/health",
            "request_url": f"http://127.0.0.1:{port}/request",
            "request_count": 2,
            "state_command": [sys.executable, str(state)],
            "cleanup_command": [sys.executable, str(cleanup_probe)],
            "ready_timeout_s": 5,
            "request_timeout_s": 2,
        },
    }
    campaign_path = tmp_path / "campaign.json"
    campaign_path.write_text(json.dumps(campaign) + "\n")
    receipt = {
        "schema": "ecpa-h3-deployment-receipt/v1",
        "registration_state": "registered",
        "admissible": True,
        "evidence_mode": "formal-real",
        "campaign_sha256": sha(campaign_path),
        "campaign_id": campaign["campaign_id"],
        "cell_id": campaign["cell_id"],
        **{
            key: identity[key]
            for key in (
                "manager_commit",
                "host_commit",
                "accelerator_commit",
                "plugin_commits",
                "model_digest",
                "workload_digest",
                "hardware",
                "topology",
            )
        },
        "authority": {
            "kind": "host",
            "parent_process_registration": True,
            "exposure_gate": True,
        },
    }
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt) + "\n")
    output = tmp_path / "run"
    subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--campaign-spec",
            str(campaign_path),
            "--deployment-receipt",
            str(receipt_path),
            "--arm",
            "ecpa",
            "--repetition",
            "1",
            "--arm-order",
            "3",
            "--output-dir",
            str(output),
        ],
        check=True,
    )
    raw = json.loads((output / "raw-recovery.json").read_text())
    assert [event["kind"] for event in raw["events"]] == [
        "fault-triggered",
        "fault-observed",
        "recovery-started",
        "request-result",
        "request-result",
        "recovery-complete",
    ]
    assert raw["fault_target"]["pid"] == raw["process_identity"]["fault_target_pid"]
    assert json.loads((output / "run-manifest.json").read_text())["cleanup"] == {
        "processes_reclaimed": True,
        "ports_reclaimed": True,
        "devices_reclaimed": True,
    }
    analyzed = subprocess.run(
        [
            sys.executable,
            str(ANALYZER),
            "--campaign",
            "h3",
            "--campaign-spec",
            str(campaign_path),
            "--records",
            str(output / "record.json"),
            "--artifact-root",
            str(output),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    summary = json.loads(analyzed.stdout)
    assert summary["status"] == "incomplete"
    assert summary["received_starts"] == 1
