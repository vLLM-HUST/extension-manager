from __future__ import annotations

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


def canonical_sha(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


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
            "request_payload": {
                "model": "test-model",
                "prompt": "Reply ECPA",
                "max_tokens": 8,
                "temperature": 0,
                "stream": False,
            },
            "response_expectation": {"text_equals": "ECPA"},
            "state_command": [sys.executable, str(state)],
            "cleanup_command": [sys.executable, str(cleanup_probe)],
            "ready_timeout_s": 5,
            "request_timeout_s": 2,
        },
    }
    campaign_path = tmp_path / "campaign.json"
    campaign_path.write_text(json.dumps(campaign) + "\n")
    output = tmp_path / "run"
    proxy_source = ROOT / "experiments/exposure_gate/loopback_traffic.py"
    starts = []
    proxy_digests = {}
    for number in range(1, 4):
        for candidate in ("vanilla-vllm-entry-points", "manual-integration", "ecpa"):
            sid = f"{campaign['cell_id']}-r{number}-{candidate}"
            run_dir = (
                output.resolve()
                if (number, candidate) == (1, "ecpa")
                else (tmp_path / sid).resolve()
            )
            registration = {
                "schema": "ecpa-formal-proxy-registration/v1",
                "evidence_class": "formal-real",
                "authority": "independent-loopback-proxy",
                "proxy_command_digest": "",
                "review_receipt_sha256": "sha256:" + "8" * 64,
                "reviewer_kind": "automated-independent",
                "proxy_source_sha256": sha(proxy_source),
                "public_port": port,
                "backend_port": port + 1,
                "predecessor_port": port + 2,
                "grant_holder": "formal-runner",
                "grant_token": number,
                "grant_expires_at": 4102444800,
            }
            proxy_argv = [
                str(Path(sys.executable).resolve()),
                str(proxy_source.resolve()),
                "--socket",
                str(run_dir / "authority.sock"),
                "--journal",
                str(run_dir / "authority-journal.jsonl"),
                "--listen-port",
                str(port),
                "--predecessor-port",
                str(port + 2),
                "--candidate-port",
                str(port + 1),
                "--predecessor-snapshot",
                '{"generation":0}',
                "--grant-holder",
                "formal-runner",
                "--grant-token",
                str(number),
                "--grant-expires-at",
                "4102444800",
                "--observer-config",
                str(run_dir / "formal-proxy-authorization.json"),
            ]
            registration["proxy_command_digest"] = canonical_sha({"argv": proxy_argv})
            proxy_sha = canonical_sha(registration)
            starts.append(
                {
                    "start_id": sid,
                    "arm": candidate,
                    "repetition": number,
                    "run_directory": str(run_dir),
                    "proxy_registration": registration,
                    "proxy_registration_sha256": proxy_sha,
                }
            )
            proxy_digests[sid] = proxy_sha
    authority = {
        "schema": "ecpa-h3-authority-registration/v1",
        "registration_state": "reviewed",
        "evidence_class": "formal-real",
        "campaign_sha256": sha(campaign_path),
        "authority_endpoint": f"http://127.0.0.1:{port}/request",
        "state_command_digest": canonical_sha(
            {"argv": campaign["probe"]["state_command"]}
        ),
        "cleanup_command_digest": canonical_sha(
            {"argv": campaign["probe"]["cleanup_command"]}
        ),
        "starts": starts,
    }
    authority["review"] = {
        "reviewer_kind": "automated-independent",
        "verdict": "APPROVED",
        "subject_sha256": canonical_sha(authority),
    }
    authority_path = tmp_path / "authority.json"
    authority_path.write_text(json.dumps(authority) + "\n")
    host_admission = {
        "schema": "ecpa-host-source-admission/v1",
        "repository": "vLLM-HUST/vllm-hust",
        "remote": "https://github.com/vLLM-HUST/vllm-hust.git",
        "candidate_commit": identity["host_commit"],
        "main_commit": identity["host_commit"],
        "candidate_reachable": True,
        "candidate_merged_to_main": True,
    }
    receipt = {
        "schema": "ecpa-h3-deployment-receipt/v2",
        "registration_state": "registered",
        "admissible": True,
        "evidence_mode": "formal-real",
        "campaign_sha256": sha(campaign_path),
        "authority_registration_sha256": sha(authority_path),
        "host_source_admission_sha256": canonical_sha(host_admission),
        "host_source_admission": host_admission,
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
        "arm_command_digests": {
            row["id"]: canonical_sha({"argv": row["launch_command"]}) for row in arms
        },
        "fault_command_digest": canonical_sha(campaign["fault"]),
        "state_command_digest": canonical_sha(
            {"argv": campaign["probe"]["state_command"]}
        ),
        "cleanup_command_digest": canonical_sha(
            {"argv": campaign["probe"]["cleanup_command"]}
        ),
        "authority": {
            "kind": "host-plus-independent-loopback-proxy",
            "parent_process_registration": True,
            "exposure_gate": True,
            "endpoint": authority["authority_endpoint"],
            "start_proxy_registration_digests": proxy_digests,
        },
        "issuer": {
            "kind": "ecpa-h3-registration-transition/v1",
            "manager_repository": "vLLM-HUST/extension-manager",
            "manager_remote": "https://github.com/vLLM-HUST/extension-manager.git",
            "host_repository": "vLLM-HUST/vllm-hust",
            "host_remote": "https://github.com/vLLM-HUST/vllm-hust.git",
            "manager_main_commit": identity["manager_commit"],
            "host_main_commit": identity["host_commit"],
        },
    }
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt) + "\n")
    result = subprocess.run(
        [
            sys.executable,
            str(RUNNER),
            "--campaign-spec",
            str(campaign_path),
            "--deployment-receipt",
            str(receipt_path),
            "--authority-registration",
            str(authority_path),
            "--arm",
            "ecpa",
            "--repetition",
            "1",
            "--arm-order",
            "3",
            "--output-dir",
            str(output),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "durable prepare" in result.stderr
    assert not output.exists()
    assert not pid_file.exists()


def test_frozen_post_probe_rejects_nonempty_wrong_response(monkeypatch) -> None:
    import importlib.util
    import urllib.request

    spec = importlib.util.spec_from_file_location("h3_http_probe_test", RUNNER)
    assert spec and spec.loader
    old_path = sys.path[:]
    sys.path.insert(0, str(RUNNER.parent))
    try:
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path[:] = old_path
    payload = {
        "model": "test-model",
        "prompt": "Reply ECPA",
        "max_tokens": 8,
        "temperature": 0,
        "stream": False,
    }
    observed = []

    class Response:
        status = 200
        headers = {"x-ecpa-tuple-supported": "true"}

        def __init__(self, body):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def read(self):
            return self.body

    bodies = [
        b"completion",
        b'{"model":"wrong","choices":[{"index":0,"text":"ECPA","finish_reason":"stop"}]}',
        b'{"model":"test-model","choices":[{"index":0,"text":"ECPA","finish_reason":"length"}]}',
        b'{"model":"test-model","choices":[{"index":0,"text":"wrong","finish_reason":"stop"}]}',
        b'{"model":"test-model","choices":[{"index":0,"text":"ECPA","finish_reason":"stop"}]}',
    ]
    for body in bodies:

        def open_response(request, timeout, response_body=body):
            observed.append(request)
            return Response(response_body)

        monkeypatch.setattr(urllib.request, "urlopen", open_response)
        result = module.request_event(
            "http://127.0.0.1:8187/v1/completions",
            "request-test",
            2,
            payload,
            {"text_equals": "ECPA"},
        )
        assert result["functional_correctness"] is (body == bodies[-1])
        assert result["response_body"] == body.decode()
        assert result["response_sha256"] == "sha256:" + hashlib.sha256(body).hexdigest()
    assert all(request.get_method() == "POST" for request in observed)
    assert all(json.loads(request.data) == payload for request in observed)
    assert all(
        request.headers["X-ecpa-request-id"] == "request-test" for request in observed
    )
