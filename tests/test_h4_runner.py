from __future__ import annotations

import hashlib
import importlib.util
import json
import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_DIR = ROOT / "experiments/formal_campaign"


def load_runner():
    sys.path.insert(0, str(SCRIPT_DIR))
    spec = importlib.util.spec_from_file_location("h4_runner", SCRIPT_DIR / "run_h4.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def campaign_file(root: Path) -> Path:
    workload = root / "workload.json"
    workload.write_text(
        json.dumps(
            {
                "prompt": "fixture",
                "max_tokens": 2,
                "temperature": 0.0,
                "seed": 12012,
                "warmup_requests": 1,
                "measured_requests": 4,
                "min_successful_measured_requests": 4,
                "concurrency": 2,
                "request_timeout_seconds": 5,
                "success_status": 200,
                "require_nonempty_completion": True,
            }
        )
        + "\n"
    )
    digest = "sha256:" + hashlib.sha256(workload.read_bytes()).hexdigest()
    campaign = root / "campaign.json"
    campaign.write_text(
        json.dumps(
            {
                "schema": "ecpa-h4-minimal-matched-cell-campaign/v1",
                "campaign_id": "H4-matched-cost-v1",
                "cell_id": "compatible-resource-pair.sampled-invocation",
                "planned_starts": 9,
                "formal_h4_result": False,
                "performance_result": False,
                "score_eligible": False,
                "arms": [
                    {"id": arm}
                    for arm in (
                        "vanilla-vllm-entry-points",
                        "manual-integration",
                        "ecpa",
                    )
                ],
                "schedule": [
                    {
                        "order": [
                            "vanilla-vllm-entry-points",
                            "manual-integration",
                            "ecpa",
                        ]
                    },
                    {
                        "order": [
                            "manual-integration",
                            "ecpa",
                            "vanilla-vllm-entry-points",
                        ]
                    },
                    {
                        "order": [
                            "ecpa",
                            "vanilla-vllm-entry-points",
                            "manual-integration",
                        ]
                    },
                ],
                "fixed_identity": {
                    "manager_commit": "1" * 40,
                    "host_commit": "2" * 40,
                    "accelerator_commit": "3" * 40,
                    "plugins": {"fixture": {"commit": "4" * 40}},
                    "model_digest": "sha256:" + "5" * 64,
                    "hardware": "fixture hardware",
                    "topology": "fixture TP2",
                    "host_version": "fixture-host",
                    "accelerator_version": "fixture-accelerator",
                    "warm_state": "cold",
                },
                "workload": {"path": workload.name, "sha256": digest},
            }
        )
        + "\n"
    )
    return campaign


def exact_receipt(runner, campaign, launch):
    fixed = campaign["fixed_identity"]
    host_admission = {
        "schema": "ecpa-host-source-admission/v1",
        "repository": "vLLM-HUST/vllm-hust",
        "remote": "https://github.com/vLLM-HUST/vllm-hust.git",
        "candidate_commit": fixed["host_commit"],
        "main_commit": fixed["host_commit"],
        "candidate_reachable": True,
        "candidate_merged_to_main": True,
    }
    return {
        "schema": "ecpa-h4-deployment-receipt/v1",
        "registration_state": "registered",
        "admissible": True,
        "evidence_mode": "formal-real",
        "campaign_sha256": campaign["_sha256"],
        "launch_spec_sha256": runner.canonical_digest(launch),
        "host_source_admission_sha256": runner.canonical_digest(host_admission),
        "host_source_admission": host_admission,
        "campaign_id": campaign["campaign_id"],
        "cell_id": campaign["cell_id"],
        "arm_command_digests": {
            arm: runner.canonical_digest(definition)
            for arm, definition in launch["arms"].items()
        },
        "manager_commit": fixed["manager_commit"],
        "host_commit": fixed["host_commit"],
        "accelerator_commit": fixed["accelerator_commit"],
        "plugin_commits": {
            name: value["commit"] for name, value in fixed["plugins"].items()
        },
        "model_digest": fixed["model_digest"],
        "workload_digest": campaign["workload"]["sha256"],
        "hardware": fixed["hardware"],
        "topology": fixed["topology"],
        "issuer": {
            "kind": "ecpa-h4-registration-transition/v1",
            "manager_repository": "vLLM-HUST/extension-manager",
            "manager_remote": "https://github.com/vLLM-HUST/extension-manager.git",
            "host_repository": "vLLM-HUST/vllm-hust",
            "host_remote": "https://github.com/vLLM-HUST/vllm-hust.git",
            "manager_main_commit": fixed["manager_commit"],
            "host_main_commit": fixed["host_commit"],
        },
    }


def launch_spec():
    arms = {}
    for arm in (
        "vanilla-vllm-entry-points",
        "manual-integration",
        "ecpa",
    ):
        arms[arm] = {
            "phase_commands": {},
            "server_command": ["python", "-m", "vllm.entrypoints.openai.api_server"],
            "environment": {"H4_ARM": arm},
            "evidence_paths": [],
            "served_model": "Qwen2.5-14B-Instruct",
        }
    return {
        "schema": "ecpa-h4-launch-spec/v1",
        "arms": arms,
        "health_url": "http://127.0.0.1:18080/health",
        "endpoint_url": "http://127.0.0.1:18080/v1/completions",
        "host": "127.0.0.1",
        "port": 18080,
        "startup_timeout_seconds": 600,
        "container_digest": "sha256:" + "1" * 64,
        "device_cleanup_command": ["false"],
    }


def test_validate_only_inputs_bind_frozen_campaign_and_all_arms(tmp_path: Path):
    runner = load_runner()
    campaign = runner.load_h4_campaign(campaign_file(tmp_path))
    launch = launch_spec()
    receipt = exact_receipt(runner, campaign, launch)
    path = tmp_path / "receipt.json"
    path.write_text("{}")
    runner.validate_receipt(receipt, campaign, path)
    runner.validate_launch_spec(launch, receipt)


def test_launch_spec_mutation_after_registration_is_rejected(tmp_path: Path):
    runner = load_runner()
    campaign = runner.load_h4_campaign(campaign_file(tmp_path))
    launch = launch_spec()
    receipt = exact_receipt(runner, campaign, launch)
    launch["arms"]["ecpa"]["environment"]["UNREGISTERED"] = "1"
    with pytest.raises(ValueError, match="differs from registered command"):
        runner.validate_launch_spec(launch, receipt)


def test_runner_executes_requests_and_reclaims_fixture_process(tmp_path: Path):
    runner = load_runner()
    campaign = runner.load_h4_campaign(campaign_file(tmp_path))
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    fixture = ROOT / "tests/fixtures/h4_http_server.py"
    launch = launch_spec()
    launch.update(
        {
            "health_url": f"http://127.0.0.1:{port}/health",
            "endpoint_url": f"http://127.0.0.1:{port}/v1/completions",
            "port": port,
            "startup_timeout_seconds": 10,
            "device_cleanup_command": ["true"],
        }
    )
    for definition in launch["arms"].values():
        definition["server_command"] = [sys.executable, str(fixture), str(port)]
    receipt_value = exact_receipt(runner, campaign, launch)
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt_value) + "\n")
    record = runner.execute_start(
        campaign,
        receipt_path,
        launch,
        tmp_path / "runs",
        1,
        "vanilla-vllm-entry-points",
    )
    assert record["status"] == "complete"
    assert all(record["cleanup"].values())
    assert (
        len(
            json.loads(
                (
                    tmp_path / "runs" / record["start_id"] / "request-results.json"
                ).read_text()
            )["requests"]
        )
        == 5
    )
    assert runner.port_closed("127.0.0.1", port)
