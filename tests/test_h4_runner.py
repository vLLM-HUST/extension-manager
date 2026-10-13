from __future__ import annotations

import importlib.util
import json
import socket
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CAMPAIGN = Path("/root/ecpa-h4-minimal-cell-20261013/campaign.json")
SCRIPT_DIR = ROOT / "experiments/formal_campaign"


def load_runner():
    sys.path.insert(0, str(SCRIPT_DIR))
    spec = importlib.util.spec_from_file_location("h4_runner", SCRIPT_DIR / "run_h4.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def exact_receipt(runner, campaign, launch):
    fixed = campaign["fixed_identity"]
    return {
        "schema": "ecpa-h4-deployment-receipt/v1",
        "registration_state": "registered",
        "admissible": True,
        "evidence_mode": "formal-real",
        "campaign_sha256": campaign["_sha256"],
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
    campaign = runner.load_h4_campaign(CAMPAIGN)
    launch = launch_spec()
    receipt = exact_receipt(runner, campaign, launch)
    path = tmp_path / "receipt.json"
    path.write_text("{}")
    runner.validate_receipt(receipt, campaign, path)
    runner.validate_launch_spec(launch, receipt)


def test_launch_spec_mutation_after_registration_is_rejected(tmp_path: Path):
    runner = load_runner()
    campaign = runner.load_h4_campaign(CAMPAIGN)
    launch = launch_spec()
    receipt = exact_receipt(runner, campaign, launch)
    launch["arms"]["ecpa"]["environment"]["UNREGISTERED"] = "1"
    with pytest.raises(ValueError, match="differs from registered command"):
        runner.validate_launch_spec(launch, receipt)


def test_runner_executes_requests_and_reclaims_fixture_process(tmp_path: Path):
    runner = load_runner()
    campaign = runner.load_h4_campaign(CAMPAIGN)
    campaign["workload"] = {
        **campaign["workload"],
        "warmup_requests": 1,
        "measured_requests": 4,
        "min_successful_measured_requests": 4,
        "concurrency": 2,
        "request_timeout_seconds": 5,
    }
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
