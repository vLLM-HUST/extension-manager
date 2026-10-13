from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "experiments/formal_campaign/analyze.py"


def load_analyzer():
    spec = importlib.util.spec_from_file_location("formal_campaign_analyze", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def identity() -> dict[str, object]:
    return {
        "manager_commit": "1" * 40,
        "host_commit": "2" * 40,
        "accelerator_commit": "3" * 40,
        "plugin_commits": {"kv-mod": "4" * 40},
        "provider_versions": {"ascend": "9.1.0"},
        "model_digest": "sha256:" + "5" * 64,
        "workload_digest": "sha256:" + "6" * 64,
        "hardware": "2x Ascend 910B2",
        "topology": "TP2",
        "warm_state": "cold",
        "container_digest": "sha256:" + "7" * 64,
    }


def campaign_spec(cell: str) -> dict[str, object]:
    return {
        "_sha256": "sha256:" + "8" * 64,
        "campaign_id": "H4-matched-cost-v1",
        "cell_id": cell,
        "arms_by_id": {
            arm: {}
            for arm in ("vanilla-vllm-entry-points", "manual-integration", "ecpa")
        },
        "workload": {
            "sha256": "sha256:" + "6" * 64,
            "prompt": "fixture",
            "max_tokens": 2,
            "temperature": 0.0,
            "seed": 12012,
            "warmup_requests": 1,
            "measured_requests": 4,
            "min_successful_measured_requests": 4,
            "success_status": 200,
            "require_nonempty_completion": True,
        },
    }


def write(path: Path, value: object) -> dict[str, str]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    return {"path": str(path), "sha256": digest(path)}


def receipt(root: Path, cell: str) -> tuple[Path, dict[str, str]]:
    path = root / "deployment-receipt.json"
    host_admission = {
        "schema": "ecpa-host-source-admission/v1",
        "repository": "vLLM-HUST/vllm-hust",
        "remote": "https://github.com/vLLM-HUST/vllm-hust.git",
        "candidate_commit": "2" * 40,
        "main_commit": "2" * 40,
        "candidate_reachable": True,
        "candidate_merged_to_main": True,
    }
    value = {
        "schema": "ecpa-h4-deployment-receipt/v1",
        "registration_state": "registered",
        "admissible": True,
        "evidence_mode": "formal-real",
        "campaign_sha256": "sha256:" + "8" * 64,
        "launch_spec_sha256": "sha256:" + "9" * 64,
        "host_source_admission_sha256": "sha256:"
        + hashlib.sha256(
            json.dumps(host_admission, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "host_source_admission": host_admission,
        "campaign_id": "H4-matched-cost-v1",
        "cell_id": cell,
        "arm_command_digests": {
            arm: "sha256:"
            + hashlib.sha256(
                json.dumps(
                    {"served_model": "fixture-model"},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            for arm in ("vanilla-vllm-entry-points", "manual-integration", "ecpa")
        },
        "manager_commit": "1" * 40,
        "host_commit": "2" * 40,
        "accelerator_commit": "3" * 40,
        "plugin_commits": {"kv-mod": "4" * 40},
        "model_digest": "sha256:" + "5" * 64,
        "workload_digest": "sha256:" + "6" * 64,
        "hardware": "2x Ascend 910B2",
        "topology": "TP2",
        "issuer": {
            "kind": "ecpa-h4-registration-transition/v1",
            "manager_repository": "vLLM-HUST/extension-manager",
            "manager_remote": "https://github.com/vLLM-HUST/extension-manager.git",
            "host_repository": "vLLM-HUST/vllm-hust",
            "host_remote": "https://github.com/vLLM-HUST/vllm-hust.git",
            "manager_main_commit": "1" * 40,
            "host_main_commit": "2" * 40,
        },
    }
    binding = write(path, value)
    binding["path"] = path.name
    return path, binding


def make_h4_record(
    module,
    root: Path,
    protocol,
    cell: str,
    rep: int,
    arm: str,
    *,
    ecpa_latency_ms: int = 101,
):
    start_id = f"{cell}-r{rep}-{arm}"
    run = root / start_id
    run.mkdir()
    _, receipt_binding = receipt(root, cell)
    process = {
        "launcher_pid": 10,
        "launcher_start_ticks": 15,
        "server_pid": 20 + rep,
        "server_start_ticks": 30 + rep,
        "boot_id": "boot-identity",
    }
    total_ms = {
        "vanilla-vllm-entry-points": 980,
        "manual-integration": 1000,
        "ecpa": 1020,
    }[arm]
    phase_names = ["discovery", "validation", "planning", "rendering", "evidence_setup"]
    cursor = rep * 10_000_000_000 + protocol["arms"].index(arm) * 2_000_000_000
    startup_start = cursor
    phases = {}
    for name in phase_names:
        end = cursor + 1_000_000
        phases[name] = {"start_ns": cursor, "end_ns": end}
        cursor = end
    phases["worker_loading"] = {
        "start_ns": cursor,
        "end_ns": startup_start + total_ms * 1_000_000,
    }
    ready = phases["worker_loading"]["end_ns"]
    latency_ms = {
        "vanilla-vllm-entry-points": 98,
        "manual-integration": 100,
        "ecpa": ecpa_latency_ms,
    }[arm]
    requests = [
        {
            "request_id": "warmup-0000",
            "kind": "warmup",
            "dispatch_ns": ready + 1,
            "complete_ns": ready + 1_000_001,
            "status_code": 200,
            "response_nonempty": True,
            "output_tokens": 1,
            "error": None,
        }
    ]
    base = ready + 2_000_000
    # The measured window gives arm-specific throughput while every request retains
    # an independently recomputable latency.
    window_ns = {
        "vanilla-vllm-entry-points": 39_603_960,
        "manual-integration": 40_000_000,
        "ecpa": 40_201_005,
    }[arm]
    for index in range(4):
        dispatch = base + index * max(1, (window_ns - latency_ms * 1_000_000) // 3)
        requests.append(
            {
                "request_id": f"measured-{index:04d}",
                "kind": "measured",
                "dispatch_ns": dispatch,
                "complete_ns": dispatch + latency_ms * 1_000_000,
                "status_code": 200,
                "response_nonempty": True,
                "output_tokens": 1,
                "error": None,
            }
        )
    for row in requests:
        row["http_request"] = module.h4_body_binding(
            module.h4_request_payload(campaign_spec(cell)["workload"], "fixture-model")
        )
        row["http_response"] = {
            "status_code": 200,
            "headers": [],
            **module.h4_body_binding(
                json.dumps(
                    {
                        "model": "fixture-model",
                        "choices": [{"text": "fixture completion"}],
                        "usage": {"completion_tokens": 1},
                    }
                ).encode()
            ),
        }
        row["response_model"] = "fixture-model"
    cleanup = {
        "processes_reclaimed": True,
        "ports_reclaimed": True,
        "devices_reclaimed": True,
    }
    child_values = {
        "raw_log": {"start_id": start_id, "name": "raw_log"},
        "request_results": {"start_id": start_id, "requests": requests},
        "process_snapshot": {
            "start_id": start_id,
            "process_identity": process,
        },
        "cleanup_report": {"start_id": start_id, "cleanup": cleanup},
    }
    child_artifacts = {
        name: write(run / f"{name}.json", value) for name, value in child_values.items()
    }
    raw = {
        "schema": "ecpa-h4-raw-measurement/v2",
        "launch_definition": {"served_model": "fixture-model"},
        "campaign_id": "H4-matched-cost-v1",
        "cell_id": cell,
        "start_id": start_id,
        "arm": arm,
        "repetition": rep,
        "arm_order": protocol["schedule"][rep - 1].index(arm) + 1,
        "workload_digest": "sha256:" + "6" * 64,
        "deployment_receipt_sha256": receipt_binding["sha256"],
        "artifact_sha256": {
            name: binding["sha256"] for name, binding in child_artifacts.items()
        },
        "process_identity": process,
        "clock": "CLOCK_MONOTONIC_RAW",
        "startup_start_ns": startup_start,
        "ready_ns": ready,
        "startup_phases": phases,
        "requests": requests,
        "resources": {
            "cpu_ms": 100.0,
            "peak_host_rss_bytes": 1000,
            "peak_device_memory_bytes": 2000,
            "process_messages": 10,
            "evidence_bytes": 500,
            "gate_open_ms": None,
            "failure_detection_ms": None,
            "rollback_ms": None,
            "recovery_ms": None,
        },
    }
    raw_binding = write(run / "raw-measurement.json", raw)
    artifacts = {
        "deployment_receipt": receipt_binding,
        "raw_measurement": raw_binding,
        **child_artifacts,
    }
    record = {
        "schema": "ecpa-formal-campaign-record/v1",
        "campaign_id": "H4-matched-cost-v1",
        "evidence_class": "formal-real",
        "deployment": {
            "registration_state": "registered",
            "receipt_sha256": receipt_binding["sha256"],
        },
        "cell_id": cell,
        "start_id": start_id,
        "status": "complete",
        "arm": arm,
        "repetition": rep,
        "arm_order": raw["arm_order"],
        "process_identity": process,
        "identity": identity(),
        "artifacts": artifacts,
        "cleanup": cleanup,
        "metrics": {},
    }
    record["metrics"] = module._recompute_h4_metrics(record, raw, campaign_spec(cell))
    return record


def h4_cell_records(module, root: Path, *, ecpa_latency_ms: int = 101):
    protocol = module.load_protocol()
    cell = protocol["h4"]["required_cells"][1]
    return cell, [
        make_h4_record(
            module,
            root,
            protocol,
            cell,
            rep,
            arm,
            ecpa_latency_ms=ecpa_latency_ms,
        )
        for rep in range(1, 4)
        for arm in protocol["arms"]
    ]


def test_h4_single_cell_emits_cell_result_but_overall_remains_incomplete(
    tmp_path: Path,
):
    module = load_analyzer()
    cell, rows = h4_cell_records(module, tmp_path)
    result = module.analyze_h4(
        module.load_protocol(), rows, tmp_path, campaign_spec(cell)
    )
    assert result["status"] == "incomplete"
    assert result["formal_result"] is False
    assert result["received_starts"] == 9
    assert result["completed_cells"][cell]["formal_result"] is True
    assert result["completed_cells"][cell]["campaign_complete"] is False
    assert result["completed_cells"][cell]["status"] == "supported"


@pytest.mark.parametrize(
    "metric",
    (
        "throughput",
        "latency_median_ms",
        "latency_p95_ms",
        "latency_p99_ms",
    ),
)
def test_h4_rejects_metric_forgery(tmp_path: Path, metric: str):
    module = load_analyzer()
    cell, rows = h4_cell_records(module, tmp_path)
    rows[0]["metrics"][metric] += 1
    with pytest.raises(ValueError, match="metrics differ from raw evidence"):
        module.analyze_h4(module.load_protocol(), rows, tmp_path, campaign_spec(cell))


def test_h4_rejects_forged_startup_total(tmp_path: Path):
    module = load_analyzer()
    cell, rows = h4_cell_records(module, tmp_path)
    rows[0]["metrics"]["startup_phases_ms"]["total"] += 1
    with pytest.raises(ValueError, match="metrics differ from raw evidence"):
        module.analyze_h4(module.load_protocol(), rows, tmp_path, campaign_spec(cell))


def test_h4_rejects_raw_artifact_reuse(tmp_path: Path):
    module = load_analyzer()
    cell, rows = h4_cell_records(module, tmp_path)
    rows[1]["artifacts"]["raw_measurement"] = rows[0]["artifacts"]["raw_measurement"]
    with pytest.raises(ValueError, match="differs from raw|reused"):
        module.analyze_h4(module.load_protocol(), rows, tmp_path, campaign_spec(cell))


def test_h4_rejects_receipt_without_exact_identity_binding(tmp_path: Path):
    module = load_analyzer()
    cell, rows = h4_cell_records(module, tmp_path)
    path = tmp_path / "deployment-receipt.json"
    value = json.loads(path.read_text())
    value["host_commit"] = "9" * 40
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    new_digest = digest(path)
    for row in rows:
        row["artifacts"]["deployment_receipt"]["sha256"] = new_digest
        row["deployment"]["receipt_sha256"] = new_digest
        raw_path = tmp_path / row["artifacts"]["raw_measurement"]["path"]
        raw = json.loads(raw_path.read_text())
        raw["deployment_receipt_sha256"] = new_digest
        raw_path.write_text(json.dumps(raw, sort_keys=True) + "\n")
        row["artifacts"]["raw_measurement"]["sha256"] = digest(raw_path)
    with pytest.raises(ValueError, match="receipt host_commit is not bound"):
        module.analyze_h4(module.load_protocol(), rows, tmp_path, campaign_spec(cell))


def test_h4_retains_failed_start_and_falsifies_completed_cell(tmp_path: Path):
    module = load_analyzer()
    cell, rows = h4_cell_records(module, tmp_path)
    rows[0]["status"] = "failed"
    rows[0]["failure"] = {"phase": "worker_loading", "class": "TimeoutError"}
    rows[0]["metrics"] = {}
    result = module.analyze_h4(
        module.load_protocol(), rows, tmp_path, campaign_spec(cell)
    )
    assert result["status"] == "incomplete"
    assert result["completed_cells"][cell]["status"] == "falsified"
    assert result["completed_cells"][cell]["failed_starts"] == [rows[0]["start_id"]]


def test_h4_cell_retains_threshold_violation(tmp_path: Path):
    module = load_analyzer()
    cell, rows = h4_cell_records(module, tmp_path, ecpa_latency_ms=103)
    result = module.analyze_h4(
        module.load_protocol(), rows, tmp_path, campaign_spec(cell)
    )
    assert result["completed_cells"][cell]["status"] == "falsified"
    assert (
        result["completed_cells"][cell]["metrics"]["cells"][cell]["threshold_violation"]
        is True
    )


def test_h4_schema_requires_raw_measurement_and_process_identity(tmp_path: Path):
    module = load_analyzer()
    cell, rows = h4_cell_records(module, tmp_path)
    del rows[0]["artifacts"]["raw_measurement"]
    del rows[0]["process_identity"]
    records = tmp_path / "records.jsonl"
    records.write_text(json.dumps(rows[0]) + "\n")
    with pytest.raises(ValueError, match="process_identity|raw_measurement"):
        module.load_records(records)


def write_artifact(path: Path, value: object) -> dict[str, str]:
    path.write_text(json.dumps(value, sort_keys=True) + "\n")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return {"path": path.name, "sha256": f"sha256:{digest}"}


def h3_campaign(cell: str) -> dict[str, object]:
    arms = [
        {
            "id": arm,
            "launch_command": ["launch", arm],
            "fault_target_pid_file": f"/{arm}.pid",
        }
        for arm in ("vanilla-vllm-entry-points", "manual-integration", "ecpa")
    ]
    return {
        "_sha256": "sha256:" + "8" * 64,
        "campaign_id": "H3-transactional-recovery-v1",
        "cell_id": cell,
        "fixed_identity": identity(),
        "arms": arms,
        "fault": {
            "id": "kill-manager",
            "signal": "SIGKILL",
            "target_role": "manager",
            "target_exit_timeout_s": 5,
        },
        "probe": {
            "health_url": "http://127.0.0.1:8187/health",
            "request_url": "http://127.0.0.1:8187/request",
            "request_count": 1,
            "request_payload": {
                "model": "test-model",
                "prompt": "Reply ECPA",
                "max_tokens": 8,
                "temperature": 0,
                "stream": False,
            },
            "response_expectation": {"text_equals": "ECPA"},
            "state_command": ["state"],
            "cleanup_command": ["cleanup"],
            "ready_timeout_s": 5,
            "request_timeout_s": 5,
        },
        "objective": {
            "max_recovery_ms": 1000,
            "max_lost_requests": 0,
            "max_duplicated_requests": 0,
            "max_operator_actions": 0,
            "expected_final_route": "predecessor",
            "allowed_rollback_classifications": ["automatic-restoration"],
        },
    }


def h3_record(module, root: Path, *, arm: str = "ecpa", rep: int = 1):
    protocol = module.load_protocol()
    cell = "manager-crash-after-prepare"
    campaign = h3_campaign(cell)
    start_id = f"{cell}-r{rep}-{arm}"
    process = {
        "launcher_pid": 10,
        "launcher_start_ticks": 20,
        "fault_target_pid": 11,
        "fault_target_start_ticks": 21,
        "boot_id": "boot-id",
    }
    target = {
        "pid": 11,
        "start_ticks": 21,
        "boot_id": "boot-id",
        "role": "manager",
    }
    predecessor = "sha256:" + "a" * 64
    evidence_identity = "sha256:" + "b" * 64
    cleanup = {
        "processes_reclaimed": True,
        "ports_reclaimed": True,
        "devices_reclaimed": True,
    }
    proxy = {
        "schema": "ecpa-formal-proxy-registration/v1",
        "evidence_class": "formal-real",
        "authority": "independent-loopback-proxy",
        "proxy_command_digest": "sha256:" + "c" * 64,
        "review_receipt_sha256": "sha256:" + "d" * 64,
        "reviewer_kind": "automated-independent",
        "proxy_source_sha256": "sha256:" + "e" * 64,
        "public_port": 8187,
        "backend_port": 18187,
        "predecessor_port": 28187,
        "grant_holder": "formal-runner",
        "grant_token": 1,
        "grant_expires_at": 4102444800,
    }
    proxy_sha = module._canonical_digest(proxy)
    starts = [
        {
            "start_id": f"{cell}-r{number}-{candidate}",
            "arm": candidate,
            "repetition": number,
            "run_directory": f"/runs/{cell}-r{number}-{candidate}",
            "proxy_registration": proxy,
            "proxy_registration_sha256": proxy_sha,
        }
        for number in range(1, 4)
        for candidate in ("vanilla-vllm-entry-points", "manual-integration", "ecpa")
    ]
    authority = {
        "schema": "ecpa-h3-authority-registration/v1",
        "registration_state": "reviewed",
        "evidence_class": "formal-real",
        "campaign_sha256": campaign["_sha256"],
        "authority_endpoint": "http://127.0.0.1:8187/request",
        "state_command_digest": module._canonical_digest({"argv": ["state"]}),
        "cleanup_command_digest": module._canonical_digest({"argv": ["cleanup"]}),
        "starts": starts,
    }
    authority["review"] = {
        "reviewer_kind": "automated-independent",
        "verdict": "APPROVED",
        "subject_sha256": module._canonical_digest(authority),
    }
    authority_binding = write_artifact(root / f"{start_id}-authority.json", authority)
    host_admission = {
        "schema": "ecpa-host-source-admission/v1",
        "repository": "vLLM-HUST/vllm-hust",
        "remote": "https://github.com/vLLM-HUST/vllm-hust.git",
        "candidate_commit": "2" * 40,
        "main_commit": "2" * 40,
        "candidate_reachable": True,
        "candidate_merged_to_main": True,
    }
    receipt = {
        "schema": "ecpa-h3-deployment-receipt/v2",
        "registration_state": "registered",
        "admissible": True,
        "evidence_mode": "formal-real",
        "campaign_sha256": campaign["_sha256"],
        "authority_registration_sha256": authority_binding["sha256"],
        "host_source_admission_sha256": module._canonical_digest(host_admission),
        "host_source_admission": host_admission,
        "campaign_id": "H3-transactional-recovery-v1",
        "cell_id": cell,
        **{
            name: identity()[name]
            for name in (
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
            row["id"]: module._canonical_digest({"argv": row["launch_command"]})
            for row in campaign["arms"]
        },
        "fault_command_digest": module._canonical_digest(campaign["fault"]),
        "state_command_digest": module._canonical_digest({"argv": ["state"]}),
        "cleanup_command_digest": module._canonical_digest({"argv": ["cleanup"]}),
        "authority": {
            "kind": "host-plus-independent-loopback-proxy",
            "parent_process_registration": True,
            "exposure_gate": True,
            "endpoint": "http://127.0.0.1:8187/request",
            "start_proxy_registration_digests": {
                row["start_id"]: row["proxy_registration_sha256"] for row in starts
            },
        },
        "issuer": {
            "kind": "ecpa-h3-registration-transition/v1",
            "manager_repository": "vLLM-HUST/extension-manager",
            "manager_remote": "https://github.com/vLLM-HUST/extension-manager.git",
            "host_repository": "vLLM-HUST/vllm-hust",
            "host_remote": "https://github.com/vLLM-HUST/vllm-hust.git",
            "manager_main_commit": "1" * 40,
            "host_main_commit": "2" * 40,
        },
    }
    receipt_binding = write_artifact(root / f"{start_id}-receipt.json", receipt)
    request_results = {
        "start_id": start_id,
        "requests": [{"request_id": "request-1", "outcome": "served"}],
    }
    process_snapshot = {"start_id": start_id, "process_identity": process}
    children = {
        "raw_log": {"start_id": start_id, "events": 4},
        "request_results": request_results,
        "process_snapshot": process_snapshot,
        "cleanup_report": {"start_id": start_id, "cleanup": cleanup},
    }
    bindings = {
        name: write_artifact(root / f"{start_id}-{name}.json", value)
        for name, value in children.items()
    }
    raw = {
        "schema": "ecpa-h3-raw-recovery/v1",
        "evidence_class": "formal-real",
        "campaign_sha256": campaign["_sha256"],
        "campaign_id": "H3-transactional-recovery-v1",
        "cell_id": cell,
        "start_id": start_id,
        "arm": arm,
        "repetition": rep,
        "arm_order": protocol["schedule"][rep - 1].index(arm) + 1,
        "deployment_receipt_sha256": receipt_binding["sha256"],
        "authority_registration_sha256": authority_binding["sha256"],
        "proxy_registration_sha256": proxy_sha,
        "process_identity": process,
        "fault_target": target,
        "pre_fault": {
            "predecessor_digest": predecessor,
            "evidence_identity_sha256": evidence_identity,
        },
        "artifact_sha256": {
            name: binding["sha256"] for name, binding in bindings.items()
        },
        "events": [
            {
                "sequence": 1,
                "monotonic_ns": 1_000_000_000,
                "kind": "fault-triggered",
                "detail": {"fault_id": "kill-manager", **target},
            },
            {
                "sequence": 2,
                "monotonic_ns": 1_100_000_000,
                "kind": "fault-observed",
                "detail": target,
            },
            {
                "sequence": 3,
                "monotonic_ns": 1_200_000_000,
                "kind": "request-result",
                "detail": {
                    "request_id": "request-1",
                    "outcome": "served",
                    "tuple_supported": True,
                    "functional_correctness": True,
                    "request_method": "POST",
                    "request_payload_sha256": "sha256:"
                    + hashlib.sha256(
                        json.dumps(
                            {
                                "model": "test-model",
                                "prompt": "Reply ECPA",
                                "max_tokens": 8,
                                "temperature": 0,
                                "stream": False,
                            },
                            sort_keys=True,
                            separators=(",", ":"),
                        ).encode()
                    ).hexdigest(),
                    "status_code": 200,
                    "response_body": (
                        '{"model":"test-model","choices":['
                        '{"index":0,"text":"ECPA","finish_reason":"stop"}]}'
                    ),
                    "response_sha256": "sha256:"
                    + hashlib.sha256(
                        b'{"model":"test-model","choices":[{"index":0,"text":"ECPA","finish_reason":"stop"}]}'
                    ).hexdigest(),
                },
            },
            {
                "sequence": 4,
                "monotonic_ns": 1_300_000_000,
                "kind": "recovery-complete",
                "detail": {
                    "final_route": "predecessor",
                    "predecessor_digest": predecessor,
                    "evidence_identity_sha256": evidence_identity,
                    "functional_correctness": True,
                    "rollback_classification": "automatic-restoration",
                },
            },
        ],
        "request_results": request_results,
        "process_snapshot": process_snapshot,
    }
    # Synthetic regression only: independent trace shape, never formal evidence.
    proxy = {"pid": 9000, "start_ticks": 42, "boot_id": target["boot_id"]}
    route = {
        "generation": 0,
        "fence": "fence-0",
        "snapshot_sha256": "sha256:"
        + hashlib.sha256(b'{"snapshot":{"generation":0}}').hexdigest(),
    }
    chain_events = []
    previous = "sha256:" + "0" * 64
    for i, (kind, ns, detail) in enumerate(
        [
            (
                "authority.start",
                900_000_000,
                {
                    "authorization": {
                        "launch_id": start_id,
                        "registration_sha256": proxy_sha,
                    }
                },
            ),
            ("route.restore.intent", 1_160_000_000, {"generation": 0}),
            ("route.restore.applied", 1_170_000_000, {}),
        ],
        1,
    ):
        e = {
            "schema": "ecpa-loopback-route-journal/v1",
            "sequence": i,
            "previous_sha256": previous,
            "kind": kind,
            "monotonic_ns": ns,
            "detail": detail,
            "route": route,
            **{"proxy_" + k: v for k, v in proxy.items()},
        }
        previous = (
            "sha256:"
            + hashlib.sha256(
                json.dumps(e, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        )
        chain_events.append(e)
    chain = {"events": chain_events, "proxy_identity": proxy, "prepared_route": route}
    chain_binding = write_artifact(root / f"{start_id}-authority-chain.json", chain)
    bindings["authority_chain"] = chain_binding
    raw["authority_chain"] = chain
    raw["artifact_sha256"]["authority_chain"] = chain_binding["sha256"]
    raw["events"].insert(
        2,
        {
            "sequence": 3,
            "monotonic_ns": 1_150_000_000,
            "kind": "recovery-started",
            "detail": {
                "manager": {
                    "pid": 9001,
                    "start_ticks": 43,
                    "boot_id": target["boot_id"],
                }
            },
        },
    )
    for i, e in enumerate(raw["events"], 1):
        e["sequence"] = i
    from experiments.formal_campaign.h3_authority_chain import verify_recovery_events

    raw["events"][-1]["detail"] = {
        "authority_facts": verify_recovery_events(
            chain_events,
            expected_proxy=proxy,
            registration_sha256=proxy_sha,
            launch_id=start_id,
            prepared_route=route,
            fault_ns=1_000_000_000,
            restart_ns=1_150_000_000,
            completion_ns=1_300_000_000,
        )
    }
    raw_binding = write_artifact(root / f"{start_id}-raw-recovery.json", raw)
    artifacts = {
        "deployment_receipt": receipt_binding,
        "authority_registration": authority_binding,
        "raw_recovery": raw_binding,
        **bindings,
    }
    record = {
        "schema": "ecpa-formal-campaign-record/v1",
        "campaign_id": "H3-transactional-recovery-v1",
        "evidence_class": "formal-real",
        "deployment": {
            "registration_state": "registered",
            "receipt_sha256": receipt_binding["sha256"],
        },
        "cell_id": cell,
        "start_id": start_id,
        "process_identity": process,
        "status": "complete",
        "arm": arm,
        "repetition": rep,
        "arm_order": raw["arm_order"],
        "identity": identity(),
        "artifacts": artifacts,
        "cleanup": cleanup,
        "metrics": {},
    }
    phase = {
        "support": "supported",
        "reason": "synthetic unit fixture only",
        "protocol": "ecpa-native-close-prepare-barrier/v1",
        "journal_path": "/unit-only/gate.sqlite",
        "barrier_path": "/unit-only/barrier.json",
        "timeout_s": 1,
    }
    next(a for a in campaign["arms"] if a["id"] == arm)["phase_barrier"] = phase
    native_rows = [
        {
            "operation": "close",
            "kind": "intent",
            "seq": 1,
            "operation_id": "unit-intent",
        }
    ]
    raw["events"][0]["detail"]["prepare_proof"] = {
        "barrier": {
            "schema": phase["protocol"],
            "phase": "durable-close-intent-before-effect",
            "launch_id": start_id,
            "manager": {
                **{k: target[k] for k in ("pid", "start_ticks", "boot_id")},
                "session": process["launcher_pid"],
            },
            "journal_path": phase["journal_path"],
            "observed_monotonic_ns": 1,
            "native_rows_sha256": "sha256:"
            + hashlib.sha256(
                json.dumps(native_rows, sort_keys=True).encode()
            ).hexdigest(),
            "intent_sequence": 1,
            "intent_operation_id": "unit-intent",
        },
        "native_rows": native_rows,
        "native_state": {
            "predecessor_digest": predecessor,
            "predecessor_generation": 0,
            "predecessor_json": '{"generation":0}',
            "candidate_generation": 1,
        },
        "target_session": process["launcher_pid"],
        "verified_monotonic_ns": 2,
    }
    raw_binding = write_artifact(root / f"{start_id}-raw.json", raw)
    record["artifacts"]["raw_recovery"] = raw_binding
    proof = raw["events"][0]["detail"]["prepare_proof"]
    recovery_rows = copy.deepcopy(proof["native_rows"])
    for operation, kind, opid in [
        ("rollback", "intent", "rollback-id"),
        ("rollback", "receipt", "rollback-id"),
    ]:
        recovery_rows.append(
            {
                "seq": len(recovery_rows) + 1,
                "operation": operation,
                "kind": kind,
                "operation_id": opid,
            }
        )
    raw["authority_chain"]["native_recovery"] = {
        "native_rows": recovery_rows,
        "native_state": proof["native_state"]
        | {"state": "ROLLED_BACK", "route_generation": 0, "route_fence": "fence-0"},
    }
    chain_binding = write_artifact(
        root / f"{start_id}-authority-chain.json", raw["authority_chain"]
    )
    record["artifacts"]["authority_chain"] = chain_binding
    raw["artifact_sha256"]["authority_chain"] = chain_binding["sha256"]
    record["artifacts"]["raw_recovery"] = write_artifact(
        root / f"{start_id}-raw-recovery.json", raw
    )
    record["metrics"] = module._recompute_h3_metrics(record, raw, campaign)
    return record, campaign, raw


def test_h3_requires_raw_metrics_and_rejects_metric_forgery(tmp_path: Path) -> None:
    analyzer = load_analyzer()
    protocol = analyzer.load_protocol()
    row, campaign, _ = h3_record(analyzer, tmp_path)
    incomplete = analyzer.analyze_h3(protocol, [row], tmp_path, campaign)
    assert incomplete["status"] == "incomplete"
    row["metrics"]["objective_met"] = True
    with pytest.raises(ValueError, match="metrics differ from raw evidence"):
        analyzer.analyze_h3(protocol, [row], tmp_path, campaign)


def test_h3_complete_exact_stack_cell_is_reported_without_claiming_campaign(
    tmp_path: Path,
) -> None:
    analyzer = load_analyzer()
    rows = []
    campaign = None
    for rep in range(1, 4):
        for arm in ["ecpa"]:
            row, campaign, _ = h3_record(analyzer, tmp_path, arm=arm, rep=rep)
            rows.append(row)
    assert campaign is not None
    result = analyzer.analyze_h3(analyzer.load_protocol(), rows, tmp_path, campaign)
    cell = campaign["cell_id"]
    assert result["status"] == "incomplete"
    assert result["formal_result"] is False
    assert cell not in result["completed_cells"]
    assert result["formal_result"] is False


def test_h3_rejects_replayed_raw_evidence_between_starts(tmp_path: Path) -> None:
    analyzer = load_analyzer()
    protocol = analyzer.load_protocol()
    first, campaign, _ = h3_record(analyzer, tmp_path, arm="ecpa")
    second, _, _ = h3_record(analyzer, tmp_path, arm="ecpa", rep=2)
    second["artifacts"]["raw_recovery"] = first["artifacts"]["raw_recovery"]
    with pytest.raises(ValueError, match="raw H3|reused"):
        analyzer.analyze_h3(protocol, [first, second], tmp_path, campaign)


def test_h3_rejects_unbound_fault_target(tmp_path: Path) -> None:
    analyzer = load_analyzer()
    row, campaign, raw = h3_record(analyzer, tmp_path)
    raw["events"][0]["detail"]["start_ticks"] += 1
    path = tmp_path / row["artifacts"]["raw_recovery"]["path"]
    path.write_text(json.dumps(raw, sort_keys=True) + "\n")
    row["artifacts"]["raw_recovery"]["sha256"] = (
        "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
    )
    with pytest.raises(ValueError, match="fault target start_ticks is not bound"):
        analyzer.analyze_h3(analyzer.load_protocol(), [row], tmp_path, campaign)


@pytest.mark.parametrize(
    "mutation", ["wrong-method", "payload-replay", "body-forgery", "response-forgery"]
)
def test_h3_recomputes_frozen_request_oracle(tmp_path: Path, mutation: str) -> None:
    analyzer = load_analyzer()
    row, campaign, raw = h3_record(analyzer, tmp_path)
    detail = next(
        event["detail"] for event in raw["events"] if event["kind"] == "request-result"
    )
    if mutation == "wrong-method":
        detail["request_method"] = "GET"
    elif mutation == "payload-replay":
        detail["request_payload_sha256"] = "sha256:" + "f" * 64
    elif mutation == "body-forgery":
        detail["response_body"] = "nonempty fake completion"
    else:
        value = json.loads(detail["response_body"])
        value["choices"][0]["text"] = "wrong answer"
        detail["response_body"] = json.dumps(value)
        detail["response_sha256"] = (
            "sha256:" + hashlib.sha256(detail["response_body"].encode()).hexdigest()
        )
    with pytest.raises(ValueError, match="frozen POST|response digest|frozen oracle"):
        analyzer._recompute_h3_metrics(row, raw, campaign)


@pytest.mark.parametrize(
    "mutation",
    [
        "request",
        "body_hash",
        "wrong_model",
        "tokens",
        "summary",
        "status",
        "missing_raw",
        "bad_base64",
    ],
)
def test_h4_http_evidence_tampering_is_rejected(tmp_path: Path, mutation: str):
    """Synthetic verifier regression, never a formal experiment."""
    module = load_analyzer()
    cell, rows = h4_cell_records(module, tmp_path)
    record = rows[0]
    raw_path = tmp_path / record["artifacts"]["raw_measurement"]["path"]
    raw = json.loads(raw_path.read_text())
    item = raw["requests"][1]
    if mutation == "request":
        item["http_request"] = module.h4_body_binding(b'{"prompt":"changed"}')
    elif mutation == "body_hash":
        item["http_response"]["body_sha256"] = "sha256:" + "0" * 64
    elif mutation in ("wrong_model", "tokens"):
        body = json.loads(module.h4_decode_body(item["http_response"]))
        if mutation == "wrong_model":
            body["model"] = "different-model"
        else:
            body["usage"]["completion_tokens"] = 999
        item["http_response"].update(module.h4_body_binding(json.dumps(body).encode()))
        # Recompute the summaries too: consistent forged summaries cannot evade
        # the frozen model/request limit check.
        item.update(module.h4_response_summary(item["http_response"]))
    elif mutation == "summary":
        item["output_tokens"] = 999
    elif mutation == "status":
        item["status_code"] = 503
    elif mutation == "missing_raw":
        del item["http_response"]
    else:
        item["http_response"]["body_base64"] = "!not-base64!"
    with pytest.raises(ValueError):
        module._recompute_h4_metrics(record, raw, campaign_spec(cell))


def test_h4_admitted_model_cannot_be_rebound(tmp_path: Path):
    module = load_analyzer()
    cell, rows = h4_cell_records(module, tmp_path)
    record = rows[0]
    raw_path = tmp_path / record["artifacts"]["raw_measurement"]["path"]
    raw = json.loads(raw_path.read_text())
    raw["launch_definition"]["served_model"] = "mutated-model"
    write(raw_path, raw)
    record["artifacts"]["raw_measurement"]["sha256"] = digest(raw_path)
    with pytest.raises(ValueError, match="admitted arm"):
        module._verify_h4_raw_artifact(record, tmp_path, campaign_spec(cell))
