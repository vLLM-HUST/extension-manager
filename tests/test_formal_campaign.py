ÚznÛéºÉ¢Šwèfrom __future__ import annotations

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
    value = {
        "schema": "ecpa-h4-deployment-receipt/v1",
        "registration_state": "registered",
        "admissible": True,
        "evidence_mode": "formal-real",
        "campaign_sha256": "sha256:" + "8" * 64,
        "campaign_id": "H4-matched-cost-v1",
        "cell_id": cell,
        "arm_command_digests": {
            arm: "sha256:" + char * 64
            for arm, char in (
                ("vanilla-vllm-entry-points", "a"),
                ("manual-integration", "b"),
                ("ecpa", "c"),
            )
        },
        "manager_commit": "1" * 40,
        "host_commit": "2" * 40,
        "accelerator_commit": "3" * 40,
        "plugin_commits": {"kv-mod": "4" * 40},
        "model_digest": "sha256:" + "5" * 64,
        "workload_digest": "sha256:" + "6" * 64,
        "hardware": "2x Ascend 910B2",
        "topology": "TP2",
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
        "schema": "ecpa-h4-raw-measurement/v1",
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
    return {
        "_sha256": "sha256:" + "8" * 64,
        "campaign_id": "H3-transactional-recovery-v1",
        "cell_id": cell,
        "fixed_identity": identity(),
        "fault": {"id": "kill-manager", "target_role": "manager"},
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
    receipt = {
        "schema": "ecpa-h3-deployment-receipt/v1",
        "registration_state": "registered",
        "admissible": True,
        "evidence_mode": "formal-real",
        "campaign_sha256": campaign["_sha256"],
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
        "authority": {
            "kind": "host",
            "parent_process_registration": True,
            "exposure_gate": True,
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
    raw_binding = write_artifact(root / f"{start_id}-raw-recovery.json", raw)
    artifacts = {
        "deployment_receipt": receipt_binding,
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
    record["metrics"] = module._recompute_h3_metrics(record, raw, campaign)
    return record, campaign, raw


def test_h3_requires_raw_metrics_and_rejects_metric_forgery(tmp_path: Path) -> None:
    analyzer = load_analyzer()
    protocol = analyzer.load_protocol()
    row, campaign, _ = h3_record(analyzer, tmp_path)
    incomplete = analyzer.analyze_h3(protocol, [row], tmp_path, campaign)
    assert incomplete["status"] == "incomplete"
    row["metrics"]["objective_met"] = False
    with pytest.raises(ValueError, match="metrics differ from raw evidence"):
        analyzer.analyze_h3(protocol, [row], tmp_path, campaign)


def test_h3_complete_exact_stack_cell_is_reported_without_claiming_campaign(
    tmp_path: Path,
) -> None:
    analyzer = load_analyzer()
    rows = []
    campaign = None
    for rep in range(1, 4):
        for arm in analyzer.load_protocol()["arms"]:
            row, campaign, _ = h3_record(analyzer, tmp_path, arm=arm, rep=rep)
            rows.append(row)
    assert campaign is not None
    result = analyzer.analyze_h3(analyzer.load_protocol(), rows, tmp_path, campaign)
    cell = campaign["cell_id"]
    assert result["status"] == "incomplete"
    assert result["formal_result"] is False
    assert result["completed_cells"][cell]["formal_result"] is True
    assert result["completed_cells"][cell]["status"] == "supported"
    assert result["completed_cells"][cell]["starts"] == 9


def test_h3_rejects_replayed_raw_evidence_between_starts(tmp_path: Path) -> None:
    analyzer = load_analyzer()
    protocol = analyzer.load_protocol()
    first, campaign, _ = h3_record(analyzer, tmp_path, arm="ecpa")
    second, _, _ = h3_record(analyzer, tmp_path, arm="manual-integration")
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
