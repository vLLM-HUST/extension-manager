from __future__ import annotations

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


def artifact_bindings(root: Path) -> dict[str, dict[str, str]]:
    bindings = {}
    for name in ("raw_log", "request_results", "process_snapshot", "cleanup_report"):
        path = root / f"{name}.json"
        path.write_text(json.dumps({"artifact": name}) + "\n")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        bindings[name] = {"path": path.name, "sha256": f"sha256:{digest}"}
    return bindings


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


def h4_metrics(arm: str, *, p99_ecpa: float = 101.0) -> dict[str, object]:
    total = {
        "manual-integration": 1000.0,
        "ecpa": 1020.0,
        "vanilla-vllm-entry-points": 980.0,
    }[arm]
    throughput = {
        "manual-integration": 100.0,
        "ecpa": 99.5,
        "vanilla-vllm-entry-points": 101.0,
    }[arm]
    p99 = {
        "manual-integration": 100.0,
        "ecpa": p99_ecpa,
        "vanilla-vllm-entry-points": 98.0,
    }[arm]
    return {
        "startup_phases_ms": {
            "discovery": 1.0,
            "validation": 2.0,
            "planning": 3.0,
            "rendering": 4.0,
            "worker_loading": 900.0,
            "evidence_setup": 10.0,
            "total": total,
        },
        "throughput": throughput,
        "latency_median_ms": 50.0,
        "latency_p95_ms": 80.0,
        "latency_p99_ms": p99,
        "cpu_ms": 100.0,
        "host_memory_bytes": 1000,
        "device_memory_bytes": 2000,
        "process_messages": 10,
        "evidence_bytes": 500,
        "gate_open_ms": None,
        "failure_detection_ms": None,
        "rollback_ms": None,
        "recovery_ms": None,
    }


def record(
    protocol: dict[str, object],
    artifacts: dict[str, dict[str, str]],
    cell: str,
    repetition: int,
    arm: str,
    *,
    p99_ecpa: float = 101.0,
) -> dict[str, object]:
    return {
        "schema": "ecpa-formal-campaign-record/v1",
        "campaign_id": "H4-matched-cost-v1",
        "evidence_class": "formal-real",
        "deployment": {
            "registration_state": "registered",
            "receipt_sha256": "sha256:" + "8" * 64,
        },
        "cell_id": cell,
        "start_id": f"{cell}-r{repetition}-{arm}",
        "status": "complete",
        "arm": arm,
        "repetition": repetition,
        "arm_order": protocol["schedule"][repetition - 1].index(arm) + 1,
        "identity": identity(),
        "artifacts": artifacts,
        "cleanup": {
            "processes_reclaimed": True,
            "ports_reclaimed": True,
            "devices_reclaimed": True,
        },
        "metrics": h4_metrics(arm, p99_ecpa=p99_ecpa),
    }


def h4_records(module, artifacts, *, p99_ecpa: float = 101.0):
    protocol = module.load_protocol()
    return [
        record(protocol, artifacts, cell, repetition, arm, p99_ecpa=p99_ecpa)
        for cell in protocol["h4"]["required_cells"]
        for repetition in range(1, 4)
        for arm in protocol["arms"]
    ]


def h3_records(module, artifacts):
    protocol = module.load_protocol()
    rows = []
    for cell in protocol["h3"]["required_cells"]:
        for repetition in range(1, 4):
            for arm in protocol["arms"]:
                rows.append(
                    {
                        "schema": "ecpa-formal-campaign-record/v1",
                        "campaign_id": "H3-transactional-recovery-v1",
                        "evidence_class": "formal-real",
                        "deployment": {
                            "registration_state": "registered",
                            "receipt_sha256": "sha256:" + "8" * 64,
                        },
                        "cell_id": cell,
                        "start_id": f"{cell}-r{repetition}-{arm}",
                        "status": "complete",
                        "arm": arm,
                        "repetition": repetition,
                        "arm_order": protocol["schedule"][repetition - 1].index(arm)
                        + 1,
                        "identity": identity(),
                        "artifacts": artifacts,
                        "cleanup": {
                            "processes_reclaimed": True,
                            "ports_reclaimed": True,
                            "devices_reclaimed": True,
                        },
                        "metrics": {
                            "injected_failure": True,
                            "objective_met": True,
                            "unsupported_tuple_served": False,
                            "predecessor_preserved": True,
                            "functional_correctness": True,
                            "evidence_identity_preserved": True,
                            "recovery_ms": 100.0,
                            "lost_requests": 0,
                            "duplicated_requests": 0,
                            "operator_actions": 0,
                            "final_route": "predecessor",
                            "rollback_classification": "automatic-restoration",
                        },
                    }
                )
    return rows


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))


def test_incomplete_campaign_emits_no_metrics(tmp_path: Path) -> None:
    analyzer = load_analyzer()
    artifacts = artifact_bindings(tmp_path)
    protocol = analyzer.load_protocol()
    one = record(
        protocol,
        artifacts,
        protocol["h4"]["required_cells"][0],
        1,
        "vanilla-vllm-entry-points",
    )

    result = analyzer.analyze_h4(protocol, [one], tmp_path)

    assert result["status"] == "incomplete"
    assert result["formal_result"] is False
    assert result["metrics"] is None
    assert result["received_starts"] == 1


def test_complete_h4_uses_manual_paired_baseline_and_frozen_thresholds(
    tmp_path: Path,
) -> None:
    analyzer = load_analyzer()
    artifacts = artifact_bindings(tmp_path)
    protocol = analyzer.load_protocol()
    rows = h4_records(analyzer, artifacts)

    result = analyzer.analyze_h4(protocol, rows, tmp_path)

    assert result["status"] == "supported"
    assert result["formal_result"] is True
    assert result["manual_baseline"] == "manual-integration"
    assert result["vanilla_reported_separately"] is True
    assert (
        result["metrics"]["overall"]["ecpa_vs_manual_startup_percent"]["median"] == 2.0
    )
    assert (
        result["metrics"]["overall"]["ecpa_vs_manual_throughput_regression_percent"][
            "median"
        ]
        == 0.5
    )
    assert (
        result["metrics"]["overall"]["ecpa_vs_manual_p99_regression_percent"]["median"]
        == 1.0
    )
    assert all(
        "vanilla_vs_manual_startup_percent" in cell
        for cell in result["metrics"]["cells"].values()
    )


def test_h4_retains_threshold_violation_as_falsified(tmp_path: Path) -> None:
    analyzer = load_analyzer()
    artifacts = artifact_bindings(tmp_path)
    protocol = analyzer.load_protocol()
    rows = h4_records(analyzer, artifacts, p99_ecpa=103.0)

    result = analyzer.analyze_h4(protocol, rows, tmp_path)

    assert result["status"] == "falsified"
    assert (
        result["metrics"]["overall"]["ecpa_vs_manual_p99_regression_percent"]["median"]
        == 3.0
    )


def test_h4_does_not_hide_one_failing_cell_in_an_aggregate(tmp_path: Path) -> None:
    analyzer = load_analyzer()
    artifacts = artifact_bindings(tmp_path)
    protocol = analyzer.load_protocol()
    rows = h4_records(analyzer, artifacts)
    failing_cell = protocol["h4"]["required_cells"][0]
    for row in rows:
        if row["cell_id"] == failing_cell and row["arm"] == "ecpa":
            row["metrics"]["latency_p99_ms"] = 110.0

    result = analyzer.analyze_h4(protocol, rows, tmp_path)

    assert result["status"] == "falsified"
    assert result["metrics"]["cells"][failing_cell]["threshold_violation"] is True


def test_h3_reports_each_cell_and_retains_direct_safety_violation(
    tmp_path: Path,
) -> None:
    analyzer = load_analyzer()
    artifacts = artifact_bindings(tmp_path)
    protocol = analyzer.load_protocol()
    rows = h3_records(analyzer, artifacts)

    supported = analyzer.analyze_h3(protocol, rows, tmp_path)

    assert supported["status"] == "supported"
    assert supported["metrics"]["objective_rate"] == 1.0
    assert set(supported["metrics"]["cells"]) == set(protocol["h3"]["required_cells"])

    rows[0]["metrics"]["unsupported_tuple_served"] = True
    falsified = analyzer.analyze_h3(protocol, rows, tmp_path)

    assert falsified["status"] == "falsified"
    assert falsified["metrics"]["direct_safety_violation"] is True
    assert (
        falsified["metrics"]["cells"][rows[0]["cell_id"]]["direct_safety_violation"]
        is True
    )


def test_intake_rejects_cross_arm_identity_drift(tmp_path: Path) -> None:
    analyzer = load_analyzer()
    artifacts = artifact_bindings(tmp_path)
    protocol = analyzer.load_protocol()
    rows = h4_records(analyzer, artifacts)
    rows[1]["identity"] = {**rows[1]["identity"], "host_commit": "9" * 40}

    with pytest.raises(ValueError, match="mixed cross-arm"):
        analyzer.analyze_h4(protocol, rows, tmp_path)


def test_intake_rejects_missing_or_modified_raw_artifact(tmp_path: Path) -> None:
    analyzer = load_analyzer()
    artifacts = artifact_bindings(tmp_path)
    protocol = analyzer.load_protocol()
    rows = h4_records(analyzer, artifacts)
    (tmp_path / "raw_log.json").write_text("modified\n")

    with pytest.raises(ValueError, match="digest differs"):
        analyzer.analyze_h4(protocol, rows, tmp_path)


def test_schema_rejects_preflight_and_unregistered_records(tmp_path: Path) -> None:
    analyzer = load_analyzer()
    artifacts = artifact_bindings(tmp_path)
    protocol = analyzer.load_protocol()
    row = record(
        protocol,
        artifacts,
        protocol["h4"]["required_cells"][0],
        1,
        "ecpa",
    )
    row["evidence_class"] = "unregistered-real-preflight"
    row["deployment"]["registration_state"] = "unregistered"
    records = tmp_path / "records.jsonl"
    write_jsonl(records, [row])

    with pytest.raises(ValueError, match="formal-real|registered"):
        analyzer.load_records(records)
