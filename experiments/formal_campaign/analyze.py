#!/usr/bin/env python3
"""Fail-closed intake and paired analysis for formal H3/H4 campaigns."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import statistics
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jsonschema

ROOT = Path(__file__).resolve().parent


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def load_protocol(root: Path = ROOT) -> dict[str, Any]:
    protocol = _load_object(root / "protocol.json")
    schema = _load_object(root / "protocol.schema.json")
    jsonschema.Draft7Validator.check_schema(schema)
    jsonschema.Draft7Validator(schema).validate(protocol)
    arms = protocol["arms"]
    schedule = protocol["schedule"]
    if any(sorted(row) != sorted(arms) for row in schedule):
        raise ValueError("protocol schedule rows must contain every arm exactly once")
    if any(
        len({schedule[row][column] for row in range(3)}) != 3 for column in range(3)
    ):
        raise ValueError("protocol schedule must be a balanced Latin square")
    if protocol["h4"]["manual_baseline"] != "manual-integration":
        raise ValueError("H4 must retain manual integration as its primary baseline")
    return protocol


def load_h4_campaign(path: Path) -> dict[str, Any]:
    campaign = _load_object(path)
    if campaign.get("schema") != "ecpa-h4-minimal-matched-cell-campaign/v1":
        raise ValueError("H4 campaign uses an unsupported schema")
    required = {
        "campaign_id",
        "cell_id",
        "arms",
        "schedule",
        "fixed_identity",
        "workload",
    }
    missing = sorted(required - campaign.keys())
    if missing:
        raise ValueError(f"H4 campaign lacks {', '.join(missing)}")
    campaign["_sha256"] = _digest_bytes(path)
    campaign["_path"] = str(path.resolve())
    campaign["arms_by_id"] = {item["id"]: item for item in campaign["arms"]}
    workload_path = (path.parent / campaign["workload"]["path"]).resolve()
    if _digest_bytes(workload_path) != campaign["workload"]["sha256"]:
        raise ValueError("H4 workload digest differs from frozen campaign")
    campaign["workload"] = _load_object(workload_path) | {
        "sha256": campaign["workload"]["sha256"]
    }
    return campaign


def load_records(path: Path, root: Path = ROOT) -> list[dict[str, Any]]:
    schema = _load_object(root / "record.schema.json")
    jsonschema.Draft7Validator.check_schema(schema)
    validator = jsonschema.Draft7Validator(schema)
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number} must contain one JSON object")
        errors = sorted(
            validator.iter_errors(value), key=lambda error: list(error.path)
        )
        if errors:
            raise ValueError(f"{path}:{line_number}: {errors[0].message}")
        records.append(value)
    return records


def _verify_artifacts(record: dict[str, Any], artifact_root: Path) -> None:
    root = artifact_root.resolve()
    resolved: dict[str, Path] = {}
    for label, binding in record["artifacts"].items():
        path = (root / binding["path"]).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError(
                f"{record['start_id']} {label} is outside artifact root or missing"
            )
        actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != binding["sha256"]:
            raise ValueError(f"{record['start_id']} {label} digest differs")
        resolved[label] = path

    receipt_binding = record["artifacts"]["deployment_receipt"]
    if receipt_binding["sha256"] != record["deployment"]["receipt_sha256"]:
        raise ValueError(
            f"{record['start_id']} deployment receipt digest differs from record"
        )
    try:
        receipt = _load_object(resolved["deployment_receipt"])
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(
            f"{record['start_id']} deployment receipt is not valid JSON"
        ) from exc
    documents = receipt.get("documents")
    if documents is None:
        deployment = receipt
    elif isinstance(documents, dict):
        deployment = documents.get("deployment")
    else:
        deployment = None
    if (
        not isinstance(deployment, dict)
        or deployment.get("registration_state") != "registered"
        or deployment.get("admissible") is not True
        or (
            receipt.get("schema") == "ecpa-h1-atomic-formal-registration/v1"
            and receipt.get("ready") is not True
        )
    ):
        raise ValueError(
            f"{record['start_id']} deployment receipt is not an admissible registration"
        )


def _digest_bytes(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _load_h4_raw_schema(root: Path = ROOT) -> dict[str, Any]:
    schema = _load_object(root / "h4-raw-artifact.schema.json")
    jsonschema.Draft7Validator.check_schema(schema)
    return schema


def _verify_h4_receipt(
    record: dict[str, Any], receipt_path: Path, campaign_spec: dict[str, Any]
) -> dict[str, Any]:
    receipt = _load_object(receipt_path)
    schema = _load_object(ROOT / "h4-deployment-receipt.schema.json")
    jsonschema.Draft7Validator.check_schema(schema)
    errors = sorted(
        jsonschema.Draft7Validator(schema).iter_errors(receipt),
        key=lambda error: list(error.path),
    )
    if errors:
        raise ValueError(
            f"{record['start_id']} deployment receipt: {errors[0].message}"
        )
    expected = {
        "campaign_id": record["campaign_id"],
        "cell_id": record["cell_id"],
        "manager_commit": record["identity"]["manager_commit"],
        "host_commit": record["identity"]["host_commit"],
        "accelerator_commit": record["identity"]["accelerator_commit"],
        "plugin_commits": record["identity"]["plugin_commits"],
        "model_digest": record["identity"]["model_digest"],
        "workload_digest": record["identity"]["workload_digest"],
        "hardware": record["identity"]["hardware"],
        "topology": record["identity"]["topology"],
    }
    for name, value in expected.items():
        if receipt.get(name) != value:
            raise ValueError(f"{record['start_id']} receipt {name} is not bound")
    if receipt["campaign_sha256"] != campaign_spec["_sha256"]:
        raise ValueError(f"{record['start_id']} receipt campaign digest differs")
    if receipt["arm_command_digests"].keys() != set(campaign_spec["arms_by_id"]):
        raise ValueError(f"{record['start_id']} receipt does not cover all arms")
    return receipt


def _duration_ms(interval: dict[str, int]) -> float:
    if interval["end_ns"] < interval["start_ns"]:
        raise ValueError("monotonic interval ends before it starts")
    return (interval["end_ns"] - interval["start_ns"]) / 1_000_000


def _recompute_h4_metrics(
    record: dict[str, Any], raw: dict[str, Any], campaign_spec: dict[str, Any]
) -> dict[str, Any]:
    start_id = record["start_id"]
    bindings = {
        "campaign_id": record["campaign_id"],
        "cell_id": record["cell_id"],
        "start_id": start_id,
        "arm": record["arm"],
        "repetition": record["repetition"],
        "arm_order": record["arm_order"],
        "workload_digest": record["identity"]["workload_digest"],
        "deployment_receipt_sha256": record["deployment"]["receipt_sha256"],
    }
    for name, expected in bindings.items():
        if raw.get(name) != expected:
            raise ValueError(f"{start_id} raw artifact {name} is not bound")
    if raw["process_identity"] != record["process_identity"]:
        raise ValueError(f"{start_id} raw process identity differs")
    if record["status"] == "complete" and (
        record["process_identity"]["server_pid"] is None
        or record["process_identity"]["server_start_ticks"] is None
    ):
        raise ValueError(f"{start_id} complete start lacks server process identity")
    for label, expected in raw["artifact_sha256"].items():
        if record["artifacts"][label]["sha256"] != expected:
            raise ValueError(f"{start_id} raw artifact manifest differs for {label}")

    phases = raw["startup_phases"]
    order = [
        "discovery",
        "validation",
        "planning",
        "rendering",
        "evidence_setup",
        "worker_loading",
    ]
    cursor = raw["startup_start_ns"]
    phase_ms: dict[str, float] = {}
    for phase in order:
        interval = phases[phase]
        if interval["start_ns"] != cursor:
            raise ValueError(f"{start_id} startup phases overlap or contain a gap")
        phase_ms[phase] = _duration_ms(interval)
        cursor = interval["end_ns"]
    if cursor != raw["ready_ns"]:
        raise ValueError(f"{start_id} startup phases do not end at readiness")
    total_ms = (raw["ready_ns"] - raw["startup_start_ns"]) / 1_000_000
    if abs(sum(phase_ms.values()) - total_ms) > 1.0:
        raise ValueError(f"{start_id} startup phase sum differs from total")
    phase_ms["total"] = total_ms

    workload = campaign_spec["workload"]
    requests = raw["requests"]
    warmups = [item for item in requests if item["kind"] == "warmup"]
    measured = [item for item in requests if item["kind"] == "measured"]
    if len(warmups) != workload["warmup_requests"]:
        raise ValueError(f"{start_id} warmup request count differs")
    if len(measured) != workload["measured_requests"]:
        raise ValueError(f"{start_id} measured request count differs")
    ids = [item["request_id"] for item in requests]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{start_id} request IDs are not unique")
    for item in requests:
        if item["complete_ns"] < item["dispatch_ns"]:
            raise ValueError(f"{start_id} request has negative latency")
    successful = [
        item
        for item in measured
        if item["status_code"] == workload["success_status"]
        and (item["response_nonempty"] or not workload["require_nonempty_completion"])
    ]
    if len(successful) < workload["min_successful_measured_requests"]:
        raise ValueError(f"{start_id} has too few successful measured requests")
    first_dispatch = min(item["dispatch_ns"] for item in measured)
    last_complete = max(item["complete_ns"] for item in measured)
    elapsed_seconds = (last_complete - first_dispatch) / 1_000_000_000
    if elapsed_seconds <= 0:
        raise ValueError(f"{start_id} measured window is not positive")
    latencies = [
        (item["complete_ns"] - item["dispatch_ns"]) / 1_000_000 for item in successful
    ]
    resources = raw["resources"]
    return {
        "startup_phases_ms": phase_ms,
        "throughput": len(successful) / elapsed_seconds,
        "latency_median_ms": _percentile(latencies, 0.50),
        "latency_p95_ms": _percentile(latencies, 0.95),
        "latency_p99_ms": _percentile(latencies, 0.99),
        "cpu_ms": resources["cpu_ms"],
        "host_memory_bytes": resources["peak_host_rss_bytes"],
        "device_memory_bytes": resources["peak_device_memory_bytes"],
        "process_messages": resources["process_messages"],
        "evidence_bytes": resources["evidence_bytes"],
        "gate_open_ms": resources.get("gate_open_ms"),
        "failure_detection_ms": resources.get("failure_detection_ms"),
        "rollback_ms": resources.get("rollback_ms"),
        "recovery_ms": resources.get("recovery_ms"),
    }


def _verify_h4_raw_artifact(
    record: dict[str, Any], artifact_root: Path, campaign_spec: dict[str, Any]
) -> None:
    root = artifact_root.resolve()
    binding = record["artifacts"].get("raw_measurement")
    if not isinstance(binding, dict):
        raise ValueError(f"{record['start_id']} lacks a raw H4 measurement")
    path = (root / binding["path"]).resolve()
    if not path.is_relative_to(root) or not path.is_file():
        raise ValueError(f"{record['start_id']} raw H4 measurement is missing")
    if _digest_bytes(path) != binding["sha256"]:
        raise ValueError(f"{record['start_id']} raw H4 measurement digest differs")
    raw = _load_object(path)
    errors = sorted(
        jsonschema.Draft7Validator(_load_h4_raw_schema()).iter_errors(raw),
        key=lambda error: list(error.path),
    )
    if errors:
        raise ValueError(
            f"{record['start_id']} raw H4 measurement: {errors[0].message}"
        )
    _verify_h4_receipt(
        record,
        (root / record["artifacts"]["deployment_receipt"]["path"]).resolve(),
        campaign_spec,
    )
    request_path = (root / record["artifacts"]["request_results"]["path"]).resolve()
    process_path = (root / record["artifacts"]["process_snapshot"]["path"]).resolve()
    cleanup_path = (root / record["artifacts"]["cleanup_report"]["path"]).resolve()
    request_document = _load_object(request_path)
    if (
        request_document.get("start_id") != record["start_id"]
        or request_document.get("requests") != raw["requests"]
    ):
        raise ValueError(f"{record['start_id']} request artifact differs from raw")
    process_document = _load_object(process_path)
    if (
        process_document.get("start_id") != record["start_id"]
        or process_document.get("process_identity") != raw["process_identity"]
    ):
        raise ValueError(f"{record['start_id']} process snapshot differs from raw")
    cleanup_document = _load_object(cleanup_path)
    if (
        cleanup_document.get("start_id") != record["start_id"]
        or cleanup_document.get("cleanup") != record["cleanup"]
    ):
        raise ValueError(f"{record['start_id']} cleanup report differs from record")
    if record["status"] == "complete":
        recomputed = _recompute_h4_metrics(record, raw, campaign_spec)
        if _canonical_digest(recomputed) != _canonical_digest(record["metrics"]):
            raise ValueError(f"{record['start_id']} metrics differ from raw evidence")


def _validate_intake(
    protocol: dict[str, Any],
    campaign: str,
    records: list[dict[str, Any]],
    artifact_root: Path,
    campaign_spec: dict[str, Any] | None = None,
) -> tuple[list[str], dict[tuple[str, int, str], dict[str, Any]]]:
    definition = protocol[campaign]
    expected_campaign = definition["campaign_id"]
    records = [row for row in records if row["campaign_id"] == expected_campaign]
    start_ids = [row["start_id"] for row in records]
    if len(start_ids) != len(set(start_ids)):
        raise ValueError("start_id values must be unique")

    indexed: dict[tuple[str, int, str], dict[str, Any]] = {}
    for row in records:
        if row["cell_id"] not in definition["required_cells"]:
            raise ValueError(f"{row['start_id']} uses an unregistered cell")
        expected_order = (
            protocol["schedule"][row["repetition"] - 1].index(row["arm"]) + 1
        )
        if row["arm_order"] != expected_order:
            raise ValueError(f"{row['start_id']} differs from the frozen arm order")
        key = (row["cell_id"], row["repetition"], row["arm"])
        if key in indexed:
            raise ValueError(f"duplicate formal start for {key}")
        _verify_artifacts(row, artifact_root)
        if campaign == "h4":
            if campaign_spec is None:
                raise ValueError("H4 intake requires the frozen campaign spec")
            if row["campaign_id"] != campaign_spec["campaign_id"]:
                raise ValueError(f"{row['start_id']} differs from frozen campaign")
            if row["cell_id"] != campaign_spec["cell_id"]:
                raise ValueError(f"{row['start_id']} differs from frozen cell")
            _verify_h4_raw_artifact(row, artifact_root, campaign_spec)
        indexed[key] = row

    missing = [
        f"{cell}/r{repetition}/{arm}"
        for cell in definition["required_cells"]
        for repetition in range(1, protocol["minimum_starts"] + 1)
        for arm in protocol["arms"]
        if (cell, repetition, arm) not in indexed
    ]

    for cell in definition["required_cells"]:
        cell_rows = [row for row in records if row["cell_id"] == cell]
        if not cell_rows:
            continue
        reference = cell_rows[0]["identity"]
        if any(row["identity"] != reference for row in cell_rows[1:]):
            raise ValueError(f"{cell} has mixed cross-arm or cross-start identity")
        receipts = {row["deployment"]["receipt_sha256"] for row in cell_rows}
        if len(receipts) != 1:
            raise ValueError(f"{cell} has mixed deployment registration receipts")
    if campaign == "h4":
        for label in (
            "raw_measurement",
            "raw_log",
            "request_results",
            "process_snapshot",
            "cleanup_report",
        ):
            digests = [row["artifacts"][label]["sha256"] for row in records]
            if len(digests) != len(set(digests)):
                raise ValueError(f"H4 {label} artifacts are reused across starts")
    return missing, indexed


def _percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight


def _paired_summary(
    values: list[float], *, seed: int, resamples: int, level: float
) -> dict[str, Any]:
    rng = random.Random(seed)
    bootstrapped = [
        statistics.median(rng.choices(values, k=len(values))) for _ in range(resamples)
    ]
    tail = (1 - level) / 2
    return {
        "pairs": len(values),
        "median": statistics.median(values),
        "confidence_level": level,
        "confidence_interval": [
            _percentile(bootstrapped, tail),
            _percentile(bootstrapped, 1 - tail),
        ],
    }


def _effect(
    indexed: dict[tuple[str, int, str], dict[str, Any]],
    cells: list[str],
    candidate: str,
    baseline: str,
    extractor: Callable[[dict[str, Any]], float],
    direction: str,
) -> list[float]:
    values = []
    for cell in cells:
        for repetition in range(1, 4):
            left = extractor(indexed[(cell, repetition, candidate)])
            right = extractor(indexed[(cell, repetition, baseline)])
            if right <= 0:
                raise ValueError(f"{cell}/r{repetition} baseline must be positive")
            numerator = left - right if direction == "increase" else right - left
            values.append(100 * numerator / right)
    return values


def _summarize_h4_cells(
    protocol: dict[str, Any],
    indexed: dict[tuple[str, int, str], dict[str, Any]],
    cells: list[str],
    rows: list[dict[str, Any]],
    *,
    overall_complete: bool,
) -> dict[str, Any]:
    definition = protocol["h4"]
    confidence = definition["confidence"]

    def summarize(values: list[float]) -> dict[str, Any]:
        return _paired_summary(
            values,
            seed=confidence["seed"],
            resamples=confidence["resamples"],
            level=confidence["level"],
        )

    failed = [row["start_id"] for row in rows if row["status"] == "failed"]
    cleanup_failures = [
        row["start_id"] for row in rows if not all(row["cleanup"].values())
    ]
    if failed or cleanup_failures:
        return {
            "status": "falsified",
            "formal_result": True,
            "campaign_complete": overall_complete,
            "starts": len(rows),
            "failed_starts": failed,
            "cleanup_failures": cleanup_failures,
            "metrics": None,
        }
    thresholds = definition["thresholds"]
    summaries: dict[str, Any] = {}
    violated = False
    for cell in cells:
        startup_percent = _effect(
            indexed,
            [cell],
            "ecpa",
            "manual-integration",
            lambda row: row["metrics"]["startup_phases_ms"]["total"],
            "increase",
        )
        startup_absolute = [
            indexed[(cell, repetition, "ecpa")]["metrics"]["startup_phases_ms"]["total"]
            - indexed[(cell, repetition, "manual-integration")]["metrics"][
                "startup_phases_ms"
            ]["total"]
            for repetition in range(1, 4)
        ]
        throughput = _effect(
            indexed,
            [cell],
            "ecpa",
            "manual-integration",
            lambda row: row["metrics"]["throughput"],
            "regression",
        )
        p99 = _effect(
            indexed,
            [cell],
            "ecpa",
            "manual-integration",
            lambda row: row["metrics"]["latency_p99_ms"],
            "increase",
        )
        values = {
            "ecpa_vs_manual_startup_percent": summarize(startup_percent),
            "ecpa_vs_manual_startup_absolute_ms": summarize(startup_absolute),
            "ecpa_vs_manual_throughput_regression_percent": summarize(throughput),
            "ecpa_vs_manual_p99_regression_percent": summarize(p99),
        }
        values["threshold_violation"] = (
            (
                values["ecpa_vs_manual_startup_percent"]["median"]
                > thresholds["startup_percent"]
                and values["ecpa_vs_manual_startup_absolute_ms"]["median"]
                > thresholds["startup_absolute_ms"]
            )
            or (
                values["ecpa_vs_manual_throughput_regression_percent"]["median"]
                > thresholds["throughput_regression_percent"]
            )
            or (
                values["ecpa_vs_manual_p99_regression_percent"]["median"]
                > thresholds["latency_p99_regression_percent"]
            )
        )
        violated = violated or values["threshold_violation"]
        summaries[cell] = values
    return {
        "status": "falsified" if violated else "supported",
        "formal_result": True,
        "campaign_complete": overall_complete,
        "starts": len(rows),
        "failed_starts": [],
        "cleanup_failures": [],
        "metrics": {"cells": summaries},
    }


def analyze_h3(
    protocol: dict[str, Any],
    records: list[dict[str, Any]],
    artifact_root: Path,
) -> dict[str, Any]:
    missing, indexed = _validate_intake(protocol, "h3", records, artifact_root)
    if missing:
        return {
            "schema": "ecpa-formal-campaign-summary/v1",
            "campaign_id": protocol["h3"]["campaign_id"],
            "status": "incomplete",
            "formal_result": False,
            "received_starts": len(indexed),
            "required_starts": len(protocol["h3"]["required_cells"]) * 9,
            "missing": missing,
            "metrics": None,
        }
    rows = list(indexed.values())
    injected = [row for row in rows if row["metrics"]["injected_failure"]]
    if not injected:
        raise ValueError("H3 contains no injected failures")
    objective_rate = sum(row["metrics"]["objective_met"] for row in injected) / len(
        injected
    )
    direct_violation = any(
        row["metrics"]["unsupported_tuple_served"]
        or not row["metrics"]["predecessor_preserved"]
        or not row["metrics"]["functional_correctness"]
        or not row["metrics"]["evidence_identity_preserved"]
        for row in rows
    )
    cleanup_failures = [
        row["start_id"] for row in rows if not all(row["cleanup"].values())
    ]
    cells = {}
    for cell in protocol["h3"]["required_cells"]:
        cell_rows = [row for row in rows if row["cell_id"] == cell]
        cell_injected = [row for row in cell_rows if row["metrics"]["injected_failure"]]
        cells[cell] = {
            "starts": len(cell_rows),
            "injected_failures": len(cell_injected),
            "objective_rate": (
                sum(row["metrics"]["objective_met"] for row in cell_injected)
                / len(cell_injected)
                if cell_injected
                else None
            ),
            "direct_safety_violation": any(
                row["metrics"]["unsupported_tuple_served"]
                or not row["metrics"]["predecessor_preserved"]
                or not row["metrics"]["functional_correctness"]
                or not row["metrics"]["evidence_identity_preserved"]
                for row in cell_rows
            ),
            "failed_starts": sum(row["status"] == "failed" for row in cell_rows),
            "cleanup_failures": [
                row["start_id"] for row in cell_rows if not all(row["cleanup"].values())
            ],
        }
    supported = (
        not direct_violation
        and not cleanup_failures
        and objective_rate >= protocol["h3"]["objective_rate_minimum"]
    )
    return {
        "schema": "ecpa-formal-campaign-summary/v1",
        "campaign_id": protocol["h3"]["campaign_id"],
        "status": "supported" if supported else "falsified",
        "formal_result": True,
        "received_starts": len(rows),
        "required_starts": len(rows),
        "missing": [],
        "metrics": {
            "injected_failures": len(injected),
            "objective_rate": objective_rate,
            "direct_safety_violation": direct_violation,
            "failed_starts": sum(row["status"] == "failed" for row in rows),
            "cleanup_failures": cleanup_failures,
            "lost_requests": sum(row["metrics"]["lost_requests"] for row in rows),
            "duplicated_requests": sum(
                row["metrics"]["duplicated_requests"] for row in rows
            ),
            "cells": cells,
        },
    }


def analyze_h4(
    protocol: dict[str, Any],
    records: list[dict[str, Any]],
    artifact_root: Path,
    campaign_spec: dict[str, Any],
) -> dict[str, Any]:
    missing, indexed = _validate_intake(
        protocol, "h4", records, artifact_root, campaign_spec
    )
    definition = protocol["h4"]
    cell = campaign_spec["cell_id"]
    cell_missing = [item for item in missing if item.startswith(f"{cell}/")]
    if not cell_missing:
        cell_rows = [row for row in indexed.values() if row["cell_id"] == cell]
        cell_result = _summarize_h4_cells(
            protocol, indexed, [cell], cell_rows, overall_complete=False
        )
    else:
        cell_result = None
    if missing:
        return {
            "schema": "ecpa-formal-campaign-summary/v1",
            "campaign_id": definition["campaign_id"],
            "status": "incomplete",
            "formal_result": False,
            "received_starts": len(indexed),
            "required_starts": len(definition["required_cells"]) * 9,
            "missing": missing,
            "metrics": None,
            "completed_cells": ({cell: cell_result} if cell_result else {}),
        }
    rows = list(indexed.values())
    failed_starts = [row["start_id"] for row in rows if row["status"] == "failed"]
    cleanup_failures = [
        row["start_id"] for row in rows if not all(row["cleanup"].values())
    ]
    if failed_starts:
        return {
            "schema": "ecpa-formal-campaign-summary/v1",
            "campaign_id": definition["campaign_id"],
            "status": "falsified",
            "formal_result": True,
            "received_starts": len(rows),
            "required_starts": len(rows),
            "missing": [],
            "metrics": None,
            "failed_starts": failed_starts,
            "cleanup_failures": cleanup_failures,
        }

    cells = definition["required_cells"]
    confidence = definition["confidence"]
    startup_ms = _effect(
        indexed,
        cells,
        "ecpa",
        "manual-integration",
        lambda row: row["metrics"]["startup_phases_ms"]["total"],
        "increase",
    )
    startup_absolute_ms = [
        indexed[(cell, repetition, "ecpa")]["metrics"]["startup_phases_ms"]["total"]
        - indexed[(cell, repetition, "manual-integration")]["metrics"][
            "startup_phases_ms"
        ]["total"]
        for cell in cells
        for repetition in range(1, 4)
    ]
    throughput = _effect(
        indexed,
        cells,
        "ecpa",
        "manual-integration",
        lambda row: row["metrics"]["throughput"],
        "regression",
    )
    p99 = _effect(
        indexed,
        cells,
        "ecpa",
        "manual-integration",
        lambda row: row["metrics"]["latency_p99_ms"],
        "increase",
    )

    def summarize(values: list[float]) -> dict[str, Any]:
        return _paired_summary(
            values,
            seed=confidence["seed"],
            resamples=confidence["resamples"],
            level=confidence["level"],
        )

    summaries = {
        "ecpa_vs_manual_startup_percent": summarize(startup_ms),
        "ecpa_vs_manual_startup_absolute_ms": summarize(startup_absolute_ms),
        "ecpa_vs_manual_throughput_regression_percent": summarize(throughput),
        "ecpa_vs_manual_p99_regression_percent": summarize(p99),
    }
    thresholds = definition["thresholds"]
    cell_summaries = {}
    for cell in cells:
        ecpa_startup_percent = _effect(
            indexed,
            [cell],
            "ecpa",
            "manual-integration",
            lambda row: row["metrics"]["startup_phases_ms"]["total"],
            "increase",
        )
        ecpa_startup_absolute = [
            indexed[(cell, repetition, "ecpa")]["metrics"]["startup_phases_ms"]["total"]
            - indexed[(cell, repetition, "manual-integration")]["metrics"][
                "startup_phases_ms"
            ]["total"]
            for repetition in range(1, 4)
        ]
        ecpa_throughput = _effect(
            indexed,
            [cell],
            "ecpa",
            "manual-integration",
            lambda row: row["metrics"]["throughput"],
            "regression",
        )
        ecpa_p99 = _effect(
            indexed,
            [cell],
            "ecpa",
            "manual-integration",
            lambda row: row["metrics"]["latency_p99_ms"],
            "increase",
        )
        vanilla_startup = _effect(
            indexed,
            [cell],
            "vanilla-vllm-entry-points",
            "manual-integration",
            lambda row: row["metrics"]["startup_phases_ms"]["total"],
            "increase",
        )
        vanilla_throughput = _effect(
            indexed,
            [cell],
            "vanilla-vllm-entry-points",
            "manual-integration",
            lambda row: row["metrics"]["throughput"],
            "regression",
        )
        vanilla_p99 = _effect(
            indexed,
            [cell],
            "vanilla-vllm-entry-points",
            "manual-integration",
            lambda row: row["metrics"]["latency_p99_ms"],
            "increase",
        )
        cell_summary = {
            "ecpa_vs_manual_startup_percent": summarize(ecpa_startup_percent),
            "ecpa_vs_manual_startup_absolute_ms": summarize(ecpa_startup_absolute),
            "ecpa_vs_manual_throughput_regression_percent": summarize(ecpa_throughput),
            "ecpa_vs_manual_p99_regression_percent": summarize(ecpa_p99),
            "vanilla_vs_manual_startup_percent": summarize(vanilla_startup),
            "vanilla_vs_manual_throughput_regression_percent": summarize(
                vanilla_throughput
            ),
            "vanilla_vs_manual_p99_regression_percent": summarize(vanilla_p99),
        }
        cell_summary["threshold_violation"] = (
            (
                cell_summary["ecpa_vs_manual_startup_percent"]["median"]
                > thresholds["startup_percent"]
                and cell_summary["ecpa_vs_manual_startup_absolute_ms"]["median"]
                > thresholds["startup_absolute_ms"]
            )
            or (
                cell_summary["ecpa_vs_manual_throughput_regression_percent"]["median"]
                > thresholds["throughput_regression_percent"]
            )
            or (
                cell_summary["ecpa_vs_manual_p99_regression_percent"]["median"]
                > thresholds["latency_p99_regression_percent"]
            )
        )
        cell_summaries[cell] = cell_summary
    supported = (
        not any(row["threshold_violation"] for row in cell_summaries.values())
        and not cleanup_failures
    )
    return {
        "schema": "ecpa-formal-campaign-summary/v1",
        "campaign_id": definition["campaign_id"],
        "status": "supported" if supported else "falsified",
        "formal_result": True,
        "received_starts": len(rows),
        "required_starts": len(rows),
        "missing": [],
        "manual_baseline": "manual-integration",
        "vanilla_reported_separately": True,
        "failed_starts": [],
        "cleanup_failures": cleanup_failures,
        "metrics": {"overall": summaries, "cells": cell_summaries},
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--campaign", choices=("h3", "h4"), required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    parser.add_argument("--campaign-spec", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    protocol = load_protocol()
    records = load_records(args.records)
    if args.campaign == "h3":
        summary = analyze_h3(protocol, records, args.artifact_root)
    else:
        if args.campaign_spec is None:
            parser.error("--campaign-spec is required for H4")
        summary = analyze_h4(
            protocol, records, args.artifact_root, load_h4_campaign(args.campaign_spec)
        )
    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
