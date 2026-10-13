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
    for label, binding in record["artifacts"].items():
        path = (root / binding["path"]).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError(
                f"{record['start_id']} {label} is outside artifact root or missing"
            )
        actual = "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != binding["sha256"]:
            raise ValueError(f"{record['start_id']} {label} digest differs")


def _validate_intake(
    protocol: dict[str, Any],
    campaign: str,
    records: list[dict[str, Any]],
    artifact_root: Path,
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
) -> dict[str, Any]:
    missing, indexed = _validate_intake(protocol, "h4", records, artifact_root)
    definition = protocol["h4"]
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
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    protocol = load_protocol()
    records = load_records(args.records)
    analyzer = analyze_h3 if args.campaign == "h3" else analyze_h4
    summary = analyzer(protocol, records, args.artifact_root)
    rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered)
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
