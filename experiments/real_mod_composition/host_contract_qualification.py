#!/usr/bin/env python3
"""Validate the non-serving profiler/KVCompress Host contract qualification."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft7Validator

HERE = Path(__file__).resolve().parent
ARTIFACT_PATH = (
    HERE / "artifacts/lifecycle-profiler-kvcompress-host-contract-20261013.json"
)
SCHEMA_PATH = HERE / "host-contract-qualification.schema.json"
ARTIFACT_SHA256 = "60af5fc2fab4dd68354da0c7b00ad810399c275195795e6b9f3fc726aab0f783"


def load_qualification(path: Path = ARTIFACT_PATH) -> dict[str, Any]:
    raw = path.read_bytes()
    if path == ARTIFACT_PATH and hashlib.sha256(raw).hexdigest() != ARTIFACT_SHA256:
        raise ValueError("checked Host contract qualification bytes drifted")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("Host contract qualification must be a JSON object")
    qualification = cast(dict[str, Any], value)
    Draft7Validator(json.loads(SCHEMA_PATH.read_text())).validate(qualification)
    validate_qualification(qualification)
    return qualification


def validate_qualification(value: dict[str, Any]) -> None:
    boundary = value["qualification"]
    if (
        value["schema"] != "ecpa-h2-host-contract-qualification/v1"
        or value["classification"]
        != "real-host-process-contract-probe-not-model-serving-or-runtime-effectiveness"
        or boundary["actual_model_started"] is not False
        or boundary["actual_workload_completed"] is not False
        or boundary["runtime_effective"] != "unmeasured"
        or boundary["performance_benefit"] != "unmeasured"
        or boundary["h2_oracle_label"] is not None
        or boundary["score_eligible"] is not False
    ):
        raise ValueError("Host contract probe was promoted beyond its evidence")

    host = value["host"]
    members = value["members"]
    if (
        host["vllm_commit"]
        != "973d9ef5acd2b9beb03e399dec1511a41fc941b5"
        or host["vllm_ascend_commit"] != "873584026"
        or members["lifecycle_profiler"]["source_commit"]
        != "88ffdce5fc6639c0b7b86a54d197f7394705c54b"
        or members["lifecycle_profiler"]["manifest_host_range"]
        != ">=0.31.1,<0.32"
        or members["kvcompress"]["source_commit"]
        != "00cc78dc7f3491eecbc79c5068e29aed9f59afc3"
    ):
        raise ValueError("Host contract probe source or Host pins drifted")

    orders = value["orders"]
    expected = {
        "profiler-then-kvcompress": (
            ["lifecycle_profiler", "kvcompress"],
            ["request_lifecycle_profiler", "ascend_kvcompress"],
        ),
        "kvcompress-then-profiler": (
            ["kvcompress", "lifecycle_profiler"],
            ["ascend_kvcompress", "request_lifecycle_profiler"],
        ),
    }
    if len(orders) != 2 or {row["order_id"] for row in orders} != set(expected):
        raise ValueError("both isolated Host contract orders are required")
    for row in orders:
        install, entry_points = expected[row["order_id"]]
        if (
            row["install_order"] != install
            or row["entry_point_call_order"] != entry_points
            or row["process_exit_code"] != 0
            or row["scheduler_patched"] is not True
            or row["kv_manager_patched"] is not True
            or row["event_bus_enabled_after_registration"] is not True
            or row["event_bus_enabled_after_profiler_close"] is not False
            or row["event_snapshot"]
            != {
                "event_count": 1,
                "finished_count": 1,
                "preempted_count": 0,
                "reclaimed_count": 0,
            }
        ):
            raise ValueError(f"Host contract order did not pass: {row['order_id']}")

    preflight = value["manager_preflight"]
    if (
        preflight["classification"]
        != "planning-and-launch-environment-only-not-host-execution"
        or preflight["both_discovered"] is not True
        or preflight["both_enabled"] is not True
        or preflight["lifecycle_profiler_activation_ready"] is not True
        or preflight["kvcompress_activation_ready"] is not True
        or set(preflight["combined_vllm_plugins"])
        != {"ascend", "ascend_kvcompress", "request_lifecycle_profiler"}
    ):
        raise ValueError("Manager preflight is incomplete or overclassified")


if __name__ == "__main__":
    print(json.dumps(load_qualification(), indent=2, sort_keys=True))
