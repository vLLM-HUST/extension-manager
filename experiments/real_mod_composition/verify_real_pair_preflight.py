  昇腾卡 2 张（规格 npu-2x）。npu-smi info 看状态；
  容器里只看得见分给你的那几张，看不到整机——这是正常的。
#!/usr/bin/env python3
"""Fail-closed verification for the retained real TP2 pair preflight."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft7Validator, FormatChecker

HERE = Path(__file__).resolve().parent
ARTIFACT = HERE / "artifacts" / "h2-real-pair-tp2-preflight-20261013.json"
SCHEMA = HERE / "real-pair-preflight.schema.json"
ARTIFACT_SHA256 = "0b6d2db298374aadf478592326d01c10719c496363436dfc61f5d8e823dd4883"
EXPECTED_ORDERS = {"profiler-then-kvcompress", "kvcompress-then-profiler"}
REQUIRED_NONCLAIMS = {
    "compression transaction occurred",
    "H2 independent correctness/ownership oracle",
    "matched control/candidate repetitions",
    "latency or throughput benefit",
    "formal H2 result",
    "H3 or H4 result",
}
REQUIRED_FAILED_REASONS = {
    "model path and model_source_fingerprint mismatch",
    "model_source_fingerprint mismatch",
    "accelerate missing; no artifact produced",
}


def load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return cast(dict[str, Any], value)


def validate_payload(payload: dict[str, Any]) -> None:
    schema = load_object(SCHEMA)
    errors = sorted(
        Draft7Validator(schema, format_checker=FormatChecker()).iter_errors(payload),
        key=lambda error: list(error.absolute_path),
    )
    if errors:
        first = errors[0]
        location = ".".join(str(part) for part in first.absolute_path) or "<root>"
        raise ValueError(f"schema validation failed at {location}: {first.message}")

    orders = payload["orders"]
    if {order["order"] for order in orders} != EXPECTED_ORDERS:
        raise ValueError("exactly both installation orders are required")
    if len({order["order"] for order in orders}) != len(orders):
        raise ValueError("duplicate installation order")
    if payload["hardware"]["tensor_parallel_size"] != len(
        payload["hardware"]["allocated_physical_devices"]
    ):
        raise ValueError("TP size must equal the number of allocated devices")

    not_established = set(payload["scientific_boundary"]["not_established"])
    missing = REQUIRED_NONCLAIMS - not_established
    if missing:
        raise ValueError(f"required non-claims missing: {sorted(missing)}")
    established = set(payload["scientific_boundary"]["established"])
    if established & REQUIRED_NONCLAIMS:
        raise ValueError("a required non-claim was promoted to established")

    failed = payload["retained_failed_attempts"]
    reasons = {attempt["reason"] for attempt in failed}
    if not reasons >= REQUIRED_FAILED_REASONS:
        raise ValueError("failed-attempt ledger is incomplete")
    for attempt in failed:
        if "cleanup_proven" in attempt and attempt["cleanup_proven"] is not True:
            raise ValueError("a claimed failed-attempt cleanup is not proven")


def verify(path: Path = ARTIFACT, *, require_canonical_bytes: bool = True) -> None:
    data = path.read_bytes()
    if require_canonical_bytes:
        observed = hashlib.sha256(data).hexdigest()
        if observed != ARTIFACT_SHA256:
            raise ValueError(
                f"artifact digest mismatch: expected {ARTIFACT_SHA256}, got {observed}"
            )
    validate_payload(cast(dict[str, Any], json.loads(data)))


if __name__ == "__main__":
    verify()
    print(
        json.dumps(
            {
                "artifact_sha256": ARTIFACT_SHA256,
                "formal_h2_result": False,
                "performance_result": False,
                "score_eligible": False,
                "status": "VALID_ACTIVATION_PREFLIGHT",
            },
            sort_keys=True,
        )
    )
