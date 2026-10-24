#!/usr/bin/env python3
"""Verify post-oracle Manager predictions for two carrier cases."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

_CHECKOUT = Path(__file__).resolve().parents[2]
if (_CHECKOUT / "BENCHMARK_ORIGINALS.json").is_file():
    sys.path.insert(0, str(_CHECKOUT))
    from scripts.benchmark_inputs import resolve_original
else:

    def resolve_original(path: Path) -> Path:
        return path


ROOT = Path(__file__).resolve().parents[2]
EXPERIMENT = ROOT / "experiments/real_mod_composition"
ARTIFACT = EXPERIMENT / "artifacts/h2-process-carrier-oracle-20261013"
ORACLE = ARTIFACT / "oracle.json"
RECEIPT = ARTIFACT / "review-receipt.json"
PREDICTIONS = ARTIFACT / "manager-predictions.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(resolve_original(path).read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def main() -> int:
    oracle = json.loads(resolve_original(ORACLE).read_text(encoding="utf-8"))
    receipt = json.loads(resolve_original(RECEIPT).read_text(encoding="utf-8"))
    predictions = json.loads(resolve_original(PREDICTIONS).read_text(encoding="utf-8"))
    require(predictions["oracle"]["sha256"] == sha256(ORACLE), "oracle digest")
    require(
        predictions["oracle"]["receipt_sha256"] == sha256(RECEIPT),
        "receipt digest",
    )
    require(
        receipt["isolation"]["planner_seen_or_run_before_oracle_freeze"] is False,
        "oracle/planner isolation",
    )
    expected = {case["case_id"]: case["decision"] for case in oracle["cases"]}
    actual = {
        item["case_id"]: item["oracle_decision"] for item in predictions["predictions"]
    }
    require(actual == expected, "case/oracle binding")
    require(
        all(
            item["oracle_decision"] == "abstain"
            and not item["score_eligible"]
            and item["host_launch_command_invoked"] is False
            and item["runtime_claim"] is False
            and item["performance_claim"] is False
            for item in predictions["predictions"]
        ),
        "unscored pre-launch boundaries",
    )
    require(
        predictions["scoring"]["new_score_eligible_cases"] == 0
        and predictions["scoring"]["r2_definite_subset_size_after_update"] == 3
        and predictions["scoring"]["r2_observed_metrics_changed"] is False,
        "scoring boundary",
    )
    require(
        predictions["process_boundary"]["host_process_started"] is False,
        "host process boundary",
    )
    print(f"PASS cases=2 scored=0 prediction_sha256={sha256(PREDICTIONS)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
