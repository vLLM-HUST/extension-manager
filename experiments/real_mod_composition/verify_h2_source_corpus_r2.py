#!/usr/bin/env python3
"""Verify H2 successor-corpus evidence ordering, labels, and metrics."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent
ARTIFACTS = ROOT / "artifacts"
R2 = ARTIFACTS / "h2-minimal-real-source-corpus-r2-20261013"
V1 = ARTIFACTS / "h2-minimal-real-source-corpus-20261013"
PREDICTIONS = ARTIFACTS / "h2-source-corpus-manager-predictions-20261013.json"
REJECT = ARTIFACTS / "h2-knorm-prelaunch-reject-20261013.json"
CURRENT = ARTIFACTS / "h2-profiler-kvcompress-formal-r2-20261013"
AUGMENTATION = ARTIFACTS / "h2-real-source-augmentation-20261013/augmentation.json"


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def git_blob_id(value: bytes) -> str:
    header = f"blob {len(value)}\0".encode()
    return hashlib.sha1(header + value).hexdigest()  # noqa: S324


def main() -> int:
    campaign = read(R2 / "campaign.json")
    oracle_index = read(R2 / "oracle-index.json")
    status = read(R2 / "status.json")
    predictions = read(PREDICTIONS)
    reject = read(REJECT)
    current_campaign = read(CURRENT / "campaign.json")
    current_oracle = read(CURRENT / "oracle.json")
    current_oracle_receipt = read(CURRENT / "oracle-receipt.json")
    current_planner = read(CURRENT / "planner/planner-receipt.json")
    current_score = read(CURRENT / "score-admission.json")

    assert campaign["schema"] == "ecpa-h2-minimal-real-source-corpus/v2"
    assert campaign["predecessor"] == {
        "campaign_sha256": digest(V1 / "campaign.json"),
        "oracle_sha256": digest(V1 / "oracle.json"),
        "prediction_artifact_sha256": digest(PREDICTIONS),
    }
    assert campaign["evidence_ordering"] == {
        "current_pair_oracle_frozen_before_manager_prediction_and_formal_launch": True,
        "labels_reassigned_after_predictions": False,
        "old_five_case_oracle_frozen_before_remaining_manager_predictions": True,
        "successor_index_created_after_underlying_evidence": True,
    }
    assert campaign["scoring_policy"]["positive_class"] == "admit"
    assert oracle_index["campaign_sha256"] == digest(R2 / "campaign.json")
    assert status["campaign_sha256"] == digest(R2 / "campaign.json")
    assert status["oracle_index_sha256"] == digest(R2 / "oracle-index.json")

    cases = {case["case_id"]: case for case in campaign["cases"]}
    assert len(cases) == len(campaign["cases"]) == 6
    assert (
        cases["pair-profiler-kvcompress-vllm-0233"]["prediction"]["decision"]
        == "unavailable"
    )
    assert cases["pair-profiler-kvcompress-vllm-0233"]["score_eligible"] is False
    assert (
        cases["pair-diffspec-kvcompress-ascend-0251"]["prediction"]["decision"]
        == "excluded"
    )
    assert cases["pair-diffspec-kvcompress-ascend-0251"]["score_eligible"] is False
    assert cases["single-bidkv-vllm-0281"]["score_eligible"] is False

    # Every manifest is portable, byte-bound, schema-bound, and Git-blob-bound.
    for case in cases.values():
        for member in case["members"]:
            assert not Path(member["snapshot_path"]).is_absolute()
            snapshot = REPO / member["snapshot_path"]
            raw = snapshot.read_bytes()
            assert digest(snapshot) == member["manifest_sha256"]
            assert git_blob_id(raw) == member["manifest_blob"]
            assert json.loads(raw)["schema_version"] == member["manifest_schema"]

    current = cases["kvcompress-lifecycle-profiler-host031-tp2"]
    assert current["oracle_decision"] == "admit"
    assert current["prediction"]["decision"] == "admit"
    assert current["score_eligible"] is True
    assert current["evidence_binding"] == {
        "campaign_sha256": digest(CURRENT / "campaign.json"),
        "oracle_sha256": digest(CURRENT / "oracle.json"),
        "oracle_receipt_sha256": digest(CURRENT / "oracle-receipt.json"),
        "planner_receipt_sha256": digest(CURRENT / "planner/planner-receipt.json"),
        "score_admission_sha256": digest(CURRENT / "score-admission.json"),
        "oracle_frozen_before_planner": True,
    }
    assert current_oracle["verdict"] == "admit"
    assert (
        current_oracle["independence"]["excluded"][0]
        == "Manager planner output or score"
    )
    assert current_oracle_receipt["campaign_sha256"] == digest(
        CURRENT / "campaign.json"
    ).removeprefix("sha256:")
    assert current_planner["campaign_sha256"] == digest(CURRENT / "campaign.json")
    assert current_planner["planner_decision"] == "admit"
    assert current_planner["all_exit_zero"] is True
    assert (
        current_score["oracle_decision"] == current_score["planner_decision"] == "admit"
    )
    assert current_score["status"] == "ADMITTED"
    assert current_score["score_eligible"] is True
    assert current_score["scope"] == {
        "compatible_host_execution": True,
        "compression_transaction": False,
        "performance": False,
    }
    assert current_campaign["formal_runs"] == []

    old = {item["case_id"]: item["result"] for item in predictions["predictions"]}
    assert old["three-vspec-knorm-profiler-vllm-0233"]["prediction"] == "reject"
    assert old["three-vspec-knorm-profiler-vllm-0233"]["score_eligible"] is True
    assert (
        reject["summary"]["manager_decision"]
        == reject["summary"]["oracle_decision"]
        == "reject"
    )
    assert reject["formal_admission"]["status"] == "ADMITTED"
    assert reject["formal_admission"]["score_eligible"] is True

    scored = [case for case in cases.values() if case["score_eligible"]]
    observed = {
        "true_positive": sum(
            case["oracle_decision"] == case["prediction"]["decision"] == "admit"
            for case in scored
        ),
        "true_negative": sum(
            case["oracle_decision"] == case["prediction"]["decision"] == "reject"
            for case in scored
        ),
        "false_positive": sum(
            case["oracle_decision"] == "reject"
            and case["prediction"]["decision"] == "admit"
            for case in scored
        ),
        "false_negative": sum(
            case["oracle_decision"] == "admit"
            and case["prediction"]["decision"] == "reject"
            for case in scored
        ),
    }
    assert status["confusion_matrix"] == {
        "positive_class": "admit",
        **observed,
        "case_count": 3,
    }
    assert observed == {
        "true_positive": 1,
        "true_negative": 2,
        "false_positive": 0,
        "false_negative": 0,
    }
    assert status["metrics"] == {
        "accuracy": 1.0,
        "admit_precision": 1.0,
        "admit_recall": 1.0,
        "reject_precision": 1.0,
        "reject_recall": 1.0,
        "threshold": 0.95,
        "threshold_met": True,
    }
    assert status["blanket_reject_baseline"]["passes"] is False
    assert status["surface_augmentation"] == {
        "path": str(AUGMENTATION.relative_to(REPO)),
        "sha256": digest(AUGMENTATION),
        "frozen_source_manifests": 8,
        "preexisting_oracle_cases": 2,
        "oracle_pending_cases": 4,
    }
    assert status["acceptance"]["paper_demotes_synthetic_seed"] is False
    assert (
        status["acceptance"]["requested_population_surface_coverage_complete"] is False
    )
    assert status["h2_acceptance_complete"] is False
    print(digest(R2 / "status.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
