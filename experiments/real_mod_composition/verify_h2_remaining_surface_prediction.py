#!/usr/bin/env python3
"""Verify the post-oracle Manager prediction for the remaining H2 surfaces."""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import asdict
from pathlib import Path

from vllm_hust_ext.config import ExtensionConfig
from vllm_hust_ext.core import plan_dict, plan_for
from vllm_hust_ext.discovery import InstalledBundle
from vllm_hust_ext.manifest import load_manifest
from vllm_hust_ext.providers.production_stack import ProductionStackProvider

_CHECKOUT = Path(__file__).resolve().parents[2]
if (_CHECKOUT / "BENCHMARK_ORIGINALS.json").is_file():
    sys.path.insert(0, str(_CHECKOUT))
    from scripts.benchmark_inputs import resolve_original
else:

    def resolve_original(path: Path) -> Path:
        return path


ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = (
    ROOT
    / "experiments/real_mod_composition/artifacts/h2-remaining-surfaces-oracle-20261013"
)
ORACLE = ARTIFACT / "oracle.json"
RECEIPT = ARTIFACT / "review-receipt.json"
PREDICTION = ARTIFACT / "manager-prediction.json"
MANAGER_BASE = "0884e3568d0b674f5e135f858e8e7f8016d2aa97"
ORACLE_COMMIT = "dfc533d33582f80fae0ee172e17aa47406d98e48"


def sha256(path: Path) -> str:
    return hashlib.sha256(resolve_original(path).read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def main() -> int:
    receipt = json.loads(resolve_original(RECEIPT).read_text(encoding="utf-8"))
    prediction = json.loads(resolve_original(PREDICTION).read_text(encoding="utf-8"))
    require(receipt["oracle_sha256"] == sha256(ORACLE), "oracle digest")
    require(
        prediction["oracle"]
        == {
            "frozen_commit": ORACLE_COMMIT,
            "sha256": sha256(ORACLE),
            "receipt_sha256": sha256(RECEIPT),
            "frozen_before_prediction": True,
        },
        "prediction oracle binding",
    )
    require(prediction["manager"]["base_commit"] == MANAGER_BASE, "Manager base")
    provider_source = ROOT / prediction["manager"]["provider_source"]
    require(resolve_original(provider_source).is_file(), "Manager provider source")
    require(
        sha256(provider_source) == prediction["manager"]["provider_source_sha256"],
        "Manager provider source digest",
    )

    manifest_path = ARTIFACT / "snapshots/production-stack-provider-manifest.json"
    manifest = load_manifest(resolve_original(manifest_path))
    bundle = InstalledBundle(
        manifest.bundle_id,
        "frozen-source:vLLM-HUST/extension-manager",
        manifest.bundle_version,
        manifest_path,
        manifest,
        (),
    )
    config = prediction["configuration"]
    replay_plan = plan_dict(plan_for(bundle, ExtensionConfig(True, config)))
    replay_check = asdict(ProductionStackProvider().check(manifest, config))
    normalized_plan = json.loads(json.dumps(replay_plan))
    normalized_check = json.loads(json.dumps(replay_check))
    require(normalized_plan == prediction["plan"], "Manager plan replay")
    require(
        normalized_check == prediction["provider_check"],
        "Manager provider check replay",
    )
    require(prediction["prediction"] == "reject", "Manager decision")
    require(prediction["oracle_decision"] == "reject", "oracle decision")
    require(prediction["decision_match"] is True, "decision match")
    require(prediction["score_eligible"] is True, "score eligibility")
    require(
        prediction["aggregate_definite_subset"]
        == {
            "case_count": 4,
            "true_positive": 1,
            "true_negative": 3,
            "false_positive": 0,
            "false_negative": 0,
            "admit_precision": 1.0,
            "admit_recall": 1.0,
            "reject_precision": 1.0,
            "reject_recall": 1.0,
        },
        "aggregate score",
    )
    require(
        prediction["process_boundary"]["host_process_started"] is False,
        "no host launch",
    )
    require(prediction["h2_complete"] is False, "H2 remains open")
    print(f"PASS prediction=reject case_count=4 sha256={sha256(PREDICTION)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
