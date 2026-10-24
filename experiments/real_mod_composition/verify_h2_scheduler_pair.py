#!/usr/bin/env python3
"""Verify the frozen H2 scheduler-pair oracle and later Manager prediction."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

from vllm_hust_ext.manifest import load_manifest

ROOT = Path(__file__).resolve().parent
ARTIFACT = ROOT / "artifacts/h2-pipeline-bidkv-oracle-20261013"
CAMPAIGN_SHA256 = (
    "sha256:a0c36781ee9776935f673e4d5904ec3dc03ffe6401971227b35b3904438eb7a5"
)
ORACLE_SHA256 = (
    "sha256:9ba8f59096de7ecc8864a67a25f27cd5a41cf8f4f182636410f1a2e3ac410a45"
)


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def main() -> int:
    artifact = ARTIFACT
    # The copied portable verifier keeps caller-owned fixtures. In the source
    # checkout, use hash-checked external originals, never an in-tree fallback.
    repo = ROOT.parent.parent
    if (repo / "BENCHMARK_ORIGINALS.json").is_file():
        sys.path.insert(0, str(repo))
        from scripts.benchmark_inputs import resolve_original

        artifact = resolve_original(artifact)
    campaign = json.loads((artifact / "campaign.json").read_text())
    oracle = json.loads((artifact / "oracle.json").read_text())
    freeze = json.loads((artifact / "oracle-freeze-receipt.json").read_text())
    prediction = json.loads((artifact / "manager-prediction.json").read_text())

    require(digest(artifact / "campaign.json") == CAMPAIGN_SHA256, "campaign digest")
    require(digest(artifact / "oracle.json") == ORACLE_SHA256, "oracle digest")
    require(freeze["campaign_sha256"] == CAMPAIGN_SHA256, "freeze campaign")
    require(freeze["oracle_sha256"] == ORACLE_SHA256, "freeze oracle")
    require(not freeze["manager_prediction_present_at_freeze"], "oracle ordering")
    for name, expected in freeze["snapshot_sha256"].items():
        require(digest(artifact / "snapshots" / name) == expected, f"snapshot {name}")

    manifests = {
        member["id"]: load_manifest(
            artifact
            / "snapshots"
            / Path(campaign["sources"][member["manifest_source"]]["snapshot"]).name
        )
        for member in campaign["members"]
    }
    pipeline = manifests["pipeline_microbatch"]
    bidkv = manifests["bidkv"]
    require(
        any(
            dict(item.attributes).get("status") == "active"
            for item in pipeline.implementation
        ),
        "Pipeline carrier",
    )
    require(
        any(
            dict(item.attributes).get("status") == "active"
            for item in bidkv.implementation
        ),
        "BidKV carrier",
    )
    require(not pipeline.requires_services and not bidkv.requires_services, "services")

    host_batch = (artifact / "snapshots/host-batch-admission.py.snapshot").read_text()
    host_preempt = (artifact / "snapshots/host-preemption.py.snapshot").read_text()
    host_config = (artifact / "snapshots/host-scheduler-config.py.snapshot").read_text()
    require('BATCH_ADMISSION_POLICY_API_VERSION = "1.1"' in host_batch, "batch API")
    require('PREEMPTION_POLICY_API_VERSION = "1.0"' in host_preempt, "preempt API")
    require("batch_admission_policy:" in host_config, "batch config")
    require("preemption_policy:" in host_config, "preempt config")

    require(oracle["decision"] == "admit" and oracle["score_eligible"], "oracle")
    require(prediction["campaign_sha256"] == CAMPAIGN_SHA256, "prediction campaign")
    require(prediction["oracle_sha256"] == ORACLE_SHA256, "prediction oracle")
    require(prediction["manager"]["source_unchanged_from_base"], "Manager base")
    require(prediction["prediction"] == "admit", "Manager prediction")
    require(prediction["matched"] and prediction["score_eligible"], "matched score")
    require(prediction["composition_error"] is None, "composition")
    require(
        prediction["projected_options"]
        == {
            "org.vllm-hust.pipeline-microbatch": {
                "--batch-admission-policy": (
                    "vllm_hust_pipeline_microbatch.policy.PipelineMicrobatchPolicy"
                )
            },
            "org.vllm-hust.bidkv": {
                "--preemption-policy": (
                    "bidkv.adapters.vllm_hust.selector.BidkvPreemptionPolicy"
                )
            },
        },
        "projected options",
    )
    boundary = prediction["process_boundary"]
    require(boundary["npu_before"]["allocated_devices_empty"], "NPU before")
    require(boundary["npu_after"]["allocated_devices_empty"], "NPU after")
    require(not boundary["host_process_started"], "host process boundary")
    require(not prediction["runtime"]["host_launch_command_invoked"], "host launch")
    require(not prediction["runtime"]["claim"], "runtime claim")
    require(not prediction["performance_claim"], "performance claim")
    require(
        prediction["corpus_update"]["current"]
        == {
            "case_count": 5,
            "true_positive": 2,
            "true_negative": 3,
            "false_positive": 0,
            "false_negative": 0,
            "admit_precision": 1.0,
            "admit_recall": 1.0,
        },
        "n=5 aggregate",
    )
    require(not prediction["corpus_update"]["h2_complete"], "H2 remains incomplete")
    print("PASS: frozen scheduler-pair oracle precedes matching Manager admit")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
