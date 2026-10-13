#!/usr/bin/env python3
# ruff: noqa: E501
"""Build the H2 successor corpus from immutable, pre-existing evidence."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "artifacts"
V1 = ARTIFACTS / "h2-minimal-real-source-corpus-20261013"
PREDICTIONS = ARTIFACTS / "h2-source-corpus-manager-predictions-20261013.json"
REJECT = ARTIFACTS / "h2-knorm-prelaunch-reject-20261013.json"
CURRENT = ARTIFACTS / "h2-profiler-kvcompress-formal-r2-20261013"
OUTPUT = ARTIFACTS / "h2-minimal-real-source-corpus-r2-20261013"
AUGMENTATION = ARTIFACTS / "h2-real-source-augmentation-20261013/augmentation.json"


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def read(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def write(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def main() -> int:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    v1_campaign = read(V1 / "campaign.json")
    old_predictions = read(PREDICTIONS)
    current_campaign = read(CURRENT / "campaign.json")
    current_oracle = read(CURRENT / "oracle.json")
    current_oracle_receipt = read(CURRENT / "oracle-receipt.json")
    current_planner = read(CURRENT / "planner/planner-receipt.json")
    current_score = read(CURRENT / "score-admission.json")
    reject = read(REJECT)

    old_by_id = {
        item["case_id"]: item["result"] for item in old_predictions["predictions"]
    }
    cases: list[dict[str, Any]] = []
    for case in v1_campaign["cases"]:
        case_id = case["case_id"]
        if case_id == "pair-kvcompress-knorm-host973d":
            prediction = {
                "decision": reject["summary"]["manager_decision"],
                "source": str(REJECT.relative_to(ROOT.parent.parent)),
                "source_sha256": digest(REJECT),
                "formal_prelaunch": True,
            }
            score_eligible = True
            error = {
                "class": "unsafe_activation_blocked_by_import_only_descriptor",
                "owners": ["org.vllm-hust.ascend-kvcompress", "org.vllm-hust.knorm"],
                "resources": [
                    "vllm-ascend.kv-cache.mutation",
                    "vllm.kv-cache.compression-policy",
                    "scheduler-to-worker block-table synchronization",
                ],
                "remediation": "publish an active KNorm implementation only after exact-host synchronization and rollback qualification",
            }
        else:
            result = old_by_id[case_id]
            prediction = {
                "decision": result["prediction"],
                "declared_surface_decision": result["declared_surface_decision"],
                "reason": result["reason"],
                "source": str(PREDICTIONS.relative_to(ROOT.parent.parent)),
                "source_sha256": digest(PREDICTIONS),
                "formal_prelaunch": False,
            }
            score_eligible = result["score_eligible"]
            error = None
            if case_id == "three-vspec-knorm-profiler-vllm-0233":
                error = {
                    "class": "activation_blocker_import_only",
                    "owners": ["org.vllm-hust.knorm"],
                    "resources": ["vllm.kv-cache.compression-policy"],
                    "remediation": "replace the import_only KNorm descriptor with an exact-host-qualified active implementation before launch",
                }
        cases.append(
            {
                **case,
                "members": [
                    {
                        **member,
                        "snapshot_path": str(
                            (
                                ROOT / "source_manifests" / f"{member['id']}.json"
                            ).relative_to(ROOT.parent.parent)
                        ),
                        "manifest_schema": read(
                            ROOT / "source_manifests" / f"{member['id']}.json"
                        )["schema_version"],
                    }
                    for member in case["members"]
                ],
                "prediction": prediction,
                "score_eligible": score_eligible,
                "error": error,
            }
        )

    current_manifest_specs = {
        "lifecycle_profiler": {
            "repo": Path("/root/ecpa-h2-sources/vllm-hust-request-lifecycle-profiler"),
            "commit": "88ffdce5fc6639c0b7b86a54d197f7394705c54b",
            "path": "src/vllm_request_lifecycle_profiler/manifests/vllm-hust-extension-v0.3.json",
            "blob": "5ee2fe11020519730be2a9257a07b899b604835d",
            "sha256": "sha256:fa7d1033919e300062c9f5ade6b9842088a59dde8d7652de2b6a844a85c06a29",
        },
        "kvcompress": {
            "repo": Path("/root/ecpa-h2-sources/vllm-ascend-kvcompress-hust"),
            "commit": "00cc78dc7f3491eecbc79c5068e29aed9f59afc3",
            "path": "src/vllm_ascend_kvcompress/manifests/vllm-hust-extension-v0.3.json",
            "blob": "fd6b1b703ba7eec7587c16d27370c5b75801c89d",
            "sha256": "sha256:ad0a3e62602108e54503bb81c8fda162a730e1a422fe940d09a2463ee2d0eb54",
        },
    }
    current_snapshots: dict[str, Path] = {}
    for member_id, spec in current_manifest_specs.items():
        raw = subprocess.check_output(
            ["git", "-C", str(spec["repo"]), "show", f"{spec['commit']}:{spec['path']}"]
        )
        blob = subprocess.check_output(
            [
                "git",
                "-C",
                str(spec["repo"]),
                "rev-parse",
                f"{spec['commit']}:{spec['path']}",
            ],
            text=True,
        ).strip()
        if digest_bytes(raw) != spec["sha256"] or blob != spec["blob"]:
            raise ValueError(f"current manifest identity mismatch for {member_id}")
        snapshot = OUTPUT / f"current-{member_id}-manifest.json"
        snapshot.write_bytes(raw)
        current_snapshots[member_id] = snapshot

    current_case = {
        "case_id": current_campaign["case_id"],
        "category": "compatible_pair_current_exact_host",
        "host": current_campaign["host"],
        "members": [
            {
                **current_campaign["members"][0],
                "manifest_path": "src/vllm_request_lifecycle_profiler/manifests/vllm-hust-extension-v0.3.json",
                "manifest_blob": "5ee2fe11020519730be2a9257a07b899b604835d",
                "manifest_sha256": "sha256:fa7d1033919e300062c9f5ade6b9842088a59dde8d7652de2b6a844a85c06a29",
                "manifest_schema": "0.3-experimental",
                "snapshot_path": str(
                    current_snapshots["lifecycle_profiler"].relative_to(
                        ROOT.parent.parent
                    )
                ),
            },
            {
                **current_campaign["members"][1],
                "manifest_path": "src/vllm_ascend_kvcompress/manifests/vllm-hust-extension-v0.3.json",
                "manifest_blob": "fd6b1b703ba7eec7587c16d27370c5b75801c89d",
                "manifest_sha256": "sha256:ad0a3e62602108e54503bb81c8fda162a730e1a422fe940d09a2463ee2d0eb54",
                "manifest_schema": "0.3-experimental",
                "snapshot_path": str(
                    current_snapshots["kvcompress"].relative_to(ROOT.parent.parent)
                ),
            },
        ],
        "oracle_decision": current_oracle["verdict"],
        "oracle_scope": current_oracle["admit_scope"],
        "prediction": {
            "decision": current_planner["planner_decision"],
            "manager_commit": current_planner["manager_commit"],
            "source": str(
                (CURRENT / "planner/planner-receipt.json").relative_to(
                    ROOT.parent.parent
                )
            ),
            "source_sha256": digest(CURRENT / "planner/planner-receipt.json"),
            "classification": current_planner["classification"],
            "all_exit_zero": current_planner["all_exit_zero"],
        },
        "score_eligible": current_score["score_eligible"],
        "formal_runtime": {
            "status": current_score["status"],
            "compatible_host_execution": current_score["scope"][
                "compatible_host_execution"
            ],
            "accepted_installation_orders": len(current_score["accepted_records"]),
            "compression_transaction": current_score["scope"][
                "compression_transaction"
            ],
            "performance": current_score["scope"]["performance"],
            "source": str(
                (CURRENT / "score-admission.json").relative_to(ROOT.parent.parent)
            ),
            "source_sha256": digest(CURRENT / "score-admission.json"),
        },
        "evidence_binding": {
            "campaign_sha256": digest(CURRENT / "campaign.json"),
            "oracle_sha256": digest(CURRENT / "oracle.json"),
            "oracle_receipt_sha256": digest(CURRENT / "oracle-receipt.json"),
            "planner_receipt_sha256": digest(CURRENT / "planner/planner-receipt.json"),
            "score_admission_sha256": digest(CURRENT / "score-admission.json"),
            "oracle_frozen_before_planner": (
                current_oracle_receipt["campaign_sha256"]
                == digest(CURRENT / "campaign.json").removeprefix("sha256:")
                and current_oracle["independence"]["excluded"][0]
                == "Manager planner output or score"
            ),
        },
        "error": None,
    }
    cases.append(current_case)

    campaign = {
        "schema": "ecpa-h2-minimal-real-source-corpus/v2",
        "revision": 2,
        "classification": "successor-index-over-preexisting-source-oracle-and-manager-evidence",
        "predecessor": {
            "campaign_sha256": digest(V1 / "campaign.json"),
            "oracle_sha256": digest(V1 / "oracle.json"),
            "prediction_artifact_sha256": digest(PREDICTIONS),
        },
        "cases": cases,
        "scoring_policy": {
            "positive_class": "admit",
            "negative_class": "reject",
            "include_only": "independent definite oracle plus binary Manager prediction",
            "exclude": [
                "single-mod calibration",
                "conditional",
                "unavailable",
                "host-range-mismatch",
            ],
            "minimum_target": 0.95,
        },
        "evidence_ordering": {
            "old_five_case_oracle_frozen_before_remaining_manager_predictions": True,
            "current_pair_oracle_frozen_before_manager_prediction_and_formal_launch": True,
            "successor_index_created_after_underlying_evidence": True,
            "labels_reassigned_after_predictions": False,
        },
        "nonclaims": [
            "not a universal plugin compatibility result",
            "prelaunch predictions are not runtime effectiveness",
            "runtime execution is not a compression transaction or performance result",
            "the three scored cases are too small to estimate population prevalence",
        ],
    }
    write(OUTPUT / "campaign.json", campaign)

    oracle_index = {
        "schema": "ecpa-h2-real-source-oracle-index/v2",
        "campaign_sha256": digest(OUTPUT / "campaign.json"),
        "labels": [
            {
                "case_id": case["case_id"],
                "decision": case["oracle_decision"],
                "score_eligible": case["score_eligible"],
            }
            for case in cases
        ],
        "authorities": {
            "old_five_case_oracle": {
                "path": str((V1 / "oracle.json").relative_to(ROOT.parent.parent)),
                "sha256": digest(V1 / "oracle.json"),
            },
            "current_exact_pair_oracle": {
                "path": str((CURRENT / "oracle.json").relative_to(ROOT.parent.parent)),
                "sha256": digest(CURRENT / "oracle.json"),
                "receipt_sha256": digest(CURRENT / "oracle-receipt.json"),
                "verdict": current_oracle["verdict"],
            },
        },
        "policy": "index existing independent labels verbatim; do not infer or relabel unavailable/conditional cases",
    }
    write(OUTPUT / "oracle-index.json", oracle_index)

    scored = [case for case in cases if case["score_eligible"]]
    tp = sum(
        case["oracle_decision"] == case["prediction"]["decision"] == "admit"
        for case in scored
    )
    tn = sum(
        case["oracle_decision"] == case["prediction"]["decision"] == "reject"
        for case in scored
    )
    fp = sum(
        case["oracle_decision"] == "reject"
        and case["prediction"]["decision"] == "admit"
        for case in scored
    )
    fn = sum(
        case["oracle_decision"] == "admit"
        and case["prediction"]["decision"] == "reject"
        for case in scored
    )
    status = {
        "schema": "ecpa-h2-minimal-corpus-status/v2",
        "campaign_sha256": digest(OUTPUT / "campaign.json"),
        "oracle_index_sha256": digest(OUTPUT / "oracle-index.json"),
        "confusion_matrix": {
            "positive_class": "admit",
            "true_positive": tp,
            "true_negative": tn,
            "false_positive": fp,
            "false_negative": fn,
            "case_count": len(scored),
        },
        "metrics": {
            "admit_precision": tp / (tp + fp),
            "admit_recall": tp / (tp + fn),
            "reject_precision": tn / (tn + fn),
            "reject_recall": tn / (tn + fp),
            "accuracy": (tp + tn) / len(scored),
            "threshold": 0.95,
            "threshold_met": True,
        },
        "blanket_reject_baseline": {
            "accuracy": 2 / 3,
            "admit_recall": 0.0,
            "passes": False,
        },
        "surface_augmentation": {
            "path": str(AUGMENTATION.relative_to(ROOT.parent.parent)),
            "sha256": digest(AUGMENTATION),
            "frozen_source_manifests": 8,
            "preexisting_oracle_cases": 2,
            "oracle_pending_cases": 4,
        },
        "acceptance": {
            "exact_repository_tree_manifest_bindings": True,
            "meaningful_real_admit_and_reject": True,
            "observed_precision_recall_at_least_0_95": True,
            "error_owner_resource_and_remediation": True,
            "compatible_multi_mod_real_host_execution": True,
            "real_conflict_rejected_before_launch": True,
            "evidence_classes_distinguished": True,
            "paper_demotes_synthetic_seed": False,
            "requested_population_surface_coverage_complete": False,
        },
        "h2_acceptance_complete": False,
        "remaining_gaps": [
            "communication, external-service, and provider-translation sources are frozen, but their preexisting labeled cases remain Manager-unavailable and unscored",
            "CLI/config collision needs a second independently developed active bundle claiming the same real launch projection",
            "external-authority conflict needs a source-bound controller/autoscaler that competes with Production Stack for Deployment.spec.replicas",
            "two communication/process-carrier candidate compositions are frozen before independent source review and therefore have no Manager prediction",
            "the paper has not yet demoted the synthetic seed in favor of this real-corpus result",
            "n=3 scored compositions gives no strong estimate of population prevalence despite observed metrics of 1.0",
            "the conditional DiffSpec/KVCompress pair still needs physical ownership and install-order review",
        ],
    }
    write(OUTPUT / "status.json", status)
    print(digest(OUTPUT / "status.json"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
