#!/usr/bin/env python3
# ruff: noqa: E501
"""Freeze real-source H2 coverage candidates before any new oracle review."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from vllm_hust_ext.config import ExtensionConfig
from vllm_hust_ext.core import plan_dict, plan_for, reject_conflicting_plans
from vllm_hust_ext.discovery import InstalledBundle
from vllm_hust_ext.manifest import load_manifest

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent
OUT = ROOT / "artifacts/h2-real-source-augmentation-20261013"
CONTRACT_CASES = REPO / "experiments/contract_planner/cases.json"
CONTRACT_ORACLE = REPO / "experiments/contract_planner/oracle.json"
SOURCE_SNAPSHOTS = REPO / "docs/corpus/source-snapshots.json"
WORKSHOP = REPO / "docs/corpus/workshop-mods.json"

SOURCES = {
    "bidkv-corpus-v02": {
        "repository": "vLLM-HUST/vllm-hust-bidkv",
        "repo": Path("/root/ecpa-h2-corpus-src-bidkv"),
        "commit": "a0cba97d9abdc99908e46616db622f0e0099127f",
        "tree": "c74c2762ad9175d59bac7b24f647e0ebcd2b9b22",
        "path": "src/bidkv/manifests/vllm-hust-extension-v0.2.json",
    },
    "mooncake-provider": {
        "repository": "intellistream/vllm-hust-ext-manager",
        "repo": REPO,
        "commit": "9a1369d23ee32f3bb84583fb1695b2ff7cf4eb43",
        "tree": "ef9151532e2c34eb42554795f67b248e11ee92ef",
        "path": "examples/mooncake-provider/src/vllm_hust_mooncake_provider/manifests/vllm-hust-extension-v0.2.json",
    },
    "production-stack-provider": {
        "repository": "intellistream/vllm-hust-ext-manager",
        "repo": REPO,
        "commit": "9a1369d23ee32f3bb84583fb1695b2ff7cf4eb43",
        "tree": "ef9151532e2c34eb42554795f67b248e11ee92ef",
        "path": "examples/production-stack-provider/src/vllm_hust_production_stack_provider/manifests/vllm-hust-extension-v0.2.json",
    },
    "unified-communication": {
        "repository": "vLLM-HUST/vllm-hust-unified-comm",
        "repo": Path("/root/ecpa-h2-augmentation-unified_comm"),
        "commit": "f00d1ef4c19a992d67ef8012952a9405d52dd447",
        "tree": "1eee1fe9cb3c49d4b588203af59ac35704323395",
        "path": "src/vllm_hust_unified_comm/vllm-hust-extension-v0.2.json",
    },
    "qos-scheduler": {
        "repository": "vLLM-HUST/vllm-hust-qos-scheduler",
        "repo": Path("/root/ecpa-h2-augmentation-qos_scheduler"),
        "commit": "13d376a7d8990c4dcf5c0903cb6fbf2398ef0fb0",
        "tree": "2a1a7b934e8ce68068dfac69a8be13b9dd32e96c",
        "path": "src/vllm_hust_qos_scheduler/vllm-hust-extension-v0.2.json",
    },
    "pipeline-microbatch": {
        "repository": "vLLM-HUST/vllm-hust-pipeline-microbatch",
        "repo": Path("/root/ecpa-h2-augmentation-pipeline_microbatch"),
        "commit": "a15a22961a0e4858da74a0ab806575c82cb254e6",
        "tree": "6944e78e49843026ed91423dcd4add94a8039929",
        "path": "src/vllm_hust_pipeline_microbatch/vllm-hust-extension-v0.2.json",
    },
    "kv-transfer-observability": {
        "repository": "vLLM-HUST/vllm-hust-kv-transfer-observability",
        "repo": Path("/root/ecpa-h2-augmentation-kv_transfer_observability"),
        "commit": "53e69013dcf27fd08a93d142288c93c701edabd3",
        "tree": "a3c89d926513461d9c31f74c82bf4f8fcb24e6bb",
        "path": "src/vllm_hust_kv_transfer_observability/vllm-hust-extension-v0.2.json",
    },
    "split-batch-full-graph": {
        "repository": "vLLM-HUST/vllm-ascend-split-batch-hust",
        "repo": Path("/root/ecpa-h2-augmentation-split_batch"),
        "commit": "b46de46e90204a0a7636a1dbc952f73178859ada",
        "tree": "d9832ad7c22b6e6dc2050c75353c3e994cddd6f0",
        "path": "src/vllm_ascend_split_batch/vllm-hust-extension-v0.2.json",
    },
}


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def file_sha(path: Path) -> str:
    return sha256(path.read_bytes())


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def static_prediction(
    member_ids: list[str], records: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    plans = []
    for member_id in member_ids:
        record = records[member_id]
        path = REPO / record["snapshot_path"]
        manifest = load_manifest(path)
        bundle = InstalledBundle(
            manifest.bundle_id,
            f"frozen-source:{record['repository']}",
            manifest.bundle_version,
            path,
            manifest,
            (),
        )
        plans.append(
            plan_for(
                bundle, ExtensionConfig(False, {}), include_external_providers=False
            )
        )
    error = None
    try:
        reject_conflicting_plans(tuple(plans))
    except ValueError as exc:
        error = str(exc)
    return {
        "declared_surface_decision": "reject" if error else "admit",
        "qualification_decision": "unavailable",
        "reason": "the frozen source tuple lacks exact host capability and external-authority reachability receipts",
        "composition_error": error,
        "plans": [plan_dict(plan) for plan in plans],
        "runtime_claim": False,
        "performance_claim": False,
    }


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    records: dict[str, dict[str, Any]] = {}
    for source_id, spec in SOURCES.items():
        actual_tree = git(spec["repo"], "rev-parse", f"{spec['commit']}^{{tree}}")
        if actual_tree != spec["tree"]:
            raise ValueError(f"tree mismatch for {source_id}: {actual_tree}")
        raw = subprocess.check_output(
            ["git", "-C", str(spec["repo"]), "show", f"{spec['commit']}:{spec['path']}"]
        )
        blob = git(spec["repo"], "rev-parse", f"{spec['commit']}:{spec['path']}")
        snapshot = OUT / f"{source_id}-manifest.json"
        snapshot.write_bytes(raw)
        manifest = json.loads(raw)
        records[source_id] = {
            "repository": spec["repository"],
            "commit": spec["commit"],
            "tree": spec["tree"],
            "manifest_path": spec["path"],
            "manifest_blob": blob,
            "manifest_sha256": sha256(raw),
            "manifest_schema": manifest["schema_version"],
            "bundle_id": manifest["extension_id"],
            "implementation_statuses": [
                item.get("status") for item in manifest.get("implementation", [])
            ],
            "process_scope": manifest["runtime"]["process_scope"],
            "lifecycle_owner": manifest["lifecycle_owner"],
            "snapshot_path": str(snapshot.relative_to(REPO)),
        }

    contract_oracle = json.loads(CONTRACT_ORACLE.read_text())
    oracle_labels = {label["case_id"]: label for label in contract_oracle["labels"]}
    augmentation = {
        "schema": "ecpa-h2-real-source-augmentation/v1",
        "classification": "frozen-real-source-candidates-and-preexisting-oracle-cases",
        "source_authorities": {
            "source_snapshots_sha256": file_sha(SOURCE_SNAPSHOTS),
            "workshop_mods_sha256": file_sha(WORKSHOP),
            "contract_cases_sha256": file_sha(CONTRACT_CASES),
            "contract_oracle_sha256": file_sha(CONTRACT_ORACLE),
            "contract_oracle_review": contract_oracle["review"],
        },
        "sources": records,
        "preexisting_oracle_cases": [
            {
                "case_id": "real-pair-bidkv-mooncake-provider",
                "members": ["bidkv-corpus-v02", "mooncake-provider"],
                "dimensions": [
                    "communication",
                    "external-service",
                    "provider-translation",
                ],
                "oracle_source_case": "case.pair-bidkv-mooncake",
                "oracle": oracle_labels["case.pair-bidkv-mooncake"],
                "oracle_frozen_before_this_prediction": True,
                "prediction": static_prediction(
                    ["bidkv-corpus-v02", "mooncake-provider"], records
                ),
                "score_eligible": False,
            },
            {
                "case_id": "real-single-production-stack-provider",
                "members": ["production-stack-provider"],
                "dimensions": ["provider-translation", "external-authority"],
                "oracle_source_case": "case.single-production",
                "oracle": oracle_labels["case.single-production"],
                "oracle_frozen_before_this_prediction": True,
                "prediction": static_prediction(["production-stack-provider"], records),
                "score_eligible": False,
            },
        ],
        "oracle_pending_cases": [
            {
                "case_id": "pending-communication-process-carriers",
                "members": [
                    "unified-communication",
                    "qos-scheduler",
                    "kv-transfer-observability",
                ],
                "dimensions": ["communication", "explicit-process-carrier-conflict"],
                "oracle_status": "pending-independent-source-review",
                "planner_status": "not-run-to-preserve-oracle-before-prediction-order",
                "score_eligible": False,
            },
            {
                "case_id": "pending-scheduler-config-collision",
                "members": ["pipeline-microbatch"],
                "required_addition": "a second independently developed real active bundle claiming the same batch-admission CLI/config projection",
                "dimensions": ["CLI/config-collision"],
                "oracle_status": "candidate-incomplete",
                "planner_status": "not-run",
                "score_eligible": False,
            },
            {
                "case_id": "pending-external-authority-conflict",
                "members": ["production-stack-provider"],
                "required_addition": "a source-bound real controller or autoscaler manifest that competes for Deployment.spec.replicas",
                "dimensions": ["external-authority-conflict"],
                "oracle_status": "candidate-incomplete",
                "planner_status": "not-run",
                "score_eligible": False,
            },
            {
                "case_id": "pending-worker-carrier-overlap",
                "members": [
                    "unified-communication",
                    "split-batch-full-graph",
                    "kv-transfer-observability",
                ],
                "dimensions": ["communication", "explicit-process-carrier-conflict"],
                "oracle_status": "pending-independent-source-review",
                "planner_status": "not-run-to-preserve-oracle-before-prediction-order",
                "score_eligible": False,
            },
        ],
        "coverage": {
            "communication": "source-frozen; preexisting labeled Mooncake case is Manager-unavailable; two richer cases await independent oracle",
            "external-service": "source-frozen and preexisting independent oracle; Manager unavailable",
            "provider-translation": "Mooncake and Production Stack manifests frozen; preexisting independent oracles; Manager unavailable",
            "CLI/config-collision": "gap: no second real same-projection active bundle frozen",
            "external-authority-conflict": "gap: provider source frozen, competing real controller/autoscaler manifest absent",
            "explicit-process-carrier-conflict": "candidate sources frozen; independent oracle pending before planner",
        },
        "nonclaims": [
            "not runtime execution",
            "not a new independent oracle",
            "modeled contract labels are retained only as prior labels and are not promoted into the scored H2 corpus",
            "no pending candidate has a Manager prediction",
        ],
    }
    path = OUT / "augmentation.json"
    path.write_text(json.dumps(augmentation, indent=2, sort_keys=True) + "\n")
    print(file_sha(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
