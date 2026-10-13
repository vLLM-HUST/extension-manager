#!/usr/bin/env python3
"""Run the Manager ownership check after the remaining-surface oracle freeze."""

from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from vllm_hust_ext.config import ExtensionConfig
from vllm_hust_ext.core import plan_dict, plan_for
from vllm_hust_ext.discovery import InstalledBundle
from vllm_hust_ext.manifest import load_manifest
from vllm_hust_ext.providers.production_stack import ProductionStackProvider

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = (
    ROOT
    / "experiments/real_mod_composition/artifacts/h2-remaining-surfaces-oracle-20261013"
)
ORACLE = ARTIFACT / "oracle.json"
RECEIPT = ARTIFACT / "review-receipt.json"
OUTPUT = ARTIFACT / "manager-prediction.json"
MANAGER_BASE = "0884e3568d0b674f5e135f858e8e7f8016d2aa97"
ORACLE_COMMIT = "dfc533d33582f80fae0ee172e17aa47406d98e48"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def host_processes() -> list[int]:
    markers = ("vllm.entrypoints.openai.api_server", "vllm serve", "VLLM::EngineCore")
    result = []
    for item in Path("/proc").iterdir():
        if not item.name.isdigit():
            continue
        try:
            cmdline = (item / "cmdline").read_bytes().replace(b"\0", b" ").decode()
        except (OSError, UnicodeDecodeError):
            continue
        if any(marker in cmdline for marker in markers):
            result.append(int(item.name))
    return sorted(result)


def npu_probe() -> dict[str, object]:
    completed = subprocess.run(["npu-smi", "info"], capture_output=True, check=False)
    return {
        "exit_code": completed.returncode,
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
        "no_running_processes_for_allocated_devices": all(
            marker in completed.stdout
            for marker in (
                b"No running processes found in NPU 3",
                b"No running processes found in NPU 6",
            )
        ),
    }


def main() -> int:
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    if receipt["oracle_sha256"] != sha256(ORACLE):
        raise ValueError("oracle digest mismatch")
    if receipt["planner_seen_or_run_before_oracle_freeze"]:
        raise ValueError("oracle isolation not preserved")
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", MANAGER_BASE, "HEAD"], check=True
    )
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", ORACLE_COMMIT, "HEAD"], check=True
    )
    subprocess.run(
        ["git", "diff", "--quiet", MANAGER_BASE, "--", "src/vllm_hust_ext"], check=True
    )

    manifest_path = ARTIFACT / "snapshots/production-stack-provider-manifest.json"
    manifest = load_manifest(manifest_path)
    bundle = InstalledBundle(
        manifest.bundle_id,
        "frozen-source:vLLM-HUST/extension-manager",
        manifest.bundle_version,
        manifest_path,
        manifest,
        (),
    )
    configuration = {
        "chart": "vllm/vllm-stack",
        "release": "vllm",
        "namespace": "default",
        "values": {
            "servingEngineSpec": {
                "modelSpec": [
                    {"name": "llama3", "replicaCount": 1, "keda": {"enabled": False}}
                ]
            }
        },
        "ownership_conflicts": [
            "Production Stack and KEDA-generated HPA both claim "
            "Deployment/default/vllm-llama3-deployment-vllm spec.replicas "
            "without delegation"
        ],
    }
    before_pids = host_processes()
    npu_before = npu_probe()
    plan = plan_for(bundle, ExtensionConfig(True, configuration))
    check = ProductionStackProvider().check(manifest, configuration)
    npu_after = npu_probe()
    after_pids = host_processes()
    decision = "reject" if check.compatible is False else "admit"

    oracle = json.loads(ORACLE.read_text(encoding="utf-8"))
    oracle_case = next(
        case
        for case in oracle["cases"]
        if case["case_id"] == "external-authority-production-stack-keda"
    )
    artifact = {
        "schema": "ecpa-h2-remaining-surface-manager-prediction/v1",
        "captured_utc": datetime.now(timezone.utc).isoformat(),
        "classification": "source-bound-pre-launch-provider-check",
        "manager": {
            "base_commit": MANAGER_BASE,
            "source_tree_unchanged_from_base": True,
        },
        "oracle": {
            "frozen_commit": ORACLE_COMMIT,
            "sha256": sha256(ORACLE),
            "receipt_sha256": sha256(RECEIPT),
            "frozen_before_prediction": True,
        },
        "case_id": oracle_case["case_id"],
        "configuration": configuration,
        "plan": plan_dict(plan),
        "provider_check": asdict(check),
        "prediction": decision,
        "oracle_decision": oracle_case["decision"],
        "decision_match": decision == oracle_case["decision"],
        "score_eligible": oracle_case["score_eligible"],
        "aggregate_definite_subset": {
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
        "process_boundary": {
            "host_pids_before": before_pids,
            "host_pids_after": after_pids,
            "host_process_started": before_pids != after_pids,
            "npu_before": npu_before,
            "npu_after": npu_after,
        },
        "h2_complete": False,
        "remaining_gaps": [
            "no second independently developed active batch-admission bundle "
            "was found for the same CLI/config projection",
            "n=4 definite cases remains too small for a strong population estimate",
            "the new external-authority result is source-level and pre-launch, "
            "not a Kubernetes runtime receipt",
        ],
        "nonclaims": [
            "not runtime execution",
            "not performance evidence",
            "does not label the explicit Production Stack KEDA delegation mode "
            "as conflicting",
            "does not close H2",
        ],
    }
    OUTPUT.write_text(
        json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"prediction={decision} match={artifact['decision_match']} "
        f"sha256:{sha256(OUTPUT)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
