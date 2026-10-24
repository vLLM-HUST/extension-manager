#!/usr/bin/env python3
"""Run Manager planning only after the independent carrier oracle is frozen."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vllm_hust_ext.config import ExtensionConfig
from vllm_hust_ext.core import plan_dict, plan_for, reject_conflicting_plans
from vllm_hust_ext.discovery import InstalledBundle
from vllm_hust_ext.manifest import activation_blocker, load_manifest

_CHECKOUT = Path(__file__).resolve().parents[2]
if (_CHECKOUT / "BENCHMARK_ORIGINALS.json").is_file():
    sys.path.insert(0, str(_CHECKOUT))
    from scripts.benchmark_inputs import resolve_original
else:

    def resolve_original(path: Path) -> Path:
        return path


ROOT = Path(__file__).resolve().parents[2]
EXPERIMENT = ROOT / "experiments/real_mod_composition"
AUGMENTATION = (
    EXPERIMENT / "artifacts/h2-real-source-augmentation-20261013/augmentation.json"
)
ORACLE_DIR = EXPERIMENT / "artifacts/h2-process-carrier-oracle-20261013"
ORACLE = ORACLE_DIR / "oracle.json"
RECEIPT = ORACLE_DIR / "review-receipt.json"
OUTPUT = ORACLE_DIR / "manager-predictions.json"
MANAGER_BASE = "4adf42698a46a5d046c8949873bb1ddf6889e881"
ORACLE_COMMIT = "3ce23fafbe5164ec3ea557456f111a19687ec6bc"


def sha256(path: Path) -> str:
    return hashlib.sha256(resolve_original(path).read_bytes()).hexdigest()


def command(argv: list[str]) -> dict[str, Any]:
    completed = subprocess.run(argv, capture_output=True, check=False)
    return {
        "argv": argv,
        "exit_code": completed.returncode,
        "stdout": completed.stdout.decode(errors="replace"),
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr": completed.stderr.decode(errors="replace"),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
    }


def host_processes() -> list[dict[str, Any]]:
    markers = (
        "vllm.entrypoints.openai.api_server",
        "vllm serve",
        "VLLM::EngineCore",
    )
    found = []
    for item in Path("/proc").iterdir():
        if not item.name.isdigit():
            continue
        try:
            cmdline = (
                (resolve_original(item / "cmdline"))
                .read_bytes()
                .replace(b"\0", b" ")
                .decode()
            )
        except (OSError, UnicodeDecodeError):
            continue
        if any(marker in cmdline for marker in markers):
            found.append({"pid": int(item.name), "cmdline": cmdline.strip()})
    return sorted(found, key=lambda item: item["pid"])


def write_new_output(path: Path, text: str, **kwargs) -> None:
    with path.open("x", **kwargs) as stream:
        stream.write(text)


def main() -> int:
    from scripts.benchmark_inputs import output_argument

    OUTPUT = output_argument(directory=False)
    oracle = json.loads(resolve_original(ORACLE).read_text(encoding="utf-8"))
    receipt = json.loads(resolve_original(RECEIPT).read_text(encoding="utf-8"))
    augmentation = json.loads(
        resolve_original(AUGMENTATION).read_text(encoding="utf-8")
    )
    if receipt["oracle_sha256"] != sha256(ORACLE):
        raise ValueError("independent oracle digest mismatch")
    if receipt["isolation"]["planner_seen_or_run_before_oracle_freeze"]:
        raise ValueError("oracle receipt does not preserve planner isolation")
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", MANAGER_BASE, "HEAD"], check=True
    )
    subprocess.run(
        ["git", "merge-base", "--is-ancestor", ORACLE_COMMIT, "HEAD"], check=True
    )
    subprocess.run(
        ["git", "diff", "--quiet", MANAGER_BASE, "--", "src/vllm_hust_ext"],
        check=True,
    )

    npu_before = command(["npu-smi", "info"])
    hosts_before = host_processes()
    predictions = []
    oracle_cases = {case["case_id"]: case for case in oracle["cases"]}
    pending_cases = {
        case["case_id"]: case for case in augmentation["oracle_pending_cases"]
    }
    for case_id in sorted(oracle_cases):
        case = oracle_cases[case_id]
        frozen = pending_cases[case_id]
        plans = []
        members = []
        for member_id in frozen["members"]:
            source = augmentation["sources"][member_id]
            snapshot = ROOT / source["snapshot_path"]
            if sha256(snapshot) != source["manifest_sha256"].removeprefix("sha256:"):
                raise ValueError(f"snapshot digest mismatch: {member_id}")
            manifest = load_manifest(resolve_original(snapshot))
            bundle = InstalledBundle(
                manifest.bundle_id,
                f"frozen-source:{source['repository']}",
                manifest.bundle_version,
                snapshot,
                manifest,
                (),
            )
            plan = plan_for(
                bundle,
                ExtensionConfig(False, {}),
                include_external_providers=False,
            )
            plans.append(plan)
            members.append(
                {
                    "source_id": member_id,
                    "commit": source["commit"],
                    "tree": source["tree"],
                    "manifest_blob": source["manifest_blob"],
                    "manifest_sha256": source["manifest_sha256"],
                    "activation_blocker": activation_blocker(manifest),
                    "plan": plan_dict(plan),
                }
            )
        composition_error = None
        try:
            reject_conflicting_plans(tuple(plans))
        except ValueError as error:
            composition_error = str(error)
        blockers = [member for member in members if member["activation_blocker"]]
        surface_prediction = "reject" if composition_error else "admit"
        qualification_prediction = (
            "reject" if composition_error or blockers else "admit"
        )
        predictions.append(
            {
                "case_id": case_id,
                "oracle_decision": case["decision"],
                "oracle_reason": case["reason"],
                "planner_surface_prediction": surface_prediction,
                "qualification_prediction": qualification_prediction,
                "composition_error": composition_error,
                "members": members,
                "score_eligible": False,
                "scoring_reason": (
                    "independent oracle abstained before planner execution"
                ),
                "host_launch_command_invoked": False,
                "runtime_claim": False,
                "performance_claim": False,
            }
        )

    hosts_after = host_processes()
    npu_after = command(["npu-smi", "info"])
    artifact = {
        "schema": "ecpa-h2-process-carrier-manager-predictions/v1",
        "captured_utc": datetime.now(timezone.utc).isoformat(),
        "classification": "pre-launch-planner-only-not-runtime",
        "manager": {
            "base_commit": MANAGER_BASE,
            "source_tree_unchanged_from_base": True,
        },
        "oracle": {
            "frozen_commit": ORACLE_COMMIT,
            "sha256": sha256(ORACLE),
            "receipt_sha256": sha256(RECEIPT),
            "frozen_before_planner": True,
        },
        "augmentation_sha256": sha256(AUGMENTATION),
        "predictions": predictions,
        "scoring": {
            "new_score_eligible_cases": 0,
            "new_true_positive": 0,
            "new_true_negative": 0,
            "new_false_positive": 0,
            "new_false_negative": 0,
            "r2_definite_subset_size_after_update": 3,
            "r2_observed_metrics_changed": False,
        },
        "process_boundary": {
            "npu_before": npu_before,
            "npu_after": npu_after,
            "host_processes_before": hosts_before,
            "host_processes_after": hosts_after,
            "host_process_started": hosts_before != hosts_after,
        },
        "h2_complete": False,
        "remaining_gaps": [
            "no exact host provider implements and binds the joint process carriers",
            (
                "no source-bound joint registration, callback, failure, and teardown "
                "ordering receipt exists"
            ),
            (
                "CLI/config same-projection and competing external-controller cases "
                "remain absent"
            ),
        ],
        "nonclaims": [
            "not runtime execution",
            "not performance",
            "planner surface admit does not override the independent abstain",
            "import-only qualification rejection does not prove a resource conflict",
        ],
    }
    write_new_output(OUTPUT, json.dumps(artifact, indent=2, sort_keys=True) + "\n")
    print(f"sha256:{sha256(OUTPUT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
