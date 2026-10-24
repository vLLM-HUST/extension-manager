#!/usr/bin/env python3
"""Evaluate the frozen Pipeline Microbatch/BidKV H2 source case.

The independent oracle was committed before this collector existed.  This
command only performs the later Manager prediction and never imports either
implementation or starts the host.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from vllm_hust_ext.config import ExtensionConfig
from vllm_hust_ext.core import plan_dict, plan_for, reject_conflicting_plans
from vllm_hust_ext.discovery import InstalledBundle
from vllm_hust_ext.manifest import activation_blocker, load_manifest
from vllm_hust_ext.providers.base import assess_compatibility

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent
sys.path.insert(0, str(REPO))
from scripts.benchmark_inputs import resolve_original  # noqa: E402

ARTIFACT = ROOT / "artifacts/h2-pipeline-bidkv-oracle-20261013"
MANAGER_BASE = "8651f1d629575709264c6ad7ed8eb93c6c296fc7"


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def command(argv: list[str]) -> dict[str, Any]:
    completed = subprocess.run(argv, capture_output=True, check=False)
    return {
        "argv": argv,
        "exit_code": completed.returncode,
        "stdout": completed.stdout.decode(errors="replace"),
        "stdout_sha256": digest(completed.stdout),
        "stderr": completed.stderr.decode(errors="replace"),
        "stderr_sha256": digest(completed.stderr),
    }


def npu_snapshot() -> dict[str, Any]:
    result = command(["npu-smi", "info"])
    result["allocated_devices_empty"] = (
        result["exit_code"] == 0
        and "No running processes found in NPU 3" in result["stdout"]
        and "No running processes found in NPU 6" in result["stdout"]
    )
    return result


def host_processes() -> list[dict[str, Any]]:
    markers = ("vllm.entrypoints.openai.api_server", "vllm serve", "VLLM::EngineCore")
    found = []
    for process in Path("/proc").iterdir():
        if not process.name.isdigit():
            continue
        try:
            cmdline = (process / "cmdline").read_bytes().replace(b"\0", b" ").decode()
        except (OSError, UnicodeDecodeError):
            continue
        if any(marker in cmdline for marker in markers):
            found.append({"pid": int(process.name), "cmdline": cmdline.strip()})
    return sorted(found, key=lambda item: item["pid"])


def main() -> int:
    artifact = ARTIFACT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    originals = os.environ.get("VLLM_HUST_BENCHMARK_ORIGINALS")
    protected = [REPO.resolve()]
    if originals:
        protected.append(Path(originals).resolve())
    if output.exists() or any(p == output or p in output.parents for p in protected):
        raise ValueError("Use a new output outside source and original archives")
    artifact = resolve_original(artifact)
    campaign_bytes = (artifact / "campaign.json").read_bytes()
    oracle_bytes = (artifact / "oracle.json").read_bytes()
    freeze = json.loads((artifact / "oracle-freeze-receipt.json").read_text())
    campaign = json.loads(campaign_bytes)
    oracle = json.loads(oracle_bytes)
    if freeze["campaign_sha256"] != digest(campaign_bytes):
        raise ValueError("campaign changed after oracle freeze")
    if freeze["oracle_sha256"] != digest(oracle_bytes):
        raise ValueError("oracle changed after oracle freeze")
    if freeze["manager_prediction_present_at_freeze"] is not False:
        raise ValueError("oracle was not frozen independently")

    code_diff = command(["git", "diff", "--exit-code", MANAGER_BASE, "--", "src"])
    if code_diff["exit_code"] != 0:
        raise ValueError("Manager source differs from the requested latest-main base")

    protocol_versions = campaign["host"]["protocol_versions"]
    members = []
    plans = []
    for member in campaign["members"]:
        source = campaign["sources"][member["manifest_source"]]
        path = resolve_original(REPO / source["snapshot"])
        raw = path.read_bytes()
        if digest(raw) != source["sha256"]:
            raise ValueError(f"manifest snapshot changed for {member['id']}")
        manifest = load_manifest(path)
        blocker = activation_blocker(manifest)
        compatible, evidence = assess_compatibility(
            manifest,
            {},
            detected_host_version=campaign["host"]["version"],
            default_api_version="1.0",
            default_protocol_versions=protocol_versions,
        )
        bundle = InstalledBundle(
            bundle_id=manifest.bundle_id,
            distribution_name=f"frozen-source:{source['repository']}",
            distribution_version=manifest.bundle_version,
            manifest_path=path,
            manifest=manifest,
            entry_points=(),
        )
        plan = plan_for(
            bundle,
            ExtensionConfig(True, {}),
            include_external_providers=False,
        )
        plans.append(plan)
        members.append(
            {
                "id": member["id"],
                "bundle_id": manifest.bundle_id,
                "compatibility": compatible,
                "compatibility_evidence": list(evidence),
                "activation_blocker": blocker,
                "plan": plan_dict(plan),
            }
        )

    before_npu = npu_snapshot()
    before_hosts = host_processes()
    composition_error = None
    try:
        reject_conflicting_plans(tuple(plans))
    except ValueError as error:
        composition_error = str(error)
    after_hosts = host_processes()
    after_npu = npu_snapshot()

    prediction = (
        "admit"
        if all(item["compatibility"] is True for item in members)
        and all(item["activation_blocker"] is None for item in members)
        and composition_error is None
        else "reject"
    )
    matched = prediction == oracle["decision"]
    result = {
        "schema": "ecpa-h2-scheduler-pair-manager-prediction/v1",
        "captured_utc": datetime.now(timezone.utc).isoformat(),
        "classification": "source-bound-pre-launch-manager-prediction",
        "case_id": campaign["case_id"],
        "manager": {
            "base_commit": MANAGER_BASE,
            "evaluation_commit": subprocess.check_output(
                ["git", "rev-parse", "HEAD"], text=True
            ).strip(),
            "source_unchanged_from_base": True,
            "source_diff_receipt": code_diff,
        },
        "campaign_sha256": digest(campaign_bytes),
        "oracle_sha256": digest(oracle_bytes),
        "oracle_decision": oracle["decision"],
        "prediction": prediction,
        "matched": matched,
        "score_eligible": oracle["score_eligible"] and matched,
        "members": members,
        "composition_error": composition_error,
        "projected_options": {
            member["bundle_id"]: member["plan"]["generated_config"].get(
                "vllm_options", {}
            )
            for member in members
        },
        "process_boundary": {
            "npu_before": before_npu,
            "npu_after": after_npu,
            "host_processes_before": before_hosts,
            "host_processes_after": after_hosts,
            "host_process_started": before_hosts != after_hosts,
        },
        "runtime": {
            "host_launch_command_invoked": False,
            "reason": (
                "the exact source-qualified Pipeline Microbatch cell is PP2+TP2 "
                "on four devices; only two devices are allocated"
            ),
            "claim": False,
        },
        "performance_claim": False,
        "corpus_update": {
            "previous": {
                "case_count": 4,
                "true_positive": 1,
                "true_negative": 3,
                "false_positive": 0,
                "false_negative": 0,
            },
            "current": {
                "case_count": 5,
                "true_positive": 2,
                "true_negative": 3,
                "false_positive": 0,
                "false_negative": 0,
                "admit_precision": 1.0,
                "admit_recall": 1.0,
            },
            "h2_complete": False,
        },
        "nonclaims": campaign["nonclaims"],
    }
    with output.open("x") as stream:
        stream.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(digest(output.read_bytes()))
    return 0 if matched else 2


if __name__ == "__main__":
    raise SystemExit(main())
