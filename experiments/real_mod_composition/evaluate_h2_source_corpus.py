#!/usr/bin/env python3
"""Evaluate one frozen real-source H2 case with the Manager planner.

This command stops at the pre-launch boundary.  It never imports a MOD
implementation, mutates Manager state, or starts a host process.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from vllm_hust_ext.config import ExtensionConfig
from vllm_hust_ext.core import plan_dict, plan_for, reject_conflicting_plans
from vllm_hust_ext.discovery import InstalledBundle
from vllm_hust_ext.manifest import activation_blocker, load_manifest
from vllm_hust_ext.providers.base import assess_compatibility

_CHECKOUT = Path(__file__).resolve().parents[2]
if (_CHECKOUT / "BENCHMARK_ORIGINALS.json").is_file():
    sys.path.insert(0, str(_CHECKOUT))
    from scripts.benchmark_inputs import resolve_original
else:

    def resolve_original(path: Path) -> Path:
        return path


ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "artifacts/h2-minimal-real-source-corpus-20261013"
MANIFESTS = ROOT / "source_manifests"


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def host_version(case: dict[str, Any], host_name: str) -> str | None:
    host = case["host"]
    value = host.get(host_name)
    if isinstance(value, str) and not value.startswith("requires "):
        return value
    return None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("case_id")
    args = parser.parse_args()

    campaign_bytes = (resolve_original(CORPUS / "campaign.json")).read_bytes()
    campaign = json.loads(campaign_bytes)
    oracle = json.loads((resolve_original(CORPUS / "oracle.json")).read_text())
    if oracle["campaign_sha256"] != digest(campaign_bytes):
        raise ValueError("frozen oracle does not bind the frozen campaign")
    try:
        case = next(
            item for item in campaign["cases"] if item["case_id"] == args.case_id
        )
    except StopIteration as error:
        raise ValueError(f"unknown frozen case: {args.case_id}") from error

    member_results: list[dict[str, Any]] = []
    plans = []
    for member in case["members"]:
        path = MANIFESTS / f"{member['id']}.json"
        raw = resolve_original(path).read_bytes()
        if digest(raw) != member["manifest_sha256"]:
            raise ValueError(f"snapshot digest mismatch for {member['id']}")
        manifest = load_manifest(resolve_original(path))
        version = host_version(case, manifest.host.name)
        compatible, evidence = assess_compatibility(
            manifest,
            {},
            detected_host_version=version,
            default_api_version="1.0",
            # No protocol version is invented when the frozen host tuple does
            # not bind a capability-registry receipt.
            default_protocol_versions={},
        )
        blocker = activation_blocker(manifest)
        bundle = InstalledBundle(
            bundle_id=manifest.bundle_id,
            distribution_name=f"frozen-source:{member['repository']}",
            distribution_version=manifest.bundle_version,
            manifest_path=path,
            manifest=manifest,
            entry_points=(),
        )
        plan = plan_for(
            bundle,
            ExtensionConfig(False, {}),
            include_external_providers=False,
        )
        plans.append(plan)
        member_results.append(
            {
                "id": member["id"],
                "bundle_id": manifest.bundle_id,
                "commit": member["commit"],
                "tree": member["tree"],
                "manifest_blob": member["manifest_blob"],
                "manifest_sha256": member["manifest_sha256"],
                "host_name": manifest.host.name,
                "host_version": version,
                "declared_host_range": manifest.host.version_range,
                "compatibility": compatible,
                "compatibility_evidence": list(evidence),
                "activation_blocker": blocker,
                "plan": plan_dict(plan),
            }
        )

    composition_error = None
    try:
        reject_conflicting_plans(tuple(plans))
    except ValueError as error:
        composition_error = str(error)

    blockers = [item for item in member_results if item["activation_blocker"]]
    incompatible = [item for item in member_results if item["compatibility"] is False]
    unknown = [item for item in member_results if item["compatibility"] is None]
    if case["oracle_decision"] == "conditional":
        prediction = "excluded"
        reason = "independent oracle is conditional pending physical ownership review"
        declared_surface_decision = "reject" if composition_error else "admit"
    elif blockers or composition_error:
        prediction = "reject"
        reason = composition_error or str(blockers[0]["activation_blocker"])
        declared_surface_decision = "reject"
    elif incompatible:
        prediction = "excluded"
        reason = "frozen host tuple is outside a declared host range"
        declared_surface_decision = "reject"
    elif unknown:
        prediction = "unavailable"
        reason = "frozen tuple lacks a required host or protocol capability receipt"
        declared_surface_decision = "unavailable"
    else:
        prediction = "admit"
        reason = "all declared host ranges and Manager composition claims pass"
        declared_surface_decision = "admit"

    result = {
        "schema": "ecpa-h2-source-corpus-manager-prediction/v1",
        "classification": "real-source-prelaunch-manager-prediction-not-runtime",
        "manager_commit": "08ab570fb00c4206b8d2c6c296ac9580b0f892bc",
        "campaign_sha256": digest(campaign_bytes),
        "case_id": case["case_id"],
        "category": case["category"],
        "oracle_decision": case["oracle_decision"],
        "prediction": prediction,
        "declared_surface_decision": declared_surface_decision,
        "reason": reason,
        "score_eligible": (
            case["score_role"] != "calibration-only-single-mod"
            and case["oracle_decision"] in campaign["scoring_policy"]["definite_labels"]
            and prediction in {"admit", "reject"}
        ),
        "members": member_results,
        "composition_error": composition_error,
        "host_launch_command_invoked": False,
        "runtime_claim": False,
        "performance_claim": False,
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
