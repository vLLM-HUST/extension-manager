#!/usr/bin/env python3
"""Verify the independently frozen H2 remaining-surface oracle."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = (
    ROOT
    / "experiments/real_mod_composition/artifacts/h2-remaining-surfaces-oracle-20261013"
)
ORACLE = ARTIFACT / "oracle.json"
RECEIPT = ARTIFACT / "review-receipt.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manager-source", type=Path)
    parser.add_argument("--production-stack-source", type=Path)
    parser.add_argument("--keda-source", type=Path)
    parser.add_argument("--pipeline-source", type=Path)
    parser.add_argument("--scheduler-lab-source", type=Path)
    parser.add_argument("--qos-source", type=Path)
    args = parser.parse_args()

    oracle = json.loads(ORACLE.read_text(encoding="utf-8"))
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    require(receipt["oracle_sha256"] == sha256(ORACLE), "oracle digest")
    require(receipt["verifier_sha256"] == sha256(Path(__file__)), "verifier digest")
    require(
        receipt["planner_seen_or_run_before_oracle_freeze"] is False, "oracle isolation"
    )
    require(receipt["verdict"] == "PASS", "review verdict")
    require(
        oracle["oracle_summary"]
        == {
            "admit": 0,
            "reject": 1,
            "unresolved": 1,
            "score_eligible": 1,
            "runtime_claim": False,
            "performance_claim": False,
        },
        "oracle summary",
    )

    cases = {case["case_id"]: case for case in oracle["cases"]}
    require(
        cases["external-authority-production-stack-keda"]["decision"] == "reject",
        "external authority label",
    )
    require(
        cases["external-authority-production-stack-keda"]["score_eligible"] is True,
        "external score eligibility",
    )
    require(
        cases["scheduler-config-collision-search"]["decision"] == "unresolved",
        "scheduler abstention",
    )
    require(
        cases["scheduler-config-collision-search"]["score_eligible"] is False,
        "scheduler exclusion",
    )

    for source_id, source in oracle["sources"].items():
        for file_path, evidence in source["files"].items():
            snapshot = ARTIFACT / evidence["snapshot"]
            require(snapshot.is_file(), f"{source_id} snapshot exists: {file_path}")
            require(
                sha256(snapshot) == evidence["sha256"],
                f"{source_id} snapshot digest: {file_path}",
            )

    roots = {
        "manager-production-provider": args.manager_source,
        "vllm-production-stack": args.production_stack_source,
        "keda": args.keda_source,
        "pipeline-microbatch": args.pipeline_source,
        "scheduler-policy-lab": args.scheduler_lab_source,
        "qos-scheduler": args.qos_source,
    }
    for source_id, repo in roots.items():
        if repo is None:
            continue
        source = oracle["sources"][source_id]
        require(
            git(repo, "rev-parse", f"{source['commit']}^{{commit}}")
            == source["commit"],
            f"{source_id} commit",
        )
        require(
            git(repo, "rev-parse", f"{source['commit']}^{{tree}}") == source["tree"],
            f"{source_id} tree",
        )
        for file_path, evidence in source["files"].items():
            require(
                git(repo, "rev-parse", f"{source['commit']}:{file_path}")
                == evidence["blob"],
                f"{source_id} blob: {file_path}",
            )
            data = subprocess.check_output(
                ["git", "-C", str(repo), "show", f"{source['commit']}:{file_path}"]
            )
            require(
                hashlib.sha256(data).hexdigest()
                == evidence.get("source_sha256", evidence["sha256"]),
                f"{source_id} source digest: {file_path}",
            )

    print(f"PASS reject=1 unresolved=1 oracle_sha256={sha256(ORACLE)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
