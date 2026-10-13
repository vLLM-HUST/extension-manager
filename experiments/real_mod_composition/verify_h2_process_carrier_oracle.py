#!/usr/bin/env python3
"""Verify the source-bound process-carrier oracle without planner output."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ARTIFACT = (
    ROOT
    / "experiments/real_mod_composition/artifacts/h2-process-carrier-oracle-20261013"
)
ORACLE = ARTIFACT / "oracle.json"
RECEIPT = ARTIFACT / "review-receipt.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-root",
        type=Path,
        help="optional directory containing unified, qos, obs, and split checkouts",
    )
    args = parser.parse_args()
    oracle = json.loads(ORACLE.read_text(encoding="utf-8"))
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))

    require(receipt["oracle_sha256"] == sha256(ORACLE), "oracle digest")
    require(receipt["verifier_sha256"] == sha256(Path(__file__)), "verifier digest")
    require(receipt["verdict"] == "PASS", "review verdict")
    require(
        oracle["oracle_summary"]
        == {
            "admit": 0,
            "reject": 0,
            "abstain": 2,
            "score_eligible": 0,
            "runtime_claim": False,
            "performance_claim": False,
        },
        "oracle summary",
    )
    require(
        {case["case_id"] for case in oracle["cases"]}
        == {
            "pending-communication-process-carriers",
            "pending-worker-carrier-overlap",
        },
        "case identities",
    )
    require(
        all(
            case["decision"] == "abstain" and not case["score_eligible"]
            for case in oracle["cases"]
        ),
        "abstain decisions",
    )
    for source in oracle["sources"].values():
        snapshot = Path(source["snapshot"])
        require(not snapshot.is_absolute(), "portable snapshot path")
        snapshot_path = ROOT / snapshot
        manifest_path = next(
            path
            for path in source["files"]
            if path.endswith("vllm-hust-extension-v0.2.json")
        )
        require(
            sha256(snapshot_path) == source["files"][manifest_path]["sha256"],
            "snapshot digest",
        )

    if args.source_root:
        aliases = {
            "unified-communication": "unified",
            "qos-scheduler": "qos",
            "kv-transfer-observability": "obs",
            "split-batch-full-graph": "split",
        }
        for name, source in oracle["sources"].items():
            repo = args.source_root / aliases[name]
            require(
                git(repo, "rev-parse", f"{source['commit']}^{{commit}}")
                == source["commit"],
                f"{name} commit",
            )
            require(
                git(repo, "rev-parse", f"{source['commit']}^{{tree}}")
                == source["tree"],
                f"{name} tree",
            )
            for path, evidence in source["files"].items():
                require(
                    git(repo, "rev-parse", f"{source['commit']}:{path}")
                    == evidence["blob"],
                    f"{name} blob {path}",
                )
                data = subprocess.check_output(
                    ["git", "-C", str(repo), "show", f"{source['commit']}:{path}"]
                )
                require(
                    hashlib.sha256(data).hexdigest() == evidence["sha256"],
                    f"{name} SHA256 {path}",
                )

    print(f"PASS cases=2 abstain=2 oracle_sha256={sha256(ORACLE)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
