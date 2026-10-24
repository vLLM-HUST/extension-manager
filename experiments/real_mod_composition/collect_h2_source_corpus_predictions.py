#!/usr/bin/env python3
# ruff: noqa: E501
"""Collect source identity and Manager-only H2 pre-launch predictions."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_CHECKOUT = Path(__file__).resolve().parents[2]
if (_CHECKOUT / "BENCHMARK_ORIGINALS.json").is_file():
    sys.path.insert(0, str(_CHECKOUT))
    from scripts.benchmark_inputs import resolve_original
else:

    def resolve_original(path: Path) -> Path:
        return path


ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent
CORPUS = ROOT / "artifacts/h2-minimal-real-source-corpus-20261013"
EXISTING_REJECT = ROOT / "artifacts/h2-knorm-prelaunch-reject-20261013.json"
OUTPUT = ROOT / "artifacts/h2-source-corpus-manager-predictions-20261013.json"
EVALUATOR = ROOT / "evaluate_h2_source_corpus.py"

SOURCE_REPOSITORIES = {
    "bidkv": Path("/root/ecpa-h2-corpus-src-bidkv"),
    "diffspec": Path("/root/ecpa-h2-corpus-src-diffspec"),
    "knorm": Path("/root/ecpa-h2-sources/vllm-hust-knorm"),
    "kvcompress": Path("/root/ecpa-h2-sources/vllm-ascend-kvcompress-hust"),
    "lifecycle_profiler": Path("/root/ecpa-h2-corpus-src-profiler"),
    "vspec": Path("/root/ecpa-h2-corpus-src-vspec"),
}
NEW_CASES = (
    "single-bidkv-vllm-0281",
    "pair-profiler-kvcompress-vllm-0233",
    "pair-diffspec-kvcompress-ascend-0251",
    "three-vspec-knorm-profiler-vllm-0233",
)


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def command(argv: list[str], *, env: dict[str, str] | None = None) -> dict[str, Any]:
    completed = subprocess.run(argv, capture_output=True, env=env, check=False)
    return {
        "argv": argv,
        "exit_code": completed.returncode,
        "stdout": completed.stdout.decode(errors="replace"),
        "stdout_sha256": digest(completed.stdout),
        "stderr": completed.stderr.decode(errors="replace"),
        "stderr_sha256": digest(completed.stderr),
    }


def npu_snapshot() -> dict[str, Any]:
    record = command(["npu-smi", "info"])
    record["no_running_processes"] = (
        record["exit_code"] == 0
        and "No running processes found in NPU 3" in record["stdout"]
        and "No running processes found in NPU 6" in record["stdout"]
    )
    return record


def host_processes() -> list[dict[str, Any]]:
    found = []
    markers = (
        "vllm.entrypoints.openai.api_server",
        "vllm serve",
        "VLLM::EngineCore",
    )
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
    campaign_bytes = (resolve_original(CORPUS / "campaign.json")).read_bytes()
    oracle_bytes = (resolve_original(CORPUS / "oracle.json")).read_bytes()
    campaign = json.loads(campaign_bytes)
    existing_bytes = resolve_original(EXISTING_REJECT).read_bytes()
    existing = json.loads(existing_bytes)
    manager_commit = subprocess.check_output(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"], text=True
    ).strip()
    manager_tree = subprocess.check_output(
        ["git", "-C", str(REPO), "rev-parse", "HEAD^{tree}"], text=True
    ).strip()
    if manager_commit != "08ab570fb00c4206b8d2c6c296ac9580b0f892bc":
        raise ValueError("collector must run against the frozen PR #125 Manager commit")

    source_records: dict[str, Any] = {}
    seen: set[str] = set()
    for case in campaign["cases"]:
        for member in case["members"]:
            member_id = member["id"]
            if member_id in seen:
                continue
            seen.add(member_id)
            source = SOURCE_REPOSITORIES[member_id]
            commit_check = command(
                [
                    "git",
                    "-C",
                    str(source),
                    "cat-file",
                    "-e",
                    f"{member['commit']}^{{commit}}",
                ]
            )
            blob = command(
                [
                    "git",
                    "-C",
                    str(source),
                    "rev-parse",
                    f"{member['commit']}:{member['manifest_path']}",
                ]
            )
            manifest = command(
                [
                    "git",
                    "-C",
                    str(source),
                    "show",
                    f"{member['commit']}:{member['manifest_path']}",
                ]
            )
            snapshot = ROOT / "source_manifests" / f"{member_id}.json"
            verified = (
                commit_check["exit_code"]
                == blob["exit_code"]
                == manifest["exit_code"]
                == 0
                and blob["stdout"].strip() == member["manifest_blob"]
                and manifest["stdout_sha256"] == member["manifest_sha256"]
                and digest(resolve_original(snapshot).read_bytes())
                == member["manifest_sha256"]
                and resolve_original(snapshot).read_bytes()
                == manifest["stdout"].encode()
            )
            source_records[member_id] = {
                "verified": verified,
                "repository_path": str(source),
                "commit_check": commit_check,
                "blob_lookup": blob,
                "manifest_read": manifest,
                "snapshot_path": str(snapshot.relative_to(REPO)),
                "snapshot_sha256": digest(resolve_original(snapshot).read_bytes()),
            }
            if not verified:
                raise ValueError(f"source verification failed for {member_id}")

    start_npu = npu_snapshot()
    start_hosts = host_processes()
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO / "src")
    predictions: list[dict[str, Any]] = []
    for case_id in NEW_CASES:
        before_npu = npu_snapshot()
        before_hosts = host_processes()
        run = command([sys.executable, str(EVALUATOR), case_id], env=env)
        after_hosts = host_processes()
        after_npu = npu_snapshot()
        if run["exit_code"] != 0:
            raise ValueError(f"Manager prediction failed for {case_id}")
        result = json.loads(run["stdout"])
        predictions.append(
            {
                "case_id": case_id,
                "command": run,
                "result": result,
                "npu_before": before_npu,
                "npu_after": after_npu,
                "host_processes_before": before_hosts,
                "host_processes_after": after_hosts,
                "host_process_started": sorted(after_hosts, key=lambda x: x["pid"])
                != sorted(before_hosts, key=lambda x: x["pid"]),
            }
        )

    end_hosts = host_processes()
    end_npu = npu_snapshot()
    existing_case = next(
        case
        for case in campaign["cases"]
        if case["case_id"] == "pair-kvcompress-knorm-host973d"
    )
    all_results = [item["result"] for item in predictions] + [
        {
            "case_id": existing_case["case_id"],
            "category": existing_case["category"],
            "oracle_decision": "reject",
            "prediction": "reject",
            "score_eligible": True,
            "evidence_sha256": digest(existing_bytes),
        }
    ]
    scored = [item for item in all_results if item["score_eligible"]]
    counts = {
        "true_positive": sum(
            item["oracle_decision"] == item["prediction"] == "admit" for item in scored
        ),
        "true_negative": sum(
            item["oracle_decision"] == item["prediction"] == "reject" for item in scored
        ),
        "false_positive": sum(
            item["oracle_decision"] == "reject" and item["prediction"] == "admit"
            for item in scored
        ),
        "false_negative": sum(
            item["oracle_decision"] == "admit" and item["prediction"] == "reject"
            for item in scored
        ),
    }
    positive_predictions = counts["true_positive"] + counts["false_positive"]
    oracle_positives = counts["true_positive"] + counts["false_negative"]
    metrics = {
        "precision": (
            counts["true_positive"] / positive_predictions
            if positive_predictions
            else None
        ),
        "recall": counts["true_positive"] / oracle_positives
        if oracle_positives
        else None,
        "status": "not-computable-no-score-eligible-manager-admit",
    }
    artifact = {
        "schema": "ecpa-h2-source-corpus-manager-predictions/v1",
        "captured_utc": datetime.now(timezone.utc).isoformat(),
        "classification": "real-source-manager-prelaunch-predictions-not-runtime",
        "manager": {"commit": manager_commit, "tree": manager_tree},
        "campaign_sha256": digest(campaign_bytes),
        "oracle_sha256": digest(oracle_bytes),
        "source_verification": source_records,
        "predictions": predictions,
        "existing_incompatible_pair": {
            "artifact": str(EXISTING_REJECT.relative_to(REPO)),
            "sha256": digest(existing_bytes),
            "formal_admission_sha256": existing["formal_admission_sha256"],
            "manager_decision": existing["summary"]["manager_decision"],
            "oracle_decision": existing["summary"]["oracle_decision"],
        },
        "confusion_matrix": {
            **counts,
            "score_eligible_cases": len(scored),
            "abstained_definite_cases": [
                item["case_id"]
                for item in all_results
                if item["oracle_decision"] in {"admit", "reject"}
                and not item["score_eligible"]
                and item["category"] != "single_mod"
            ],
            "excluded_cases": [
                item["case_id"]
                for item in all_results
                if item["prediction"] in {"excluded", "unavailable"}
            ],
        },
        "metrics": metrics,
        "process_boundary": {
            "npu_start": start_npu,
            "npu_end": end_npu,
            "host_processes_start": start_hosts,
            "host_processes_end": end_hosts,
            "all_npu_snapshots_empty": all(
                snap["no_running_processes"]
                for item in predictions
                for snap in (item["npu_before"], item["npu_after"])
            )
            and start_npu["no_running_processes"]
            and end_npu["no_running_processes"],
            "host_process_started": any(
                item["host_process_started"] for item in predictions
            ),
        },
        "h2_acceptance_complete": False,
        "remaining_acceptance_gaps": [
            "no score-eligible Manager admit exists in this frozen old-source corpus",
            "the old profiler/kvcompress case lacks a bound vLLM 0.23.3 request-lifecycle-events capability receipt",
            "precision and recall are undefined with zero score-eligible admit predictions",
            "pre-launch predictions do not replace formal runtime evidence",
            "the conditional pair still needs exact physical ownership and install-order review",
        ],
        "nonclaims": [
            "not runtime execution",
            "not performance",
            "not a complete H2 precision/recall result",
            "no unavailable or host-range-mismatch case is forced into a binary label",
        ],
    }
    write_new_output(OUTPUT, json.dumps(artifact, indent=2, sort_keys=True) + "\n")
    print(digest(resolve_original(OUTPUT).read_bytes()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
