#!/usr/bin/env python3
"""Verify the portable H2 real-source pre-launch prediction artifact."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

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
ARTIFACT = ROOT / "artifacts/h2-source-corpus-manager-predictions-20261013.json"
EXISTING = ROOT / "artifacts/h2-knorm-prelaunch-reject-20261013.json"


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def verify_command(record: dict[str, object]) -> None:
    stdout = record["stdout"]
    stderr = record["stderr"]
    assert isinstance(stdout, str) and isinstance(stderr, str)
    assert record["stdout_sha256"] == digest(stdout.encode())
    assert record["stderr_sha256"] == digest(stderr.encode())


def main() -> int:
    artifact = json.loads(resolve_original(ARTIFACT).read_text())
    campaign = json.loads((resolve_original(CORPUS / "campaign.json")).read_text())
    oracle = json.loads((resolve_original(CORPUS / "oracle.json")).read_text())
    assert artifact["campaign_sha256"] == digest(
        (resolve_original(CORPUS / "campaign.json")).read_bytes()
    )
    assert artifact["oracle_sha256"] == digest(
        (resolve_original(CORPUS / "oracle.json")).read_bytes()
    )
    assert oracle["campaign_sha256"] == artifact["campaign_sha256"]
    assert artifact["manager"] == {
        "commit": "08ab570fb00c4206b8d2c6c296ac9580b0f892bc",
        "tree": "7f49e308bd1e68cd51a1129ca09eb635bf4f0a3a",
    }

    expected_members = {
        member["id"]: member for case in campaign["cases"] for member in case["members"]
    }
    assert set(artifact["source_verification"]) == set(expected_members)
    for member_id, record in artifact["source_verification"].items():
        expected = expected_members[member_id]
        assert record["verified"] is True
        for name in ("commit_check", "blob_lookup", "manifest_read"):
            verify_command(record[name])
            assert record[name]["exit_code"] == 0
        assert record["blob_lookup"]["stdout"].strip() == expected["manifest_blob"]
        assert record["manifest_read"]["stdout_sha256"] == expected["manifest_sha256"]
        assert not Path(record["snapshot_path"]).is_absolute()
        snapshot = REPO / record["snapshot_path"]
        assert (
            digest(resolve_original(snapshot).read_bytes()) == record["snapshot_sha256"]
        )
        assert record["snapshot_sha256"] == expected["manifest_sha256"]

    expected = {
        "single-bidkv-vllm-0281": ("admit", "unavailable", False),
        "pair-profiler-kvcompress-vllm-0233": ("admit", "unavailable", False),
        "pair-diffspec-kvcompress-ascend-0251": ("conditional", "excluded", False),
        "three-vspec-knorm-profiler-vllm-0233": ("reject", "reject", True),
    }
    assert {item["case_id"] for item in artifact["predictions"]} == set(expected)
    for item in artifact["predictions"]:
        verify_command(item["command"])
        assert item["command"]["exit_code"] == 0
        result = json.loads(item["command"]["stdout"])
        assert result == item["result"]
        assert (
            result["oracle_decision"],
            result["prediction"],
            result["score_eligible"],
        ) == expected[item["case_id"]]
        assert result["host_launch_command_invoked"] is False
        assert result["runtime_claim"] is False
        assert result["performance_claim"] is False
        assert item["host_process_started"] is False
        assert item["host_processes_before"] == item["host_processes_after"] == []
        for snapshot_name in ("npu_before", "npu_after"):
            snapshot = item[snapshot_name]
            verify_command(snapshot)
            assert snapshot["exit_code"] == 0
            assert snapshot["no_running_processes"] is True
        assert not any(
            token in {"run", "formal-run", "serve"} for token in item["command"]["argv"]
        )

    existing = artifact["existing_incompatible_pair"]
    assert existing["sha256"] == digest(resolve_original(EXISTING).read_bytes())
    assert existing["manager_decision"] == existing["oracle_decision"] == "reject"
    assert artifact["confusion_matrix"] == {
        "abstained_definite_cases": ["pair-profiler-kvcompress-vllm-0233"],
        "excluded_cases": [
            "single-bidkv-vllm-0281",
            "pair-profiler-kvcompress-vllm-0233",
            "pair-diffspec-kvcompress-ascend-0251",
        ],
        "false_negative": 0,
        "false_positive": 0,
        "score_eligible_cases": 2,
        "true_negative": 2,
        "true_positive": 0,
    }
    assert artifact["metrics"] == {
        "precision": None,
        "recall": None,
        "status": "not-computable-no-score-eligible-manager-admit",
    }
    assert artifact["process_boundary"]["all_npu_snapshots_empty"] is True
    assert artifact["process_boundary"]["host_process_started"] is False
    assert artifact["h2_acceptance_complete"] is False
    print(digest(resolve_original(ARTIFACT).read_bytes()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
