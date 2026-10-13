#!/usr/bin/env python3
"""Verify the portable exact-stack KNorm pre-launch reject artifact."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ART = ROOT / "artifacts/h2-knorm-prelaunch-reject-20261013.json"
CORPUS = ROOT / "artifacts/h2-minimal-real-source-corpus-20261013"


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def main() -> int:
    a = json.loads(ART.read_text())
    campaign = json.loads((CORPUS / "campaign.json").read_text())
    status = json.loads((CORPUS / "status.json").read_text())
    assert a["source_review"]["decision"] == "reject"
    assert a["oracle"]["campaign_sha256"] == a["campaign_sha256"]
    assert a["formal_admission"]["status"] == "ADMITTED"
    assert a["formal_admission"]["score_eligible"] is True
    assert (
        a["summary"]["manager_decision"] == a["summary"]["oracle_decision"] == "reject"
    )
    assert status["case_count"] == len(campaign["cases"]) == 5
    assert status["manager_predictions_completed"] == 1
    assert status["metrics"] is None
    assert status["h2_acceptance_complete"] is False
    true_negatives = sum(
        c["score_role"] == "formal-true-negative" for c in campaign["cases"]
    )
    assert true_negatives == 1
    for order in a["orders"]:
        assert order["host_launch_command_invoked"] is False
        assert (
            order["npu_snapshot_count"] == 10
            and order["all_npu_snapshots_empty"] is True
        )
        assert order["host_processes_before_after"] == [[], []]
        evidence = order["formal_record"]["runtime_evidence"]
        assert evidence == {
            "cleanup_complete": True,
            "host_started": False,
            "model_loaded": False,
            "process_owned_observation": False,
            "receipt_sha256": order["receipt_sha256"],
            "workload_completed": False,
        }
        assert all(c["args"][0] not in {"run", "formal-run"} for c in order["commands"])
        assert [c["exit_code"] for c in order["commands"]] == [
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            2,
        ]
        last = order["commands"][-1]
        assert "implementation status: import_only" in last["stderr"]
        for c in order["commands"]:
            assert digest_bytes(c["stdout"].encode()) == c["stdout_sha256"]
            assert digest_bytes(c["stderr"].encode()) == c["stderr_sha256"]
    print(digest_bytes(ART.read_bytes()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
