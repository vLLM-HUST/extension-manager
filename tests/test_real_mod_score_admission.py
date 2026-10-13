from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from experiments.real_mod_composition.score_admission import (
    DEFAULT_CAMPAIGN,
    DEFAULT_PREFLIGHTS,
    assess,
)


def test_checked_preflights_are_explicitly_ineligible() -> None:
    result = assess(DEFAULT_CAMPAIGN, DEFAULT_PREFLIGHTS)
    assert result["status"] == "INCOMPLETE"
    assert result["score_eligible"] is False
    assert result["metrics"] is None
    assert result["blockers"] == [
        "formal-real-runtime-records-missing",
        "independent-oracle-missing",
        "installation-order-coverage-incomplete",
    ]
    assert len(result["excluded_preflights"]) == 3
    assert all(
        item["reason"] == "preflight-is-not-formal-real"
        for item in result["excluded_preflights"]
    )


def test_cannot_relabel_preflight_as_score_eligible(tmp_path: Path) -> None:
    artifact = json.loads(DEFAULT_PREFLIGHTS[0].read_text())
    artifact["score_eligible"] = True
    changed = tmp_path / "changed.json"
    changed.write_text(json.dumps(artifact))
    with pytest.raises(ValueError, match="does not fail closed"):
        assess(DEFAULT_CAMPAIGN, (changed,))


def test_formal_record_must_bind_oracle_and_campaign(tmp_path: Path) -> None:
    record = {
        "schema": "ecpa-h2-formal-runtime-record/v1",
        "classification": "formal-real-host-composition",
        "case_id": "kvcompress-knorm-vllm-0.23.3",
        "order_id": "kvcompress-then-knorm",
        "campaign_sha256": "sha256:" + "0" * 64,
        "oracle_sha256": "sha256:" + "1" * 64,
        "planner_decision": "admit",
        "runtime_evidence": {
            "host_started": True,
            "model_loaded": True,
            "workload_completed": True,
            "process_owned_observation": True,
            "cleanup_complete": True,
            "receipt_sha256": "sha256:" + "2" * 64,
        },
    }
    path = tmp_path / "record.json"
    path.write_text(json.dumps(record))
    with pytest.raises(ValueError, match="campaign"):
        assess(DEFAULT_CAMPAIGN, DEFAULT_PREFLIGHTS, record_paths=(path,))


def test_complete_bound_pair_can_enter_score(tmp_path: Path) -> None:
    campaign_digest = (
        "sha256:" + hashlib.sha256(DEFAULT_CAMPAIGN.read_bytes()).hexdigest()
    )
    oracle = {
        "schema": "ecpa-h2-real-mod-oracle/v1",
        "status": "automated-independent-reviewed",
        "campaign_sha256": campaign_digest,
        "review": {"kind": "automated-independent", "verdict": "PASS"},
        "labels": [{"case_id": "kvcompress-knorm-vllm-0.23.3", "decision": "admit"}],
    }
    oracle_path = tmp_path / "oracle.json"
    oracle_path.write_text(json.dumps(oracle, sort_keys=True))
    oracle_digest = "sha256:" + hashlib.sha256(oracle_path.read_bytes()).hexdigest()

    records = []
    for order_id in ("kvcompress-then-knorm", "knorm-then-kvcompress"):
        record = {
            "schema": "ecpa-h2-formal-runtime-record/v1",
            "classification": "formal-real-host-composition",
            "case_id": "kvcompress-knorm-vllm-0.23.3",
            "order_id": order_id,
            "campaign_sha256": campaign_digest,
            "oracle_sha256": oracle_digest,
            "planner_decision": "admit",
            "runtime_evidence": {
                "host_started": True,
                "model_loaded": True,
                "workload_completed": True,
                "process_owned_observation": True,
                "cleanup_complete": True,
                "receipt_sha256": "sha256:" + "2" * 64,
            },
        }
        path = tmp_path / f"{order_id}.json"
        path.write_text(json.dumps(record))
        records.append(path)

    result = assess(
        DEFAULT_CAMPAIGN,
        DEFAULT_PREFLIGHTS,
        oracle_path=oracle_path,
        record_paths=tuple(records),
    )
    assert result["status"] == "ADMITTED"
    assert result["score_eligible"] is True
    assert result["blockers"] == []
