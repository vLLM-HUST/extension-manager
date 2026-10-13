#!/usr/bin/env python3
"""Verify the real-source H2 augmentation freeze and evidence ordering."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent.parent
OUT = ROOT / "artifacts/h2-real-source-augmentation-20261013"
ARTIFACT = OUT / "augmentation.json"


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def blob_id(value: bytes) -> str:
    return hashlib.sha1(f"blob {len(value)}\0".encode() + value).hexdigest()  # noqa: S324


def main() -> int:
    artifact = json.loads(ARTIFACT.read_text())
    authorities = artifact["source_authorities"]
    assert authorities["source_snapshots_sha256"] == sha256(
        REPO / "docs/corpus/source-snapshots.json"
    )
    assert authorities["workshop_mods_sha256"] == sha256(
        REPO / "docs/corpus/workshop-mods.json"
    )
    assert authorities["contract_cases_sha256"] == sha256(
        REPO / "experiments/contract_planner/cases.json"
    )
    assert authorities["contract_oracle_sha256"] == sha256(
        REPO / "experiments/contract_planner/oracle.json"
    )
    assert authorities["contract_oracle_review"]["verdict"] == "MERGE"

    assert len(artifact["sources"]) == 8
    for source in artifact["sources"].values():
        assert not Path(source["snapshot_path"]).is_absolute()
        path = REPO / source["snapshot_path"]
        raw = path.read_bytes()
        manifest = json.loads(raw)
        assert sha256(path) == source["manifest_sha256"]
        assert blob_id(raw) == source["manifest_blob"]
        assert manifest["schema_version"] == source["manifest_schema"]
        assert manifest["extension_id"] == source["bundle_id"]

    prior = artifact["preexisting_oracle_cases"]
    assert len(prior) == 2
    for case in prior:
        assert case["oracle"]["decision"] == "admit"
        assert case["oracle_frozen_before_this_prediction"] is True
        assert case["prediction"]["declared_surface_decision"] == "admit"
        assert case["prediction"]["qualification_decision"] == "unavailable"
        assert case["prediction"]["runtime_claim"] is False
        assert case["prediction"]["performance_claim"] is False
        assert case["score_eligible"] is False

    pending = artifact["oracle_pending_cases"]
    assert len(pending) == 4
    assert all(case["score_eligible"] is False for case in pending)
    assert all(case["planner_status"].startswith("not-run") for case in pending)
    assert {
        case["case_id"]
        for case in pending
        if case["oracle_status"].startswith("pending")
    } == {
        "pending-communication-process-carriers",
        "pending-worker-carrier-overlap",
    }
    assert artifact["coverage"]["CLI/config-collision"].startswith("gap:")
    assert artifact["coverage"]["external-authority-conflict"].startswith("gap:")
    assert "no pending candidate has a Manager prediction" in artifact["nonclaims"]
    print(sha256(ARTIFACT))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
