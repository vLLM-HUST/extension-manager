from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from experiments.real_mod_composition.score_admission import (
    DEFAULT_CAMPAIGN,
    DEFAULT_PREFLIGHTS,
    ROOT,
    assess,
)
from scripts.benchmark_inputs import resolve_original

FORMAL = (
    ROOT
    / "experiments/real_mod_composition/artifacts"
    / "h2-profiler-kvcompress-formal-20261013"
)


def _sha(path: Path) -> str:
    return "sha256:" + hashlib.sha256(resolve_original(path).read_bytes()).hexdigest()


def _paths(root: Path) -> tuple[tuple[Path, ...], tuple[Path, ...]]:
    runs = (root / "profiler-then-kvcompress", root / "kvcompress-then-profiler")
    return (
        tuple(run / "formal-runtime-record.json" for run in runs),
        tuple(run / "formal-runtime-receipt.json" for run in runs),
    )


def _assess_formal(root: Path) -> dict[str, object]:
    records, receipts = _paths(root)
    return assess(
        root / "campaign.json",
        (),
        oracle_path=root / "oracle.json",
        planner_path=root / "planner/planner-receipt.json",
        record_paths=records,
        receipt_paths=receipts,
    )


def _reseal_run(run: Path) -> None:
    """Update hashes so tamper tests reach semantic evidence checks."""
    manifest_path = run / "sha256.json"
    manifest = json.loads(resolve_original(manifest_path).read_text())
    for name in manifest:
        manifest[name] = _sha(run / name).removeprefix("sha256:")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    receipt_path = run / "formal-runtime-receipt.json"
    receipt = json.loads(resolve_original(receipt_path).read_text())
    receipt["raw_manifest_sha256"] = _sha(manifest_path)
    receipt["raw_result_sha256"] = _sha(run / "result.json")
    receipt["request_sha256"] = _sha(run / "request.json")
    receipt["response_sha256"] = _sha(run / "response.json")
    receipt["npu_after_sha256"] = _sha(run / "npu-after.txt")
    trace = run / receipt["process_owned_observation"]["path"]
    receipt["process_owned_observation"]["sha256"] = _sha(trace)
    receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    record_path = run / "formal-runtime-record.json"
    record = json.loads(resolve_original(record_path).read_text())
    record["runtime_evidence"]["receipt_sha256"] = _sha(receipt_path)
    record_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")


def _align_fixture_campaign(root: Path) -> None:
    """Build a valid synthetic fixture without altering the frozen real evidence."""
    campaign_path = root / "campaign.json"
    campaign = json.loads(resolve_original(campaign_path).read_text())
    campaign["model"]["served_name_template"] = "ecpa-h2-{order_id}"
    campaign_path.write_text(json.dumps(campaign, indent=2, sort_keys=True) + "\n")
    campaign_digest = _sha(campaign_path)
    oracle_path = root / "oracle.json"
    oracle = json.loads(resolve_original(oracle_path).read_text())
    oracle["campaign_sha256"] = campaign_digest
    oracle_path.write_text(json.dumps(oracle, indent=2, sort_keys=True) + "\n")
    oracle_digest = _sha(oracle_path)
    planner_path = root / "planner/planner-receipt.json"
    planner = json.loads(resolve_original(planner_path).read_text())
    planner["campaign_sha256"] = campaign_digest
    planner_path.write_text(json.dumps(planner, indent=2, sort_keys=True) + "\n")
    planner_digest = _sha(planner_path)
    for run in (root / "profiler-then-kvcompress", root / "kvcompress-then-profiler"):
        result_path = run / "result.json"
        result = json.loads(resolve_original(result_path).read_text())
        result["formal_inputs"]["campaign_sha256"] = campaign_digest
        result["formal_inputs"]["oracle_sha256"] = oracle_digest
        result["formal_inputs"]["planner_receipt_sha256"] = planner_digest
        result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
        receipt_path = run / "formal-runtime-receipt.json"
        receipt = json.loads(resolve_original(receipt_path).read_text())
        receipt["campaign_sha256"] = campaign_digest
        receipt["oracle_sha256"] = oracle_digest
        receipt["planner_receipt_sha256"] = planner_digest
        receipt_path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        record_path = run / "formal-runtime-record.json"
        record = json.loads(resolve_original(record_path).read_text())
        record["campaign_sha256"] = campaign_digest
        record["oracle_sha256"] = oracle_digest
        record_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
        _reseal_run(run)


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


def test_cannot_relabel_preflight_as_score_eligible(tmp_path: Path) -> None:
    artifact = json.loads(resolve_original(DEFAULT_PREFLIGHTS[0]).read_text())
    artifact["score_eligible"] = True
    changed = tmp_path / "changed.json"
    changed.write_text(json.dumps(artifact))
    with pytest.raises(ValueError, match="does not fail closed"):
        assess(DEFAULT_CAMPAIGN, (changed,))


def test_record_requires_explicit_receipt() -> None:
    record = FORMAL / "profiler-then-kvcompress/formal-runtime-record.json"
    with pytest.raises(ValueError, match="explicit runtime receipt"):
        assess(FORMAL / "campaign.json", (), record_paths=(record,))


def test_checked_in_pair_fails_closed_on_unbound_planner() -> None:
    with pytest.raises(ValueError, match="does not bind the frozen campaign"):
        _assess_formal(FORMAL)


def test_source_bound_pair_with_matching_frozen_workload_is_admitted(
    tmp_path: Path,
) -> None:
    copied = tmp_path / "formal"
    shutil.copytree(resolve_original(FORMAL), copied)
    _align_fixture_campaign(copied)
    result = _assess_formal(copied)
    assert result["status"] == "ADMITTED"
    assert result["score_eligible"] is True
    assert result["blockers"] == []
    assert result["scope"] == {
        "compatible_host_execution": True,
        "compression_transaction": False,
        "performance": False,
    }
    assert {item["order_id"] for item in result["accepted_records"]} == {
        "profiler-then-kvcompress",
        "kvcompress-then-profiler",
    }
    assert all(
        item["runtime_evidence_recomputed"]["cleanup_complete"]
        for item in result["accepted_records"]
    )


def test_planner_command_bytes_are_rehashed(tmp_path: Path) -> None:
    copied = tmp_path / "formal"
    shutil.copytree(resolve_original(FORMAL), copied)
    _align_fixture_campaign(copied)
    with (copied / "planner/manager-07-stdout.bin").open("ab") as stream:
        stream.write(b"tamper")
    with pytest.raises(ValueError, match="planner stdout artifact digest mismatch"):
        _assess_formal(copied)


def test_planner_campaign_binding_is_recomputed(tmp_path: Path) -> None:
    copied = tmp_path / "formal"
    shutil.copytree(resolve_original(FORMAL), copied)
    _align_fixture_campaign(copied)
    planner_path = copied / "planner/planner-receipt.json"
    planner = json.loads(resolve_original(planner_path).read_text())
    planner["campaign_sha256"] = "sha256:" + "0" * 64
    planner_path.write_text(json.dumps(planner))
    with pytest.raises(ValueError, match="does not bind the frozen campaign"):
        _assess_formal(copied)


@pytest.mark.parametrize(
    "tamper",
    [
        "request-prompt",
        "trace-pid",
        "engine-log",
        "npu-cleanup",
        "cleanup-port",
        "cleanup-survivor",
        "cleanup-npu-result",
    ],
)
def test_resealed_boolean_relabel_cannot_forge_runtime(
    tmp_path: Path, tamper: str
) -> None:
    copied = tmp_path / "formal"
    shutil.copytree(resolve_original(FORMAL), copied)
    _align_fixture_campaign(copied)
    run = copied / "profiler-then-kvcompress"
    receipt = json.loads(
        (resolve_original(run / "formal-runtime-receipt.json")).read_text()
    )
    if tamper == "request-prompt":
        request = run / "request.json"
        payload = json.loads(resolve_original(request).read_text())
        payload["prompt"] = "forged"
        request.write_text(json.dumps(payload))
        expected = "frozen workload prompt"
    elif tamper == "trace-pid":
        trace = run / receipt["process_owned_observation"]["path"]
        lines = [
            json.loads(line)
            for line in resolve_original(trace).read_text().splitlines()
        ]
        lines[0]["pid"] += 1
        trace.write_text(
            "".join(json.dumps(line, sort_keys=True) + "\n" for line in lines)
        )
        expected = "not process-owned"
    elif tamper == "engine-log":
        stdout = run / "stdout.bin"
        stdout.write_text(
            resolve_original(stdout)
            .read_text()
            .replace("Ascend KV compression scheduler bound", "forged scheduler bound")
        )
        expected = "KVCompress binding"
    elif tamper == "npu-cleanup":
        npu = run / "npu-after.txt"
        npu.write_text(
            resolve_original(npu)
            .read_text()
            .replace(
                "No running processes found in NPU 6", "Process 999 still owns NPU 6"
            )
        )
        expected = "cleanup"
    else:
        result_path = run / "result.json"
        result = json.loads(resolve_original(result_path).read_text())
        if tamper == "cleanup-port":
            result["port_refused_after_stop"] = False
        elif tamper == "cleanup-survivor":
            result["surviving_owned_processes"] = [{"pid": 999}]
        else:
            result["allocated_npu_process_tables_empty"] = False
        result_path.write_text(json.dumps(result))
        expected = "cleanup"
    _reseal_run(run)
    with pytest.raises(ValueError, match=expected):
        _assess_formal(copied)
