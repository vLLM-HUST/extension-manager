from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from experiments.real_mod_composition.score_admission import (
    ROOT,
    _validate_oracle,
    assess,
)
from scripts.benchmark_inputs import resolve_original

CHECKED_R2 = (
    ROOT
    / "experiments/real_mod_composition/artifacts"
    / "h2-profiler-kvcompress-formal-r2-20261013"
)


def _bare(path: Path) -> str:
    return hashlib.sha256(resolve_original(path).read_bytes()).hexdigest()


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _fixture(
    root: Path, verdict: str = "admit"
) -> tuple[Path, Path, dict[str, object]]:
    root.mkdir()
    prior = root / "prior"
    prior.mkdir()
    (prior / "review.json").write_text("independent source review\n")
    (prior / "verify.py").write_text("# frozen verifier\n")
    prior_campaign = "a" * 64
    prior_receipt = {
        "schema": "ecpa-h2-independent-ownership-oracle-receipt/v1",
        "review": "review.json",
        "review_sha256": _bare(prior / "review.json"),
        "verifier": "verify.py",
        "verifier_sha256": _bare(prior / "verify.py"),
        "campaign_sha256": prior_campaign,
        "verdict": verdict,
        "last_verification": {"result": "PASS"},
    }
    prior_receipt_path = prior / "prior-receipt.json"
    _write(prior_receipt_path, prior_receipt)

    commits = {name: str(index) * 40 for index, name in enumerate("1234", 1)}
    trees = {name: chr(96 + index) * 40 for index, name in enumerate("1234", 1)}
    model = {
        "path": "/model",
        "dtype": "bfloat16",
        "max_model_len": 2048,
        "served_name_template": "formal-{order_id}",
    }
    workload = {
        "endpoint": "/v1/completions",
        "prompt": "ok",
        "max_tokens": 24,
        "temperature": 0,
        "seed": 1234,
    }
    campaign: dict[str, object] = {
        "campaign_revision": 2,
        "case_id": "pair",
        "predecessor_campaign": {
            "sha256": prior_campaign,
            "status": "excluded-fail-closed",
        },
        "model": model,
        "workload": workload,
        "host": {
            "tensor_parallel_size": 2,
            "core": {"commit": commits["3"]},
            "ascend": {"commit": commits["4"]},
        },
        "kvcompress": {"compression_threshold_tokens": 9216},
        "members": [
            {
                "id": "lifecycle_profiler",
                "commit": commits["1"],
                "tree": trees["1"],
            },
            {"id": "kvcompress", "commit": commits["2"], "tree": trees["2"]},
        ],
    }
    campaign_path = root / "campaign.json"
    _write(campaign_path, campaign)
    campaign_digest = _bare(campaign_path)
    sources = {}
    for index, name in enumerate(
        ("lifecycle_profiler", "kvcompress", "host_core", "host_ascend"), 1
    ):
        sources[name] = {
            "commit": commits[str(index)],
            "tree": trees[str(index)],
            "files": {f"source-{index}.py": "f" * 40},
        }
    oracle: dict[str, object] = {
        "schema": "ecpa-h2-independent-source-oracle/v2",
        "case_id": "pair",
        "verdict": verdict,
        "campaign": {"revision": 2, "sha256": campaign_digest},
        "prior_independent_receipt": {
            "path": str(prior_receipt_path),
            "sha256": _bare(prior_receipt_path),
            "review_sha256": prior_receipt["review_sha256"],
            "prior_campaign_sha256": prior_campaign,
        },
        "revision_2_assessment": {"source_ownership_changed": False},
        "frozen_runtime_inputs": {
            "model": model,
            "workload": workload,
            "tensor_parallel_size": 2,
            "compression_threshold_tokens": 9216,
        },
        "sources": sources,
        "ownership_decision": {"conflict": verdict == "reject"},
    }
    oracle_path = root / "oracle.json"
    _write(oracle_path, oracle)
    (root / "verify.py").write_text("# independent v2 verifier\n")
    receipt = {
        "schema": "ecpa-h2-independent-source-oracle-receipt/v2",
        "campaign_sha256": campaign_digest,
        "oracle": "oracle.json",
        "oracle_sha256": _bare(oracle_path),
        "verifier": "verify.py",
        "verifier_sha256": _bare(root / "verify.py"),
        "verdict": verdict,
        "verification": {"result": "PASS"},
    }
    _write(root / "oracle-receipt.json", receipt)
    return campaign_path, oracle_path, campaign


def _reseal_current_receipt(oracle_path: Path) -> None:
    receipt_path = oracle_path.parent / "oracle-receipt.json"
    receipt = json.loads(resolve_original(receipt_path).read_text())
    receipt["oracle_sha256"] = _bare(oracle_path)
    _write(receipt_path, receipt)


def test_checked_in_r2_real_pair_is_admitted_from_portable_copy(
    tmp_path: Path,
) -> None:
    root = tmp_path / "portable-r2"
    shutil.copytree(resolve_original(CHECKED_R2), root)
    runs = (
        root / "profiler-then-kvcompress",
        root / "kvcompress-then-profiler",
    )
    result = assess(
        root / "campaign.json",
        (),
        oracle_path=root / "oracle.json",
        planner_path=root / "planner/planner-receipt.json",
        record_paths=tuple(run / "formal-runtime-record.json" for run in runs),
        receipt_paths=tuple(run / "formal-runtime-receipt.json" for run in runs),
    )
    assert result["status"] == "ADMITTED"
    assert result["score_eligible"] is True
    assert result["oracle_sha256"] == (
        "sha256:5ea6f2ff4e89d8bddb0e69ca99d04ee00278d4a7f70396e5ac72f2632cf4c6d2"
    )
    assert result["oracle_decision"] == result["planner_decision"] == "admit"
    assert result["scope"] == {
        "compatible_host_execution": True,
        "compression_transaction": False,
        "performance": False,
    }
    assert [item["receipt_sha256"] for item in result["accepted_records"]] == [
        "sha256:c3da3a02a56d5d4d899694617d966832e83c00ecdbabb2ea5bd235a3819590b9",
        "sha256:055a3985d6ed5d8f7b13c5a3f73e2ed0db7bf788e945294573ffd53c86a3f9eb",
    ]


@pytest.mark.parametrize("verdict", ["admit", "reject"])
def test_v2_oracle_verifies_full_independent_chain(
    tmp_path: Path, verdict: str
) -> None:
    campaign_path, oracle_path, campaign = _fixture(tmp_path / "case", verdict)
    decision, digest = _validate_oracle(
        oracle_path, campaign, "sha256:" + _bare(campaign_path)
    )
    assert decision == verdict
    assert digest == "sha256:" + _bare(oracle_path)


@pytest.mark.parametrize(
    ("tamper", "message"),
    [
        ("campaign", "frozen campaign and case"),
        ("case", "frozen campaign and case"),
        ("receipt", "independent oracle receipt"),
        ("prior-review", "prior independent source receipt"),
        ("source", "campaign member lifecycle_profiler"),
    ],
)
def test_v2_oracle_tampering_fails_closed(
    tmp_path: Path, tamper: str, message: str
) -> None:
    campaign_path, oracle_path, campaign = _fixture(tmp_path / "case")
    oracle = json.loads(resolve_original(oracle_path).read_text())
    if tamper == "campaign":
        oracle["campaign"]["sha256"] = "0" * 64
    elif tamper == "case":
        oracle["case_id"] = "different"
    elif tamper == "prior-review":
        oracle["prior_independent_receipt"]["review_sha256"] = "0" * 64
    elif tamper == "source":
        oracle["sources"]["lifecycle_profiler"]["commit"] = "0" * 40
    else:
        receipt_path = oracle_path.parent / "oracle-receipt.json"
        receipt = json.loads(resolve_original(receipt_path).read_text())
        receipt["oracle_sha256"] = "0" * 64
        _write(receipt_path, receipt)
    if tamper != "receipt":
        _write(oracle_path, oracle)
        _reseal_current_receipt(oracle_path)
    with pytest.raises(ValueError, match=message):
        _validate_oracle(oracle_path, campaign, "sha256:" + _bare(campaign_path))
