"""Exact reference ABI boundary; CPU bytes never claim native completion."""

import json

import pytest

from experiments.formal_campaign import h3_native_registration as reg
from experiments.formal_campaign.h3_owned_worker_carrier import (
    checked_reference,
    reference,
)
from experiments.native_attention_candidate.semantic_producer_registry import sha


def test_sdk_contract_raw_sha_converts_without_mutating_sdk_bytes(
    tmp_path, monkeypatch
):
    contract = tmp_path / "contract.json"
    contract.write_bytes(b'{"CPU_ABI_ONLY":true}\n')
    raw_ref = {"path": str(contract), "sha256": sha(contract.read_bytes())}
    launch = tmp_path / "launch.json"
    launch.write_text(json.dumps({"contracts": [raw_ref]}))
    guard = tmp_path / "guard.json"
    guard.write_text(json.dumps({"bundle_ids": ["CPU_ABI_ONLY"]}))
    phase = {
        "native_guard": reference(guard),
        "semantic_launch_spec": reference(launch),
    }
    monkeypatch.setattr(reg, "_phases", lambda start: [phase])
    before = launch.read_bytes()
    result = reg.source_artifacts({})
    ref = result[0]["contracts"][0]
    assert ref == dict(raw_ref, sha256="sha256:" + raw_ref["sha256"])
    assert checked_reference(ref) == contract
    assert launch.read_bytes() == before
    contract.write_bytes(b'{"CPU_ABI_ONLY":"changed"}\n')
    with pytest.raises(ValueError, match="bytes differ"):
        checked_reference(ref)
