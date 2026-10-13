from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from vllm_hust_ext.providers.base import assess_compatibility

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "experiments" / "real_mod_composition" / "audit.py"
SPEC = importlib.util.spec_from_file_location("real_mod_composition_audit", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
audit_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit_module)


def test_source_manifests_are_exact_git_blobs() -> None:
    manifests = audit_module.load_sources()
    assert len(manifests) == 7
    assert {manifest.schema_version for manifest in manifests.values()} <= {
        "0.3",
        "0.3-experimental",
    }


def test_preflight_keeps_source_rejects_and_candidates_distinct() -> None:
    results = {item["case_id"]: item for item in audit_module.audit()}
    assert set(results) == {
        "vspec-knorm-profiler-vllm-0.23.3",
        "bidkv-latchmoe-vllm-0.28.1rc1.dev319",
        "profiler-bidkv-vllm-0.28.1rc1.dev319",
        "diffspec-vspec-vllm-0.25.1rc1",
        "diffspec-vspec-vllm-0.28.1rc1.dev319",
        "kvcompress-knorm-vllm-0.23.3",
    }
    assert results["vspec-knorm-profiler-vllm-0.23.3"]["preflight_result"] == (
        "candidate-only"
    )
    assert results["bidkv-latchmoe-vllm-0.28.1rc1.dev319"]["preflight_result"] == (
        "candidate-only"
    )
    assert results["profiler-bidkv-vllm-0.28.1rc1.dev319"]["host_mismatches"] == [
        {"member": "lifecycle_profiler", "reason": "host-version"}
    ]
    assert results["diffspec-vspec-vllm-0.25.1rc1"]["host_mismatches"] == []
    assert results["diffspec-vspec-vllm-0.25.1rc1"]["protocol_mismatches"] == [
        {
            "member": "diffspec",
            "protocol": "vllm.general_plugins",
            "reason": "protocol-version",
        }
    ]
    assert results["diffspec-vspec-vllm-0.28.1rc1.dev319"]["host_mismatches"] == [
        {"member": "vspec", "reason": "host-version"}
    ]
    overlap = results["kvcompress-knorm-vllm-0.23.3"]
    assert overlap["preflight_result"] == "candidate-only"
    assert overlap["same_name_resource_conflicts"] == []
    assert overlap["physical_ownership_observation"]["status"] == "unknown"
    assert overlap["physical_ownership_observation"]["oracle_label"] is None
    required_orders = overlap["physical_ownership_observation"][
        "installation_orders_required"
    ]
    assert required_orders == [
        ["kvcompress", "knorm"],
        ["knorm", "kvcompress"],
    ]
    assert all(item["runtime_effective"] == "unmeasured" for item in results.values())


def test_manager_rejects_both_sides_of_diffspec_vspec_core_skew() -> None:
    manifests = audit_module.load_sources()
    diffspec_result, diffspec_evidence = assess_compatibility(
        manifests["diffspec"],
        {
            "host_version": "0.25.1rc1",
            "host_api_version": "1",
            "protocol_versions": {
                "vllm.general_plugins": "0.25.1rc1",
                "vllm-ascend.runtime-patch-surface": "0.25.1rc1",
            },
        },
    )
    assert diffspec_result is False
    assert (
        "protocol vllm.general_plugins 0.25.1rc1 is outside" in (diffspec_evidence[0])
    )
    vspec_result, vspec_evidence = assess_compatibility(
        manifests["vspec"], {"host_version": "0.28.1rc1.dev319"}
    )
    assert vspec_result is False
    assert "host version 0.28.1rc1.dev319 is outside" in vspec_evidence[0]


def test_tampered_snapshot_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_dir = tmp_path / "source_manifests"
    source_dir.mkdir()
    index = audit_module._load(SCRIPT.parent / "sources.json")
    (tmp_path / "sources.json").write_text(json.dumps(index), encoding="utf-8")
    for source in index["sources"]:
        original = SCRIPT.parent / source["snapshot_path"]
        (source_dir / original.name).write_bytes(original.read_bytes())
    (source_dir / "knorm.json").write_bytes(b"{}\n")
    monkeypatch.setattr(audit_module, "HERE", tmp_path)
    with pytest.raises(ValueError, match="Git blob mismatch"):
        audit_module.load_sources()


def test_tampered_physical_owner_excerpt_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observations_path = SCRIPT.parent / "ownership_observations.json"
    observations = json.loads(observations_path.read_text())
    observations["observations"][0]["sources"][0]["excerpt"] += "# tampered\n"
    (tmp_path / "ownership_observations.json").write_text(
        json.dumps(observations), encoding="utf-8"
    )
    monkeypatch.setattr(audit_module, "HERE", tmp_path)
    with pytest.raises(ValueError, match="excerpt digest mismatch"):
        audit_module.load_ownership_observations({"kvcompress", "knorm"})
