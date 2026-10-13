"""Audit real sealed bytes without inventing a semantic producer."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from experiments.exposure_gate.semantic_obligation_gap import PACKAGE, verify_gap

ROOT = Path(__file__).resolve().parents[1]


def test_actual_sealed_invocation_is_not_semantic_admission():
    result = verify_gap(ROOT / PACKAGE)
    assert result["historical_qualification"]["real_model_completions"] == 1
    assert (
        result["historical_qualification"]["worker_invocation_coverage_complete"] == 1
    )
    assert result["formal_traffic_admissible"] is False
    assert result["runtime_effectiveness"] is None
    assert result["semantic_obligation_status"] == "unverified"
    assert all(item["event"] == "invoked" for item in result["observed_obligations"])
    assert len(result["missing_edges"]) == 6


@pytest.mark.parametrize(
    "field", ["formal_result", "performance_result", "effective_semantics_result"]
)
def test_summary_cannot_promote_invocation_archive(tmp_path, field):
    package = tmp_path / "qualification"
    shutil.copytree(ROOT / PACKAGE, package)
    path = package / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest[field] = True
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError, match="promotes semantic evidence"):
        verify_gap(package)


def test_gap_refuses_changed_raw_archive(tmp_path):
    package = tmp_path / "qualification"
    shutil.copytree(ROOT / PACKAGE, package)
    path = package / "retained.tar.gz"
    path.write_bytes(path.read_bytes() + b"unbound")
    with pytest.raises(ValueError, match="retained archive changed"):
        verify_gap(package)
