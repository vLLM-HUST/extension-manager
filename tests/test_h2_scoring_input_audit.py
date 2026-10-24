from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from experiments.real_mod_composition.h2_scoring_input_audit import AUDIT, verify
from scripts.benchmark_inputs import resolve_original

ROOT = Path(__file__).resolve().parents[1]


def test_report_consumption_is_excluded_from_conflict_detection_score():
    result = verify(ROOT)
    assert result["score_eligible"] is False
    assert result["unreported_conflict_detection"] == "unverified"
    assert result["corrected_definite_subset"] == {
        "case_count": 4,
        "true_positive": 2,
        "true_negative": 2,
        "false_positive": 0,
        "false_negative": 0,
    }


@pytest.mark.parametrize("mutation", ["promote", "change_counterfactual", "rescore"])
def test_input_audit_rejects_promotion_or_nonisolated_comparison(tmp_path, mutation):
    audit = json.loads(resolve_original(ROOT / AUDIT).read_text())
    for path in [AUDIT, *audit["historical_paths"].values()]:
        target = tmp_path / path
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(resolve_original(ROOT / path), target)
    if mutation == "promote":
        audit["score_eligible"] = True
    elif mutation == "change_counterfactual":
        audit["configurations"]["without_report"]["namespace"] = "another"
    else:
        audit["scoring_exclusion"]["corrected_definite_subset"]["case_count"] = 5
    (tmp_path / AUDIT).write_text(json.dumps(audit))
    with pytest.raises(ValueError):
        verify(tmp_path)
