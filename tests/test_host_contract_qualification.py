"""The real Host contract probe stays a non-serving, non-score artifact."""

from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path

import pytest

from scripts.benchmark_inputs import resolve_original

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / "experiments/real_mod_composition"
sys.path.insert(0, str(EXPERIMENT))

import host_contract_qualification as contract  # noqa: E402


def test_checked_qualification_is_activation_ready_but_not_scoreable() -> None:
    value = contract.load_qualification()
    assert value["qualification"] == {
        "actual_model_started": False,
        "actual_workload_completed": False,
        "both_install_orders_isolated": True,
        "h2_oracle_label": None,
        "lifecycle_profiler_activation_ready_for_exact_host": True,
        "pair_contract_activation_ready_for_model_serving_campaign": True,
        "performance_benefit": "unmeasured",
        "runtime_effective": "unmeasured",
        "score_eligible": False,
    }
    assert hashlib.sha256(
        resolve_original(contract.ARTIFACT_PATH).read_bytes()
    ).hexdigest() == (contract.ARTIFACT_SHA256)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("actual_model_started", True),
        ("actual_workload_completed", True),
        ("runtime_effective", True),
        ("performance_benefit", "positive"),
        ("h2_oracle_label", "compatible"),
        ("score_eligible", True),
    ],
)
def test_non_serving_probe_cannot_be_promoted(field: str, value: object) -> None:
    candidate = copy.deepcopy(contract.load_qualification())
    candidate["qualification"][field] = value
    with pytest.raises(ValueError):
        contract.validate_qualification(candidate)


def test_both_isolated_orders_are_required() -> None:
    candidate = copy.deepcopy(contract.load_qualification())
    candidate["orders"].pop()
    with pytest.raises(ValueError, match="both isolated"):
        contract.validate_qualification(candidate)
