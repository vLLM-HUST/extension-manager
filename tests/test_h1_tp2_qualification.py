from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path("experiments/false_effective").resolve()
CANDIDATE_ROOT = ROOT / "deployment-candidates"
RECEIPT = CANDIDATE_ROOT / "h1-reachable-stack-tp2-qualification-20261013.json"
sys.path.insert(0, str(ROOT))

import h1_tp2_qualification as qualification  # noqa: E402
from harness import canonical  # noqa: E402


def _receipt() -> dict[str, object]:
    raw = RECEIPT.read_bytes()
    value = json.loads(raw)
    assert raw == canonical(value) + b"\n"
    return value


def test_receipt_binds_exact_three_arm_reachable_stack_qualification() -> None:
    receipt = _receipt()
    qualification.validate_receipt(receipt)
    assert receipt["classification"] == (
        "exact-reachable-stack-functional-qualification"
    )
    assert [row["arm"] for row in receipt["runs"]] == [
        "vanilla-vllm-entry-points",
        "manual-integration",
        "ecpa",
    ]
    assert receipt["runs"][2]["target_kind"] == "direct-venv-python-module"
    assert receipt["qualification"] == {
        "exact_environment_frozen": True,
        "exact_runtime_ascend_profile_qualified": True,
        "all_three_activation_arms_qualified": True,
    }
    assert receipt["formal_h1_starts"] == 0
    assert receipt["formal_h1_result"] is False
    assert receipt["performance_result"] is False


def test_receipt_retains_failed_console_script_target_and_rejects_promotion() -> None:
    receipt = _receipt()
    failed = receipt["rejected_target_attempt"]
    assert failed["target_kind"] == "managed-ecpa-host-launch-console-script"
    assert failed["cleanup_proven"] is True
    assert "fd 3" in failed["reason"]
    assert "deadlocked" in failed["reason"]

    promoted = copy.deepcopy(receipt)
    promoted["formal_h1_starts"] = 1
    with pytest.raises(ValueError, match="digest is stale|promoted"):
        qualification.validate_receipt(promoted)


def test_receipt_rejects_result_or_environment_digest_drift() -> None:
    receipt = _receipt()
    stale = copy.deepcopy(receipt)
    stale["runs"][0]["result_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="digest is stale"):
        qualification.validate_receipt(stale)

    stale = copy.deepcopy(receipt)
    stale["environment"]["wheel_sha256"]["accelerator_plugin"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="digest is stale|environment drifted"):
        qualification.validate_receipt(stale)
