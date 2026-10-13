  昇腾卡 2 张（规格 npu-2x）。npu-smi info 看状态；
  容器里只看得见分给你的那几张，看不到整机——这是正常的。
import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (
    ROOT
    / "experiments"
    / "real_mod_composition"
    / "verify_real_pair_preflight.py"
)
SPEC = importlib.util.spec_from_file_location("verify_real_pair_preflight", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def _artifact() -> dict:
    return json.loads(verifier.ARTIFACT.read_text(encoding="utf-8"))


def test_checked_in_real_pair_preflight_is_exact_and_non_scoreable() -> None:
    verifier.verify()
    artifact = _artifact()
    assert hashlib.sha256(verifier.ARTIFACT.read_bytes()).hexdigest() == (
        verifier.ARTIFACT_SHA256
    )
    assert {order["order"] for order in artifact["orders"]} == (
        verifier.EXPECTED_ORDERS
    )
    assert artifact["formal_h2_result"] is False
    assert artifact["performance_result"] is False
    assert artifact["score_eligible"] is False


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("formal_h2_result", True),
        ("performance_result", True),
        ("score_eligible", True),
    ],
)
def test_promotion_attempts_fail_closed(field: str, value: bool) -> None:
    artifact = _artifact()
    artifact[field] = value
    with pytest.raises(ValueError, match="schema validation failed"):
        verifier.validate_payload(artifact)


def test_missing_order_fails_closed() -> None:
    artifact = _artifact()
    artifact["orders"].pop()
    with pytest.raises(ValueError, match="schema validation failed"):
        verifier.validate_payload(artifact)


def test_missing_scientific_boundary_fails_closed() -> None:
    artifact = _artifact()
    artifact["scientific_boundary"]["not_established"].remove(
        "compression transaction occurred"
    )
    with pytest.raises(ValueError, match="required non-claims missing"):
        verifier.validate_payload(artifact)


def test_failed_attempt_ledger_cannot_be_silently_dropped() -> None:
    artifact = _artifact()
    artifact["retained_failed_attempts"].pop()
    with pytest.raises(ValueError, match="schema validation failed"):
        verifier.validate_payload(artifact)


def test_changed_artifact_bytes_fail_digest_binding(tmp_path: Path) -> None:
    changed = tmp_path / "changed.json"
    artifact = _artifact()
    artifact["model"] += "-changed"
    changed.write_text(json.dumps(artifact), encoding="utf-8")
    with pytest.raises(ValueError, match="artifact digest mismatch"):
        verifier.verify(changed)
