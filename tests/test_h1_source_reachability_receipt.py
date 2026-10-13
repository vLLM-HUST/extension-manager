from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path("experiments/false_effective").resolve()
CANDIDATE_ROOT = ROOT / "deployment-candidates"
RECEIPT = CANDIDATE_ROOT / "h1-local-source-archive-receipt-20261013.json"
sys.path.insert(0, str(ROOT))

import source_reachability_receipt as reachability  # noqa: E402
from harness import canonical  # noqa: E402


def _receipt() -> dict[str, object]:
    raw = RECEIPT.read_bytes()
    value = json.loads(raw)
    assert raw == canonical(value) + b"\n"
    return value


def test_receipt_binds_exact_local_objects_and_archives_without_remote_claim() -> None:
    receipt = _receipt()
    reachability.validate_receipt(receipt)

    assert [row["name"] for row in receipt["sources"]] == [
        "runtime",
        "mod",
        "accelerator_plugin",
    ]
    assert all(
        row["local_repository"]["exact_identity_verified"] for row in receipt["sources"]
    )
    assert all(row["archive"]["exact_identity_exported"] for row in receipt["sources"])
    assert all(row["archive"]["self_contained"] is False for row in receipt["sources"])
    assert all(row["archive"]["prerequisite_commits"] for row in receipt["sources"])
    assert all(
        row["remote_reachability"]["checked"] is False for row in receipt["sources"]
    )
    assert receipt["summary"]["repository_reachability_blocker_cleared"] is False
    assert receipt["summary"]["formal_registration_eligible"] is False


def test_receipt_rejects_remote_or_formal_promotion() -> None:
    receipt = _receipt()
    remote = copy.deepcopy(receipt)
    remote["sources"][0]["remote_reachability"] = {
        "checked": True,
        "reachable": True,
        "reason": "invented",
    }
    with pytest.raises(ValueError, match="must not imply remote reachability"):
        reachability.validate_receipt(remote)

    promoted = copy.deepcopy(receipt)
    promoted["summary"]["formal_registration_eligible"] = True
    with pytest.raises(ValueError, match="qualification boundary drifted"):
        reachability.validate_receipt(promoted)


def test_receipt_rejects_archive_head_or_declared_tree_drift() -> None:
    receipt = _receipt()
    wrong_head = copy.deepcopy(receipt)
    wrong_head["sources"][1]["archive"]["heads"] = {
        "refs/heads/feature/formal-arm-launch-modes": "0" * 40
    }
    with pytest.raises(ValueError, match="archive head"):
        reachability.validate_receipt(wrong_head)

    wrong_tree = copy.deepcopy(receipt)
    wrong_tree["sources"][2]["declared_identity"]["tree"] = "0" * 40
    with pytest.raises(ValueError, match="differs from the H1 candidate"):
        reachability.validate_receipt(wrong_tree)
