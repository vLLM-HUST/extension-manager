from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path("experiments/false_effective").resolve()
sys.path.insert(0, str(ROOT))

import h1_automated_review as review_module  # noqa: E402
from formal_registration_candidate import (  # noqa: E402
    transition_dry_run,
    validate_candidate,
)
from h1_automated_review import (  # noqa: E402
    CHECK_IDS,
    REVIEW_BLOCKERS,
    apply_review,
    build_review_receipt,
    validate_review_receipt,
)
from harness import canonical, digest_bytes  # noqa: E402

CANDIDATE = ROOT / "deployment-candidates/h1-formal-registration-commands-20261013.json"


def candidate() -> dict[str, object]:
    return json.loads(CANDIDATE.read_text())


def test_review_is_deterministic_content_addressed_and_explicitly_nonhuman() -> None:
    value = candidate()
    first = build_review_receipt(value)
    second = build_review_receipt(value)
    assert first == second
    core = {key: item for key, item in first.items() if key != "receipt_digest"}
    assert first["receipt_digest"] == digest_bytes(canonical(core))
    assert first["reviewer_kind"] == "automated-independent"
    assert first["human_review"] is False
    assert set(first["checks"]) == set(CHECK_IDS)
    assert {item["verdict"] for item in first["checks"].values()} == {"PASS"}
    jsonschema.Draft7Validator(
        json.loads(review_module.SCHEMA_PATH.read_text())
    ).validate(first)


def test_review_clears_only_review_blockers_and_never_promotes_candidate() -> None:
    value = candidate()
    reviewed = apply_review(value, build_review_receipt(value))
    validate_candidate(reviewed, live=False)
    assert reviewed["registration_state"] == "candidate-only"
    assert reviewed["admissible"] is False
    assert reviewed["formal_h1_starts"] == 0
    assert set(REVIEW_BLOCKERS).isdisjoint(reviewed["remaining_blockers"])
    assert reviewed["remaining_blockers"] == ["producer-admission-receipt-not-issued"]
    report = transition_dry_run(reviewed, live=False)
    assert report["ready"] is False
    assert report["official_files_mutated"] is False
    assert report["unsatisfied_preconditions"] == reviewed["remaining_blockers"]


@pytest.mark.parametrize("check_id", CHECK_IDS)
def test_receipt_rejects_a_tampered_check(check_id: str) -> None:
    value = candidate()
    receipt = build_review_receipt(value)
    receipt["checks"][check_id]["assertions"].append("fabricated assertion")
    with pytest.raises(ValueError, match="digest is stale|differs from deterministic"):
        validate_review_receipt(value, receipt)


def test_reviewed_candidate_rejects_human_misrepresentation() -> None:
    value = candidate()
    reviewed = apply_review(value, build_review_receipt(value))
    reviewed["independent_reviews"]["commands"]["human_review"] = True
    with pytest.raises((ValueError, jsonschema.ValidationError)):
        validate_candidate(reviewed, live=False)


def test_review_rejects_fixture_command_even_with_a_self_consistent_digest() -> None:
    value = candidate()
    command = value["arms"][0]["commands"]["sut"]
    command["arguments"].append("tests/fixtures/formal_service.py")
    core = {key: item for key, item in command.items() if key != "digest"}
    command["digest"] = digest_bytes(canonical(core))
    with pytest.raises(ValueError, match="fixture or synthetic"):
        build_review_receipt(value)


def test_review_rejects_managed_python_console_script_target() -> None:
    value = candidate()
    ecpa = value["arms"][2]
    ecpa["runner_arguments"]["executable"] = (
        "/root/ecpa-h1-reachable-candidate-venv/bin/ecpa-host-launch"
    )
    with pytest.raises(ValueError, match="direct venv Python ELF"):
        build_review_receipt(value)


def test_artifact_review_fails_when_retention_contract_is_incomplete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = tmp_path / "runner.py"
    runner.write_text("formal-record-index.json\n")
    monkeypatch.setattr(review_module, "RUNNER_PATH", runner)
    with pytest.raises(ValueError, match="retention path is incomplete"):
        build_review_receipt(candidate())


def test_owner_amendment_preserves_machine_and_formal_gates() -> None:
    amendment = json.loads(review_module.AMENDMENT_PATH.read_text())
    assert amendment["replacement_mode"] == "automated-independent"
    assert amendment["original_mode"] == "human-independent-review"
    assert "formal-validator" in amendment["unchanged_gates"]
    assert "official-atomic-registration" in amendment["unchanged_gates"]
    assert any("not human review" in item for item in amendment["non_claims"])
