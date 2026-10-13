from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest
from jsonschema import ValidationError

ROOT = Path("experiments/false_effective").resolve()
CANDIDATE_ROOT = ROOT / "deployment-candidates"
CANDIDATE_PATH = CANDIDATE_ROOT / "h1-formal-registration-commands-20261013.json"
DRY_RUN_PATH = (
    CANDIDATE_ROOT / "h1-formal-registration-transition-dry-run-20261013.json"
)
sys.path.insert(0, str(ROOT))

import formal_registration_candidate as registration  # noqa: E402
from harness import canonical, digest_bytes, digest_file  # noqa: E402


def _candidate() -> dict[str, object]:
    raw = CANDIDATE_PATH.read_bytes()
    value = json.loads(raw)
    assert raw == canonical(value) + b"\n"
    return value


def test_checked_candidate_freezes_exact_three_arm_five_source_nine_start_plan() -> (
    None
):
    candidate = _candidate()
    registration.validate_candidate(candidate, live=False)

    assert candidate["experiment_manager_identity"]["commit"] == (
        "9f075f8e70da574fb90bdd392cf7c7e424c75972"
    )
    assert candidate["formal_h1_starts"] == 0
    assert candidate["admissible"] is False
    assert candidate["machine_checks"] == {
        "activation_probes_executed": True,
        "five_sources_per_arm_complete": True,
        "nine_start_schedule_complete": True,
        "three_arms_complete": True,
    }
    assert all(value is None for value in candidate["independent_reviews"].values())
    assert len(candidate["schedule"]) == 9
    assert [row["start"] for row in candidate["schedule"]] == list(range(1, 10))

    source_digests = {}
    for arm in candidate["arms"]:
        assert len(arm["lifecycle_fact_commands"]) == 5
        for phase, command in arm["lifecycle_fact_commands"].items():
            source_digests.setdefault(phase, set()).add(command["digest"])
        receipt = arm["activation_probe_observation"]["receipt"]
        assert receipt["activation_contract"] == arm["activation_contract"]
        assert arm["registry_candidate"]["admission"] is None
    assert all(len(digests) == 1 for digests in source_digests.values())


def test_candidate_inputs_bind_repository_bytes() -> None:
    candidate = _candidate()
    repository_inputs = {
        "plan": CANDIDATE_ROOT / "h1-kv-materialization-plan.json",
        "workload": CANDIDATE_ROOT / "h1-qwen2.5-7b-workload.json",
        "fault": CANDIDATE_ROOT / "h1-partial-worker-coverage-fault.json",
    }
    for name, path in repository_inputs.items():
        assert candidate["inputs"][name]["sha256"] == digest_file(path)
    assert candidate["inputs"]["plan"]["sha256"] == (
        "sha256:ebf6400897b268944bda5fde6e990b8f8ce54259b96a39afff0541df8367124f"
    )


def test_transition_dry_run_is_blocked_and_does_not_mutate_official_files() -> None:
    candidate = _candidate()
    official = (
        ROOT / "first-formal-real-study.json",
        ROOT / "first-formal-real-deployment.json",
        ROOT / "verified-adapters.json",
    )
    before = {path: path.read_bytes() for path in official}
    report = registration.transition_dry_run(candidate, live=False)

    assert report["ready"] is False
    assert report["official_files_mutated"] is False
    assert report["partial_transition_allowed"] is False
    assert report["candidate_digest"] == digest_bytes(CANDIDATE_PATH.read_bytes())
    assert report["unsatisfied_preconditions"] == candidate["remaining_blockers"]
    assert {path: path.read_bytes() for path in official} == before
    assert json.loads(DRY_RUN_PATH.read_text()) == report


def test_candidate_rejects_machine_promotion_and_review_substitution() -> None:
    candidate = _candidate()
    promoted = copy.deepcopy(candidate)
    promoted["formal_h1_starts"] = 1
    with pytest.raises(ValidationError):
        registration.validate_candidate(promoted, live=False)

    reviewed = copy.deepcopy(candidate)
    reviewed["independent_reviews"]["commands"] = True
    with pytest.raises(ValidationError):
        registration.validate_candidate(reviewed, live=False)

    admitted = copy.deepcopy(candidate)
    admitted["arms"][0]["registry_candidate"]["admission"] = {"fake": True}
    with pytest.raises(ValidationError):
        registration.validate_candidate(admitted, live=False)


def test_candidate_rejects_command_and_source_registration_drift() -> None:
    candidate = _candidate()
    stale = copy.deepcopy(candidate)
    stale["arms"][0]["commands"]["sut"]["digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="registration digest drifted"):
        registration.validate_candidate(stale, live=False)

    wrong_phase = copy.deepcopy(candidate)
    source = wrong_phase["arms"][0]["lifecycle_fact_commands"]["service-ready"]
    source["arguments"][1] = "workload-http"
    core = {key: value for key, value in source.items() if key != "digest"}
    source["digest"] = digest_bytes(canonical(core))
    wrong_phase["arms"][0]["registry_candidate"]["lifecycle_fact_command_digests"][
        "service-ready"
    ] = source["digest"]
    with pytest.raises(ValueError, match="source subcommand drifted"):
        registration.validate_candidate(wrong_phase, live=False)
