from __future__ import annotations

import copy
import json
import os
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path("experiments/false_effective").resolve()
CANDIDATES = ROOT / "deployment-candidates"
sys.path.insert(0, str(ROOT))

import h1_atomic_registration as transaction  # noqa: E402
from harness import canonical, digest_bytes  # noqa: E402

from vllm_hust_ext.h1_producer_admission import (  # noqa: E402
    issue_producer_admission,
)

REPOSITORY = Path.cwd().resolve()
OFFICIAL = tuple(path for _, path in transaction.WRITE_SET)


def _current_inputs() -> tuple[bytes, bytes]:
    candidate_raw = (
        CANDIDATES / "h1-formal-registration-commands-reviewed-20261013.json"
    ).read_bytes()
    review_raw = (CANDIDATES / "h1-automated-review-receipt-20261013.json").read_bytes()
    qualification_raw = (
        CANDIDATES / "h1-reachable-stack-tp2-qualification-20261013.json"
    ).read_bytes()
    study = json.loads((ROOT / "first-formal-real-study.json").read_text())
    issuance = issue_producer_admission(
        candidate_raw=candidate_raw,
        review_raw=review_raw,
        qualification_raw=qualification_raw,
        producer_candidate=study["producer_candidate"],
    )
    return candidate_raw, canonical(issuance) + b"\n"


def _repository_copy(tmp_path: Path) -> Path:
    for relative in (*OFFICIAL, transaction.PROTOCOL_RELATIVE):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(REPOSITORY / relative, target)
    _write_pre_admission_fixture(tmp_path)
    return tmp_path


def _write_pre_admission_fixture(root: Path) -> None:
    """Reconstruct the exact gate state consumed by the registration transaction."""
    study_path = root / transaction.STUDY_RELATIVE
    study = json.loads(study_path.read_text())
    study.update(
        {
            "status": "pre-admission",
            "admissible": False,
            "blockers": [
                "adapter-registry-empty",
                "deployment-identity-unfrozen",
                "commands-not-deployment-reviewed",
            ],
            "fixed_identity": {key: None for key in study["fixed_identity"]},
        }
    )
    study_path.write_bytes(canonical(study) + b"\n")

    deployment_path = root / transaction.DEPLOYMENT_RELATIVE
    deployment = json.loads(deployment_path.read_text())
    deployment.update(
        {
            "registration_state": "unregistered",
            "admissible": False,
            "producer_admission_receipt": None,
            "deployment_identity": {
                key: None for key in deployment["deployment_identity"]
            },
            "reviews": {key: False for key in deployment["reviews"]},
            "blockers": [
                "adapter-registry-empty",
                "deployment-identity-unfrozen",
                "commands-not-deployment-reviewed",
            ],
        }
    )
    deployment["bindings"]["study_sha256"] = transaction._hex_digest(
        canonical(study) + b"\n"
    )
    for row in deployment["arm_registrations"]:
        row["registration"] = None
    for row in deployment["source_registrations"]:
        row["registration"] = None
    deployment_path.write_bytes(canonical(deployment) + b"\n")

    registry = {"schema": "ecpa-formal-adapter-registry/v2", "adapters": []}
    (root / transaction.REGISTRY_RELATIVE).write_bytes(canonical(registry) + b"\n")

    matrix_path = root / transaction.MATRIX_RELATIVE
    matrix = json.loads(matrix_path.read_text())
    experiment = next(
        row
        for row in matrix["experiments"]
        if row["id"] == study["experiment_id"]
    )
    experiment["status"] = "pre-admission"
    matrix_path.write_bytes(canonical(matrix) + b"\n")


def test_transition_binds_three_arms_five_sources_and_nine_start_schedule(
    tmp_path: Path,
) -> None:
    root = _repository_copy(tmp_path)
    candidate_raw, issuance_raw = _current_inputs()
    packet = transaction.build_transition(
        candidate_raw=candidate_raw,
        issuance_raw=issuance_raw,
        repository_root=root,
    )

    assert packet["formal_h1_starts"] == 0
    assert packet["qualification_promoted"] is False
    assert packet["partial_transition_allowed"] is False
    assert [row["role"] for row in packet["write_set"]] == [
        "study",
        "deployment",
        "registry",
        "claims_matrix",
    ]
    study = packet["documents"]["study"]
    deployment = packet["documents"]["deployment"]
    registry = packet["documents"]["registry"]
    assert study["schedule"] == [
        ["vanilla-vllm-entry-points", "manual-integration", "ecpa"],
        ["manual-integration", "ecpa", "vanilla-vllm-entry-points"],
        ["ecpa", "vanilla-vllm-entry-points", "manual-integration"],
    ]
    assert [entry["arm"] for entry in registry["adapters"]] == study["arms"]
    assert len(deployment["source_registrations"]) == 5
    assert all(
        len(row["registration"]["registry_ids"]) == 3
        for row in deployment["source_registrations"]
    )
    assert deployment["bindings"]["study_sha256"] == transaction._hex_digest(
        canonical(study) + b"\n"
    )
    assert packet["write_set_digest"] == digest_bytes(canonical(packet["write_set"]))


def test_transition_reproduces_current_official_registration(tmp_path: Path) -> None:
    root = _repository_copy(tmp_path)
    candidate_raw, issuance_raw = _current_inputs()
    packet = transaction.build_transition(
        candidate_raw=candidate_raw,
        issuance_raw=issuance_raw,
        repository_root=root,
    )

    for role, relative in transaction.WRITE_SET:
        assert canonical(packet["documents"][role]) + b"\n" == (
            REPOSITORY / relative
        ).read_bytes()


def test_commit_rejects_changed_preimage_without_writing(tmp_path: Path) -> None:
    root = _repository_copy(tmp_path)
    candidate_raw, issuance_raw = _current_inputs()
    packet = transaction.build_transition(
        candidate_raw=candidate_raw,
        issuance_raw=issuance_raw,
        repository_root=root,
    )
    changed = root / transaction.MATRIX_RELATIVE
    changed.write_bytes(changed.read_bytes() + b" ")
    before = {path: (root / path).read_bytes() for path in OFFICIAL}

    with pytest.raises(ValueError, match="preimage changed"):
        transaction.commit_transition(packet, repository_root=root)
    assert {path: (root / path).read_bytes() for path in OFFICIAL} == before


def test_failed_replace_rolls_back_every_official_member(tmp_path: Path) -> None:
    root = _repository_copy(tmp_path)
    candidate_raw, issuance_raw = _current_inputs()
    packet = transaction.build_transition(
        candidate_raw=candidate_raw,
        issuance_raw=issuance_raw,
        repository_root=root,
    )
    before = {path: (root / path).read_bytes() for path in OFFICIAL}
    calls = 0

    def fail_third(source: os.PathLike[str], destination: os.PathLike[str]) -> None:
        nonlocal calls
        calls += 1
        if calls == 3:
            raise OSError("injected replace failure")
        os.replace(source, destination)

    with pytest.raises(OSError, match="injected replace failure"):
        transaction.commit_transition(packet, repository_root=root, replace=fail_third)
    assert {path: (root / path).read_bytes() for path in OFFICIAL} == before


def test_successful_commit_writes_the_exact_content_addressed_documents(
    tmp_path: Path,
) -> None:
    root = _repository_copy(tmp_path)
    candidate_raw, issuance_raw = _current_inputs()
    packet = transaction.build_transition(
        candidate_raw=candidate_raw,
        issuance_raw=issuance_raw,
        repository_root=root,
    )
    transaction.commit_transition(packet, repository_root=root)

    for row in packet["write_set"]:
        assert (root / row["path"]).read_bytes() == (
            canonical(packet["documents"][row["role"]]) + b"\n"
        )
    assert json.loads((root / transaction.STUDY_RELATIVE).read_text())["status"] == (
        "admitted"
    )
    assert json.loads((root / transaction.REGISTRY_RELATIVE).read_text())["adapters"]


def test_transition_rejects_stale_or_fabricated_admission_binding(
    tmp_path: Path,
) -> None:
    root = _repository_copy(tmp_path)
    candidate_raw, issuance_raw = _current_inputs()
    issuance = json.loads(issuance_raw)
    issuance["bindings"]["candidate_sha256"] = "sha256:" + "0" * 64
    core = {key: value for key, value in issuance.items() if key != "receipt_digest"}
    issuance["receipt_digest"] = digest_bytes(canonical(core))

    with pytest.raises(ValueError, match="does not bind"):
        transaction.build_transition(
            candidate_raw=candidate_raw,
            issuance_raw=canonical(issuance) + b"\n",
            repository_root=root,
        )


def test_transition_packet_rejects_split_write_set(tmp_path: Path) -> None:
    root = _repository_copy(tmp_path)
    candidate_raw, issuance_raw = _current_inputs()
    packet = transaction.build_transition(
        candidate_raw=candidate_raw,
        issuance_raw=issuance_raw,
        repository_root=root,
    )
    split = copy.deepcopy(packet)
    split["write_set"].pop()
    split["write_set_digest"] = digest_bytes(canonical(split["write_set"]))
    with pytest.raises(ValueError, match="split write set"):
        transaction.validate_transition(split, repository_root=root)


def test_successful_commit_accepts_git_worktree_marker(tmp_path: Path) -> None:
    root = _repository_copy(tmp_path)
    git_directory = tmp_path / "real-git-dir"
    git_directory.mkdir()
    (root / ".git").write_text(f"gitdir: {git_directory}\n")
    candidate_raw, issuance_raw = _current_inputs()
    packet = transaction.build_transition(
        candidate_raw=candidate_raw,
        issuance_raw=issuance_raw,
        repository_root=root,
    )
    transaction.commit_transition(packet, repository_root=root)
    assert (git_directory / "ecpa-h1-registration.lock").is_file()
    assert json.loads((root / transaction.STUDY_RELATIVE).read_text())["status"] == (
        "admitted"
    )
