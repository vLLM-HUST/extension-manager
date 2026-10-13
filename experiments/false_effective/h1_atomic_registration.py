"""Build and commit the fail-closed H1 formal-registration transaction.

The transaction admits no experiment result.  It only turns the reviewed H1
command candidate into the four mutually consistent repository documents that
authorize the first formal start.  Qualification runs remain qualification.
"""

from __future__ import annotations

import argparse
import copy
import fcntl
import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from formal_registration_candidate import validate_candidate
from harness import FORMAL_LIFECYCLE_FACT_SOURCES, canonical, digest_bytes
from jsonschema import Draft7Validator

from vllm_hust_ext.formal_adapter_admission import (
    validate_formal_adapter_admission,
)
from vllm_hust_ext.h1_producer_admission import (
    validate_producer_admission_issuance,
)

HERE = Path(__file__).resolve().parent
REPOSITORY_ROOT = HERE.parents[1]
STUDY_RELATIVE = Path("experiments/false_effective/first-formal-real-study.json")
DEPLOYMENT_RELATIVE = Path(
    "experiments/false_effective/first-formal-real-deployment.json"
)
REGISTRY_RELATIVE = Path("experiments/false_effective/verified-adapters.json")
MATRIX_RELATIVE = Path("docs/research/claims-to-experiment-matrix.json")
PROTOCOL_RELATIVE = Path("experiments/false_effective/protocol.json")
WRITE_SET = (
    ("study", STUDY_RELATIVE),
    ("deployment", DEPLOYMENT_RELATIVE),
    ("registry", REGISTRY_RELATIVE),
    ("claims_matrix", MATRIX_RELATIVE),
)
SCHEMA = "ecpa-h1-atomic-formal-registration/v1"
Pathish = str | bytes | os.PathLike[str] | os.PathLike[bytes]
Replace = Callable[[Pathish, Pathish], None]
EXPECTED_ARMS = (
    "vanilla-vllm-entry-points",
    "manual-integration",
    "ecpa",
)


def _load_canonical(raw: bytes, label: str) -> dict[str, Any]:
    value = json.loads(raw)
    if not isinstance(value, dict) or raw != canonical(value) + b"\n":
        raise ValueError(f"{label} is not one canonical JSON object")
    return value


def _hex_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _schema(path: Path, value: dict[str, Any]) -> None:
    Draft7Validator(json.loads(path.read_text())).validate(value)


def _fixed_identity(candidate: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    declared = candidate["declared_identity"]
    software = declared["software"]
    model = declared["model"]
    study_identity = {
        "runtime_commit": software["runtime"]["commit"],
        "accelerator_plugin_commit": software["accelerator_plugin"]["commit"],
        "manager_commit": software["manager"]["commit"],
        "model": f"{model['repository']}@{model['revision']}",
        "workload_request_sha256": declared["workload"]["sha256"],
        "hardware": declared["npu"]["device_family"],
        "topology": declared["topology"],
        "container_digest": None,
        "environment_digest": declared["environment_digest"],
        "fault_descriptor_sha256": declared["fault"]["sha256"],
        "plugin_entry_point": copy.deepcopy(
            candidate["arms"][0]["registry_candidate"]["scenario_bindings"][
                "partial-worker-coverage"
            ]["entry_point"]
        ),
        "warm_state": declared["warm_state"],
    }
    deployment_identity = {
        **study_identity,
        "runtime_tree": software["runtime"]["tree"],
        "accelerator_plugin_tree": software["accelerator_plugin"]["tree"],
        "manager_tree": software["manager"]["tree"],
    }
    return study_identity, deployment_identity


def _registry_entries(
    candidate: dict[str, Any], admission: dict[str, Any]
) -> list[dict[str, Any]]:
    entries = []
    for row in candidate["arms"]:
        entry = copy.deepcopy(row["registry_candidate"])
        if entry.pop("admission") is not None:
            raise ValueError("candidate already contains an admission")
        entry["admission"] = copy.deepcopy(admission)
        entries.append(entry)
    if tuple(entry["arm"] for entry in entries) != EXPECTED_ARMS:
        raise ValueError("registration does not contain the exact three H1 arms")
    return entries


def _arm_registration(entry: dict[str, Any]) -> dict[str, Any]:
    roles = (
        ("sut", "sut_command_digest"),
        ("manager", "manager_command_digest"),
        ("target", "target_command_digest"),
        ("observer", "observer_command_digest"),
    )
    return {
        "registry_id": entry["id"],
        "registry_entry_sha256": _hex_digest(canonical(entry)),
        "commands": [
            {"role": role, "command_digest": entry[field]}
            for role, field in roles
            if field in entry
        ],
        "activation_probe_digest": entry["activation_probe"]["command_digest"],
    }


def _validate_schedule(candidate: dict[str, Any], study: dict[str, Any]) -> None:
    expected = [
        (index, repetition, arm_order, arm)
        for repetition, order in enumerate(study["schedule"], 1)
        for arm_order, (index, arm) in enumerate(
            zip(
                range((repetition - 1) * 3 + 1, repetition * 3 + 1),
                order,
                strict=True,
            ),
            1,
        )
    ]
    actual = [
        (row["start"], row["repetition"], row["arm_order"], row["arm"])
        for row in candidate["schedule"]
    ]
    if actual != expected or tuple(study["arms"]) != EXPECTED_ARMS:
        raise ValueError("candidate differs from the frozen Latin-square schedule")


def build_transition(
    *,
    candidate_raw: bytes,
    issuance_raw: bytes,
    repository_root: Path = REPOSITORY_ROOT,
) -> dict[str, Any]:
    """Build and fully validate a non-mutating four-document transaction."""
    root = repository_root.resolve()
    candidate = _load_canonical(candidate_raw, "reviewed candidate")
    issuance = _load_canonical(issuance_raw, "producer admission issuance")
    validate_candidate(candidate, live=False)
    validate_producer_admission_issuance(issuance)
    if candidate["remaining_blockers"] != ["producer-admission-receipt-not-issued"]:
        raise ValueError("reviewed candidate has blockers beyond producer admission")
    if candidate["formal_h1_starts"] != 0:
        raise ValueError("registration cannot consume an H1 result")
    bindings = issuance["bindings"]
    if bindings["candidate_sha256"] != digest_bytes(candidate_raw):
        raise ValueError("producer admission does not bind the reviewed candidate")
    if (
        issuance["formal_h1_starts"] != 0
        or issuance["official_files_mutated"] is not False
    ):
        raise ValueError(
            "producer admission issuance crossed the registration boundary"
        )
    admission = validate_formal_adapter_admission(issuance["admission"])

    before_values = {
        role: json.loads((root / relative).read_text()) for role, relative in WRITE_SET
    }
    study = copy.deepcopy(before_values["study"])
    deployment = copy.deepcopy(before_values["deployment"])
    matrix = copy.deepcopy(before_values["claims_matrix"])
    if (
        study["status"] != "pre-admission"
        or study["admissible"] is not False
        or deployment["registration_state"] != "unregistered"
        or deployment["admissible"] is not False
        or before_values["registry"]
        != {"schema": "ecpa-formal-adapter-registry/v2", "adapters": []}
    ):
        raise ValueError("official H1 documents are not at the unregistered preimage")
    producer = study["producer_candidate"]
    if bindings["producer_candidate_sha256"] != digest_bytes(canonical(producer)):
        raise ValueError("producer admission does not bind the preregistered producer")
    admission_to_producer = {
        "repository": "repository",
        "pull_request": "pull_request",
        "reviewed_head": "reviewed_head",
        "reviewed_tree": "reviewed_tree",
        "base": "base",
        "state": "observed_state",
        "merge_commit": "merge_commit",
        "human_line_review": "human_line_review",
        "observed_at": "observed_at",
    }
    if any(
        admission[admission_field] != producer[producer_field]
        for admission_field, producer_field in admission_to_producer.items()
    ):
        raise ValueError("producer admission differs from the preregistered producer")
    expected_sources = {
        "host": candidate["declared_identity"]["software"]["runtime"]["commit"],
        "accelerator_plugin": candidate["declared_identity"]["software"][
            "accelerator_plugin"
        ]["commit"],
        "manager": candidate["declared_identity"]["software"]["manager"]["commit"],
        "mod": candidate["declared_identity"]["software"]["mod"]["commit"],
    }
    if bindings["source_commits"] != expected_sources:
        raise ValueError("producer admission source commits differ from the candidate")
    _validate_schedule(candidate, study)
    study_identity, deployment_identity = _fixed_identity(candidate)
    entries = _registry_entries(candidate, admission)
    registry = {"schema": "ecpa-formal-adapter-registry/v2", "adapters": entries}

    study.update(
        {
            "status": "admitted",
            "admissible": True,
            "blockers": [],
            "fixed_identity": study_identity,
        }
    )
    experiment = next(
        (row for row in matrix["experiments"] if row["id"] == study["experiment_id"]),
        None,
    )
    if experiment is None or experiment["status"] != "pre-admission":
        raise ValueError("claims matrix lacks the pre-admission H1 experiment")
    experiment["status"] = "admitted"

    deployment.update(
        {
            "registration_state": "registered",
            "admissible": True,
            "producer_admission_receipt": admission,
            "deployment_identity": deployment_identity,
            "reviews": {key: True for key in deployment["reviews"]},
            "blockers": [],
        }
    )
    deployment["bindings"]["study_sha256"] = _hex_digest(canonical(study) + b"\n")
    deployment["bindings"]["protocol_sha256"] = _hex_digest(
        (root / PROTOCOL_RELATIVE).read_bytes()
    )
    deployment["arm_registrations"] = [
        {"arm": entry["arm"], "registration": _arm_registration(entry)}
        for entry in entries
    ]
    registry_ids = [entry["id"] for entry in entries]
    phase_digests = entries[0]["lifecycle_fact_command_digests"]
    if any(
        entry["lifecycle_fact_command_digests"] != phase_digests for entry in entries
    ):
        raise ValueError("five source commands differ across comparison arms")
    if set(phase_digests) != set(FORMAL_LIFECYCLE_FACT_SOURCES):
        raise ValueError("registration does not contain the exact five sources")
    for row in deployment["source_registrations"]:
        row["registration"] = {
            "registry_ids": registry_ids,
            "command_digest": phase_digests[row["phase"]],
        }

    documents = {
        "study": study,
        "deployment": deployment,
        "registry": registry,
        "claims_matrix": matrix,
    }
    _schema(HERE / "first-formal-real-study.schema.json", study)
    _schema(HERE / "first-formal-real-deployment.schema.json", deployment)
    after_raw = {role: canonical(value) + b"\n" for role, value in documents.items()}
    before_raw = {role: (root / relative).read_bytes() for role, relative in WRITE_SET}
    manifest = [
        {
            "role": role,
            "path": str(relative),
            "before_sha256": digest_bytes(before_raw[role]),
            "after_sha256": digest_bytes(after_raw[role]),
        }
        for role, relative in WRITE_SET
    ]
    packet = {
        "schema": SCHEMA,
        "ready": True,
        "formal_h1_starts": 0,
        "qualification_promoted": False,
        "candidate_sha256": digest_bytes(candidate_raw),
        "producer_admission_issuance_sha256": digest_bytes(issuance_raw),
        "documents": documents,
        "write_set": manifest,
        "write_set_digest": digest_bytes(canonical(manifest)),
        "partial_transition_allowed": False,
    }
    validate_transition(packet, repository_root=root)
    return packet


def validate_transition(
    packet: dict[str, Any], *, repository_root: Path = REPOSITORY_ROOT
) -> None:
    root = repository_root.resolve()
    if (
        packet.get("schema") != SCHEMA
        or packet.get("ready") is not True
        or packet.get("formal_h1_starts") != 0
        or packet.get("qualification_promoted") is not False
        or packet.get("partial_transition_allowed") is not False
    ):
        raise ValueError("registration transaction crosses the evidence boundary")
    manifest = packet.get("write_set")
    if not isinstance(manifest, list) or [row.get("role") for row in manifest] != [
        role for role, _ in WRITE_SET
    ]:
        raise ValueError("registration transaction has a split write set")
    if [row.get("path") for row in manifest] != [str(path) for _, path in WRITE_SET]:
        raise ValueError("registration transaction paths drifted")
    if packet.get("write_set_digest") != digest_bytes(canonical(manifest)):
        raise ValueError("registration transaction manifest digest is stale")
    documents = packet.get("documents")
    if not isinstance(documents, dict) or set(documents) != {
        role for role, _ in WRITE_SET
    }:
        raise ValueError("registration transaction documents are incomplete")
    for row in manifest:
        if row["before_sha256"] != digest_bytes((root / row["path"]).read_bytes()):
            raise ValueError("official registration preimage changed")
        if row["after_sha256"] != digest_bytes(
            canonical(documents[row["role"]]) + b"\n"
        ):
            raise ValueError("official registration output digest is stale")
    study = documents["study"]
    deployment = documents["deployment"]
    registry = documents["registry"]
    matrix = documents["claims_matrix"]
    if (
        study["status"] != "admitted"
        or study["admissible"] is not True
        or study["blockers"]
        or deployment["registration_state"] != "registered"
        or deployment["admissible"] is not True
        or deployment["blockers"]
        or deployment["bindings"]["study_sha256"]
        != _hex_digest(canonical(study) + b"\n")
        or len(registry["adapters"]) != 3
        or tuple(entry["arm"] for entry in registry["adapters"]) != EXPECTED_ARMS
    ):
        raise ValueError("registration transaction cross-document invariants failed")
    experiment = next(
        row for row in matrix["experiments"] if row["id"] == study["experiment_id"]
    )
    if experiment["status"] != "admitted":
        raise ValueError("claims matrix is not synchronized with H1 admission")
    ids = {entry["id"] for entry in registry["adapters"]}
    if len(ids) != 3 or any(
        set(row["registration"]["registry_ids"]) != ids
        for row in deployment["source_registrations"]
    ):
        raise ValueError("five lifecycle sources do not cover all three arms")


def commit_transition(
    packet: dict[str, Any],
    *,
    repository_root: Path = REPOSITORY_ROOT,
    replace: Replace = os.replace,
) -> None:
    """Commit all members under one lock, rolling back every failed replace."""
    root = repository_root.resolve()
    lock_path = root / ".git" / "ecpa-h1-registration.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        validate_transition(packet, repository_root=root)
        transaction_root = Path(tempfile.mkdtemp(prefix="h1-registration-", dir=root))
        replaced: list[tuple[Path, Path]] = []
        try:
            for row in packet["write_set"]:
                role = row["role"]
                destination = root / row["path"]
                staged = transaction_root / f"{role}.new"
                backup = transaction_root / f"{role}.old"
                staged.write_bytes(canonical(packet["documents"][role]) + b"\n")
                backup.write_bytes(destination.read_bytes())
                for path in (staged, backup):
                    path.chmod(0o600)
                    with path.open("rb") as stream:
                        os.fsync(stream.fileno())
                replace(staged, destination)
                replaced.append((destination, backup))
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            rollback_errors = []
            for destination, backup in reversed(replaced):
                try:
                    os.replace(backup, destination)
                except OSError as exc:
                    rollback_errors.append(exc)
            if rollback_errors:
                raise RuntimeError("H1 registration rollback failed") from (
                    rollback_errors[0]
                )
            raise
        finally:
            shutil.rmtree(transaction_root, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("candidate", type=Path)
    parser.add_argument("issuance", type=Path)
    parser.add_argument("--packet", type=Path, required=True)
    parser.add_argument("--commit", action="store_true")
    args = parser.parse_args()
    packet = build_transition(
        candidate_raw=args.candidate.read_bytes(),
        issuance_raw=args.issuance.read_bytes(),
    )
    args.packet.parent.mkdir(parents=True, exist_ok=True)
    args.packet.write_bytes(canonical(packet) + b"\n")
    if args.commit:
        commit_transition(packet)


if __name__ == "__main__":
    main()
