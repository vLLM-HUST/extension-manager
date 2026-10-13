"""Validate the non-admitting Host parent-identity producer candidate.

The candidate deliberately remains blocked while its Host commit exists only
in the local checkout.  Functional TP2 evidence and a locally built wheel do
not substitute for a repository-reachable, merged producer source.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator

HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "host-parent-registration-candidate.schema.json"
CANDIDATE_PATH = HERE / "artifacts/host-parent-registration-candidate-20261013.json"
SCHEMA = "ecpa-host-parent-identity-producer-candidate/v1"
REQUIRED_BLOCKERS = [
    "host-candidate-commit-not-repository-reachable",
    "host-candidate-commit-not-merged",
]


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _review_subject(candidate: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in candidate.items() if key != "review"}


def _expected_blockers(candidate: dict[str, Any]) -> list[str]:
    source = candidate["host_source"]
    if set(source["source_blobs"]) != set(source["changed_paths"]):
        raise ValueError("Host source blob set differs from changed paths")
    blockers: list[str] = []
    if not source["remote_observation"]["candidate_reachable"]:
        blockers.append(REQUIRED_BLOCKERS[0])
    if source["observed_state"] != "merged" or source["merge_commit"] is None:
        blockers.append(REQUIRED_BLOCKERS[1])
    return blockers


def validate_candidate(candidate: dict[str, Any]) -> dict[str, Any]:
    Draft7Validator(json.loads(SCHEMA_PATH.read_text())).validate(candidate)
    registration = candidate["registration"]
    if (
        candidate["schema"] != SCHEMA
        or candidate["classification"]
        != "source-bound-non-admitting-functional-preflight"
        or candidate["formal_result"] is not False
        or candidate["performance_result"] is not False
        or registration["state"] != "blocked"
        or registration["admissible"] is not False
    ):
        raise ValueError("Host parent candidate promoted a non-formal preflight")
    blockers = _expected_blockers(candidate)
    if blockers != registration["blockers"] or blockers != REQUIRED_BLOCKERS:
        raise ValueError("Host parent candidate did not fail closed on source state")
    source = candidate["host_source"]
    if (
        source["candidate_parent"] != source["base_commit"]
        or source["remote_observation"]["matching_refs"]
        or source["remote_observation"]["main_commit"] != source["base_commit"]
        or source["remote_ref"] is not None
        or source["pull_request"] is not None
        or source["merge_commit"] is not None
    ):
        raise ValueError("Host source reachability facts are contradictory")
    preflight = candidate["functional_preflight"]
    if (
        preflight["classification"] != "unregistered-functional-preflight"
        or preflight["formal_result"] is not False
        or preflight["performance_result"] is not False
        or preflight["runtime_candidate_commit"] != source["candidate_commit"]
        or preflight["runtime_wheel_sha256"] != candidate["wheel"]["sha256"]
    ):
        raise ValueError("functional preflight is not bound to the Host candidate")
    review = candidate["review"]
    subject_digest = digest_bytes(canonical(_review_subject(candidate)))
    if review["subject_digest"] != subject_digest:
        raise ValueError("Host parent review subject digest is stale")
    core = {key: value for key, value in review.items() if key != "receipt_digest"}
    if review["receipt_digest"] != digest_bytes(canonical(core)):
        raise ValueError("Host parent review receipt digest is stale")
    if review["verdict"] != "BLOCKED" or review["blockers"] != blockers:
        raise ValueError("Host parent review did not preserve admission blockers")
    return candidate


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
    ).stdout


def verify_local_inputs(
    candidate: dict[str, Any],
    *,
    host_repo: Path,
    wheel_path: Path,
    manager_repo: Path,
) -> dict[str, Any]:
    """Recheck every local byte/source binding without granting admission."""
    validate_candidate(candidate)
    source = candidate["host_source"]
    commit = source["candidate_commit"]
    if _git(host_repo, "rev-parse", f"{commit}^").decode().strip() != source[
        "candidate_parent"
    ]:
        raise ValueError("Host candidate parent drifted")
    if _git(host_repo, "rev-parse", f"{commit}^{{tree}}").decode().strip() != source[
        "candidate_tree"
    ]:
        raise ValueError("Host candidate tree drifted")
    changed = _git(
        host_repo, "diff", "--name-only", source["base_commit"], commit
    ).decode().splitlines()
    if changed != source["changed_paths"]:
        raise ValueError("Host candidate changed-path set drifted")
    for path, blob in source["source_blobs"].items():
        actual = _git(host_repo, "rev-parse", f"{commit}:{path}").decode().strip()
        if actual != blob:
            raise ValueError(f"Host candidate blob drifted: {path}")
    patch = _git(host_repo, "diff", "--binary", source["base_commit"], commit)
    if digest_bytes(patch) != source["patch_sha256"]:
        raise ValueError("Host candidate patch digest drifted")
    if digest_bytes(wheel_path.read_bytes()) != candidate["wheel"]["sha256"]:
        raise ValueError("Host candidate wheel digest drifted")
    context = candidate["manager_review_context"]
    if _git(manager_repo, "rev-parse", "HEAD").decode().strip() != context["commit"]:
        raise ValueError("Manager review commit drifted")
    if _git(manager_repo, "rev-parse", "HEAD^{tree}").decode().strip() != context[
        "tree"
    ]:
        raise ValueError("Manager review tree drifted")
    artifact_path = manager_repo / candidate["functional_preflight"]["artifact_path"]
    if digest_bytes(artifact_path.read_bytes()) != candidate["functional_preflight"][
        "artifact_sha256"
    ]:
        raise ValueError("Host parent TP2 preflight artifact drifted")
    artifact = json.loads(artifact_path.read_bytes())
    expected = candidate["functional_preflight"]
    observed_roles = [
        f"{row['role']}:{row['ordinal']}"
        for row in artifact["execution"]["host_assigned_processes"]
    ]
    if (
        artifact["classification"] != expected["classification"]
        or artifact["formal_result"] is not expected["formal_result"]
        or artifact["performance_result"] is not expected["performance_result"]
        or artifact["stack"]["runtime_candidate_commit"]
        != expected["runtime_candidate_commit"]
        or artifact["stack"]["runtime_wheel_sha256"]
        != expected["runtime_wheel_sha256"]
        or artifact["stack"]["manager_merged_commit"]
        != expected["executed_manager_commit"]
        or artifact["stack"]["accelerator_plugin_commit"]
        != expected["accelerator_plugin_commit"]
        or artifact["stack"]["hardware"] != expected["hardware"]
        or artifact["stack"]["topology"] != expected["topology"]
        or observed_roles != expected["host_assigned_roles"]
        or any(
            value != 0
            for value in artifact["cleanup"].values()
            if isinstance(value, int)
        )
        or artifact["cleanup"]["port_8187"] != "free"
    ):
        raise ValueError("Host parent TP2 preflight facts drifted")
    return candidate


def load_candidate(path: Path = CANDIDATE_PATH) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if path.read_bytes() != canonical(value) + b"\n":
        raise ValueError("Host parent registration candidate is not canonical JSON")
    return validate_candidate(value)
