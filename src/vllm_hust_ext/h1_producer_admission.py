"""Issue a content-addressed H1 producer-admission receipt.

The embedded formal adapter admission remains the existing v1 shape.  Its
``human_line_review`` bit refers only to the already completed Host PR #27
review.  The deployment commands, activation paths, observer independence,
and artifact retention gates come from the owner-amended automated-independent
review receipt.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from .formal_adapter_admission import validate_formal_adapter_admission

ISSUANCE_SCHEMA = "ecpa-h1-producer-admission-issuance/v1"
REVIEW_SCHEMA = "ecpa-h1-automated-independent-review/v1"
QUALIFICATION_SCHEMA = "ecpa-h1-reachable-stack-tp2-qualification/v1"
_CANDIDATE_SCHEMA = "ecpa-h1-formal-registration-candidate/v1"
_ARMS = {"vanilla-vllm-entry-points", "manual-integration", "ecpa"}
_CHECKS = {
    "commands",
    "activation_paths",
    "observer_independence",
    "artifact_retention",
}
_REVIEW_BLOCKERS = (
    "commands-not-independently-reviewed",
    "activation-paths-not-independently-reviewed",
    "observer-independence-not-independently-reviewed",
    "artifact-retention-not-independently-reviewed",
)
_AMENDMENT = {
    "id": "h1-review-mode-owner-amendment-2026-10-13",
    "digest": (
        "sha256:e52dc2b3c171fabcada7ff5dc4370b28ad758f72b2c68292430af80b4165da9c"
    ),
}
_PRODUCER = {
    "repository": "vLLM-HUST/vllm-hust",
    "pull_request": 27,
    "reviewed_head": "f3eb4b09ba91a1720c4e35de41a91e6dc351fd5b",
    "reviewed_tree": "bcdb8c810b60c11e77cb8af2002bd9039600b808",
    "base": "fc06902b7dd7aa1610438cd061ccf7f04b31c609",
    "observed_state": "merged",
    "merge_commit": "b326fafe5405b9996db9c9f0d7758536148ecc9b",
    "human_line_review": True,
    "observed_at": "2026-10-12T20:28:43+08:00",
}
_PRODUCER_REPOSITORY_ID = 1352192170
_PRODUCER_NODE_ID = "R_kgDOUJjQqg"
_HUMAN_REVIEW_EVIDENCE = {
    "reviewer": "Apei-520",
    "review_comment_id": 5853006976,
    "verdict": "APPROVE",
    "reviewed_head": _PRODUCER["reviewed_head"],
}


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def digest_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _load_canonical(raw: bytes, description: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{description} is not valid JSON") from exc
    if not isinstance(value, dict) or raw != canonical(value) + b"\n":
        raise ValueError(f"{description} is not canonical JSON")
    return value


def _source_commits(candidate: dict[str, Any]) -> dict[str, str]:
    software = candidate["declared_identity"]["software"]
    return {
        "host": software["runtime"]["commit"],
        "accelerator_plugin": software["accelerator_plugin"]["commit"],
        "manager": software["manager"]["commit"],
        "mod": software["mod"]["commit"],
    }


def _validate_candidate(candidate: dict[str, Any]) -> dict[str, str]:
    if (
        candidate.get("schema") != _CANDIDATE_SCHEMA
        or candidate.get("classification")
        != "deployment-bound-non-admitting-command-candidate"
        or candidate.get("registration_state") != "candidate-only"
        or candidate.get("admissible") is not False
        or candidate.get("formal_h1_starts") != 0
        or set(candidate.get("machine_checks", {}).values()) != {True}
        or len(candidate.get("arms", [])) != 3
        or {arm.get("arm") for arm in candidate["arms"]} != _ARMS
        or candidate.get("remaining_blockers")
        != ["producer-admission-receipt-not-issued"]
    ):
        raise ValueError("H1 registration candidate has not preserved its gates")
    software = candidate.get("declared_identity", {}).get("software")
    if not isinstance(software, dict) or set(software) != {
        "runtime",
        "accelerator_plugin",
        "manager",
        "mod",
    }:
        raise ValueError("H1 registration candidate source set is incomplete")
    if any(
        source.get("repository_reachable") is not True
        for source in software.values()
    ):
        raise ValueError("H1 registration candidate contains an unreachable source")
    manager = software["manager"]
    if (
        manager.get("repository") != "vLLM-HUST/extension-manager"
        or manager.get("remote_ref") != "refs/heads/main"
        or candidate.get("experiment_manager_identity")
        != {
            "commit": manager.get("commit"),
            "tree": manager.get("tree"),
            "note": (
                "merged Manager source for the non-admitting reachable-stack candidate"
            ),
        }
    ):
        raise ValueError("H1 Manager producer is not bound to merged main")
    return _source_commits(candidate)


def _validate_review(
    candidate: dict[str, Any], review: dict[str, Any]
) -> bytes:
    embedded = candidate.get("automated_review_receipt")
    expected_refs = {
        check_id: {
            "reviewer_kind": "automated-independent",
            "human_review": False,
            "check_id": check_id,
            "verdict": "PASS",
            "receipt_digest": review.get("receipt_digest"),
        }
        for check_id in _CHECKS
    }
    if embedded != review or candidate.get("independent_reviews") != expected_refs:
        raise ValueError("reviewed candidate references differ from the attestation")
    review_subject = copy.deepcopy(candidate)
    del review_subject["automated_review_receipt"]
    review_subject["independent_reviews"] = {
        check_id: None for check_id in _CHECKS
    }
    review_subject["remaining_blockers"] = [
        *candidate["remaining_blockers"],
        *_REVIEW_BLOCKERS,
    ]
    review_subject_raw = canonical(review_subject) + b"\n"
    core = {key: value for key, value in review.items() if key != "receipt_digest"}
    checks = review.get("checks")
    if (
        review.get("schema") != REVIEW_SCHEMA
        or review.get("reviewer_kind") != "automated-independent"
        or review.get("human_review") is not False
        or review.get("protocol_amendment") != _AMENDMENT
        or review.get("machine_qualification_preserved") is not True
        or review.get("official_files_mutated") is not False
        or review.get("formal_h1_starts") != 0
        or review.get("subject")
        != {
            "schema": _CANDIDATE_SCHEMA,
            "candidate_digest": digest_bytes(review_subject_raw),
        }
        or not isinstance(checks, dict)
        or set(checks) != _CHECKS
        or any(check.get("verdict") != "PASS" for check in checks.values())
        or review.get("receipt_digest") != digest_bytes(canonical(core))
    ):
        raise ValueError("automated-independent review attestation is invalid")
    return review_subject_raw


def _validate_qualification(
    qualification: dict[str, Any],
    source_commits: dict[str, str],
    manager_wheel: str,
) -> None:
    runs = qualification.get("runs")
    core = {
        key: value for key, value in qualification.items() if key != "receipt_digest"
    }
    if (
        qualification.get("schema") != QUALIFICATION_SCHEMA
        or qualification.get("classification")
        != "exact-reachable-stack-functional-qualification"
        or qualification.get("formal_h1_starts") != 0
        or qualification.get("formal_h1_result") is not False
        or qualification.get("official_files_mutated") is not False
        or qualification.get("performance_result") is not False
        or qualification.get("qualification")
        != {
            "all_three_activation_arms_qualified": True,
            "exact_environment_frozen": True,
            "exact_runtime_ascend_profile_qualified": True,
        }
        or qualification.get("environment", {}).get("source_commits")
        != source_commits
        or qualification.get("environment", {}).get("wheel_sha256", {}).get(
            "manager"
        )
        != manager_wheel
        or qualification.get("receipt_digest") != digest_bytes(canonical(core))
        or not isinstance(runs, list)
        or len(runs) != 3
        or {run.get("arm") for run in runs} != _ARMS
        or any(
            run.get("success") is not True
            or run.get("cleanup_proven") is not True
            or run.get("health_status") != 200
            or run.get("completion_status") != 200
            or run.get("completion_nonempty") is not True
            or run.get("formal_h1_start") is not False
            or run.get("performance_result") is not False
            or run.get("allocated_npu_process_tables_empty") is not True
            or run.get("port_refused_after_stop") is not True
            or run.get("surviving_owned_processes") != []
            for run in runs
        )
    ):
        raise ValueError("three-arm TP2 functional qualification is invalid")


def issue_producer_admission(
    *,
    candidate_raw: bytes,
    review_raw: bytes,
    qualification_raw: bytes,
    producer_candidate: dict[str, Any],
) -> dict[str, Any]:
    """Recompute all machine gates and issue a deterministic receipt envelope."""
    candidate = _load_canonical(candidate_raw, "registration candidate")
    review = _load_canonical(review_raw, "review attestation")
    try:
        qualification = json.loads(qualification_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("qualification receipt is not valid JSON") from exc
    if producer_candidate != _PRODUCER:
        raise ValueError("Host PR #27 producer facts differ from the reviewed identity")
    source_commits = _validate_candidate(candidate)
    review_subject_raw = _validate_review(candidate, review)
    manager_wheel = candidate["declared_identity"]["software"]["manager"][
        "wheel_sha256"
    ]
    _validate_qualification(qualification, source_commits, manager_wheel)

    admission = validate_formal_adapter_admission(
        {
            "schema": "ecpa-formal-adapter-admission/v1",
            "repository": producer_candidate["repository"],
            "repository_id": _PRODUCER_REPOSITORY_ID,
            "node_id": _PRODUCER_NODE_ID,
            "default_branch": "main",
            "pull_request": producer_candidate["pull_request"],
            "reviewed_head": producer_candidate["reviewed_head"],
            "reviewed_tree": producer_candidate["reviewed_tree"],
            "base": producer_candidate["base"],
            "state": producer_candidate["observed_state"],
            "merge_commit": producer_candidate["merge_commit"],
            "human_line_review": producer_candidate["human_line_review"],
            "commands_reviewed": True,
            "activation_path_reviewed": True,
            "observer_independence_reviewed": True,
            "observed_at": producer_candidate["observed_at"],
        }
    )
    core = {
        "schema": ISSUANCE_SCHEMA,
        "admission": admission,
        "bindings": {
            "candidate_sha256": digest_bytes(candidate_raw),
            "review_sha256": digest_bytes(review_raw),
            "review_receipt_digest": review["receipt_digest"],
            "review_subject_candidate_sha256": digest_bytes(review_subject_raw),
            "qualification_sha256": digest_bytes(qualification_raw),
            "producer_candidate_sha256": digest_bytes(canonical(producer_candidate)),
            "source_commits": source_commits,
        },
        "review_modes": {
            "producer_source": "existing-human-line-review",
            "deployment_checks": "automated-independent",
            "protocol_amendment": _AMENDMENT,
        },
        "human_review_evidence": _HUMAN_REVIEW_EVIDENCE,
        "machine_gates": {
            "reachable_sources": True,
            "candidate_machine_shape": True,
            "commands_reviewed": True,
            "activation_path_reviewed": True,
            "observer_independence_reviewed": True,
            "artifact_retention_reviewed": True,
            "three_arm_tp2_functional_qualification": True,
            "source_identity_match": True,
        },
        "formal_h1_starts": 0,
        "official_files_mutated": False,
        "non_claims": [
            "The deployment review is automated-independent, not human review.",
            "The TP2 qualification runs are preflights, not formal H1 starts.",
            "The qualification receipt is not a performance result.",
            (
                "This issuance does not mutate the official study, deployment, "
                "or registry."
            ),
        ],
    }
    receipt = {**core, "receipt_digest": digest_bytes(canonical(core))}
    validate_producer_admission_issuance(receipt)
    return receipt


def validate_producer_admission_issuance(value: Any) -> dict[str, Any]:
    """Validate a self-contained issuance envelope before extracting admission."""
    fields = {
        "schema",
        "admission",
        "bindings",
        "review_modes",
        "human_review_evidence",
        "machine_gates",
        "formal_h1_starts",
        "official_files_mutated",
        "non_claims",
        "receipt_digest",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("producer-admission issuance fields are incomplete")
    if (
        value["schema"] != ISSUANCE_SCHEMA
        or value["formal_h1_starts"] != 0
        or value["official_files_mutated"] is not False
        or value["review_modes"]
        != {
            "producer_source": "existing-human-line-review",
            "deployment_checks": "automated-independent",
            "protocol_amendment": _AMENDMENT,
        }
        or value["human_review_evidence"] != _HUMAN_REVIEW_EVIDENCE
        or not isinstance(value["machine_gates"], dict)
        or any(gate is not True for gate in value["machine_gates"].values())
        or not isinstance(value["non_claims"], list)
        or len(value["non_claims"]) < 4
    ):
        raise ValueError("producer-admission issuance boundary is invalid")
    validate_formal_adapter_admission(value["admission"])
    bindings = value["bindings"]
    if not isinstance(bindings, dict) or set(bindings) != {
        "candidate_sha256",
        "review_sha256",
        "review_receipt_digest",
        "review_subject_candidate_sha256",
        "qualification_sha256",
        "producer_candidate_sha256",
        "source_commits",
    }:
        raise ValueError("producer-admission issuance bindings are incomplete")
    digests = {key: item for key, item in bindings.items() if key != "source_commits"}
    if any(
        not isinstance(digest, str)
        or not digest.startswith("sha256:")
        or len(digest) != 71
        for digest in digests.values()
    ):
        raise ValueError("producer-admission issuance digest is malformed")
    core = {key: item for key, item in value.items() if key != "receipt_digest"}
    if value["receipt_digest"] != digest_bytes(canonical(core)):
        raise ValueError("producer-admission issuance digest is stale")
    return dict(value)


def main() -> None:
    parser = argparse.ArgumentParser(description="Issue H1 producer admission")
    parser.add_argument("candidate", type=Path)
    parser.add_argument("review", type=Path)
    parser.add_argument("qualification", type=Path)
    parser.add_argument("producer_study", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    producer_study = json.loads(args.producer_study.read_bytes())
    receipt = issue_producer_admission(
        candidate_raw=args.candidate.read_bytes(),
        review_raw=args.review.read_bytes(),
        qualification_raw=args.qualification.read_bytes(),
        producer_candidate=producer_study["producer_candidate"],
    )
    args.output.write_bytes(canonical(receipt) + b"\n")


if __name__ == "__main__":
    main()
