from __future__ import annotations

import copy
import json
from pathlib import Path

import jsonschema
import pytest

from vllm_hust_ext.h1_producer_admission import (
    canonical,
    issue_producer_admission,
    validate_producer_admission_issuance,
)

ROOT = Path("experiments/false_effective")
CANDIDATE = (
    ROOT
    / "deployment-candidates/h1-formal-registration-commands-reviewed-20261013.json"
)
UNREVIEWED_CANDIDATE = (
    ROOT / "deployment-candidates/h1-formal-registration-commands-20261013.json"
)
REVIEW = ROOT / "deployment-candidates/h1-automated-review-receipt-20261013.json"
QUALIFICATION = (
    ROOT
    / "deployment-candidates/h1-reachable-stack-tp2-qualification-20261013.json"
)


def inputs() -> tuple[bytes, bytes, bytes, dict[str, object]]:
    study = json.loads((ROOT / "first-formal-real-study.json").read_text())
    return (
        CANDIDATE.read_bytes(),
        REVIEW.read_bytes(),
        QUALIFICATION.read_bytes(),
        study["producer_candidate"],
    )


def issue() -> dict[str, object]:
    candidate, review, qualification, producer = inputs()
    return issue_producer_admission(
        candidate_raw=candidate,
        review_raw=review,
        qualification_raw=qualification,
        producer_candidate=producer,
    )


def test_issuer_binds_existing_human_review_and_three_machine_inputs() -> None:
    candidate, review, qualification, _ = inputs()
    receipt = issue()

    assert receipt["admission"]["human_line_review"] is True
    assert receipt["review_modes"] == {
        "producer_source": "existing-human-line-review",
        "deployment_checks": "automated-independent",
        "protocol_amendment": {
            "id": "h1-review-mode-owner-amendment-2026-10-13",
            "digest": (
                "sha256:e52dc2b3c171fabcada7ff5dc4370b28ad758f72b2c68292430af80b4165da9c"
            ),
        },
    }
    assert receipt["bindings"]["candidate_sha256"].endswith(
        __import__("hashlib").sha256(candidate).hexdigest()
    )
    assert receipt["bindings"]["candidate_sha256"] == (
        "sha256:1b9a01a9ef84b55b03ef88880d861f51131771ab08d95320dfb36c900295bf53"
    )
    assert receipt["bindings"]["review_subject_candidate_sha256"] == (
        "sha256:88ff58dcf1e2392064356293c7b32c173019dbf93d9f768879288a5248e82c55"
    )
    assert receipt["bindings"]["review_sha256"].endswith(
        __import__("hashlib").sha256(review).hexdigest()
    )
    assert receipt["bindings"]["qualification_sha256"] == (
        "sha256:5b77acdb1f510b55d6bb05a3762e0e1ca4a3670a0c1f4c390d4d7700f875af4c"
    )
    assert receipt["formal_h1_starts"] == 0
    assert receipt["official_files_mutated"] is False
    assert validate_producer_admission_issuance(receipt) == receipt

    schema = json.loads(
        (ROOT / "h1-producer-admission-issuance.schema.json").read_text()
    )
    jsonschema.Draft7Validator(schema).validate(receipt)


def test_checked_in_issuance_is_canonical_and_self_validating() -> None:
    path = (
        ROOT
        / "deployment-candidates/h1-producer-admission-issuance-20261013.json"
    )
    raw = path.read_bytes()
    receipt = json.loads(raw)
    assert raw == canonical(receipt) + b"\n"
    assert validate_producer_admission_issuance(receipt) == receipt


def test_issuer_rejects_forged_human_review_fact() -> None:
    candidate, review, qualification, producer = inputs()
    producer = copy.deepcopy(producer)
    producer["reviewed_head"] = "0" * 40
    with pytest.raises(ValueError, match="producer facts differ"):
        issue_producer_admission(
            candidate_raw=candidate,
            review_raw=review,
            qualification_raw=qualification,
            producer_candidate=producer,
        )


def test_issuer_rejects_unreviewed_candidate_as_final_subject() -> None:
    _, review, qualification, producer = inputs()
    with pytest.raises(ValueError, match="has not preserved its gates"):
        issue_producer_admission(
            candidate_raw=UNREVIEWED_CANDIDATE.read_bytes(),
            review_raw=review,
            qualification_raw=qualification,
            producer_candidate=producer,
        )


@pytest.mark.parametrize(
    ("input_name", "mutate", "message"),
    [
        (
            "candidate",
            lambda value: value["declared_identity"]["software"]["runtime"].update(
                repository_reachable=False
            ),
            "unreachable source",
        ),
        (
            "review",
            lambda value: value.update(human_review=True),
            "review",
        ),
        (
            "qualification",
            lambda value: value["runs"][0].update(formal_h1_start=True),
            "functional qualification is invalid",
        ),
        (
            "qualification",
            lambda value: value["runs"][0].update(performance_result=True),
            "functional qualification is invalid",
        ),
        (
            "qualification",
            lambda value: value["runs"][0].update(cleanup_proven=False),
            "functional qualification is invalid",
        ),
    ],
)
def test_issuer_fails_closed_on_gate_drift(input_name, mutate, message) -> None:
    candidate, review, qualification, producer = inputs()
    values = {
        "candidate": json.loads(candidate),
        "review": json.loads(review),
        "qualification": json.loads(qualification),
    }
    mutate(values[input_name])
    if input_name == "review":
        # Preserve self-consistency so the semantic false-human gate is tested.
        core = {
            key: value
            for key, value in values["review"].items()
            if key != "receipt_digest"
        }
        values["review"]["receipt_digest"] = (
            "sha256:" + __import__("hashlib").sha256(canonical(core)).hexdigest()
        )
    encoded = {
        "candidate": canonical(values["candidate"]) + b"\n",
        "review": canonical(values["review"]) + b"\n",
        "qualification": json.dumps(values["qualification"], indent=2).encode(),
    }
    with pytest.raises(ValueError, match=message):
        issue_producer_admission(
            candidate_raw=encoded["candidate"],
            review_raw=encoded["review"],
            qualification_raw=encoded["qualification"],
            producer_candidate=producer,
        )


def test_issuance_digest_and_gate_tampering_are_rejected() -> None:
    receipt = issue()
    receipt["machine_gates"]["artifact_retention_reviewed"] = False
    with pytest.raises(ValueError, match="boundary is invalid"):
        validate_producer_admission_issuance(receipt)

    receipt = issue()
    receipt["receipt_digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="digest is stale"):
        validate_producer_admission_issuance(receipt)
