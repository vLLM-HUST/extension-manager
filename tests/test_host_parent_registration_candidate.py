"""The checked candidate is review material, never formal-real evidence."""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest
from jsonschema import ValidationError

ROOT = Path(__file__).resolve().parents[1]
EXPERIMENT = ROOT / "experiments/exposure_gate"
sys.path.insert(0, str(EXPERIMENT))

import host_parent_registration as registration  # noqa: E402


def candidate() -> dict:
    return json.loads(registration.CANDIDATE_PATH.read_bytes())


def test_checked_candidate_is_source_bound_and_blocked() -> None:
    value = registration.load_candidate()
    assert value["registration"] == {
        "admissible": False,
        "blockers": registration.REQUIRED_BLOCKERS,
        "state": "blocked",
    }
    assert value["host_source"]["candidate_commit"] == (
        "379a0ad35e9de6928e3481d375692204b0dee6e4"
    )
    assert value["wheel"]["sha256"] == (
        "sha256:a850a238b7ac0b6fdb9fd0ceb833dd843c0242570977b0f14fae482fe8d3d551"
    )
    assert value["manager_review_context"]["commit"] == (
        "32cebf7215a22fa0ae80ed613ed86de2f88226ba"
    )
    assert value["review"]["verdict"] == "BLOCKED"


def test_committed_preflight_bytes_are_exactly_bound() -> None:
    value = registration.load_candidate()
    path = registration.resolve_original(
        ROOT / value["functional_preflight"]["artifact_path"]
    )
    assert registration.digest_bytes(path.read_bytes()) == value[
        "functional_preflight"
    ]["artifact_sha256"]
    observed = json.loads(path.read_bytes())
    assert observed["classification"] == "unregistered-functional-preflight"
    assert observed["formal_result"] is False
    assert observed["performance_result"] is False


def test_unreachable_candidate_cannot_be_promoted() -> None:
    value = candidate()
    value["registration"].update(state="registered", admissible=True)
    with pytest.raises((ValueError, ValidationError)):
        registration.validate_candidate(value)


def test_claiming_remote_reachability_without_new_receipt_fails_closed() -> None:
    value = candidate()
    value["host_source"]["remote_observation"]["candidate_reachable"] = True
    value["host_source"]["remote_observation"]["matching_refs"] = [
        "refs/heads/formal-api-parent"
    ]
    with pytest.raises((ValueError, ValidationError)):
        registration.validate_candidate(value)


def test_review_receipt_is_content_addressed() -> None:
    value = candidate()
    value["wheel"]["size_bytes"] += 1
    with pytest.raises(ValueError, match="subject digest is stale"):
        registration.validate_candidate(value)


def test_artifact_is_canonical_json() -> None:
    raw = registration.CANDIDATE_PATH.read_bytes()
    assert raw == registration.canonical(json.loads(raw)) + b"\n"
    assert hashlib.sha256(raw).hexdigest() == (
        "491d7a671dcaa2a26d07fdf9d67e5e2eeaef9f91a85f1338e237e333dd77b1b6"
    )
