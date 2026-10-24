"""Retained real model execution and adversarial evidence checks."""

import json
import tarfile
from pathlib import Path

import pytest

from experiments.formal_campaign.h3_model_qualification import verify, verify_archive
from scripts.benchmark_inputs import resolve_original

ARCHIVE = resolve_original(
    Path(__file__).resolve().parents[1]
    / "experiments/formal_campaign/artifacts/h3-model-qualification-20261013/raw.tar.gz"
)


def test_real_two_backend_qualification():
    result = verify_archive(ARCHIVE)
    assert result["classification"] == "QUALIFIED_NONFORMAL"
    assert result["real_model_completions"] == 7
    assert result["two_distinct_tp2_backend_worker_sets"]
    assert not result["formal_result"]


@pytest.mark.parametrize(
    ("name", "mutation", "error"),
    [
        ("fault.json", lambda x: x.update(signal="SIGTERM"), "not killed"),
        ("proxy-after.json", lambda x: x.update(status=503), "marker completion"),
        (
            "prepare-proof.json",
            lambda x: x["native_rows"][1].update(operation_id="replayed"),
            "digest changed",
        ),
        (
            "restart.json",
            lambda x: x.update(monotonic_ns=1),
            "during crash",
        ),
    ],
)
def test_reject_mutated_execution(tmp_path, name, mutation, error):
    with tarfile.open(ARCHIVE) as archive:
        archive.extractall(tmp_path, filter="data")
    path = tmp_path / name
    value = json.loads(path.read_text())
    mutation(value)
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match=error):
        verify(tmp_path)


@pytest.mark.parametrize("name", ["proxy-after.json", "candidate/direct-after.json"])
def test_after_completions_must_follow_restart(tmp_path, name):
    with tarfile.open(ARCHIVE) as archive:
        archive.extractall(tmp_path, filter="data")
    path = tmp_path / name
    value = json.loads(path.read_text())
    value["started_monotonic_ns"] = 1
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="preceded restart"):
        verify(tmp_path)


def test_cleanup_must_follow_candidate_after_completion(tmp_path):
    with tarfile.open(ARCHIVE) as archive:
        archive.extractall(tmp_path, filter="data")
    cleanup = tmp_path / "cleanup-owned-processes.json"
    value = json.loads(cleanup.read_text())
    value["observed_monotonic_ns"] = (
        json.loads((tmp_path / "proxy-after.json").read_text())["finished_monotonic_ns"]
        + 1
    )
    cleanup.write_text(json.dumps(value))
    with pytest.raises(ValueError, match="cleanup predates"):
        verify(tmp_path)


def test_rehashed_wrong_predecessor_cannot_change_frozen_native_binding(tmp_path):
    import hashlib

    with tarfile.open(ARCHIVE) as archive:
        archive.extractall(tmp_path, filter="data")
    path = tmp_path / "authority.jsonl"
    events = [json.loads(line) for line in path.read_text().splitlines()]
    previous = "sha256:" + "0" * 64
    encoded = []
    for event in events:
        event["route"]["snapshot_sha256"] = "sha256:" + "a" * 64
        event["previous_sha256"] = previous
        raw = json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False)
        previous = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
        encoded.append(raw)
    path.write_text("\n".join(encoded) + "\n")
    with pytest.raises(ValueError, match="authority predecessor differs"):
        verify(tmp_path)
