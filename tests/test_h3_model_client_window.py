"""Portable retained-model crash-window evidence and counterexample checks."""

import hashlib
import json
import tarfile
from pathlib import Path

import pytest

from experiments.formal_campaign.h3_model_client_window import verify, verify_archive

ARCHIVE = (
    Path(__file__).resolve().parents[1]
    / "experiments/formal_campaign/artifacts/h3-model-client-window-20261013/raw.tar.gz"
)


def unpack(root):
    with tarfile.open(ARCHIVE) as archive:
        archive.extractall(root, filter="data")


def rewrite_chain(path, mutate):
    events = [json.loads(line) for line in path.read_text().splitlines()]
    mutate(events)
    previous = "sha256:" + "0" * 64
    encoded = []
    for event in events:
        event["previous_sha256"] = previous
        raw = json.dumps(event, sort_keys=True, separators=(",", ":"), allow_nan=False)
        previous = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
        encoded.append(raw)
    path.write_text("\n".join(encoded) + "\n")


def test_real_model_finite_delivery_window():
    result = verify_archive(ARCHIVE)
    window = result["finite_delivery_window"]
    assert window["request_count"] == 60
    assert window["lost_requests"] == 0
    assert window["backend_execution_duplicates"] is None
    assert window["duplicated_requests"] is None
    assert result["observed_delivered_generations"] == [0]
    assert not result["candidate_exposed"]
    assert not result["formal_result"]
    assert result["full_objective_satisfied"] is None


def test_truncated_finite_window_cannot_publish_counts(tmp_path):
    unpack(tmp_path)
    rewrite_chain(tmp_path / "client.jsonl", lambda events: events.pop())
    with pytest.raises(ValueError, match="finite delivery coverage incomplete"):
        verify(tmp_path)


def test_request_response_join_keys_are_not_evidence(tmp_path):
    unpack(tmp_path)

    def mutate(events):
        for event in events:
            if (
                event["kind"] == "request.complete"
                and "/request-" in event["detail"]["request_id"]
            ):
                event["detail"]["admission_id"] = "forged-header-join"
                return

    rewrite_chain(tmp_path / "authority.jsonl", mutate)
    with pytest.raises(ValueError, match="unique authority admission/completion"):
        verify(tmp_path)


def test_exact_prompt_cannot_change_after_model_launch(tmp_path):
    unpack(tmp_path)
    (tmp_path / "model-prompt.txt").write_text("changed oracle prompt")
    with pytest.raises(ValueError, match="frozen input changed"):
        verify(tmp_path)


def test_client_registered_backend_is_the_actual_launched_epoch(tmp_path):
    unpack(tmp_path)
    path = tmp_path / "client-spec.json"
    spec = json.loads(path.read_text())
    spec["backend_registration"]["28187"]["process_identity"]["pid"] = 1
    path.write_text(json.dumps(spec, sort_keys=True, indent=2) + "\n")
    frozen_path = tmp_path / "frozen-client-inputs.json"
    frozen = json.loads(frozen_path.read_text())
    frozen["spec_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    frozen_path.write_text(json.dumps(frozen))
    (tmp_path / "backend-registration.json").write_text(
        json.dumps(spec["backend_registration"])
    )
    with pytest.raises(ValueError, match="actual launch"):
        verify(tmp_path)


def test_cleanup_must_follow_all_finite_requests(tmp_path):
    unpack(tmp_path)
    markers = [
        "predecessor/direct-before.json",
        "candidate/direct-before.json",
        "proxy-before.json",
        "predecessor/during-crash.json",
        "candidate/during-crash.json",
        "proxy-after.json",
        "candidate/direct-after.json",
    ]
    late_marker = max(
        json.loads((tmp_path / name).read_text())["finished_monotonic_ns"]
        for name in markers
    )
    path = tmp_path / "cleanup-owned-processes.json"
    cleanup = json.loads(path.read_text())
    cleanup["observed_monotonic_ns"] = late_marker + 1
    path.write_text(json.dumps(cleanup))
    with pytest.raises(ValueError, match="client cleanup predates"):
        verify(tmp_path)


def test_native_recovery_marker_is_not_an_unbound_report(tmp_path):
    unpack(tmp_path)
    path = tmp_path / "recovery-marker.json"
    marker = json.loads(path.read_text())
    marker["identity"] = json.loads((tmp_path / "fault.json").read_text())["target"]
    path.write_text(json.dumps(marker))
    with pytest.raises(ValueError, match="native fault/recovery window"):
        verify(tmp_path)


def test_post_proxy_marker_candidate_open_rejected_through_client_stop(tmp_path):
    import copy

    from experiments.formal_campaign.h3_authority_chain import snapshot_digest

    unpack(tmp_path)
    marker_end = json.loads((tmp_path / "proxy-after.json").read_text())[
        "finished_monotonic_ns"
    ]
    client_stop = json.loads((tmp_path / "client.jsonl").read_text().splitlines()[-1])[
        "monotonic_ns"
    ]
    candidate = json.loads((tmp_path / "spec.json").read_text())["candidate"]

    def mutate(events):
        for index in range(1, len(events)):
            previous_ns = events[index - 1]["monotonic_ns"]
            current_ns = events[index]["monotonic_ns"]
            if marker_end < previous_ns + 1 < current_ns < client_stop:
                exposure = copy.deepcopy(events[index])
                exposure["monotonic_ns"] = previous_ns + 1
                exposure["kind"] = "route.open.applied"
                exposure["route"] = {
                    "generation": 1,
                    "fence": "fence-1",
                    "snapshot_sha256": snapshot_digest(candidate),
                }
                exposure["detail"] = {"generation": 1}
                events.insert(index, exposure)
                for sequence, event in enumerate(events, 1):
                    event["sequence"] = sequence
                return
        raise AssertionError("fixture has no post-marker/pre-stop event gap")

    rewrite_chain(tmp_path / "authority.jsonl", mutate)
    with pytest.raises(ValueError, match="candidate exposure|before-effect"):
        verify(tmp_path)
