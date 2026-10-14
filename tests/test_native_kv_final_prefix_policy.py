"""Real CPU HTTP/Unix clocks plus semantic rehashed archive counterexamples."""

import base64
import json
import shutil

import pytest
from test_native_kv_challenge_pipeline import (
    test_new_kv_long_nonce_http_and_actual_three_peer_semantic_transport as run_cpu,
)

from experiments.native_challenge_candidate import kv_archive, kv_time_policy
from experiments.native_challenge_candidate.request_runner import canonical, sha


@pytest.fixture(scope="module")
def real_archive(tmp_path_factory):
    root = tmp_path_factory.mktemp("ackcpu")
    run_cpu(root, "late-final-prefix", True, kv_time_policy.FINAL_PREFIX_POLICY)
    return root / "archive"


def load(root, name):
    return json.loads((root / name).read_bytes())


def write(root, name, value):
    (root / name).write_bytes(canonical(value))


def rehash_events(root, events, after):
    previous = "0" * 64
    for event in events:
        event["previous_sha256"] = previous
        event.pop("event_sha256")
        event["event_sha256"] = sha(canonical(event))
        previous = event["event_sha256"]
    (root / "native.jsonl").write_bytes(b"".join(canonical(e) + b"\n" for e in events))
    after["status"]["acknowledged_prefix"]["last_event_sha256"] = previous


def rehash_receipt(receipt):
    raw = canonical(receipt["status"]) + b"\n"
    receipt["status_raw_base64"] = base64.b64encode(raw).decode()
    receipt["status_raw_sha256"] = sha(raw)


def refresh_manifest(root):
    manifest = load(root, "manifest.json")
    manifest["file_sha256"] = {
        name: sha((root / name).read_bytes()) for name in manifest["file_sha256"]
    }
    write(root, "manifest.json", manifest)
    return sha((root / "manifest.json").read_bytes())


@pytest.mark.parametrize(
    "case",
    [
        "fact-after-HTTP",
        "accept-before-fact",
        "TTL",
        "ACK-before-prefix",
        "future-source-clock",
        "foreign-peer",
        "foreign-source",
        "missing-clocks",
        "phase-budget",
        "unknown-policy",
        "legacy-no-upgrade",
    ],
)
def test_fully_rehashed_temporal_or_binding_forgery_rejected(
    real_archive, tmp_path, case
):
    root = tmp_path / "archive"
    shutil.copytree(real_archive, root)
    events = [json.loads(x) for x in (root / "native.jsonl").read_bytes().splitlines()]
    after = load(root, "collector-after.json")
    metadata = load(root, "response-metadata.json")
    recipe = load(root, "recipe.json")
    phase = recipe["phases"][0]
    event = events[-1]
    fact = json.loads(base64.b64decode(event["raw_base64"]))
    if case == "fact-after-HTTP":
        fact["monotonic_ns"] = metadata["received_monotonic_ns"] + 1
        fact["observed_after_barrier_monotonic_ns"] = fact["monotonic_ns"] + 1
    elif case == "accept-before-fact":
        event["accepted_monotonic_ns"] = fact["monotonic_ns"] - 1
    elif case == "TTL":
        event["accepted_monotonic_ns"] = fact["monotonic_ns"] + 5_000_000_001
        after["status"]["issued_monotonic_ns"] = event["accepted_monotonic_ns"] + 1
        after["authentication_clock"]["completed_monotonic_ns"] = (
            event["accepted_monotonic_ns"] + 2
        )
    elif case == "ACK-before-prefix":
        after["status"]["issued_monotonic_ns"] = metadata["received_monotonic_ns"] + 1
        after["authentication_clock"]["dispatch_monotonic_ns"] = metadata[
            "received_monotonic_ns"
        ]
    elif case == "future-source-clock":
        after["status"]["issued_monotonic_ns"] = (
            after["authentication_clock"]["completed_monotonic_ns"] + 1
        )
    elif case == "foreign-peer":
        after["kernel_peer"]["pid"] += 1
    elif case == "foreign-source":
        after["status"]["collector_source_sha256"] = "0" * 64
    elif case == "missing-clocks":
        del after["authentication_clock"]
        del after["status"]["issued_monotonic_ns"]
    elif case == "phase-budget":
        after["authentication_clock"]["completed_monotonic_ns"] += 181_000_000_000
    elif case == "unknown-policy":
        phase["ack_time_policy"] = "unregistered"
    else:
        del phase["ack_time_policy"]
        del phase["ack_client_source_sha256"]
    raw = canonical(fact)
    event["raw_base64"] = base64.b64encode(raw).decode()
    event["raw_sha256"] = sha(raw)
    rehash_events(root, events, after)
    rehash_receipt(after)
    write(root, "collector-after.json", after)
    write(root, "recipe.json", recipe)
    expected = refresh_manifest(root)
    with pytest.raises((ValueError, KeyError)):
        kv_archive.verify(root, expected, "phase0")
