"""Fully rehashed offline counterexamples of an actual CPU Unix/HTTP fixture."""

from __future__ import annotations

import base64
import json
import shutil
from pathlib import Path

import pytest
from test_native_attention_unix_candidate import observation as source_observation

from experiments.exposure_gate import native_semantic_collector as native
from experiments.native_attention_candidate import attention_consumer

observation = source_observation


def load(path):
    return json.loads(path.read_bytes())


def write(path, value):
    path.write_bytes(native.canonical(value))


def verify(root, source_resolver=None):
    return attention_consumer.verify_observation(
        load(root / "recipe.json"),
        "phase",
        root / "rpc",
        descriptor=load(root / "descriptor.json"),
        spec_path=root / "spec.json",
        policy_path=root / "policy.json",
        journal_path=root / "native.jsonl",
        source_resolver=source_resolver,
    )


def rechain(root, events):
    previous = "0" * 64
    for sequence, event in enumerate(events):
        event["sequence"] = sequence
        event["previous_sha256"] = previous
        event.pop("event_sha256", None)
        event["event_sha256"] = native.sha(native.canonical(event))
        previous = event["event_sha256"]
    (root / "native.jsonl").write_bytes(
        b"".join(native.canonical(event) + b"\n" for event in events)
    )
    receipt = load(root / "rpc/collector-after.json")
    receipt["status"]["acknowledged_prefix"] = dict(
        next_sequence=len(events),
        last_event_sha256=previous,
    )
    raw = native.canonical(receipt["status"])
    receipt["status_raw_base64"] = base64.b64encode(raw).decode()
    receipt["status_raw_sha256"] = native.sha(raw)
    write(root / "rpc/collector-after.json", receipt)


@pytest.mark.parametrize(
    "case",
    [
        "entry_checksum_changed",
        "cache_descriptor_fork",
        "metadata_seq_fork",
        "false_ACK_extra",
        "false_ACK_classification",
        "missing_OP_layer",
        "late_source_fact",
        "native_call_before_readback",
        "missing_final_ACK",
    ],
)
def test_rehashed_attention_counterexamples(observation, tmp_path, case):
    root = tmp_path / case
    shutil.copytree(
        observation["root"], root, ignore=shutil.ignore_patterns("native.sock")
    )
    events = [
        json.loads(line) for line in (root / "native.jsonl").read_bytes().splitlines()
    ]
    if case == "missing_final_ACK":
        (root / "rpc/collector-after.json").unlink()
    elif case == "missing_OP_layer":
        assert events[-1]["kind"] == "attention.operator.accepted"
        events.pop()
        rechain(root, events)
    else:
        event = events[-1]
        assert event["kind"] == "attention.operator.accepted"
        fact = json.loads(base64.b64decode(event["raw_base64"], validate=True))
        if case == "entry_checksum_changed":
            fact["native_selected_destination_sha256"]["K"] = "0" * 64
        elif case == "cache_descriptor_fork":
            fact["native_arguments"]["cache_views"]["K"]["storage_ptr"] += 1
        elif case == "metadata_seq_fork":
            fact["metadata_seq_lengths_kv"][0] += 1
        elif case.startswith("false_ACK"):
            ack = fact["materialization_ack"]
            if case == "false_ACK_extra":
                ack["counterfactual_field"] = True
            else:
                ack["classification"] = "COUNTERFACTUAL_CLASS"
            ack["ack_sha256"] = native.sha(
                native.canonical({k: v for k, v in ack.items() if k != "ack_sha256"})
            )
        elif case == "late_source_fact":
            metadata = load(root / "rpc/response-metadata.json")
            fact["monotonic_ns"] = metadata["received_monotonic_ns"] + 1
            event["accepted_monotonic_ns"] = fact["monotonic_ns"] + 1
        elif case == "native_call_before_readback":
            fact["native_call_started_ns"] = (
                fact["native_entry_readback_started_ns"] - 1
            )
        raw = native.canonical(fact)
        event["raw_base64"] = base64.b64encode(raw).decode()
        event["raw_sha256"] = native.sha(raw)
        rechain(root, events)
    with pytest.raises((ValueError, KeyError, OSError, IndexError, TypeError)):
        verify(root)


def test_portable_source_resolver_preserves_original_recipe(observation, tmp_path):
    root = observation["root"]
    recipe = load(root / "recipe.json")
    original = (root / "recipe.json").read_bytes()
    mapping = {}

    def visit(value):
        if isinstance(value, dict):
            if isinstance(value.get("path"), str) and value.get("sha256"):
                path = Path(value["path"])
                if str(path) not in mapping:
                    target = tmp_path / value["sha256"]
                    target.write_bytes(path.read_bytes())
                    mapping[str(path)] = target
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(recipe)
    observed = verify(root, lambda original: mapping[original])
    assert observed["operator_receipt_count"] == 56
    assert observed["finite_native_argument_completion_join"] is True
    assert observed["formal_result"] is False and observed["hardware_result"] is False
    assert observed["attention_consumption"] is None
    assert (root / "recipe.json").read_bytes() == original
    current = str(Path(attention_consumer.__file__).resolve())
    mapping[current].write_bytes(b"wrong source")
    with pytest.raises(ValueError):
        verify(root, lambda original: mapping[original])
