"""Unrun actual CPU fixture cases: partial completion never waives existing facts."""

from __future__ import annotations

import base64
import copy
import json

import pytest
from test_native_attention_drain_consumer import read, write_rehashed
from test_native_attention_drain_unix import observation as source_observation

from experiments.native_attention_candidate import attention_consumer as base

observation = source_observation


def partial(observation, journal):
    return base._verify_attention_archive(
        observation["spec"],
        observation["policy"],
        journal,
        drain_policy_path=observation["drain_policy"],
        acknowledged_prefix=None,
        _owner=object(),
        _allow_incomplete=True,
    )


def test_typed_incomplete_drain_has_no_ack_or_successful_native_proof(
    observation, tmp_path
):
    events = read(observation)
    events.pop(
        next(
            i
            for i in reversed(range(len(events)))
            if events[i]["kind"] == "attention.worker.drained"
        )
    )
    journal, _ = write_rehashed(observation, tmp_path, events)
    report = partial(observation, journal)
    assert report["full_phase_source_drained"] is False
    assert report["acknowledged_prefix_status"] == "unknown"
    assert report["attention_complete_transactions"] == []
    assert report["source_operator_completion_join"] is False
    assert report["formal_registration"] is False
    with pytest.raises(ValueError, match="full phase source drain"):
        base.verify_attention_archive(
            observation["spec"],
            observation["policy"],
            journal,
            drain_policy_path=observation["drain_policy"],
        )


@pytest.mark.parametrize("case", ["tensor-bytes", "OP", "ACK", "epoch", "chain"])
def test_incomplete_mode_rejects_existing_corrupt_facts(observation, tmp_path, case):
    events = copy.deepcopy(read(observation))
    events.pop(
        next(
            i
            for i in reversed(range(len(events)))
            if events[i]["kind"] == "attention.worker.drained"
        )
    )
    if case in {"OP", "ACK"}:
        event = next(e for e in events if e["kind"] == "attention.operator.accepted")
        fact = json.loads(base64.b64decode(event["raw_base64"], validate=True))
        if case == "OP":
            fact["native_selected_destination_sha256"]["K"] = "0" * 64
        else:
            ack = fact["materialization_ack"]
            ack["classification"] = "FORGED"
            ack["ack_sha256"] = base.sha(
                base.canonical({k: v for k, v in ack.items() if k != "ack_sha256"})
            )
        raw = base.canonical(fact)
        event.update(
            raw_base64=base64.b64encode(raw).decode(), raw_sha256=base.sha(raw)
        )
    elif case == "epoch":
        event = next(e for e in events if e["kind"] == "native.accepted")
        fact = json.loads(base64.b64decode(event["raw_base64"], validate=True))
        fact["launch_id"] = "wrong-launch"
        raw = base.canonical(fact)
        event.update(
            raw_base64=base64.b64encode(raw).decode(), raw_sha256=base.sha(raw)
        )
    journal, _ = write_rehashed(observation, tmp_path, events)
    if case == "tensor-bytes":
        event = next(e for e in events if e["kind"] == "tensor.artifact.accepted")
        artifact = tmp_path / event["artifact"]["basename"]
        raw = artifact.read_bytes()
        artifact.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
    elif case == "chain":
        raw = journal.read_bytes()
        journal.write_bytes(raw.replace(b'"event_sha256":"', b'"event_sha256":"0', 1))
    with pytest.raises(ValueError):
        partial(observation, journal)
