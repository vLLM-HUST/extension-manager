"""Actual CPU socket fixtures and fully rehashed drain-control counterexamples."""

from __future__ import annotations

import base64
import copy
import json

import pytest
from test_native_attention_drain_unix import observation as source_observation

from experiments.native_attention_candidate import attention_consumer as base
from experiments.native_attention_candidate import drain_consumer, drain_time_policy

observation = source_observation


@pytest.mark.parametrize("observation", [True], indirect=True)
def test_live_authenticated_source_completion_wait(observation):
    result = observation["result"]
    assert result["mixed_attention_HTTP_ACK_join"] is True, result
    assert result["operator_receipt_count"] == result["tensor_receipt_count"] == 56
    assert list(observation["output"].glob("collector-drain-poll-*.json"))
    assert result["formal_result"] is False


def read(observation):
    return [json.loads(x) for x in observation["journal"].read_bytes().splitlines()]


def write_rehashed(observation, tmp_path, events):
    target = tmp_path / "native.jsonl"
    for artifact in observation["root"].glob("*.json"):
        if len(artifact.stem) == 64:
            (tmp_path / artifact.name).write_bytes(artifact.read_bytes())
    previous = "0" * 64
    for seq, e in enumerate(events):
        e["sequence"], e["previous_sha256"] = seq, previous
        e.pop("event_sha256", None)
        e["event_sha256"] = base.sha(base.canonical(e))
        previous = e["event_sha256"]
    target.write_bytes(b"".join(base.canonical(e) + b"\n" for e in events))
    return target, dict(next_sequence=len(events), last_event_sha256=previous)


def verify(observation, journal, prefix):
    return base.verify_attention_archive(
        observation["spec"],
        observation["policy"],
        journal,
        acknowledged_prefix=prefix,
        drain_policy_path=observation["drain_policy"],
    )


def test_complete_actual_CPU_source_drains_and_HTTP_ACK_join(observation):
    events = read(observation)
    prefix = dict(
        next_sequence=len(events), last_event_sha256=events[-1]["event_sha256"]
    )
    result = verify(observation, observation["journal"], prefix)
    assert result["source_operator_completion_join"] is True
    assert result["full_phase_source_drained"] is True
    assert len(result["source_drains"]) == 2
    recipe = drain_consumer.declare_drain_recipe(observation["recipe"])
    actual = drain_consumer.verify_observation(
        recipe,
        "phase",
        observation["output"],
        descriptor=observation["descriptor"],
        spec_path=observation["spec"],
        journal_path=observation["journal"],
        policy_path=observation["policy"],
        drain_policy_path=observation["drain_policy"],
    )
    assert actual["observed_typed_HTTP_ACK_join"] is True
    assert actual["operator_receipt_count"] == actual["tensor_receipt_count"] == 56
    assert actual["formal_result"] is False
    assert actual["attention_consumption"] is None


def test_explicit_nonwitness_tail_recipe_preserves_all_actual_CPU_effect_witnesses(
    observation,
):
    recipe = drain_consumer.declare_drain_recipe(
        observation["recipe"],
        upload_tail_policy=drain_time_policy.NONWITNESS_UPLOAD_TAIL,
    )
    assert recipe["attention_drain_contract"]["schema"] == drain_consumer.TAIL_CONTRACT
    actual = drain_consumer.verify_observation(
        recipe,
        "phase",
        observation["output"],
        descriptor=observation["descriptor"],
        spec_path=observation["spec"],
        journal_path=observation["journal"],
        policy_path=observation["policy"],
        drain_policy_path=observation["drain_policy"],
    )
    temporal = actual["ACK_time_contract"]
    assert temporal["upload_tail_policy"] == drain_time_policy.NONWITNESS_UPLOAD_TAIL
    assert set(temporal["required_destination_upload_witness_sequences"]) == {"0", "1"}
    assert actual["operator_receipt_count"] == actual["tensor_receipt_count"] == 56
    assert temporal["nonwitness_upload_tail_sequences"] == []
    assert actual["formal_result"] is False


def test_upload_tail_policy_is_never_implicit_or_unknown(observation):
    original = drain_consumer.declare_drain_recipe(observation["recipe"])
    assert original["attention_drain_contract"]["schema"] == drain_consumer.CONTRACT
    assert "upload_tail_policy" not in original["attention_drain_contract"]
    with pytest.raises(ValueError, match="unknown nonwitness"):
        drain_consumer.declare_drain_recipe(
            observation["recipe"], upload_tail_policy="any-late-fact"
        )
    explicit = drain_consumer.declare_drain_recipe(
        observation["recipe"],
        upload_tail_policy=drain_time_policy.NONWITNESS_UPLOAD_TAIL,
    )
    del explicit["attention_drain_contract"]["upload_tail_policy"]
    with pytest.raises(ValueError, match="scope differs"):
        drain_consumer.require_declared_drain_recipe(explicit)


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_close",
        "missing_ack",
        "wrong_rank",
        "early_close",
        "replay_close",
        "fact_after_close",
    ],
)
def test_full_rehashed_chain_cannot_hide_missing_or_postclose_data(
    observation, tmp_path, mutation
):
    events = copy.deepcopy(read(observation))
    close = [i for i, e in enumerate(events) if e["kind"] == "attention.worker.drained"]
    if mutation == "missing_close":
        events.pop(close[-1])
    elif mutation == "replay_close":
        events.append(copy.deepcopy(events[close[-1]]))
    elif mutation == "fact_after_close":
        pid = events[close[-1]]["peer"]["pid"]
        events.append(
            copy.deepcopy(
                next(
                    e
                    for e in events
                    if e.get("peer", {}).get("pid") == pid
                    and e["kind"] == "native.accepted"
                )
            )
        )
    else:
        e = events[close[-1]]
        fact = json.loads(base64.b64decode(e["raw_base64"]))
        if mutation == "missing_ack":
            fact["source_ack_count"] -= 1
        elif mutation == "wrong_rank":
            fact["process"]["ordinal"] = 0
        else:
            fact["monotonic_ns"] = fact["source_drain_completed_monotonic_ns"] = 1
        raw = base.canonical(fact)
        e["raw_base64"], e["raw_sha256"] = base64.b64encode(raw).decode(), base.sha(raw)
    journal, prefix = write_rehashed(observation, tmp_path, events)
    with pytest.raises(ValueError):
        verify(observation, journal, prefix)


def test_actual_closed_chain_cannot_use_preclose_or_forged_ACK(observation):
    events = read(observation)
    for prefix in [
        dict(
            next_sequence=len(events) - 2, last_event_sha256=events[-3]["event_sha256"]
        ),
        dict(next_sequence=len(events), last_event_sha256="0" * 64),
    ]:
        with pytest.raises(ValueError, match="ACK prefix"):
            verify(observation, observation["journal"], prefix)


def test_existing_recipe_cannot_implicitly_admit_new_drain(observation):
    with pytest.raises(ValueError, match="not preregistered"):
        drain_consumer.require_declared_drain_recipe(observation["recipe"])


def test_declared_source_tamper_is_rejected(observation):
    recipe = drain_consumer.declare_drain_recipe(observation["recipe"])
    path = next(iter(recipe["attention_drain_contract"]["source_sha256"]))
    recipe["attention_drain_contract"]["source_sha256"][path] = "0" * 64
    with pytest.raises(ValueError, match="bytes/paths"):
        drain_consumer.require_declared_drain_recipe(recipe)
