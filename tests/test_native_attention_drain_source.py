"""Pinned native removal control flow and source drain semantics; CPU only."""

from __future__ import annotations

import ast
import copy
import gzip
import json
from types import SimpleNamespace as NS

import pytest

from experiments.native_attention_candidate import build_drain_source_patch as builder
from experiments.native_attention_candidate import drain_collector as receiver
from experiments.native_attention_candidate import phase_drain as producer


@pytest.fixture
def source_state(monkeypatch):
    monkeypatch.setenv(producer.ENV, "1")
    monkeypatch.setattr(producer, "_records", {})
    monkeypatch.setattr(producer, "_closed", set())
    process = dict(role="worker", ordinal=0, pid=101)

    def scope(role):
        return dict(
            process=process, launch_id="launch", plan_id="plan", monotonic_ns=10
        )

    ack = dict(sequence=5, event_sha256="a" * 64, raw_sha256="b" * 64)
    producer.record_ack("request", ack)
    runner = NS(
        requests={"request": object()},
        num_prompt_logprobs={},
        input_batch=NS(req_id_to_index={"request": 0}),
        _on_request_state_removed=lambda req, state: None,
        late_interaction_runner=NS(on_requests_finished=lambda ids: None),
    )
    runner.input_batch.remove_request = lambda req: (
        runner.input_batch.req_id_to_index.pop(req, None)
    )
    output = NS(
        finished_req_ids={"request"}, num_scheduled_tokens={}, scheduled_new_reqs=[]
    )
    return process, scope, ack, runner, output


def pinned_actual_removal(runner, output):
    binding = json.loads((builder.SNAPSHOT / "binding.json").read_bytes())
    entry = binding["files"]["vllm/v1/worker/gpu_model_runner.py"]
    tree = ast.parse(
        gzip.decompress((builder.SNAPSHOT / entry["snapshot"]).read_bytes())
    )
    cls = next(
        n
        for n in tree.body
        if isinstance(n, ast.ClassDef) and n.name == "GPUModelRunner"
    )
    fn = next(
        n
        for n in cls.body
        if isinstance(n, ast.FunctionDef) and n.name == "_update_states"
    )
    # Execute exact pinned source removal statements before cache zeroing and
    # scheduling. The batch storage/callbacks are explicitly CPU test doubles;
    # this is not full Host/Ascend execution or a native source-role receipt.
    module = ast.Module(body=fn.body[1:4], type_ignores=[])
    exec(
        compile(module, "pinned-Host-_update_states-removal", "exec"),
        {"self": runner, "scheduler_output": output},
    )


def test_source_ack_requires_actual_removal_and_binds_all_intake(source_state):
    process, scope, ack, runner, output = source_state
    with pytest.raises(ValueError, match="has not been removed"):
        producer.after_finished_request_removal(
            runner, output, scope=scope, publish=lambda f: None
        )
    pinned_actual_removal(runner, output)
    observed = []

    def publish(fact):
        observed.append(fact)
        return dict(raw_sha256=producer.digest(fact))

    producer.after_finished_request_removal(
        runner, output, scope=scope, publish=publish
    )
    fact = observed[0]
    assert fact["source_ack_count"] == 1 and fact["source_last_ack"] == ack
    with pytest.raises(ValueError, match="after source-owned"):
        producer.record_ack("request", ack)
    with pytest.raises(ValueError, match="replayed"):
        producer.after_finished_request_removal(
            runner, output, scope=scope, publish=publish
        )


@pytest.mark.parametrize(
    "mutation",
    [
        "missing_ack",
        "wrong_digest",
        "wrong_rank",
        "wrong_request",
        "retained_row",
        "clock",
        "false_finish",
        "source_field",
        "before_last_ack",
    ],
)
def test_pure_complete_sender_prefix_counterfactual(
    source_state, mutation, monkeypatch
):
    process, scope, ack, runner, output = source_state
    pinned_actual_removal(runner, output)
    monkeypatch.setattr(producer.time, "monotonic_ns", lambda: 11)
    facts = []
    producer.after_finished_request_removal(
        runner,
        output,
        scope=scope,
        publish=lambda fact: (
            facts.append(fact) or dict(raw_sha256=producer.digest(fact))
        ),
    )
    fact = copy.deepcopy(facts[0])
    records = [ack]
    sender = {"process": process}
    spec = dict(
        native_launch_id="launch",
        native_plan_id="plan",
        frozen_monotonic_ns=1,
        max_event_age_ns=100,
    )
    phase = dict(expected_ranks=[0, 1])
    receiver.verify_drain(
        fact,
        sender=sender,
        spec=spec,
        phase=phase,
        records=records,
        accepted_monotonic_ns=12,
        previous_ack_accepted_monotonic_ns=10,
    )
    if mutation == "missing_ack":
        records = []
    elif mutation == "wrong_digest":
        fact["source_ack_chain_sha256"] = "0" * 64
    elif mutation == "wrong_rank":
        fact["process"]["ordinal"] = 1
    elif mutation == "wrong_request":
        fact["plan_id"] = "foreign"
    elif mutation == "retained_row":
        fact["native_input_batch_contains"] = True
    elif mutation == "clock":
        fact["source_drain_completed_monotonic_ns"] = 13
    elif mutation == "false_finish":
        fact["scheduled_finished"] = False
    elif mutation == "source_field":
        fact["unknown_owner_override"] = True
    elif mutation == "before_last_ack":
        fact["monotonic_ns"] = 9
    with pytest.raises(ValueError):
        receiver.verify_drain(
            fact,
            sender=sender,
            spec=spec,
            phase=phase,
            records=records,
            accepted_monotonic_ns=12,
            previous_ack_accepted_monotonic_ns=10,
        )


def test_ack_failure_and_resubmission_cannot_source_close(source_state):
    _process, scope, _ack, runner, output = source_state
    pinned_actual_removal(runner, output)
    output.scheduled_new_reqs = [NS(req_id="request")]
    with pytest.raises(ValueError, match="resubmitted"):
        producer.after_finished_request_removal(
            runner, output, scope=scope, publish=lambda f: None
        )
    output.scheduled_new_reqs = []
    with pytest.raises(ValueError, match="lacks actual raw ACK"):
        producer.after_finished_request_removal(
            runner, output, scope=scope, publish=lambda f: None
        )
    assert "request" not in producer._closed


def test_new_patch_preserves_ascend_and_native_source_order(tmp_path):
    manifest = builder.emit(tmp_path / "new")
    assert manifest["Ascend_source_changed"] is False
    assert manifest["native_ELF_rebuild_required"] is False
    _binding, _before, after = builder.sources()
    source = after["vllm/v1/worker/gpu_model_runner.py"]
    method = source[source.index("    def _update_states(") :]
    assert method.index("self.input_batch.remove_request(req_id)") < method.index(
        "after_finished_request_removal(\n"
    )
    assert (
        "return _observer(factory())"
        in after["vllm/plugins/native_block_table_observer.py"]
    )


def test_real_thread_source_close_waits_for_pending_authenticated_publication(
    source_state,
):
    import threading

    _process, scope, _ack, runner, output = source_state
    pinned_actual_removal(runner, output)
    entered, release, closed = threading.Event(), threading.Event(), threading.Event()
    receipts = []

    def pending():
        entered.set()
        assert release.wait(2)
        return dict(sequence=6, event_sha256="c" * 64, raw_sha256="d" * 64)

    def finish():
        producer.after_finished_request_removal(
            runner,
            output,
            scope=scope,
            publish=lambda fact: (
                receipts.append(fact) or dict(raw_sha256=producer.digest(fact))
            ),
        )
        closed.set()

    sending = threading.Thread(
        target=lambda: producer.acknowledged_publication("request", pending)
    )
    sending.start()
    assert entered.wait(2)
    closing = threading.Thread(target=finish)
    closing.start()
    assert not closed.is_set()  # actual pending callback owns the source lock
    release.set()
    sending.join(2)
    closing.join(2)
    assert closed.is_set() and not sending.is_alive() and not closing.is_alive()
    assert receipts[0]["source_ack_count"] == 2
    assert receipts[0]["source_last_ack"]["sequence"] == 6
    with pytest.raises(ValueError, match="publication after source-owned"):
        producer.acknowledged_publication("request", lambda: None)
