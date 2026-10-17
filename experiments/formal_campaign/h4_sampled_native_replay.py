"""Independent H4 full-native archive replay; no H3 traffic-domain projection."""
from __future__ import annotations
import base64
import json
from pathlib import Path
from experiments.formal_campaign import h4_sampled_native_collector, h4_sampled_native_client
from experiments.native_attention_candidate import attention_consumer, request_drain_consumer
from experiments.native_kv_tensor_candidate.projection_tensor_join import verify_projection_tensor_join

native = h4_sampled_native_collector.native
canonical = native.canonical

def require(value, reason):
    if not value:
        raise ValueError(reason)

def check_ref(ref):
    path = Path(ref["path"])
    require(path.is_absolute() and path.resolve() == path and not path.is_symlink(), "unsafe proof path")
    require(native.sha(path.read_bytes()) == ref["sha256"].removeprefix("sha256:"), "proof bytes changed")
    return path

def verify_archived_senders(senders, enrolled):
    require(len(senders) == len(enrolled) == 3, "three complete original native senders required")
    def indexed(rows):
        result = {}
        for item in rows:
            p = item["process"]
            slot = (p["role"], p["ordinal"])
            require(slot not in result, "duplicate native sender")
            # Source scoping differs by role, but identity/kernel/credentials
            # must exactly match the independently archived enrollment object.
            result[slot] = {k: v for k,v in item.items() if k != "source_files"}
        require(set(result) == {("api-server",0),("worker",0),("worker",1)}, "native sender slots differ")
        return result
    require(canonical(indexed_as_list(indexed(senders))) == canonical(indexed_as_list(indexed(enrolled))),
            "native sender identity/credentials changed")

def indexed_as_list(value):
    return [value[k] for k in sorted(value)]

def verify_functional_response(request_id, request_body, response_body):
    data, request = json.loads(response_body), json.loads(request_body)
    choices, usage = data.get("choices"), data.get("usage")
    require(request["max_tokens"] == 64 and data.get("id") == "cmpl-" + request_id
            and data.get("model") == request["model"]
            and type(choices) is list and len(choices) == 1
            and type(choices[0].get("index")) is int and choices[0]["index"] == 0
            and choices[0].get("finish_reason") in {"stop","length"}
            and type(choices[0].get("text")) is str and bool(choices[0]["text"].strip())
            and type(usage) is dict
            and all(type(usage.get(k)) is int for k in ("prompt_tokens","completion_tokens","total_tokens"))
            and 16 <= usage["completion_tokens"] <= 64 and usage["prompt_tokens"] > 0
            and usage["total_tokens"] == usage["prompt_tokens"] + usage["completion_tokens"],
            "H4 actual functional response/usage differs")

def replay_sampled_native_report(
    ref,
    *,
    request_id,
    request_body,
    response_body,
    response_expectation,
    enrollment,
    deadline_ns,
):
    record = json.loads(check_ref(ref).read_bytes())
    require(all(type(record[k]) is int for k in ("original_sent_ns","backend_sent_ns","backend_received_ns","verified_monotonic_ns","original_deadline_ns"))
            and type(deadline_ns) is int, "native clocks must retain exact integer types")
    require(
        record["request_id"] == request_id
        and record["response_sha256"] == h4_sampled_native_collector.native.sha(response_body)
        and base64.b64decode(record["response_body_base64"], validate=True)
        == response_body
        and record["original_deadline_ns"] == deadline_ns
        and 0
        < record["original_sent_ns"]
        <= record["backend_sent_ns"]
        <= record["backend_received_ns"]
        <= record["verified_monotonic_ns"]
        <= deadline_ns
        and deadline_ns - record["original_sent_ns"] == 120_000_000_000,
        "native raw consume report request/response/deadline differs",
    )
    for path_key, hash_key in (
        ("native_spec", "spec_sha256"),
        ("tensor_policy", "policy_sha256"),
        ("drain_policy", "drain_sha256"),
    ):
        require(
            h4_sampled_native_collector.native.sha(Path(record[path_key]).read_bytes())
            == record[hash_key],
            "native original input bytes changed",
        )
    spec = json.loads(Path(record["native_spec"]).read_bytes())
    require(spec["native_plan_id"] == enrollment["native_plan_id"]
            and spec["native_launch_id"] == enrollment["native_launch_id"],
            "H4 native Plan/launch differs from actual enrolled epoch")
    verify_archived_senders(spec["senders"], enrollment["source_peers"])
    owner, materializations = object(), {}
    report = attention_consumer._verify_attention_archive(
        record["native_spec"],
        record["tensor_policy"],
        record["journal"],
        acknowledged_prefix=record["sealed_prefix"],
        drain_policy_path=record["drain_policy"],
        drain_protocol=h4_sampled_native_collector,
        _owner=owner,
        _owned_materializations=materializations,
    )
    require(
        report == record["full_archive"], "native full original archive replay differs"
    )
    phase = record["phase"]
    require(
        [p for p in spec["phases"] if p["client_request_id"] == request_id] == [phase]
        and phase["external_request_id"] == f"cmpl-{request_id}-0",
        "native original phase/request mapping differs",
    )
    phase = dict(
        phase,
        ack_time_policy="source-fact-in-http-final-prefix-ack-v1",
        rpc_budget_s=120,
        ack_client_source_sha256=h4_sampled_native_collector.native.sha(
            Path(h4_sampled_native_client.__file__).read_bytes()
        ),
    )
    events = [
        json.loads(line) for line in Path(record["journal"]).read_bytes().splitlines()
    ]
    temporal = request_drain_consumer.verify_time_contract(
        phase,
        events,
        {
            "sent_monotonic_ns": record["backend_sent_ns"],
            "received_monotonic_ns": record["backend_received_ns"],
            "client": record["before"]["authentication_clock"]["client"],
        },
        record["before"],
        record["after"],
        record["descriptor"],
        spec["senders"][0]["peer_uid"],
    )
    require(temporal == record["temporal"], "native original time replay differs")
    sent_ns, received_ns = record["original_sent_ns"], record["backend_received_ns"]
    native = h4_sampled_native_collector.native
    root = Path(record["journal"]).parent
    phase = record["phase"]
    complete = [
        t
        for t in report["attention_complete_transactions"]
        if t["phase_id"] == phase["phase_id"]
    ]
    require(
        len(complete) == 1,
        "request lacks full56 native OP/tensor completion",
    )
    runtime = complete[0]["runtime_request_id"]
    tx = complete[0]["transaction_id"]
    payloads = {}
    projections = {}
    for event in events:
        if event.get("phase") == phase and event.get("kind") == "native.accepted":
            fact = json.loads(base64.b64decode(event["raw_base64"], validate=True))
            if fact["schema"] == native.PROJECTION_V2:
                projections[fact["process"]["ordinal"]] = fact
    for event in events:
        if event.get("phase") != phase or "raw_base64" not in event:
            continue
        fact = json.loads(base64.b64decode(event["raw_base64"], validate=True))
        require(
            event["accepted_monotonic_ns"] <= deadline_ns,
            "native source accepted after original deadline",
        )
        if event["kind"] == "tensor.artifact.accepted":
            payload = (root / event["artifact"]["basename"]).read_bytes()
            require(
                native.sha(payload) == event["artifact"]["sha256"],
                "typed payload changed after full archive consumption",
            )
            typed = materializations[event["sequence"]]._report_after_fresh_read(
                payload, owner
            )
            clocks = [
                typed[k]
                for k in (
                    "source_before_gather_ns",
                    "reference_after_gather_ns",
                    "write_completed_barrier_ns",
                    "destination_readback_completed_ns",
                )
            ]
            require(
                clocks == sorted(clocks)
                and all(sent_ns <= x <= received_ns for x in clocks),
                "actual native tensor clocks outside request",
            )
            payloads[event["sequence"]] = typed
        if event["kind"] == "attention.operator.accepted":
            projection = projections[fact["process"]["ordinal"]]
            row = projection["host_cpu_block_ids"]
            require(
                fact["process"] == projection["process"]
                and fact["actual_cpu_block_ids"][: len(row)] == row
                and projection["monotonic_ns"] <= fact["metadata_bound_monotonic_ns"],
                "native OP did not read the same-worker materialized full row",
            )
            require(
                all(
                    sent_ns <= fact[k] <= received_ns
                    for k in (
                        "materialization_ack_registered_monotonic_ns",
                        "metadata_bound_monotonic_ns",
                        "native_entry_readback_started_ns",
                        "native_entry_readback_completed_ns",
                        "native_call_started_ns",
                        "native_call_returned_ns",
                        "native_stream_completed_ns",
                    )
                ),
                "actual cached OP clocks outside request",
            )
    require(len(payloads) == 56, "missing original two-rank/all28 tensor receipts")
    verify_projection_tensor_join(
        events,
        payloads,
        runtime_request_id=runtime,
        transaction_id=tx,
        phase_id=phase["phase_id"],
        effect_upload_sequences=set(temporal["effect_upload_sequences"]),
    )
    verify_functional_response(request_id, request_body, response_body)
    return record
