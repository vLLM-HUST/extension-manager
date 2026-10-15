"""CPU timing/selection counterexamples, never hardware or formal evidence."""

import base64
import copy
import json

import pytest

from experiments.exposure_gate import native_semantic_collector as native
from experiments.native_attention_candidate import drain_time_policy as timing
from experiments.native_kv_tensor_candidate.projection_tensor_join import (
    verify_projection_tensor_join,
)


def encode(event, fact):
    event["raw_base64"] = base64.b64encode(native.canonical(fact)).decode()
    return event


@pytest.fixture
def clocks():
    # Deliberately small logical times: this fixture is not a recorded runtime.
    sent, received = 100, 500
    phase = {
        "external_request_id": "request",
        "expected_ranks": [0, 1],
        "ack_time_policy": timing.FINAL_PREFIX_POLICY,
        "ack_client_source_sha256": "client-source",
        "rpc_budget_s": 180,
    }
    collector = {"pid": 12, "boot_id": "boot"}
    client = {"pid": 13, "boot_id": "boot"}
    descriptor = {
        "collector": collector,
        "collector_source_sha256": "collector-source",
        "spec_sha256": "spec",
        "archive_identity": {},
        "socket_identity": {},
    }
    events = [{"kind": "collector.start", "event_sha256": "start"}]

    def add(kind, rank, stamp, **extra):
        process = {
            "role": "worker",
            "ordinal": rank,
            "pid": rank + 20,
            "process_epoch": 1,
            "start_identity": f"epoch-{rank}",
        }
        fact = {
            "schema": "test",
            "monotonic_ns": stamp,
            "process": process,
            "runtime_request_id": "runtime",
            "plan_id": "plan",
            "launch_id": "launch",
            **extra,
        }
        e = {
            "kind": kind,
            "sequence": len(events),
            "event_sha256": str(len(events)),
            "phase": {"external_request_id": "request"},
            "accepted_monotonic_ns": stamp + 1,
        }
        events.append(encode(e, fact))
        return e

    for rank in (0, 1):
        add(
            "native.accepted",
            rank,
            150,
            schema=native.PROJECTION_V2,
            host_cpu_block_ids=[1, 2],
            attention_group=0,
            transaction_id="projection",
        )
        add(
            "native.accepted",
            rank,
            200,
            schema=native.UPLOAD,
            observed_after_barrier_monotonic_ns=210,
            uploaded_rows=[{"group": 0, "row": 0, "blocks": [1, 2]}],
        )
        for layer in range(28):
            add(
                "attention.operator.accepted",
                rank,
                300 + layer,
                layer_index=layer,
                native_entry_readback_started_ns=250 + layer,
            )
    tail = add(
        "native.accepted",
        1,
        510,
        schema=native.UPLOAD,
        observed_after_barrier_monotonic_ns=511,
        uploaded_rows=[{"group": 0, "row": 0, "blocks": [1, 2, 3]}],
    )
    for rank in (0, 1):
        add("attention.worker.drained", rank, 600)

    def receipt(issued, dispatch, completed, prefix):
        status = {
            **descriptor,
            "issued_monotonic_ns": issued,
            "acknowledged_prefix": prefix,
        }
        raw = native.canonical(status)
        return {
            "status": status,
            "status_raw_base64": base64.b64encode(raw).decode(),
            "status_raw_sha256": native.sha(raw),
            "kernel_peer": {"pid": 12, "uid": 0},
            "authentication_clock": {
                "schema": "ecpa-native-status-authentication-clock/v1",
                "client": client,
                "client_source_sha256": "client-source",
                "dispatch_monotonic_ns": dispatch,
                "completed_monotonic_ns": completed,
            },
        }

    before = receipt(50, 40, 60, {"next_sequence": 1, "last_event_sha256": "start"})
    after = receipt(
        700,
        690,
        710,
        {"next_sequence": len(events), "last_event_sha256": events[-1]["event_sha256"]},
    )
    return dict(
        phase=phase,
        events=events,
        metadata={
            "sent_monotonic_ns": sent,
            "received_monotonic_ns": received,
            "client": client,
        },
        before=before,
        after=after,
        descriptor=descriptor,
        peer_uid=0,
    ), tail["sequence"]


def test_explicit_tail_policy_keeps_http_witnesses_and_full_ack(clocks):
    args, tail = clocks
    with pytest.raises(ValueError, match="causal window"):
        timing.verify_time_contract(**args)
    result = timing.verify_time_contract(
        **args, upload_tail_policy=timing.NONWITNESS_UPLOAD_TAIL
    )
    assert result["nonwitness_upload_tail_sequences"] == [tail]
    assert tail not in result["effect_upload_sequences"]
    assert set(result["required_destination_upload_witness_sequences"]) == {"0", "1"}
    assert result["selected_records"] == len(args["events"]) - 1
    assert result["formal_result"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        "first_upload",
        "operator",
        "tensor",
        "mapping",
        "projection",
        "missing_close",
        "epoch",
        "after_close",
        "ttl",
        "prefix",
    ],
)
def test_late_nonwitness_cannot_supply_effect_or_escape_closure(clocks, mutation):
    args, tail = copy.deepcopy(clocks)
    events = args["events"]
    event = events[tail]
    fact = json.loads(base64.b64decode(event["raw_base64"]))
    if mutation == "first_upload":
        early = next(
            e
            for e in events[1:]
            if e["kind"] == "native.accepted"
            and json.loads(base64.b64decode(e["raw_base64"]))["schema"] == native.UPLOAD
        )
        raw = json.loads(base64.b64decode(early["raw_base64"]))
        raw["uploaded_rows"][0]["blocks"] = [7, 8]
        encode(early, raw)
    elif mutation in {"operator", "tensor", "mapping", "projection"}:
        if mutation == "operator":
            event = next(
                e for e in events if e["kind"] == "attention.operator.accepted"
            )
        elif mutation == "projection":
            event = events[1]
        else:
            event["kind"] = (
                "tensor.artifact.accepted"
                if mutation == "tensor"
                else "native.accepted"
            )
        fact = json.loads(base64.b64decode(event["raw_base64"]))
        fact["monotonic_ns"] = 510
        if mutation == "mapping":
            fact["schema"] = native.MAPPING
        encode(event, fact)
    elif mutation == "missing_close":
        events[-1]["kind"] = "absent"
    elif mutation == "epoch":
        fact["process"]["process_epoch"] = 2
        encode(event, fact)
    elif mutation == "after_close":
        fact["monotonic_ns"] = fact["observed_after_barrier_monotonic_ns"] = 601
        event["accepted_monotonic_ns"] = 602
        encode(event, fact)
    elif mutation == "ttl":
        event["accepted_monotonic_ns"] = 5_000_000_512
        for close in events[-2:]:
            terminal = json.loads(base64.b64decode(close["raw_base64"]))
            terminal["monotonic_ns"] = 5_000_000_600
            close["accepted_monotonic_ns"] = 5_000_000_601
            encode(close, terminal)
        args["after"]["status"]["issued_monotonic_ns"] = 5_000_000_700
        args["after"]["authentication_clock"].update(
            dispatch_monotonic_ns=5_000_000_690,
            completed_monotonic_ns=5_000_000_710,
        )
    else:
        args["after"]["status"]["acknowledged_prefix"]["next_sequence"] -= 1
    raw = native.canonical(args["after"]["status"])
    args["after"].update(
        status_raw_base64=base64.b64encode(raw).decode(),
        status_raw_sha256=native.sha(raw),
    )
    with pytest.raises(ValueError, match="TTL" if mutation == "ttl" else None):
        timing.verify_time_contract(
            **args, upload_tail_policy=timing.NONWITNESS_UPLOAD_TAIL
        )


def test_projection_join_never_uses_excluded_tail_to_supply_missing_rank(clocks):
    args, tail = clocks
    result = timing.verify_time_contract(
        **args, upload_tail_policy=timing.NONWITNESS_UPLOAD_TAIL
    )
    events = copy.deepcopy(args["events"])
    # Keep raw rows; omit the only rank-1 HTTP witness from the effect allowlist.
    allowed = set(result["effect_upload_sequences"])
    rank1 = result["required_destination_upload_witness_sequences"]["1"]
    allowed.remove(rank1)
    with pytest.raises(ValueError, match="no later same-worker uploaded full row"):
        verify_projection_tensor_join(
            events[1:],
            {},
            runtime_request_id="runtime",
            transaction_id="unused",
            effect_upload_sequences=allowed,
        )
