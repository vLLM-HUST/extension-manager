"""Prospective source-close control clocks; effects retain the HTTP cutoff.

Only the drain consumer calls this after checking source-owned closure records.
The complete unfiltered journal and authenticated final ACK are preserved.
"""

from __future__ import annotations

import base64
import json

from experiments.exposure_gate import native_semantic_collector as native
from experiments.native_challenge_candidate.request_runner import require, sha

FINAL_PREFIX_POLICY = "source-fact-in-http-final-prefix-ack-v1"
MAX_ACCEPT_DELAY_NS = 5_000_000_000
NONWITNESS_UPLOAD_TAIL = "http-effect-witnesses-source-closed-nonwitness-upload-tail-v1"


def upload_tail_partition(phase, selected, sent, received):
    """Select effect uploads before HTTP; never use a late upload to fill a gap.

    Called only after the full archive verifies every sender and source closure.
    This additional predicate keeps the whole chain, including nonwitness rows.
    """
    decoded = [
        (event, json.loads(base64.b64decode(event["raw_base64"], validate=True)))
        for event in selected
    ]
    uploads = [
        (e, f)
        for e, f in decoded
        if e["kind"] == "native.accepted" and f["schema"] == native.UPLOAD
    ]
    projections = [
        (e, f)
        for e, f in decoded
        if e["kind"] == "native.accepted" and f["schema"] == native.PROJECTION_V2
    ]
    require(
        phase["expected_ranks"] == [0, 1]
        and len(projections) == 2
        and {f["process"]["ordinal"] for _, f in projections} == {0, 1},
        "nonwitness tail requires both original worker projections",
    )
    in_http = {
        e["sequence"]
        for e, f in uploads
        if type(f["monotonic_ns"]) is int
        and type(f["observed_after_barrier_monotonic_ns"]) is int
        and sent
        <= f["monotonic_ns"]
        <= f["observed_after_barrier_monotonic_ns"]
        <= received
    }
    destination_witnesses = {}
    closures = {}
    for _, projection in projections:
        rank = projection["process"]["ordinal"]
        require(
            sent <= projection["monotonic_ns"] <= received, "projection outside HTTP"
        )
        operators = [
            (e, f)
            for e, f in decoded
            if e["kind"] == "attention.operator.accepted"
            and f["process"] == projection["process"]
            and f["runtime_request_id"] == projection["runtime_request_id"]
        ]
        require(
            len(operators) == 28
            and {f["layer_index"] for _, f in operators} == set(range(28)),
            "nonwitness tail cannot fill missing cached-operator coverage",
        )
        first_entry = min(f["native_entry_readback_started_ns"] for _, f in operators)
        witnesses = [
            e["sequence"]
            for e, f in uploads
            if e["sequence"] in in_http
            and native.projection_upload_match(projection, f)
            and f["observed_after_barrier_monotonic_ns"] <= first_entry
        ]
        require(
            bool(witnesses), "nonwitness tail cannot supply first destination upload"
        )
        destination_witnesses[str(rank)] = min(witnesses)
        closes = [
            (e, f)
            for e, f in decoded
            if e["kind"] == "attention.worker.drained"
            and f["process"] == projection["process"]
            and f["runtime_request_id"] == projection["runtime_request_id"]
        ]
        require(
            len(closes) == 1,
            "nonwitness tail requires exact same-worker source closure",
        )
        closures[
            (
                sha(native.canonical(projection["process"])),
                projection["runtime_request_id"],
            )
        ] = (*closes[0], max(e["sequence"] for e, _ in operators))
    tails = set()
    for event, fact in uploads:
        if event["sequence"] in in_http:
            continue
        key = (sha(native.canonical(fact["process"])), fact["runtime_request_id"])
        require(key in closures, "nonwitness tail source epoch differs")
        close, terminal, last_operator_sequence = closures[key]
        require(
            type(fact["observed_after_barrier_monotonic_ns"]) is int
            and sent
            <= fact["monotonic_ns"]
            <= fact["observed_after_barrier_monotonic_ns"]
            <= terminal["monotonic_ns"]
            and last_operator_sequence < event["sequence"] < close["sequence"]
            and event["accepted_monotonic_ns"] <= terminal["monotonic_ns"],
            "nonwitness upload is not before its source-owned closure",
        )
        tails.add(event["sequence"])
    return in_http, tails, destination_witnesses


def verify_time_contract(
    phase,
    events,
    metadata,
    before,
    after,
    descriptor,
    peer_uid,
    *,
    upload_tail_policy=None,
):
    """Replay recorded clocks; no fresh OS authentication or scope promotion."""
    selected = [
        e
        for e in events[1:]
        if e.get("phase", {}).get("external_request_id") == phase["external_request_id"]
    ]
    first = before["status"]["acknowledged_prefix"]["next_sequence"]
    sent, received = metadata["sent_monotonic_ns"], metadata["received_monotonic_ns"]
    policy = phase.get("ack_time_policy")
    require(
        policy == FINAL_PREFIX_POLICY,
        "source drain requires prospective final ACK time policy",
    )
    require(
        upload_tail_policy in (None, NONWITNESS_UPLOAD_TAIL),
        "unknown nonwitness upload tail policy",
    )
    require(
        type(sent) is int and type(received) is int and 0 < sent <= received,
        "KV HTTP clocks invalid",
    )
    require(bool(selected), "final ACK policy has no selected request facts")
    expected = descriptor["collector"]
    for receipt in (before, after):
        raw = base64.b64decode(receipt["status_raw_base64"], validate=True)
        require(
            isinstance(receipt.get("authentication_clock"), dict)
            and "issued_monotonic_ns" in receipt["status"],
            "prospective ACK source/client clocks missing",
        )
        status, clock = receipt["status"], receipt["authentication_clock"]
        require(
            sha(raw) == receipt["status_raw_sha256"] and json.loads(raw) == status,
            "ACK time receipt raw bytes differ",
        )
        require(
            status["collector"] == expected
            and status["collector_source_sha256"]
            == descriptor["collector_source_sha256"]
            and status["spec_sha256"] == descriptor["spec_sha256"]
            and status["archive_identity"] == descriptor["archive_identity"]
            and status["socket_identity"] == descriptor["socket_identity"]
            and receipt["kernel_peer"] == {"pid": expected["pid"], "uid": peer_uid},
            "ACK time peer/source/owner binding differs",
        )
        require(
            clock["schema"] == "ecpa-native-status-authentication-clock/v1"
            and clock["client"] == metadata["client"]
            and clock["client"]["boot_id"] == expected["boot_id"]
            and clock["client_source_sha256"] == phase["ack_client_source_sha256"],
            "ACK time client/source/boot binding differs",
        )
        issued = status["issued_monotonic_ns"]
        dispatch, completed = (
            clock["dispatch_monotonic_ns"],
            clock["completed_monotonic_ns"],
        )
        require(
            all(type(x) is int and x > 0 for x in (issued, dispatch, completed))
            and dispatch <= issued <= completed,
            "source ACK issue clock is outside real client authentication window",
        )
    before_clock, after_clock = (
        before["authentication_clock"],
        after["authentication_clock"],
    )
    issued = after["status"]["issued_monotonic_ns"]
    require(
        after_clock["completed_monotonic_ns"] - before_clock["dispatch_monotonic_ns"]
        <= phase["rpc_budget_s"] * 1_000_000_000,
        "total status/HTTP phase exceeds frozen budget",
    )
    require(
        before_clock["completed_monotonic_ns"]
        <= sent
        <= received
        <= after_clock["dispatch_monotonic_ns"]
        <= issued,
        "ACK source/client clocks do not bound HTTP causally",
    )
    prefix = after["status"]["acknowledged_prefix"]
    require(
        prefix
        == {
            "next_sequence": len(events),
            "last_event_sha256": events[-1]["event_sha256"],
        },
        "final durable ACK prefix does not cover complete retained raw chain",
    )
    require(first < prefix["next_sequence"], "new final ACK has no fresh native facts")
    effect_uploads, tails, witnesses = set(), set(), {}
    if upload_tail_policy is not None:
        effect_uploads, tails, witnesses = upload_tail_partition(
            phase, selected, sent, received
        )
    for event in selected:
        fact = json.loads(base64.b64decode(event["raw_base64"]))
        stamp, accepted = fact["monotonic_ns"], event["accepted_monotonic_ns"]
        require(
            type(stamp) is int
            and type(accepted) is int
            and first <= event["sequence"] < prefix["next_sequence"]
            and sent
            <= stamp
            <= (
                issued
                if event["kind"] == "attention.worker.drained"
                or event["sequence"] in tails
                else received
            )
            and stamp <= accepted <= issued
            and accepted - stamp <= MAX_ACCEPT_DELAY_NS,
            "native fact/acceptance violates final-prefix causal window or TTL",
        )
    return {
        "policy": "source-drained-full-phase-ack-v1",
        "effect_source_time_policy": policy,
        "source_close_records": sum(
            e["kind"] == "attention.worker.drained" for e in selected
        ),
        "selected_records": len(selected),
        "source_final_ACK_issued_monotonic_ns": issued,
        "recorded_client_authentication_window_verified": True,
        "fresh_OS_peer_authentication_performed": False,
        "formal_result": False,
        **(
            {
                "upload_tail_policy": upload_tail_policy,
                "effect_upload_sequences": sorted(effect_uploads),
                "nonwitness_upload_tail_sequences": sorted(tails),
                "required_destination_upload_witness_sequences": witnesses,
            }
            if upload_tail_policy is not None
            else {}
        ),
    }
