"""Prospective source-close control clocks; effects retain the HTTP cutoff.

Only the drain consumer calls this after checking source-owned closure records.
The complete unfiltered journal and authenticated final ACK are preserved.
"""

from __future__ import annotations

import base64
import json

from experiments.native_challenge_candidate.request_runner import require, sha

FINAL_PREFIX_POLICY = "source-fact-in-http-final-prefix-ack-v1"
MAX_ACCEPT_DELAY_NS = 5_000_000_000


def verify_time_contract(phase, events, metadata, before, after, descriptor, peer_uid):
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
    for event in selected:
        fact = json.loads(base64.b64decode(event["raw_base64"]))
        stamp, accepted = fact["monotonic_ns"], event["accepted_monotonic_ns"]
        require(
            type(stamp) is int
            and type(accepted) is int
            and first <= event["sequence"] < prefix["next_sequence"]
            and sent
            <= stamp
            <= (issued if event["kind"] == "attention.worker.drained" else received)
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
    }
