"""Distinct v2 transport replay; unchanged original client/native finite window.

Original v1 client scheduling domain stays frozen. Only explicit v2 transport
enrollments may extend its route; no normalization/relabelled journal is made.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from experiments.formal_campaign import h3_client_trace as client
from experiments.formal_campaign import h3_native_client, h3_native_collector
from experiments.formal_campaign.h3_dynamic_authority import (
    canonical,
    check_ref,
    digest,
    read_dynamic_journal,
    require,
)
from experiments.formal_campaign.h3_dynamic_client import verify_enrollment
from experiments.formal_campaign.h3_observer_authority import JOURNAL, PROFILE
from experiments.native_attention_candidate import (
    attention_consumer,
    request_drain_consumer,
)
from experiments.native_kv_tensor_candidate.projection_tensor_join import (
    verify_projection_tensor_join,
)


def replay_native_report(
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
    require(
        record["request_id"] == request_id
        and record["response_sha256"] == h3_native_collector.native.sha(response_body)
        and base64.b64decode(record["response_body_base64"], validate=True)
        == response_body
        and record["original_deadline_ns"] == deadline_ns
        and 0
        < record["original_sent_ns"]
        <= record["backend_sent_ns"]
        <= record["backend_received_ns"]
        <= record["verified_monotonic_ns"]
        <= deadline_ns
        and deadline_ns - record["original_sent_ns"] == 10_000_000_000,
        "native raw consume report request/response/deadline differs",
    )
    for path_key, hash_key in (
        ("native_spec", "spec_sha256"),
        ("tensor_policy", "policy_sha256"),
        ("drain_policy", "drain_sha256"),
    ):
        require(
            h3_native_collector.native.sha(Path(record[path_key]).read_bytes())
            == record[hash_key],
            "native original input bytes changed",
        )
    spec = json.loads(Path(record["native_spec"]).read_bytes())
    require(
        spec["native_plan_id"] == enrollment["plan_id"]
        and spec["native_launch_id"] == enrollment["launch_id"]
        and all(
            any(
                s["process"]
                == {
                    **m["event"]["process"],
                    **{k: v for k, v in m["identity"].items() if k != "launch_id"},
                }
                for m in enrollment["members"]
            )
            for s in spec["senders"]
        )
        and len(spec["senders"]) == 3,
        "native original epoch/membership differs",
    )
    owner, materializations = object(), {}
    report = attention_consumer._verify_attention_archive(
        record["native_spec"],
        record["tensor_policy"],
        record["journal"],
        acknowledged_prefix=record["sealed_prefix"],
        drain_policy_path=record["drain_policy"],
        drain_protocol=h3_native_collector,
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
        rpc_budget_s=10,
        ack_client_source_sha256=h3_native_collector.native.sha(
            Path(h3_native_client.__file__).read_bytes()
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
    native = h3_native_collector.native
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
    data, request = json.loads(response_body), json.loads(request_body)
    choices = data.get("choices")
    require(
        data.get("id") == f"cmpl-{request_id}"
        and data.get("model") == request["model"]
        and isinstance(choices, list)
        and len(choices) == 1
        and choices[0].get("index") == 0
        and choices[0].get("finish_reason") == "stop"
        and choices[0].get("text") == response_expectation["text_equals"],
        "original H3 functional response oracle failed",
    )
    return record


def verify_native_window(
    spec,
    trace_path,
    authority_path,
    *,
    policy,
    frozen_probe,
    expected_client,
    fault_ns,
    recovery_ns,
    allow_incomplete=False,
    live_receipt,
):
    client.validate_spec(spec)
    require(
        spec["authority_domain"] == PROFILE
        and (
            spec["request_count"],
            spec["concurrency"],
            spec["interval_s"],
            spec["timeout_s"],
            spec["dispatch_slack_s"],
        )
        == (60, 8, 0.2, 10, 0.5)
        and spec["payload"] == frozen_probe["request_payload"]
        and spec["response_expectation"] == frozen_probe["response_expectation"],
        "native original workload/domain differs",
    )
    events = read_dynamic_journal(authority_path, domain=JOURNAL)
    require(
        events[0]["policy_sha256"] == digest(canonical(policy))
        and all(
            events[0]["authority"][k] == v
            for k, v in spec["authority_process_identity"].items()
        ),
        "native actual authority epoch/policy differs",
    )
    enrollments, current, opened = {}, None, None
    revoked, launches, kernels, nonces, memberships = set(), set(), set(), set(), set()
    generation = 0
    collectors = {}
    transports = {}
    from experiments.formal_campaign.h3_observer_live_route import (
        routing_copy,
        verify_transport,
    )

    enrolled = [
        e["detail"]["enrollment"] for e in events if e["kind"] == "backend.enrolled"
    ]
    require(
        len(enrolled) == 1
        and spec.get("initial_enrollment_sha256") == enrolled[0]["sha256"],
        "initial actual native enrollment differs",
    )
    public = {}
    private = {}
    peers = {}
    for event in events:
        detail, kind = event["detail"], event["kind"]
        if kind == "observer.actual-bound":
            binding = detail["binding"]
            require(
                binding["enrollment_sha256"] in enrollments
                and binding["enrollment_sha256"] not in collectors,
                "original observer binding absent/duplicated",
            )
            collectors[binding["enrollment_sha256"]] = binding[
                "original_collector_identity"
            ]
        elif kind == "observer.transport.enrolled":
            require(
                opened is None and current is not None and not transports,
                "transport enrollment before close or repeated",
            )
            value = detail["transport"]
            committed = [
                e
                for e in events
                if e["kind"] == "observer.live-transport.committed"
                and e["monotonic_ns"] < event["monotonic_ns"]
            ]
            require(
                len(committed) == 1 and current["sha256"] in revoked,
                "transport lacks unique actual committed verifier/old revocation",
            )
            actual = committed[0]["detail"]
            verify_transport(
                value,
                current,
                receipt=live_receipt,
                descriptor=actual["successor_descriptor"],
                commit=actual["actual_transport"],
                observed_ns=event["monotonic_ns"],
                revoked=revoked,
            )
            frontier = sorted({e["detail"]["request_id"] for e in private.values()})
            require(
                value["commit"]["fault"]["triggered_ns"] == fault_ns
                and value["commit"]["old_client_request_ids"] == frontier,
                "transport original fault/old RID frontier differs",
            )
            original = current
            current = routing_copy(value)
            generation = value["generation"]
            require(
                current["sha256"] not in enrollments
                and value["successor_descriptor"]["collector"]
                != collectors[original["sha256"]],
                "transport reused original enrollment/collector epoch",
            )
            enrollments[current["sha256"]] = current
            transports[current["sha256"]] = value
            collectors[current["sha256"]] = value["successor_descriptor"]["collector"]
        elif kind == "observer.transport.route-open":
            require(
                current is not None
                and current["sha256"] in transports
                and current["sha256"] not in revoked
                and detail["transport_enrollment_sha256"] == current["sha256"]
                and event["route"]["generation"] == current["generation"]
                and opened is None,
                "new transport route lacks exact fresh source enrollment",
            )
            opened = current["sha256"]
        elif kind == "route.closed":
            if current is not None:
                revoked.add(current["sha256"])
            opened = None
        elif kind == "backend.enrolled":
            require(opened is None, "native backend enrolled before close")
            enrollment = detail["enrollment"]
            verify_enrollment(enrollment, policy, event["monotonic_ns"])
            api = enrollment["backend"]["process_identity"]
            key = (api["pid"], api["start_ticks"], api["boot_id"])
            require(
                enrollment["generation"] == generation + 1
                and enrollment["launch_id"] not in launches
                and key not in kernels
                and enrollment["nonce"] not in nonces
                and enrollment["membership_epoch"] not in memberships
                and enrollment["sha256"] not in enrollments
                and (
                    current is None or enrollment["generation"] > current["generation"]
                ),
                "native epoch/membership reused",
            )
            enrollments[enrollment["sha256"]] = enrollment
            current = enrollment
            generation = enrollment["generation"]
            launches.add(enrollment["launch_id"])
            kernels.add(key)
            nonces.add(enrollment["nonce"])
            memberships.add(enrollment["membership_epoch"])
        elif kind == "route.open.applied":
            require(
                current is not None
                and current["sha256"] not in transports
                and current["sha256"] not in revoked
                and event["route"]["generation"] == current["generation"]
                and detail["enrollment_sha256"] == current["sha256"],
                "native prepared route lacks current enrollment",
            )
            opened = current["sha256"]
        elif kind == "request.private-forward":
            require(
                opened == detail["enrollment_sha256"]
                and current["sha256"] not in revoked
                and event["route"]["generation"] == current["generation"],
                "native private route closed",
            )
            aid = detail["admission_id"]
            require(
                aid not in private
                and not any(
                    e["detail"]["request_id"] == detail["request_id"]
                    for e in private.values()
                ),
                "native request/admission replayed",
            )
            if current["sha256"] in transports:
                require(
                    detail["request_id"]
                    not in transports[current["sha256"]]["commit"][
                        "old_client_request_ids"
                    ],
                    "old unknown/lost RID cannot be replayed through successor",
                )
            private[aid] = event
        elif kind == "request.peer-bound":
            aid = detail["admission_id"]
            require(
                aid in private
                and aid not in peers
                and opened == detail["enrollment_sha256"]
                and current["sha256"] not in revoked
                and event["route"]["generation"] == current["generation"],
                "native peer admission differs",
            )
            peers[aid] = event
        elif kind == "request.public-admit":
            aid = detail["admission_id"]
            require(
                aid in peers
                and aid not in public
                and opened == detail["enrollment_sha256"]
                and current["sha256"] not in revoked
                and event["route"]["generation"] == current["generation"],
                "native public release closed/replayed",
            )
            public[aid] = event
    traces = client.read_client_trace(trace_path)
    require(
        traces
        and traces[0]["kind"] == "client.start"
        and sum(e["kind"] == "client.start" for e in traces) == 1
        and sum(e["kind"] == "client.stop" for e in traces) <= 1
        and all(
            e["kind"]
            in {"client.start", "client.stop", "request.start", "request.finish"}
            for e in traces
        )
        and traces[0]["detail"]["spec_sha256"] == client.sha(client.canonical(spec))
        and all(e["client"] == expected_client for e in traces),
        "native original client source/trace differs",
    )
    stops = [e for e in traces if e["kind"] == "client.stop"]
    require(
        not stops
        or (traces[-1] is stops[0] and stops[0]["detail"]["request_count"] == 60),
        "native client stop misplaced or count changed",
    )
    sends = {
        e["detail"]["request_id"]: e for e in traces if e["kind"] == "request.start"
    }
    finishes = {
        e["detail"]["request_id"]: e for e in traces if e["kind"] == "request.finish"
    }
    expected = {f"{spec['start_id']}/request-{i:05d}" for i in range(60)}
    require(
        sends
        and set(finishes) <= set(sends) <= expected
        and len(sends) == sum(e["kind"] == "request.start" for e in traces)
        and len(finishes) == sum(e["kind"] == "request.finish" for e in traces),
        "native original attempts duplicated/unknown or finish lacks start",
    )
    complete = bool(stops) and set(sends) == set(finishes) == expected
    require(
        allow_incomplete or complete, "native original finite60 attempts incomplete"
    )
    lost, ontime, slips = 0, 0, 0
    recoveries = []
    anchor = traces[0]["detail"]["schedule_anchor_ns"]
    payload = client.canonical(spec["payload"])
    for rid, event in sends.items():
        start = event["detail"]
        index = int(rid.rsplit("-", 1)[-1])
        require(
            start["scheduled_ns"] == anchor + int(index * 0.2 * 1e9)
            and type(start["sent_ns"]) is int
            and type(start["deadline_ns"]) is int
            and 0 < start["sent_ns"] <= event["monotonic_ns"]
            and start["deadline_ns"] == start["sent_ns"] + 10_000_000_000
            and base64.b64decode(start["body_base64"], validate=True) == payload
            and start["body_sha256"] == client.sha(payload),
            "native original payload/schedule/deadline changed",
        )
        slips += (
            not start["scheduled_ns"]
            <= start["sent_ns"]
            <= start["scheduled_ns"] + 500_000_000
        )
        if rid in finishes:
            end = finishes[rid]["detail"]
            require(
                start["sent_ns"] <= end["finished_ns"] <= finishes[rid]["monotonic_ns"]
                and event["monotonic_ns"] <= finishes[rid]["monotonic_ns"],
                "native actual attempt clocks invalid",
            )
    # Every public release is independently replayed, even when the client
    # disconnected, timed out, or failed to record a finish. No success proof is
    # made optional by partial-window classification.
    by_request = {}
    for aid, p in public.items():
        detail = p["detail"]
        rid = detail["request_id"]
        require(
            rid in sends and rid not in by_request,
            "native public request unknown/replayed",
        )
        by_request[rid] = p
        start = sends[rid]["detail"]
        a, peer = private[aid], peers[aid]
        for event in (p, a, peer):
            require(
                event["detail"]["request_id"] == rid
                and event["detail"]["enrollment_sha256"] == detail["enrollment_sha256"],
                "native request bound to another admission/epoch",
            )
        record = json.loads(check_ref(detail["native_report"]).read_bytes())
        body = base64.b64decode(record["response_body_base64"], validate=True)
        enrollment_key = detail["enrollment_sha256"]
        verify_report_receiver(record, enrollment_key, collectors, transports)
        require(
            detail["status"] == 200
            and detail["request_sha256"]
            == a["detail"]["request_sha256"]
            == start["body_sha256"]
            and detail["method"] == a["detail"]["method"] == "POST"
            and detail["body_sha256"] == client.sha(body)
            and record["original_sent_ns"] == start["sent_ns"]
            and start["sent_ns"]
            <= a["monotonic_ns"]
            < peer["monotonic_ns"]
            < p["monotonic_ns"]
            <= start["deadline_ns"]
            and record["verified_monotonic_ns"] == detail["native_verified_ns"]
            and record["verified_monotonic_ns"] <= p["monotonic_ns"]
            and detail["native_prefix_sha256"]
            == h3_native_collector.native.sha(Path(record["journal"]).read_bytes()),
            "native complete exact public request/body/clock join differs",
        )
        replayed = replay_native_report(
            detail["native_report"],
            request_id=rid,
            request_body=payload,
            response_body=body,
            response_expectation=spec["response_expectation"],
            enrollment=enrollments[detail["enrollment_sha256"]],
            deadline_ns=start["deadline_ns"],
        )
        selected = [
            t
            for t in replayed["full_archive"]["attention_complete_transactions"]
            if t["phase_id"] == replayed["phase"]["phase_id"]
        ]
        require(
            len(selected) == 1
            and selected[0]["runtime_request_id"] == detail["runtime_request_id"]
            and selected[0]["transaction_id"] == detail["transaction_id"],
            "native public runtime/transaction differs from full proof",
        )
    used = set()
    for rid, event in finishes.items():
        start, end = sends[rid]["detail"], event["detail"]
        if end["status"] != 200 or end["finished_ns"] > start["deadline_ns"]:
            lost += 1
            continue
        aid = end["admission_id"]
        require(
            aid in public and aid not in used and public[aid] is by_request.get(rid),
            "native successful delivery lacks unique public release",
        )
        used.add(aid)
        body = base64.b64decode(end["body_base64"], validate=True)
        require(
            public[aid]["detail"]["body_sha256"] == client.sha(body)
            and public[aid]["monotonic_ns"]
            <= end["finished_ns"]
            <= start["deadline_ns"],
            "native successful delivery bytes/clock differs",
        )
        ontime += 1
        selected = public[aid]
        if (
            selected["detail"]["enrollment_sha256"] in transports
            and fault_ns < end["finished_ns"]
        ):
            recoveries.append(end["finished_ns"])
    times = [e["detail"]["sent_ns"] for e in sends.values()]
    require(
        min(times) < fault_ns and (allow_incomplete or fault_ns < max(times)),
        "actual fault outside original finite window",
    )
    # Recovery is first actual on-time original-client delivery using exact
    # successor full native proof; commit/ready/publication clocks are not it.
    measured_recovery = min(recoveries) if recoveries else None
    require(
        recovery_ns is None or recovery_ns == measured_recovery,
        "caller recovery clock differs from original delivered request",
    )
    recovery_ns = measured_recovery
    covered = (
        complete
        and not slips
        and recovery_ns is not None
        and min(times) < fault_ns < recovery_ns < max(times)
    )
    return {
        "schema": "ecpa-h3-observer-live-finite-delivery/v2",
        "recovery_ns": measured_recovery,
        "transport_enrollment_sha256": next(iter(transports), None),
        "coverage": "complete-finite-delivery-window" if covered else "coverage-failed",
        "requests": 60,
        "requests_expected": 60,
        "requests_started": len(sends),
        "requests_finished": len(finishes),
        "lost_requests": lost if complete else None,
        "on_time_deliveries": ontime,
        "dispatch_slips": slips,
        "backend_execution_duplicates": None,
        "formal_result": False,
    }


def verify_report_receiver(record, enrollment_key, collectors, transports):
    require(
        enrollment_key in collectors
        and record["descriptor"]["collector"] == collectors[enrollment_key],
        "native receiver is not actual enrolled collector epoch",
    )
    if enrollment_key in transports:
        require(
            record["descriptor"] == transports[enrollment_key]["successor_descriptor"],
            "full native proof came from another successor receiver descriptor",
        )
