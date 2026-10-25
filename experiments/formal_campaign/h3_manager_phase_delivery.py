"""Manager-after-launch window retaining every original public native proof check."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from experiments.formal_campaign import h3_client_trace as client
from experiments.formal_campaign import h3_native_collector
from experiments.formal_campaign.h3_dynamic_authority import (
    canonical,
    check_ref,
    digest,
    read_dynamic_journal,
    require,
)
from experiments.formal_campaign.h3_dynamic_client import verify_enrollment
from experiments.formal_campaign.h3_native_authority import JOURNAL, PROFILE
from experiments.formal_campaign.h3_native_delivery import replay_native_report


def verify_manager_window(
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
    require(
        spec.get("manager_phase_domain") == "ecpa-h3-manager-phase-campaign/v1"
        and spec.get("initial_enrollment_sha256") is None
        and all(
            e["monotonic_ns"] > fault_ns
            for e in events
            if e["kind"] == "backend.enrolled"
        ),
        "Manager after-launch may enroll only its actual post-fault replacement",
    )
    public = {}
    private = {}
    peers = {}
    for event in events:
        detail, kind = event["detail"], event["kind"]
        if kind == "route.closed":
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
            require(aid not in private, "native admission replayed")
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
    times = [e["detail"]["sent_ns"] for e in sends.values()]
    require(
        min(times) < fault_ns and (allow_incomplete or fault_ns < max(times)),
        "actual fault outside original finite window",
    )
    covered = (
        complete
        and not slips
        and recovery_ns is not None
        and min(times) < fault_ns < recovery_ns < max(times)
    )
    return {
        "schema": "ecpa-h3-manager-phase-finite-delivery/v1",
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
