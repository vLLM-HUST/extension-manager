"""Explicit dynamic-domain finite-window verifier; legacy defaults stay strict.

This consumes real ``backend.enrolled`` events in order, never a mutated static
backend map or a projection into the legacy authority journal format.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path
from urllib.parse import urlparse

from experiments.formal_campaign.h3_client_trace import read_client_trace, validate_spec
from experiments.formal_campaign.h3_dynamic_authority import (
    PROFILE,
    canonical,
    digest,
    read_dynamic_journal,
    require,
    validate_policy,
)
from experiments.formal_campaign.h3_worker_recovery import verify_parent_worker_ancestry
from vllm_hust_ext.host_evidence import parse_host_event


def verify_enrollment(value, policy, observed_ns):
    subject = {k: v for k, v in value.items() if k != "sha256"}
    require(
        value["sha256"] == digest(canonical(subject)), "dynamic enrollment hash differs"
    )
    require(
        value["policy_sha256"] == digest(canonical(policy))
        and value["start_id"] == policy["start_id"]
        and value["registration_sha256"] == policy["registration_sha256"]
        and 0 < value["observed_ns"] < observed_ns,
        "dynamic enrollment policy/start/clock differs",
    )
    from vllm_hust_ext.plan_artifact import read_plan_artifact

    declared = {
        read_plan_artifact(Path(ref["path"])).plan.plan_id
        for ref in policy["plan_artifacts"]
    }
    runtime_ids = {
        binding["runtime_plan_id"] for binding in policy["native_plan_bindings"]
    }
    require(
        value["plan_id"] in declared | runtime_ids,
        "enrollment raw Plan is outside source-derived deployment",
    )
    require(
        len(value["nonce"]) == len(value["membership_epoch"]) == 32
        and all(
            c in "0123456789abcdef" for c in value["nonce"] + value["membership_epoch"]
        ),
        "actual enrollment nonce/membership is malformed",
    )
    members = value["members"]
    require(
        {(m["role"], m["ordinal"]) for m in members}
        == {("api-server", 0), ("worker", 0), ("worker", 1)}
        and len(members) == 3,
        "dynamic raw membership coverage differs",
    )
    parent = next(m for m in members if m["role"] == "api-server")
    for member in members:
        event = parse_host_event(canonical(member["event"]))
        process, kernel = event["process"], member["identity"]
        require(
            process.get("assignment_source") == "host"
            and process["role"] == member["role"]
            and process["ordinal"] == member["ordinal"]
            and process["pid"] == kernel["pid"]
            and int(process["start_identity"].rsplit(":", 1)[1])
            == kernel["start_ticks"]
            and event["plan_id"] == value["plan_id"]
            and event["launch_id"] == value["launch_id"]
            and kernel["launch_id"] == value["launch_id"],
            "dynamic raw Host/kernel/Plan identity differs",
        )
        if member["role"] == "worker":
            verify_parent_worker_ancestry(
                {
                    "parent": parent["identity"],
                    "worker": kernel,
                    "parent_worker_ancestry": member["parent_worker_ancestry"],
                }
            )
    require(
        value["backend"]["process_identity"]
        == {k: parent["identity"][k] for k in ("pid", "start_ticks", "boot_id")}
        and value["backend"]["generation"] == value["generation"]
        and value["backend"]["launch_id"] == value["launch_id"]
        and value["backend"]["model"] == policy["model"]
        and str(value["backend"]["listener_inode"]).isdigit(),
        "dynamic actual listener/backend differs from API parent",
    )


def verify_dynamic_window(
    spec,
    client_path: Path,
    authority_path: Path,
    *,
    policy,
    frozen_probe,
    expected_client,
    fault_ns,
    recovery_ns,
):
    validate_spec(spec)
    validate_policy(policy)
    require(
        spec.get("authority_domain") == PROFILE
        and spec.get("dynamic_policy_sha256") == digest(canonical(policy)),
        "explicit registered dynamic domain required",
    )
    require(
        (
            spec["request_count"],
            spec["concurrency"],
            spec["interval_s"],
            spec["timeout_s"],
        )
        == (60, 8, 0.2, 10),
        "original H3 workload changed",
    )
    require(
        spec["payload"] == frozen_probe["request_payload"]
        and spec["response_expectation"] == frozen_probe["response_expectation"],
        "dynamic client changed the frozen functional workload",
    )
    require(spec["start_id"] == policy["start_id"], "dynamic client start differs")
    client_events = read_client_trace(client_path)
    require(
        client_events
        and client_events[0]["kind"] == "client.start"
        and client_events[-1]["kind"] == "client.stop",
        "finite client trace is incomplete",
    )
    begin = client_events[0]
    require(
        begin["client"] == expected_client
        and begin["detail"]["spec_sha256"] == digest(canonical(spec))
        and begin["detail"]["start_id"] == spec["start_id"],
        "client process/spec binding differs",
    )
    require(
        sum(e["kind"] == "client.start" for e in client_events) == 1
        and sum(e["kind"] == "client.stop" for e in client_events) == 1,
        "client markers replayed",
    )
    starts = [e for e in client_events if e["kind"] == "request.start"]
    finishes = [e for e in client_events if e["kind"] == "request.finish"]
    ids = {f"{spec['start_id']}/request-{i:05d}" for i in range(60)}
    require(
        len(starts) == len(finishes) == 60
        and {e["detail"]["request_id"] for e in starts} == ids
        and {e["detail"]["request_id"] for e in finishes} == ids,
        "original finite request attempts missing/duplicated",
    )
    sent = {e["detail"]["request_id"]: e["detail"] for e in starts}
    ended = {e["detail"]["request_id"]: e["detail"] for e in finishes}
    anchor = begin["detail"]["schedule_anchor_ns"]
    for i in range(60):
        row = sent[f"{spec['start_id']}/request-{i:05d}"]
        scheduled = anchor + int(i * 0.2 * 1e9)
        require(
            row["scheduled_ns"] == scheduled
            and scheduled
            <= row["sent_ns"]
            <= scheduled + int(spec["dispatch_slack_s"] * 1e9)
            and row["deadline_ns"] == row["sent_ns"] + 10_000_000_000,
            "frozen request schedule/deadline changed",
        )
        body = base64.b64decode(row["body_base64"], validate=True)
        require(
            body == canonical(spec["payload"]) and row["body_sha256"] == digest(body),
            "request bytes differ",
        )
    events = read_dynamic_journal(authority_path)
    expected_authority = spec["authority_process_identity"]
    require(
        all(
            events[0]["authority"][k] == expected_authority[k]
            for k in ("pid", "start_ticks", "boot_id")
        ),
        "dynamic authority epoch differs",
    )
    require(
        events[0]["policy_sha256"] == digest(canonical(policy))
        and events[0]["detail"]["authorization"]["launch_id"] == policy["start_id"]
        and events[0]["detail"]["authorization"]["registration_sha256"]
        == policy["registration_sha256"],
        "authority start is not independently registered",
    )
    require(
        spec.get("dynamic_registration_sha256") == policy["registration_sha256"],
        "dynamic client registration differs",
    )
    enrolled = [
        e["detail"]["enrollment"] for e in events if e["kind"] == "backend.enrolled"
    ]
    require(
        enrolled and spec.get("initial_enrollment_sha256") == enrolled[0]["sha256"],
        "initial actual enrollment differs",
    )
    current, active, generation, closed = None, None, 0, True
    revoked, launches, kernels, admissions, completions, peers = (
        set(),
        set(),
        set(),
        {},
        {},
        {},
    )
    all_admissions = {}
    for event in events:
        kind, detail = event["kind"], event["detail"]
        if kind == "route.closed":
            if current is not None:
                revoked.add(current["sha256"])
            active = None
            closed = True
        elif kind == "backend.enrolled":
            require(closed, "generation enrolled before public close")
            value = detail["enrollment"]
            verify_enrollment(value, policy, event["monotonic_ns"])
            api = value["backend"]["process_identity"]
            key = (api["pid"], api["start_ticks"], api["boot_id"])
            require(
                value["generation"] == generation + 1
                and value["launch_id"] not in launches
                and key not in kernels,
                "replacement enrollment reused dead launch/kernel/generation",
            )
            current, generation = value, value["generation"]
            launches.add(value["launch_id"])
            kernels.add(key)
        elif kind == "route.open.applied":
            require(
                current is not None
                and current["sha256"] not in revoked
                and detail["enrollment_sha256"] == current["sha256"]
                and event["route"]["generation"] == current["generation"],
                "route opened stale/unverified membership",
            )
            active = current
            closed = False
        elif kind == "request.admit":
            require(
                active is not None
                and detail["enrollment_sha256"] == active["sha256"]
                and event["route"]["generation"] == active["generation"],
                "request admitted without current enrollment",
            )
            aid, rid = detail["admission_id"], detail["request_id"]
            require(
                aid not in admissions
                and detail["request_sha256"] == digest(canonical(spec["payload"]))
                and detail["method"] == "POST",
                "admission replay/wrong request",
            )
            admissions[aid] = (event, active)
            all_admissions.setdefault(rid, []).append(aid)
        elif kind == "request.peer-bound":
            aid = detail["admission_id"]
            require(
                aid in admissions and aid not in peers,
                "peer socket lacks one original admission",
            )
            admitted, enrollment = admissions[aid]
            endpoint = urlparse(policy["backend_endpoint"])
            require(
                enrollment["sha256"] not in revoked
                and detail["enrollment_sha256"] == enrollment["sha256"]
                and detail["server_endpoint"] == [endpoint.hostname, endpoint.port]
                and detail["client_endpoint"][0] == "127.0.0.1"
                and str(detail["accepted_socket_inode"]).isdigit()
                and admitted["monotonic_ns"] < event["monotonic_ns"],
                (
                    "HTTP delivery was not bound to the admitted API's actual "
                    "accepted TCP peer"
                ),
            )
            peers[aid] = event
        elif kind == "request.complete":
            aid = detail["admission_id"]
            require(
                aid in admissions and aid in peers and aid not in completions,
                "completion has no unique admission and pre-send peer proof",
            )
            admitted, enrollment = admissions[aid]
            require(
                detail["enrollment_sha256"] == enrollment["sha256"]
                and enrollment["sha256"] not in revoked
                and detail["backend_identity"] == enrollment["backend"]
                and all(
                    detail[k] == admitted["detail"][k]
                    for k in ("request_id", "method", "request_sha256")
                )
                and peers[aid]["monotonic_ns"] < event["monotonic_ns"],
                "completion uses revoked/cross-generation backend",
            )
            body = base64.b64decode(detail["body_base64"], validate=True)
            require(
                digest(body) == detail["body_sha256"],
                "authority response body hash differs",
            )
            completions[aid] = event
    lost, response_ids = 0, []
    for rid in ids:
        start, end = sent[rid], ended[rid]
        body = base64.b64decode(end["body_base64"], validate=True)
        require(
            digest(body) == end["body_sha256"]
            and start["sent_ns"] <= end["finished_ns"],
            "client response bytes/clock differ",
        )
        if end["status"] != 200 or end["finished_ns"] > start["deadline_ns"]:
            lost += 1
            continue
        aid = end.get("admission_id")
        require(
            aid in completions and aid in all_admissions.get(rid, []),
            "successful delivery lacks independent dynamic completion",
        )
        event = completions[aid]
        admission = admissions[aid][0]
        require(
            event["detail"]["status"] == 200
            and event["detail"]["body_sha256"] == digest(body)
            and start["sent_ns"]
            <= admission["monotonic_ns"]
            < peers[aid]["monotonic_ns"]
            < event["monotonic_ns"]
            <= end["finished_ns"],
            "client response differs from actual backend bytes/order",
        )
        parsed = json.loads(body)
        choices = parsed.get("choices", [])
        require(
            parsed.get("model") == spec["payload"]["model"]
            and parsed.get("id")
            and len(choices) == 1
            and choices[0].get("index") == 0
            and choices[0].get("finish_reason") == "stop"
            and choices[0].get("text") == spec["response_expectation"]["text_equals"],
            "frozen functional oracle failed",
        )
        response_ids.append(parsed["id"])
    times = [e["detail"]["sent_ns"] for e in starts]
    covered = (
        recovery_ns is not None
        and min(times) < fault_ns < recovery_ns < max(times)
        and any(fault_ns <= t <= recovery_ns for t in times)
    )
    return {
        "authority_domain": PROFILE,
        "coverage": "complete-finite-delivery-window"
        if covered
        else (
            "recovery-not-observed"
            if recovery_ns is None
            else "recovery-outside-frozen-window"
        ),
        "request_count": 60,
        "lost_requests": lost,
        "duplicate_admissions": sum(
            max(0, len(a) - 1) for a in all_admissions.values()
        ),
        "reused_successful_response_ids": len(response_ids) - len(set(response_ids)),
        "duplicated_requests": None,
        "backend_execution_duplicates": None,
        "objective_met": None,
        "formal_result": False,
        "generation_count": generation,
    }
