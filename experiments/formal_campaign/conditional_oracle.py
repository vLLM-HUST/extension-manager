"""Independent raw reader for the genuine Pipeline/BidKV conditional boundary.

This function does NOT authenticate a journal, grant or cleanup summary itself.
A future typed intake must first retain its independently source/epoch-bound Host
journal and membership and pass their EXACT API/scheduler original processes.
Result is condition evidence, never a deployment receipt/formal H4 admission.
"""

from __future__ import annotations

import json

BATCH = "vllm_hust_pipeline_microbatch.policy.PipelineMicrobatchPolicy"
PREEMPT = "bidkv.adapters.vllm_hust.selector.BidkvPreemptionPolicy"
GROUP = "vllm.conditional_resource_pair"
SCHEMA = "ecpa-h4-host-conditional-scheduler-fact/v1"
SELECTED = tuple(range(16)) + tuple(16 + 16 * i for i in range(16))


def require(value, why):
    if not value:
        raise ValueError(why)


def evaluate(
    raw,
    *,
    plan_id,
    launch_id,
    api_process,
    scheduler_process,
    model,
    pp,
    tp,
    request_rows,
    selected_request_ids,
    control_raw,
    control_context,
    request_body,
    served_model,
    schedule=None,
    started=None,
    allow_incomplete=False,
    expected_arm=None,
    terminal_raw_ns=None,
):
    from experiments.formal_campaign.analyze import (
        h4_decode_body,
        h4_request_identity_observation,
        h4_response_summary,
    )
    from vllm_hust_ext.host_evidence import parse_host_event

    require(
        type(pp) is int and pp > 1 and type(tp) is int and tp > 0,
        "actual PP>1 and explicit TP required; historical TP2 is not a gate",
    )
    require(
        (len(request_rows) <= 272 if allow_incomplete else len(request_rows) == 272)
        and len(selected_request_ids) == 32,
        "original272/32 required",
    )
    actual_rows = {r["request_id"]: r for r in request_rows}
    by_request = {
        r["request_id"]: r for r in (schedule if schedule is not None else request_rows)
    }
    started = started if started is not None else actual_rows
    require(
        len(by_request) == 272
        and len(actual_rows) == len(request_rows)
        and len(set(selected_request_ids)) == 32
        and set(selected_request_ids) <= set(by_request),
        "request inventory aliases",
    )
    require(
        tuple(
            r["request_id"]
            for r in (schedule if schedule is not None else request_rows)
            if r["all_index"] in SELECTED
        )
        == tuple(selected_request_ids),
        "original fixed32 selection differs",
    )
    functional_failures = []
    for row in request_rows:
        response = row["http_response"]
        summary = h4_response_summary(response)
        identity = h4_request_identity_observation(
            row["request_id"], row["request_headers"], response
        )
        require(
            row["original_deadline_ns"] == row["dispatch_ns"] + 120_000_000_000
            and row["dispatch_ns"] <= row["complete_ns"]
            and h4_decode_body(row["http_request"]) == request_body,
            "original HTTP request/body/deadline changed",
        )
        if not (
            row["error"] is None
            and not row["watchdog_fired"]
            and row["complete_ns"] <= row["original_deadline_ns"]
            and summary["status_code"] == 200
            and summary["response_nonempty"]
            and summary["response_model"] == served_model
            and 0 < summary["output_tokens"] <= 64
            and identity["server_completion_matches_sent_request_id"] is True
        ):
            functional_failures.append(row["request_id"])
    require(
        allow_incomplete or not functional_failures,
        "original HTTP/body/identity/absolute120 outcome failed",
    )
    mappings, reverse, configured, batch_seen, preemption_seen = (
        {},
        {},
        [],
        set(),
        set(),
    )
    called = dict(batch=set(), preemption=set())
    violations = []
    require(
        control_context["schema"] == "ecpa-h4-conditional-original-rid-selection/v1",
        "unknown control source domain",
    )
    binding = {
        k: control_context[k]
        for k in ("schema", "start_id", "plan_id", "launch_id", "nonce")
    }
    require(
        binding["plan_id"] == plan_id and binding["launch_id"] == launch_id,
        "selection authority context moved to another actual epoch",
    )
    for role, original in (("api", api_process), ("scheduler", scheduler_process)):
        actual = control_context["kernels"][role]
        require(
            actual["pid"] == original["pid"]
            and actual["start_ticks"]
            == int(original["start_identity"].rsplit(":", 1)[1]),
            "control peer differs from original source-owned publisher",
        )
    sequences = dict(api=0, scheduler=0)
    control_records = {}
    used_control = set()
    import hashlib

    for line in control_raw.splitlines():
        record = json.loads(line)
        packet = record["packet"]
        role = packet["role"]
        require(
            role in sequences
            and all(packet[k] == v for k, v in binding.items())
            and packet["sequence"] == sequences[role] + 1
            and record["packet_sha256"]
            == hashlib.sha256(
                json.dumps(
                    packet, sort_keys=True, separators=(",", ":"), allow_nan=False
                ).encode()
            ).hexdigest()
            and record["peer"] == control_context["kernels"][role],
            "original control packet/peer/sequence changed",
        )
        require(
            set(packet) == set(binding) | {"role", "sequence", "operation", "payload"}
            and packet["operation"] == ("mapping" if role == "api" else "query"),
            "unknown control packet fields/operation",
        )
        sequences[role] = packet["sequence"]
        control_records[(role, packet["sequence"])] = record
        if role == "api":
            payload = packet["payload"]
            require(
                set(payload) == {"external_request_id", "runtime_request_id"},
                "unknown mapping payload fields",
            )
            runtime = payload["runtime_request_id"]
            external = payload["external_request_id"]
            matches = [rid for rid in by_request if external == "cmpl-" + rid + "-0"]
            require(
                len(matches) == 1
                and runtime not in reverse
                and external not in mappings,
                "unknown/duplicate actual API control mapping",
            )
            rid = matches[0]
            require(rid in started, "API mapping lacks actual original HTTP dispatch")
            require(
                record["result"] == {"selected": rid in selected_request_ids},
                "selection result differs from original fixed32",
            )
            mappings[external] = (runtime, record["observed_monotonic_ns"])
            reverse[runtime] = rid
        else:
            require(
                set(packet["payload"]) == {"runtime_request_ids"},
                "unknown scheduler query fields",
            )
            rids = packet["payload"]["runtime_request_ids"]
            require(
                all(r in reverse for r in rids) and len(rids) == len(set(rids)),
                "scheduler queried unknown/duplicate original RID",
            )
            require(
                record["result"]
                == {
                    "selected": [r for r in rids if reverse[r] in selected_request_ids]
                },
                "source selection changed",
            )
    require(
        allow_incomplete or len(mappings) == 272,
        "original full API mapping frontier incomplete",
    )
    public_mappings = set()
    unique = set()
    for line in raw.splitlines():
        event = parse_host_event(line)
        if event["entry_point"]["group"] != GROUP:
            continue
        require(event["event_id"] not in unique, "duplicate original Host event")
        unique.add(event["event_id"])
        require(
            event["plan_id"] == plan_id and event["launch_id"] == launch_id,
            "conditional journal moved to another Plan/launch",
        )
        fact = json.loads(event["detail"])
        require(
            fact["schema"] == SCHEMA
            and fact["action"] in ("mapping", "configured", "batch", "preemption"),
            "unknown source condition fact",
        )
        require(
            type(fact["observed_raw_ns"]) is int
            and fact["observed_raw_ns"] > 0
            and type(fact["observed_monotonic_ns"]) is int
            and fact["observed_monotonic_ns"] > 0,
            "actual source clocks missing",
        )
        require(
            fact["evidence_mode"] == "sampled-invocation", "wrong source evidence mode"
        )
        require(
            terminal_raw_ns is None or fact["observed_raw_ns"] <= terminal_raw_ns,
            "Host fact after original producer terminal",
        )
        action, payload = fact["action"], fact["payload"]
        expected = api_process if action == "mapping" else scheduler_process
        require(
            event["process"] == expected and event["binding_status"] == "bound",
            "condition fact is not exact independently observed original Host epoch",
        )
        if action in ("mapping", "batch", "preemption"):
            ref = payload["control_reference"]
            key = (ref["role"], ref["sequence"])
            require(
                key in control_records and key not in used_control,
                "missing/reused actual control query/mapping",
            )
            original_control = control_records[key]
            require(
                ref["request_sha256"] == original_control["packet_sha256"]
                and original_control["observed_monotonic_ns"]
                <= fact["observed_monotonic_ns"],
                "public fact not joined to actual control ACK",
            )
            used_control.add(key)
        if action == "mapping":
            require(
                ref["role"] == "api"
                and original_control["packet"]["payload"]
                == {
                    k: payload[k] for k in ("external_request_id", "runtime_request_id")
                },
                "public mapping moved to another control packet",
            )
            external, runtime = (
                payload["external_request_id"],
                payload["runtime_request_id"],
            )
            require(
                isinstance(runtime, str)
                and runtime
                and external in mappings
                and mappings[external][0] == runtime
                and external not in public_mappings,
                "duplicate/substituted API mapping",
            )
            matches = [rid for rid in by_request if external == "cmpl-" + rid + "-0"]
            require(
                len(matches) == 1,
                "mapping lacks original exact response/request identity",
            )
            rid = matches[0]
            row = started[rid]
            require(
                row["dispatch_ns"] <= fact["observed_raw_ns"],
                "actual API mapping predates original HTTP dispatch",
            )
            if fact["observed_raw_ns"] > min(
                row["original_deadline_ns"],
                actual_rows[rid]["complete_ns"]
                if rid in actual_rows
                else row["original_deadline_ns"],
            ):
                violations.append(
                    dict(
                        action="mapping",
                        outcome="outside-original-request-window",
                        request_id=rid,
                    )
                )
            require(
                rid in selected_request_ids
                and mappings[external][1] <= fact["observed_monotonic_ns"],
                "unselected/public mapping predates control ACK",
            )
            public_mappings.add(external)
        elif action == "configured":
            require(
                event["event"] == "resolved"
                and (
                    expected_arm is None or payload["activation_route"] == expected_arm
                ),
                "configured source route differs from actual registered arm",
            )
            require(not configured, "multiple scheduler controller configurations")
            require(
                payload["batch_policy"] == payload["batch_option"] == BATCH
                and payload["preemption_policy"]
                == payload["preemption_option"]
                == PREEMPT,
                "actual two distinct controller implementations differ",
            )
            require(
                payload["batch_enabled"] is True
                and payload["preemption_enabled"] is True
                and payload["max_num_seqs"] == 1
                and payload["model"] == model
                and payload["pipeline_parallel_size"] == pp
                and payload["tensor_parallel_size"] == tp,
                "actual controller/topology/model/maxseq condition false",
            )
            config = payload["batch_configuration"]
            require(
                config["pipeline_parallel_size"] == pp
                and config["tensor_parallel_size"] == tp
                and type(config["microbatch_count"]) is int
                and 1 < config["microbatch_count"] <= payload["max_concurrent_batches"],
                "actual Pipeline configuration condition false",
            )
            configured.append(fact)
        else:
            require(
                configured
                and fact["observed_monotonic_ns"]
                >= configured[0]["observed_monotonic_ns"],
                "dispatch precedes actual controller creation",
            )
            require(
                payload["policy"] == (BATCH if action == "batch" else PREEMPT)
                and payload["validation_stage"] == "original-host-validation-complete",
                "wrong actual policy/validation stage",
            )
            require(
                payload["controller_id"]
                == configured[0]["payload"][
                    "batch_controller_id"
                    if action == "batch"
                    else "preemption_controller_id"
                ],
                "actual controller instance changed",
            )
            context = payload["context"]
            candidates = context["requests" if action == "batch" else "candidates"]
            ids = {r["request_id"] for r in candidates}
            require(len(ids) == len(candidates), "duplicate source candidate")
            require(
                ref["role"] == "scheduler"
                and set(original_control["packet"]["payload"]["runtime_request_ids"])
                == ids
                and original_control["result"]["selected"],
                "public decision lacks original source32 query",
            )
            result, policy_result, outcome = (
                payload["result"],
                payload["policy_result"],
                payload["outcome"],
            )
            require(
                outcome
                in (
                    "accepted",
                    "abstained",
                    "abstained-builtin-fallback",
                    "invalid-builtin-fallback",
                    "exception-builtin-fallback",
                ),
                "unknown actual validation outcome",
            )
            actual_accepted = set()
            if action == "batch":
                require(context["pipeline_parallel_size"] == pp, "dispatch PP changed")
                valid = (
                    policy_result is not None
                    and bool(policy_result["batch_id"])
                    and policy_result["batch_id"] not in context["in_flight_batch_ids"]
                    and bool(policy_result["request_ids"])
                    and len(policy_result["request_ids"])
                    == len(set(policy_result["request_ids"]))
                    and set(policy_result["request_ids"]) <= ids
                )
                if outcome == "accepted":
                    require(
                        valid
                        and payload["error"] is None
                        and result == policy_result
                        and payload["stats"]["enabled"] is True
                        and payload["stats"]["failures"] == 0,
                        "Host accepted invalid admission/in-flight batch/fallback",
                    )
                    actual_accepted = set(result["request_ids"])
                elif outcome == "abstained":
                    require(
                        result is None
                        and policy_result is None
                        and context["in_flight_batch_ids"]
                        and payload["stats"]["enabled"] is True,
                        "invalid actual abstention",
                    )
                else:
                    require(
                        result is None
                        and payload["stats"]["enabled"] is False
                        and payload["stats"]["failures"] > 0,
                        "false disabled batch fallback",
                    )
                    if outcome == "invalid-builtin-fallback":
                        require(
                            policy_result is not None
                            and not valid
                            and payload["error"] is None,
                            "false invalid batch decision",
                        )
                    elif outcome == "exception-builtin-fallback":
                        require(
                            policy_result is None and payload["error"] is not None,
                            "false batch exception",
                        )
                    elif outcome == "abstained-builtin-fallback":
                        require(
                            policy_result is None
                            and not context["in_flight_batch_ids"]
                            and ids
                            and payload["error"] is None,
                            "false batch fallback abstention",
                        )
                    else:
                        raise ValueError("unknown batch fallback")
                    violations.append(dict(action=action, outcome=outcome))
            else:
                require(
                    context["requesting_request_id"] in ids and ids,
                    "preemption lacks real candidates",
                )
                if outcome == "accepted":
                    require(
                        policy_result in ids
                        and result == policy_result
                        and payload["error"] is None
                        and payload["stats"]["enabled"] is True
                        and payload["stats"]["failures"] == 0,
                        "invalid actual selected victim",
                    )
                    actual_accepted = {result}
                else:
                    builtin = context["builtin_victim_id"]
                    if builtin not in ids:
                        builtin = (
                            max(
                                candidates,
                                key=lambda c: (c["priority"], c["arrival_time"]),
                            )
                            if context["scheduling_policy"] == "priority"
                            else candidates[-1]
                        )["request_id"]
                    require(
                        result == builtin and result in ids,
                        "actual builtin fallback victim differs from "
                        "original algorithm",
                    )
                    if outcome == "abstained-builtin-fallback":
                        require(
                            policy_result is None
                            and payload["error"] is None
                            and payload["stats"]["enabled"] is True,
                            "false abstention",
                        )
                    elif outcome == "invalid-builtin-fallback":
                        require(
                            policy_result not in ids
                            and policy_result is not None
                            and payload["error"] is None
                            and payload["stats"]["enabled"] is False
                            and payload["stats"]["failures"] > 0,
                            "false invalid victim",
                        )
                    elif outcome == "exception-builtin-fallback":
                        require(
                            policy_result is None
                            and payload["error"] is not None
                            and payload["stats"]["enabled"] is False
                            and payload["stats"]["failures"] > 0,
                            "false victim exception",
                        )
                    else:
                        raise ValueError("unknown victim fallback")
                    violations.append(dict(action=action, outcome=outcome))
            for runtime in ids:
                require(
                    runtime in reverse,
                    "scheduler RID lacks earlier authenticated API mapping",
                )
                rid = reverse[runtime]
                mapped = mappings["cmpl-" + rid + "-0"][1]
                require(
                    mapped <= fact["observed_monotonic_ns"],
                    "dispatch precedes API mapping",
                )
                if rid in selected_request_ids:
                    called[action].add(rid)
                    original = started[rid]
                    upper = min(
                        original["original_deadline_ns"],
                        actual_rows[rid]["complete_ns"]
                        if rid in actual_rows
                        else original["original_deadline_ns"],
                    )
                    in_window = (
                        original["dispatch_ns"] <= fact["observed_raw_ns"] <= upper
                    )
                    if not in_window:
                        violations.append(
                            dict(
                                action=action,
                                outcome="outside-original-request-window",
                                request_id=rid,
                            )
                        )
                    if runtime in actual_accepted and in_window:
                        (batch_seen if action == "batch" else preemption_seen).add(rid)
    require(
        (len(configured) <= 1 if allow_incomplete else len(configured) == 1),
        "real controller configuration not observed",
    )
    require(
        allow_incomplete
        or public_mappings == {"cmpl-" + rid + "-0" for rid in selected_request_ids},
        "selected32 public API mappings incomplete",
    )
    required_control = {
        key
        for key, rec in control_records.items()
        if (key[0] == "api" and rec["result"]["selected"])
        or (key[0] == "scheduler" and rec["result"]["selected"])
    }
    require(
        used_control <= required_control
        and (allow_incomplete or used_control == required_control),
        "selected control packets/public facts not exact one-to-one",
    )
    public_mapping_complete = public_mappings == {
        "cmpl-" + rid + "-0" for rid in selected_request_ids
    }
    selected_control_complete = used_control == required_control
    api_frontier_complete = len(mappings) == 272
    missing_batch = sorted(set(selected_request_ids) - batch_seen)
    missing_preemption = sorted(set(selected_request_ids) - preemption_seen)
    return dict(
        schema="ecpa-h4-conditional-scheduler-observation/v1",
        actual_source_condition_observed=len(configured) == 1,
        functional_failures=functional_failures,
        selected_batch_accepted=sorted(batch_seen),
        selected_preemption_selected=sorted(preemption_seen),
        called_contexts={k: sorted(v) for k, v in called.items()},
        actual_fallback_or_failure=violations,
        missing_batch=missing_batch,
        missing_preemption=missing_preemption,
        selected_public_mapping_complete=public_mapping_complete,
        selected_control_join_complete=selected_control_complete,
        original_api_frontier_complete=api_frontier_complete,
        sampled_accepted_coverage_complete=public_mapping_complete
        and selected_control_complete
        and api_frontier_complete
        and not missing_batch
        and not missing_preemption
        and not violations
        and not functional_failures,
        absent_dispatch_is_unknown=True,
        formal_admission=False,
        performance_result=False,
    )
