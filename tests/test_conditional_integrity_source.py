"""Future focused negative reader tests. Source only; NOT RUN for this packet.

Fixture events isolate joins, not a real source/Plan/epoch qualification. Actual
host parser is substituted only at this unit boundary; intake still requires
original authenticated raw events in production.
"""

import copy
import json
from unittest.mock import patch

import pytest
from experiments.formal_campaign.conditional_common import canonical, sha
from experiments.formal_campaign.conditional_intake import verify_terminal_epoch
from experiments.formal_campaign.qualify_conditional import request_schedule

from experiments.formal_campaign import conditional_oracle as oracle


def fixture():
    schedule = request_schedule("unit-original")
    selected = [r["request_id"] for r in schedule if r["selected"]]
    api = dict(pid=101, start_identity="boot:100")
    scheduler = dict(pid=102, start_identity="boot:200")
    ctx = dict(
        schema="ecpa-h4-conditional-original-rid-selection/v1",
        start_id="unit-original",
        plan_id="a" * 64,
        launch_id="unit-launch",
        nonce="b" * 64,
        kernels=dict(
            api=dict(pid=101, start_ticks=100), scheduler=dict(pid=102, start_ticks=200)
        ),
    )
    binding = {
        k: ctx[k] for k in ("schema", "start_id", "plan_id", "launch_id", "nonce")
    }
    controls = []
    events = []
    seq = dict(api=0, scheduler=0)

    def control(role, operation, payload, result):
        seq[role] += 1
        packet = dict(
            binding, role=role, sequence=seq[role], operation=operation, payload=payload
        )
        record = dict(
            packet=packet,
            packet_sha256=sha(canonical(packet)),
            peer=ctx["kernels"][role],
            result=result,
            observed_monotonic_ns=5,
        )
        controls.append(record)
        return dict(
            role=role, sequence=seq[role], request_sha256=record["packet_sha256"]
        )

    def event(action, payload):
        fact = dict(
            schema=oracle.SCHEMA,
            action=action,
            evidence_mode="sampled-invocation",
            payload=payload,
            observed_raw_ns=10,
            observed_monotonic_ns=10 if action != "configured" else 1,
        )
        events.append(
            dict(
                event_id=str(len(events)),
                entry_point=dict(group=oracle.GROUP),
                plan_id=ctx["plan_id"],
                launch_id=ctx["launch_id"],
                event="resolved" if action == "configured" else "invoked",
                process=api if action == "mapping" else scheduler,
                binding_status="bound",
                detail=json.dumps(fact),
            )
        )

    event(
        "configured",
        dict(
            activation_route="ecpa",
            batch_policy=oracle.BATCH,
            batch_option=oracle.BATCH,
            preemption_policy=oracle.PREEMPT,
            preemption_option=oracle.PREEMPT,
            batch_enabled=True,
            preemption_enabled=True,
            max_num_seqs=1,
            model="/unit-model",
            pipeline_parallel_size=2,
            tensor_parallel_size=1,
            max_concurrent_batches=2,
            batch_configuration=dict(
                pipeline_parallel_size=2, tensor_parallel_size=1, microbatch_count=2
            ),
            batch_controller_id="batch-controller",
            preemption_controller_id="preemption-controller",
        ),
    )
    for row in schedule:
        rid = row["request_id"]
        runtime = "runtime-" + rid
        ref = control(
            "api",
            "mapping",
            dict(external_request_id="cmpl-" + rid + "-0", runtime_request_id=runtime),
            dict(selected=row["selected"]),
        )
        if row["selected"]:
            event(
                "mapping",
                dict(
                    external_request_id="cmpl-" + rid + "-0",
                    runtime_request_id=runtime,
                    control_reference=ref,
                ),
            )
    for rid in selected:
        runtime = "runtime-" + rid
        for action in ("batch", "preemption"):
            ref = control(
                "scheduler",
                "query",
                dict(runtime_request_ids=[runtime]),
                dict(selected=[runtime]),
            )
            context = (
                dict(
                    requests=[dict(request_id=runtime)],
                    in_flight_batch_ids=[],
                    pipeline_parallel_size=2,
                )
                if action == "batch"
                else dict(
                    candidates=[dict(request_id=runtime, priority=0, arrival_time=1)],
                    requesting_request_id=runtime,
                    builtin_victim_id=runtime,
                    scheduling_policy="fcfs",
                )
            )
            result = (
                dict(batch_id="batch-" + rid, request_ids=[runtime])
                if action == "batch"
                else runtime
            )
            event(
                action,
                dict(
                    controller_id=action + "-controller",
                    policy=oracle.BATCH if action == "batch" else oracle.PREEMPT,
                    context=context,
                    stats=dict(enabled=True, failures=0),
                    policy_result=result,
                    result=result,
                    outcome="accepted",
                    error=None,
                    validation_stage="original-host-validation-complete",
                    control_reference=ref,
                ),
            )
    rows = [
        dict(
            r,
            dispatch_ns=1,
            original_deadline_ns=120_000_000_001,
            complete_ns=90,
            error=None,
            watchdog_fired=False,
            http_request={},
            http_response={},
            request_headers=[],
        )
        for r in schedule
    ]
    args = dict(
        plan_id=ctx["plan_id"],
        launch_id=ctx["launch_id"],
        api_process=api,
        scheduler_process=scheduler,
        model="/unit-model",
        pp=2,
        tp=1,
        request_rows=rows,
        selected_request_ids=selected,
        control_context=ctx,
        request_body=b"unit",
        served_model="unit",
        schedule=schedule,
        expected_arm="ecpa",
        terminal_raw_ns=100,
    )
    return events, controls, args


def evaluate(events, controls, args):
    with (
        patch("vllm_hust_ext.host_evidence.parse_host_event", side_effect=json.loads),
        patch(
            "experiments.formal_campaign.analyze.h4_decode_body", return_value=b"unit"
        ),
        patch(
            "experiments.formal_campaign.analyze.h4_response_summary",
            return_value=dict(
                status_code=200,
                response_nonempty=True,
                response_model="unit",
                output_tokens=64,
            ),
        ),
        patch(
            "experiments.formal_campaign.analyze.h4_request_identity_observation",
            return_value=dict(server_completion_matches_sent_request_id=True),
        ),
    ):
        return oracle.evaluate(
            b"\n".join(canonical(e) for e in events) + b"\n",
            control_raw=b"\n".join(canonical(c) for c in controls) + b"\n",
            **args,
        )


def change_fact(events, action, change):
    event = next(e for e in events if json.loads(e["detail"])["action"] == action)
    fact = json.loads(event["detail"])
    change(fact["payload"])
    event["detail"] = json.dumps(fact)


def test_exact_query_and_mapping_unit_fixture():
    e, c, a = fixture()
    assert evaluate(e, c, a)["sampled_accepted_coverage_complete"] is True


def test_delete_all_scheduler_queries_rejects_public_facts():
    e, c, a = fixture()
    c = [r for r in c if r["packet"]["role"] != "scheduler"]
    with pytest.raises(ValueError, match="control query"):
        evaluate(e, c, a)


def test_delete_selected_api_public_mapping_rejects_complete_path():
    e, c, a = fixture()
    e = [r for r in e if json.loads(r["detail"])["action"] != "mapping"]
    with pytest.raises(ValueError, match="public API mappings incomplete"):
        evaluate(e, c, a)


def test_other_query_sha_cannot_authorize_decision():
    e, c, a = fixture()
    change_fact(
        e, "batch", lambda p: p["control_reference"].update(request_sha256="0" * 64)
    )
    with pytest.raises(ValueError, match="control ACK"):
        evaluate(e, c, a)


def test_inflight_batch_id_cannot_be_accepted():
    e, c, a = fixture()
    change_fact(
        e,
        "batch",
        lambda p: p["context"].update(in_flight_batch_ids=[p["result"]["batch_id"]]),
    )
    with pytest.raises(ValueError, match="invalid admission"):
        evaluate(e, c, a)


def test_builtin_abstention_does_not_count_selected_effect():
    e, c, a = fixture()
    change_fact(
        e,
        "preemption",
        lambda p: p.update(policy_result=None, outcome="abstained-builtin-fallback"),
    )
    result = evaluate(e, c, a)
    assert (
        not result["sampled_accepted_coverage_complete"]
        and len(result["missing_preemption"]) == 1
    )


def test_wrong_builtin_fallback_is_not_an_actual_validated_result():
    e, c, a = fixture()
    change_fact(
        e,
        "preemption",
        lambda p: p.update(
            policy_result=None,
            outcome="abstained-builtin-fallback",
            result="another-rid",
        ),
    )
    with pytest.raises(ValueError, match="builtin fallback victim"):
        evaluate(e, c, a)


def test_late_real_decision_is_retained_as_failure_not_effect():
    e, c, a = fixture()
    change_fact(e, "batch", lambda p: None)
    index = next(
        i for i, r in enumerate(e) if json.loads(r["detail"])["action"] == "batch"
    )
    fact = json.loads(e[index]["detail"])
    fact["observed_raw_ns"] = 95
    e[index]["detail"] = json.dumps(fact)
    result = evaluate(e, c, a)
    assert (
        not result["sampled_accepted_coverage_complete"]
        and len(result["missing_batch"]) == 1
    )


def test_wrong_or_live_cleanup_epoch_cannot_release():
    expected = dict(pid=123, start_ticks=11, session=123, boot_id="unit-boot")
    row = dict(
        original=expected,
        boot_raw="unit-boot\n",
        stat_raw=None,
        missing_type="PermissionError",
        observed_raw_ns=100,
    )
    with pytest.raises(ValueError, match="unknown proc error"):
        verify_terminal_epoch(row, expected)
    row["missing_type"] = "FileNotFoundError"
    wrong = dict(expected, start_ticks=12)
    with pytest.raises(ValueError, match="epoch/boot"):
        verify_terminal_epoch(row, wrong)


def test_request_timeout_record_never_extends_original_deadline():
    e, c, a = fixture()
    a["request_rows"][0]["original_deadline_ns"] += 1
    with pytest.raises(ValueError, match="deadline"):
        evaluate(e, c, a)


def test_independently_compiled_plan_roundtrips_original_resource_uri_profile():
    from types import SimpleNamespace as N

    from experiments.formal_campaign.conditional_plan import compile_actual

    from vllm_hust_ext.ecpa_model import PluginIdentity

    ids = ["org.vllm-hust.bidkv", "org.vllm-hust.pipeline-microbatch"]
    bundles = [
        N(
            bundle_id=i,
            manifest=N(
                resource_claims=[
                    N(
                        scope="vllm-process",
                        resource="vllm.scheduler." + str(n),
                        mode="exclusive",
                    )
                ]
            ),
        )
        for n, i in enumerate(ids)
    ]
    config = N(extension=lambda _id: N(configuration={}))
    plugins = tuple(PluginIdentity("org", str(n), "1.0", "a" * 64) for n in range(2))
    with (
        patch(
            "vllm_hust_ext.semantic_runtime_binding.installed_plugin_identities",
            return_value=(plugins, {}),
        ),
        patch(
            "vllm_hust_ext.providers.vllm.VllmProvider.plan",
            side_effect=[N(extension_id=i, generated_config={}) for i in ids],
        ),
        patch("vllm_hust_ext.core.reject_conflicting_plans"),
        patch(
            "experiments.formal_campaign.conditional_plan.version",
            return_value="0.31.0",
        ),
    ):
        plan, raw = compile_actual(
            dict(
                argv=["actual-host"],
                cwd="/actual-sdk",
                environment={"ECPA_H4_CONDITIONAL_MODE": "lifecycle-only"},
            ),
            bundles,
            config,
            request_schedule("unit-original"),
        )
    assert len(raw) > 0 and all(o.event == "resolved" for o in plan.obligations)
    assert all(c.uri.startswith("urn:ecpa:resource:vllm-process.") for c in plan.claims)


def test_other_clean_run_cannot_substitute_root_cleanup(tmp_path):
    from experiments.formal_campaign.conditional_common import reference
    from experiments.formal_campaign.conditional_intake import verify_cleanup

    expected = dict(
        start_id="actual-original",
        run_directory=str(tmp_path / "actual"),
        phase=dict(path="/actual-phase", sha256="a" * 64),
    )
    value = dict(
        schema="ecpa-h4-conditional-independent-root-terminal/v1",
        released=True,
        run_directory=str(tmp_path / "other"),
        start_id="other-original",
        phase=expected["phase"],
        campaign={},
        launch={},
        inputs={},
        receipt={},
    )
    path = tmp_path / "other-clean.json"
    path.write_bytes(canonical(value))
    with pytest.raises(ValueError, match="different original start"):
        verify_cleanup(
            reference(path),
            campaign_ref={},
            launch_ref={},
            inputs_ref={},
            start=expected,
            receipt_ref={},
            admission={},
            source_result={},
        )


def test_actual_socket_drip_is_interrupted_by_watchdog(monkeypatch):
    import socket
    import threading

    from experiments.formal_campaign import absolute_http

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    stop = threading.Event()
    errors = []

    def server():
        try:
            with listener.accept()[0] as peer:
                peer.recv(65536)
                peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nx")
                stop.wait(2)
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=server)
    worker.start()
    real_timer = threading.Timer
    # Only the test's wall scheduling is accelerated. The actual production
    # request still declares dispatch+original120 and uses real socket close.
    monkeypatch.setattr(
        absolute_http.threading,
        "Timer",
        lambda seconds, callback: real_timer(0.02, callback),
    )
    try:
        row = absolute_http.request_once(
            f"http://127.0.0.1:{listener.getsockname()[1]}/v1/completions",
            b"{}",
            120,
            "unit-original",
            "measured",
        )
        assert row["watchdog_fired"] is True and row["error"] is not None
        assert row["original_deadline_ns"] == row["dispatch_ns"] + 120_000_000_000
    finally:
        stop.set()
        listener.close()
        worker.join(3)
    assert not worker.is_alive() and not errors


def test_partial_mode_missing_all_public_mappings_never_has_positive_effects():
    e, c, a = fixture()
    e = [r for r in e if json.loads(r["detail"])["action"] != "mapping"]
    a["allow_incomplete"] = True
    result = evaluate(e, c, a)
    assert result["selected_public_mapping_complete"] is False
    assert result["selected_control_join_complete"] is False
    assert result["sampled_accepted_coverage_complete"] is False
    assert not result["functional_failures"]  # Missing effects are independent.


def test_partial_mode_unused_selected_query_prevents_positive_effects():
    e, c, a = fixture()
    a["allow_incomplete"] = True
    # Retain an authenticated extra selected source query with no public result.
    extra = copy.deepcopy(
        next(r for r in reversed(c) if r["packet"]["role"] == "scheduler")
    )
    extra["packet"]["sequence"] += 1
    extra["packet_sha256"] = sha(canonical(extra["packet"]))
    c.append(extra)
    result = evaluate(e, c, a)
    assert (
        result["selected_control_join_complete"] is False
        and result["sampled_accepted_coverage_complete"] is False
    )


def trace_fixture(model="expected-model"):
    """Canonical unit-only raw HTTP/trace; never a qualified runtime input."""
    from experiments.formal_campaign.analyze import (
        h4_body_binding,
        h4_request_identity_observation,
        h4_response_summary,
    )

    schedule = request_schedule("unit-trace")
    binding = dict(start_id="unit-trace", plan_id="a" * 64, launch_id="unit-launch")
    body = b'{"original":"unit"}'
    events = []

    def append(kind, detail, clock):
        events.append(
            dict(
                schema="ecpa-h4-conditional-original-request-trace/v1",
                **binding,
                kind=kind,
                detail=detail,
                observed_raw_ns=clock,
            )
        )

    append("client.start", dict(request_count=272, selected_count=32), 1)
    for declaration in schedule:
        rid = declaration["request_id"]
        dispatch = 1000 + declaration["all_index"] * 1000
        deadline = dispatch + 120_000_000_000
        append(
            "request.start",
            dict(
                request_id=rid,
                all_index=declaration["all_index"],
                dispatch_ns=dispatch,
                original_deadline_ns=deadline,
                body_sha256=sha(body),
            ),
            dispatch + 1,
        )
        headers = [["X-Request-Id", rid]]
        response = dict(
            status_code=200,
            headers=[],
            **h4_body_binding(
                canonical(
                    dict(
                        id="cmpl-" + rid,
                        model=model,
                        choices=[dict(text="actual-unit-body")],
                        usage=dict(completion_tokens=64),
                    )
                )
            ),
        )
        row = dict(
            request_id=rid,
            kind=declaration["kind"],
            request_headers=headers,
            request_identity=h4_request_identity_observation(rid, headers, response),
            dispatch_ns=dispatch,
            original_deadline_ns=deadline,
            complete_ns=dispatch + 5,
            error=None,
            http_request=h4_body_binding(body),
            http_response=response,
            watchdog_fired=False,
            **h4_response_summary(response),
        )
        append("request.end", row, dispatch + 6)
    append("client.stop", dict(started=272, completed=272), 300000)
    return events, schedule, body, binding


def chain_trace(events):
    out = []
    previous = "0" * 64
    for sequence, event in enumerate(events):
        material = dict(event, sequence=sequence, previous_sha256=previous)
        material["event_sha256"] = sha(canonical(material))
        previous = material["event_sha256"]
        out.append(canonical(material))
    return b"\n".join(out) + b"\n"


def replay_unit_trace(events, schedule, body, binding):
    from experiments.formal_campaign.conditional_request_trace import replay_trace

    return replay_trace(
        chain_trace(events),
        schedule,
        body,
        binding=binding,
        allow_incomplete=True,
        served_model="expected-model",
    )


def test_wrong_response_model_full272_is_functional_failure_for_both_modes():
    from experiments.formal_campaign.conditional_intake import (
        functional_window_complete,
    )

    events, schedule, body, binding = trace_fixture(model="wrong-model")
    result = replay_unit_trace(events, schedule, body, binding)
    assert result["original_start_count"] == 272 and result["stop"] is not None
    assert not result["complete"] and len(result["actual_failures"]) == 272
    for oracle_result in (
        None,
        dict(
            functional_failures=[r["request_id"] for r in schedule],
            sampled_accepted_coverage_complete=False,
        ),
    ):
        assert not functional_window_complete(
            result, dict(first_health={"real-unit-observation": True}), oracle_result
        )


def test_absent_bidkv_effect_does_not_change_valid_functional_support():
    from experiments.formal_campaign.conditional_intake import (
        functional_window_complete,
    )

    events, schedule, body, binding = trace_fixture()
    trace = replay_unit_trace(events, schedule, body, binding)
    assert trace["complete"] is True
    assert functional_window_complete(
        trace,
        dict(first_health={"real-unit-observation": True}),
        dict(functional_failures=[], sampled_accepted_coverage_complete=False),
    )
    assert not functional_window_complete(
        trace,
        dict(first_health={"real-unit-observation": True}),
        dict(
            functional_failures=["wrong-model"], sampled_accepted_coverage_complete=True
        ),
    )


def test_rechained_foreign_trace_schema_is_rejected():
    events, schedule, body, binding = trace_fixture()
    for event in events:
        event["schema"] = "foreign-domain"
    with pytest.raises(ValueError, match="domain/fields/RAW"):
        replay_unit_trace(events, schedule, body, binding)


def test_rechained_extra_trace_field_is_rejected():
    events, schedule, body, binding = trace_fixture()
    events[1]["unknown"] = "not-original"
    with pytest.raises(ValueError, match="domain/fields/RAW"):
        replay_unit_trace(events, schedule, body, binding)


def test_rechained_stop_before_request_end_is_rejected():
    events, schedule, body, binding = trace_fixture()
    events[-1]["observed_raw_ns"] = events[-2]["observed_raw_ns"] - 1
    with pytest.raises(ValueError, match="domain/fields/RAW"):
        replay_unit_trace(events, schedule, body, binding)


def test_noepoch_typeerror_cannot_become_formal_runtime_failure():
    from experiments.formal_campaign.conditional_intake import no_epoch_cause

    source = dict(
        schema="ecpa-h4-conditional-source-result/v1",
        failure_category="unqualified-verification-error",
        errors=[dict(stage="runtime", type="TypeError")],
    )
    with pytest.raises(ValueError, match="schema/ABI/integrity"):
        no_epoch_cause(source, {}, {}, [], {})


def test_noepoch_actual_timeout_uses_original_exact_typed_clock_taxonomy():
    from experiments.formal_campaign.conditional_intake import no_epoch_cause

    source = dict(
        schema="ecpa-h4-conditional-source-result/v1",
        failure_category="runtime-interruption",
        errors=[
            dict(
                stage="runtime", type="TimeoutError", message="original startup budget"
            )
        ],
        failure="TimeoutError: original startup budget",
        runtime_interruption=dict(
            schema="ecpa-h4-source-runtime-interruption/v1",
            family="timeout",
            exception_type="builtins.TimeoutError",
            observed_monotonic_ns=20,
            observed_raw_ns=30,
        ),
        failure_observed_monotonic_ns=21,
        failure_observed_raw_ns=31,
        end_raw_ns=40,
    )
    with patch(
        "experiments.formal_campaign.h4_sampled_intake.independent_runner_signal",
        return_value=None,
    ):
        cause = no_epoch_cause(
            source,
            dict(terminal_raw_ns=50),
            {},
            [],
            dict(before_monotonic_ns=10, after_ns=15),
        )
        assert cause["kind"] == "source-observed-runtime-interruption"
        source["runtime_interruption"]["exception_type"] = "builtins.TypeError"
        with pytest.raises(ValueError, match="typed cause/clocks"):
            no_epoch_cause(
                source,
                dict(terminal_raw_ns=50),
                {},
                [],
                dict(before_monotonic_ns=10, after_ns=15),
            )


def receipt_fixture(tmp_path):
    from experiments.formal_campaign.conditional_common import reference

    from vllm_hust_ext.ecpa_model import (
        EvidenceObligation,
        HostCompatibility,
        Plan,
        PluginIdentity,
        PredecessorSnapshot,
    )
    from vllm_hust_ext.plan_artifact import plan_artifact_bytes

    plan = Plan(
        (PluginIdentity("unit", "only-unit-static", "1.0", "a" * 64),),
        HostCompatibility("vllm", "0.31.0", "vllm", "1.0"),
        (),
        (EvidenceObligation("unit-only-static", "unit-role", "resolved", (0,)),),
        PredecessorSnapshot(0, None, {}),
        False,
    )
    path = tmp_path / "unit-plan.json"
    raw = plan_artifact_bytes(plan)
    path.write_bytes(raw)
    starts = [
        dict(
            start_id="original-" + str(i),
            plan=reference(path),
            phase=dict(path="/unit-phase-" + str(i), sha256=str(i) * 64),
        )
        for i in range(9)
    ]
    inputs = dict(
        evidence_mode="sampled-invocation",
        starts=starts,
        protocol_sources={"unit-source": "static-scope-only"},
    )

    def material(s):
        return dict(
            observation=None,
            runtime_closure={},
            qualification={},
            plan_id=plan.plan_id,
            plan_sha256=sha(raw),
            phase_sha256=s["phase"]["sha256"],
            source=inputs["protocol_sources"],
        )

    receipt = dict(
        schema="ecpa-h4-conditional-deployment-receipt/v1",
        registration_state="registered",
        admissible=True,
        evidence_mode=inputs["evidence_mode"],
        original_registration={},
        campaign={},
        launch={},
        conditional_inputs={},
        source_observation={},
        qualification={},
        starts=[dict(start_id=s["start_id"], material=material(s)) for s in starts],
    )
    campaign = dict(source_provenance_policy={}, fixed_identity={})
    return receipt, campaign, inputs


def test_static_receipt_requires_the_complete_original_nine_inventory(tmp_path):
    from experiments.formal_campaign.conditional_registration import (
        validate_receipt_static,
    )

    receipt, campaign, inputs = receipt_fixture(tmp_path)
    with patch("experiments.formal_campaign.source_provenance.validate_observation"):
        validate_receipt_static(receipt, campaign, inputs)
        receipt["starts"] = []
        with pytest.raises(ValueError, match="Latin9 inventory"):
            validate_receipt_static(receipt, campaign, inputs)


@pytest.mark.parametrize(
    "field,value",
    [("registration_state", "unregistered"), ("evidence_mode", "lifecycle-only")],
)
def test_static_receipt_cannot_change_state_or_mode(tmp_path, field, value):
    from experiments.formal_campaign.conditional_registration import (
        validate_receipt_static,
    )

    receipt, campaign, inputs = receipt_fixture(tmp_path)
    receipt[field] = value
    with pytest.raises(ValueError, match="whole-nine conditional receipt"):
        validate_receipt_static(receipt, campaign, inputs)


def test_static_receipt_other_slot_cannot_substitute_registered_plan_hash(tmp_path):
    from experiments.formal_campaign.conditional_registration import (
        validate_receipt_static,
    )

    receipt, campaign, inputs = receipt_fixture(tmp_path)
    receipt["starts"][8]["material"]["plan_sha256"] = "f" * 64
    with (
        patch("experiments.formal_campaign.source_provenance.validate_observation"),
        pytest.raises(ValueError, match="whole-nine registered Plan"),
    ):
        validate_receipt_static(receipt, campaign, inputs)


@pytest.mark.parametrize("field", ["qualification", "runtime_closure"])
def test_another_slot_cannot_replace_currently_replayed_qualification_or_runtime(
    tmp_path, field
):
    from experiments.formal_campaign.conditional_registration import (
        validate_current_materials,
    )

    receipt, _, _ = receipt_fixture(tmp_path)
    current = copy.deepcopy(receipt["starts"][0]["material"])
    validate_current_materials(receipt, current)
    receipt["starts"][8]["material"][field] = {
        "other-run": "not-the-current-independent-material"
    }
    with pytest.raises(ValueError, match="qualification/runtime material"):
        validate_current_materials(receipt, current)
