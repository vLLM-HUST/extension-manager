"""Failed-start admission regression tests; source fixtures are never real evidence.

Not imported or executed while the current product window is active.
"""

import base64
import json
from types import SimpleNamespace

import pytest

from experiments.formal_campaign import h3_observer_cleanup as cleanup
from experiments.formal_campaign import h3_observer_delivery as delivery
from experiments.formal_campaign import h3_observer_intake as intake
from experiments.formal_campaign import h3_observer_loss as loss
from experiments.formal_campaign import h3_observer_registration as registration
from vllm_hust_ext.exposure_gate import GateError


def kernel(pid):
    return dict(pid=pid, start_ticks=pid * 100, session=pid, boot_id="CPU-only")


@pytest.fixture
def partial_intake(tmp_path, monkeypatch):
    """Reach the actual intake delivery call with independently isolated CPU gates."""

    def save(name, value):
        path = tmp_path / name
        path.write_text(json.dumps(value))
        return path

    authority, carrier = kernel(1), kernel(2)
    hosts = [kernel(3), kernel(4), kernel(5)]
    collector, client = kernel(6), kernel(7)
    start_id = "observer-loss-r1-ecpa"
    spec_path = save("campaign.json", {"CPU-only": "campaign"})
    receipt_path = save("receipt.json", {"CPU-only": "receipt"})
    policy = {"registration_sha256": "CPU-only-scope"}
    policy_path = save("policy.json", policy)
    start = dict(
        start_id=start_id,
        arm="ecpa",
        repetition=1,
        arm_order=1,
        authority=dict(
            command=["CPU-only-authority"],
            public_port=29611,
            journal="CPU-only-journal",
        ),
        policy=dict(path=str(policy_path), sha256="CPU-only-policy"),
        recipe_template={"CPU-only": "recipe"},
        client_template=dict(
            start_id=start_id, payload={"model": "CPU-only", "prompt": "unchanged"}
        ),
    )
    spec = {
        "original_campaign": {"CPU-only": "original"},
        "observer_cleanup": {"external_services": []},
    }
    original = {
        "campaign_id": "H3-transactional-recovery-v1",
        "cell_id": "observer-loss",
        "fault": {"signal": "SIGKILL", "target_exit_timeout_s": 1},
        "probe": {"CPU-only": "probe"},
        "objective": {
            "max_lost_requests": 0,
            "max_recovery_ms": 100,
            "max_operator_actions": 0,
        },
    }
    monkeypatch.setattr(
        registration,
        "validate_receipt_for_start",
        lambda *a, **k: SimpleNamespace(selected=lambda sid: (spec, original, start)),
    )
    monkeypatch.setattr(registration, "validate_materialization", lambda *a, **k: None)
    recipe = {
        "authority": {
            "process_identity": {
                k: authority[k] for k in ("pid", "start_ticks", "boot_id")
            },
            "backend_endpoint": "http://127.0.0.1:29621",
        }
    }
    save("runtime-recipe.json", recipe)
    save(
        "runner-authority-observation.json",
        dict(
            kernel=authority,
            command=start["authority"]["command"],
            receipt=intake.reference(receipt_path),
            policy=start["policy"],
            observed_ns=2,
        ),
    )
    save(
        "runner-authority-peer-observation.json",
        dict(kernel=authority, argv=start["authority"]["command"]),
    )
    save("runner-carrier-observation.json", dict(kernel=carrier, observed_ns=5))
    marker = save(
        "phase0.launch-observation.json", dict(pid=3, launched_monotonic_ns=10)
    )
    phase = dict(
        observed_ns=30,
        parent=hosts[0],
        worker=hosts[1],
        parent_event={},
        worker_event={},
    )
    save("runner-before-ack.json", phase)
    monkeypatch.setattr(intake, "verify_parent_worker_ancestry", lambda *a: None)
    monkeypatch.setattr(intake, "_event", lambda *a: None)
    fault = dict(target=collector, signal="SIGKILL", triggered_ns=40)
    save("runner-fault.json", fault)
    save("runner-observer-dead.json", {"observed_dead_ns": 50})
    raw = dict(
        fault=fault,
        pidfd_observed_dead_ns=50,
        client_kernel=client,
        host_kernels_immediately_after_observer_death=hosts,
        client_barrier={"first_request_started_ns": 35},
    )
    save("observer-fault-raw.json", raw)
    save("phase0.actual-membership.json", [{"identity": k} for k in hosts])
    bound = dict(
        phase_index=0, observer=collector, enrollment_sha256="CPU-only-enrollment"
    )
    monkeypatch.setattr(
        intake,
        "read_dynamic_journal",
        lambda *a, **k: [
            dict(
                authority=authority,
                policy_sha256=intake.digest(intake.canonical(policy)),
                kind="authority.start",
            ),
            dict(
                kind="observer.actual-bound", monotonic_ns=25, detail={"binding": bound}
            ),
        ],
    )
    monkeypatch.setattr(
        loss, "validate_raw", lambda *a, **k: {"host_preserved_after_fault": True}
    )
    monkeypatch.setattr(loss, "verify_first_request_prefix", lambda *a, **k: True)
    runtime_client = dict(
        start["client_template"],
        authority_process_identity=recipe["authority"]["process_identity"],
        authority_domain=__import__(
            "experiments.formal_campaign.h3_observer_authority", fromlist=["PROFILE"]
        ).PROFILE,
        dynamic_policy_sha256=intake.digest(intake.canonical(policy)),
        dynamic_registration_sha256=policy["registration_sha256"],
        initial_enrollment_sha256="CPU-only-enrollment",
    )
    save("runtime-client-spec.json", runtime_client)
    save(
        "client-ready.json",
        {"client": {k: client[k] for k in ("pid", "start_ticks", "boot_id")}},
    )
    epochs = dict(
        authority=authority,
        carrier=carrier,
        host=hosts,
        collector=collector,
        client=client,
    )
    context = cleanup.context_for(spec_path, receipt_path, spec, start)
    owned = cleanup.ordered_kernels([authority, carrier, *hosts, collector, client])
    save(
        "runner-terminal.json",
        dict(
            schema="ecpa-h3-observer-independent-runner-terminal/v1",
            context=context,
            run_epochs=epochs,
            start_id=start_id,
            fault=fault,
            observed_dead_ns=50,
            observed_ns=90,
            carrier_complete=False,
        ),
    )
    save(
        "runner-cleanup-ownership.json",
        dict(context=context, run_epochs=epochs, owned_kernels=owned, captured_ns=105),
    )
    save("runner-cleanup-before.json", {"CPU-only": "before"})
    save("runner-cleanup-after.json", {"CPU-only": "after"})
    monkeypatch.setattr(
        cleanup,
        "verify",
        lambda *a, **k: {
            "processes_reclaimed": True,
            "ports_reclaimed": True,
            "devices_reclaimed": True,
            "external_services_preserved": True,
        },
    )
    save(
        "runner-observations.json",
        dict(
            schema="ecpa-h3-dynamic-runner-observations/v1",
            start_id=start_id,
            host_launches=[
                dict(
                    marker=marker.name,
                    marker_sha256=intake.reference(marker)["sha256"],
                    kernel=hosts[0],
                    observed_ns=20,
                )
            ],
            phases={"before": phase},
            fault=fault,
            observed_dead_ns=50,
            cleanup_owned_kernels=owned,
            cleanup_run_epochs=epochs,
            cleanup_started_ns=100,
            recorded_ns=140,
            cleanup_errors=[],
            error="CPU-only failed carrier",
        ),
    )
    return lambda: intake.intake(
        spec_path, receipt_path, start_id, tmp_path, native=True
    )


def test_canonical_partial_without_carrier_complete_retains_failed_start(
    partial_intake, monkeypatch
):
    def valid_partial(*args, **kwargs):
        assert kwargs["allow_incomplete"] is True
        return {"coverage": "coverage-failed", "lost_requests": None}

    monkeypatch.setattr(delivery, "verify_native_window", valid_partial)
    result = partial_intake()
    assert result["formal_start_validated"] is True and result["objective_met"] is False
    assert result["partial_failed_start"] is True and result["operator_actions"] is None
    assert result["independent_terminal_assessment"]["client_stop_ns"] is None


def test_original_parser_value_error_propagates_instead_of_formal_promotion(
    partial_intake, monkeypatch, tmp_path
):
    bad = tmp_path / "noncanonical.jsonl"
    bad.write_bytes(b"{broken-record}\n")

    def malformed_recorded_facts(*args, **kwargs):
        return delivery.client.read_client_trace(bad)

    monkeypatch.setattr(delivery, "verify_native_window", malformed_recorded_facts)
    with pytest.raises(ValueError):
        partial_intake()


def test_original_verifier_accepts_canonical_request_prefix_but_rejects_unknown_rid(
    tmp_path, monkeypatch
):
    client = {"pid": 123, "start_ticks": 456, "boot_id": "CPU-only"}
    spec = dict(
        schema="ecpa-h3-client-window-spec/v1",
        start_id="observer-loss-r1-ecpa",
        authority_domain=delivery.PROFILE,
        authority_process_identity=client,
        request_count=60,
        concurrency=8,
        interval_s=0.2,
        timeout_s=10,
        dispatch_slack_s=0.5,
        request_url="http://127.0.0.1:8187/v1/completions",
        retry_policy="single-attempt-no-retry",
        payload={"model": "CPU-only", "prompt": "unchanged"},
        response_expectation={"text_equals": "CPU-only"},
        initial_enrollment_sha256="epoch",
    )
    body = delivery.client.canonical(spec["payload"])
    rid = spec["start_id"] + "/request-00000"
    rows = [
        dict(
            kind="client.start",
            client=client,
            monotonic_ns=90,
            detail=dict(
                spec_sha256=delivery.client.sha(delivery.client.canonical(spec)),
                schedule_anchor_ns=100,
            ),
        ),
        dict(
            kind="request.start",
            client=client,
            monotonic_ns=101,
            detail=dict(
                request_id=rid,
                scheduled_ns=100,
                sent_ns=100,
                deadline_ns=10_000_000_100,
                body_base64=base64.b64encode(body).decode(),
                body_sha256=delivery.client.sha(body),
            ),
        ),
    ]
    policy = {"CPU": "only"}
    events = [
        dict(
            kind="authority.start",
            authority=client,
            policy_sha256=delivery.digest(delivery.canonical(policy)),
            monotonic_ns=1,
            detail={},
        ),
        dict(
            kind="backend.enrolled",
            monotonic_ns=91,
            detail={
                "enrollment": dict(
                    sha256="epoch",
                    generation=1,
                    launch_id="launch1",
                    nonce="nonce1",
                    membership_epoch="membership1",
                    backend={"process_identity": client},
                )
            },
        ),
    ]
    monkeypatch.setattr(delivery, "read_dynamic_journal", lambda *a, **k: events)
    monkeypatch.setattr(delivery, "verify_enrollment", lambda *a: None)
    path = tmp_path / "actual-prefix.jsonl"

    def write_chain():
        previous = "sha256:" + "0" * 64
        raw = []
        for index, row in enumerate(rows, 1):
            row.update(
                schema=delivery.client.SCHEMA, sequence=index, previous_sha256=previous
            )
            line = delivery.client.canonical(row)
            previous = delivery.client.sha(line)
            raw.append(line + b"\n")
        path.write_bytes(b"".join(raw))

    def verify():
        return delivery.verify_native_window(
            spec,
            path,
            tmp_path / "authority",
            policy=policy,
            frozen_probe={
                "request_payload": spec["payload"],
                "response_expectation": spec["response_expectation"],
            },
            expected_client=client,
            fault_ns=200,
            recovery_ns=None,
            allow_incomplete=True,
        )

    write_chain()
    result = verify()
    assert result["coverage"] == "coverage-failed" and result["lost_requests"] is None
    rows[1]["detail"]["request_id"] = "unknown-recorded-rid"
    write_chain()
    with pytest.raises(GateError, match="duplicated/unknown"):
        verify()
