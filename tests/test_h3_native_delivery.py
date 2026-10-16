"""CPU-only partial-window/release counterexamples; no native qualification."""

import base64
import copy

import pytest

from experiments.formal_campaign import h3_native_delivery as d
from experiments.formal_campaign.h3_owned_worker_carrier import reference
from vllm_hust_ext.exposure_gate import GateError


@pytest.fixture
def partial(tmp_path, monkeypatch):
    kernel = {"pid": 123, "start_ticks": 456, "boot_id": "CPU-only"}
    spec = dict(
        schema="ecpa-h3-client-window-spec/v1",
        start_id="worker-crash-r1-ecpa",
        authority_domain=d.PROFILE,
        authority_process_identity=kernel,
        request_count=60,
        concurrency=8,
        interval_s=0.2,
        timeout_s=10,
        dispatch_slack_s=0.5,
        request_url="http://127.0.0.1:8187/v1/completions",
        retry_policy="single-attempt-no-retry",
        payload={"model": "CPU-only", "prompt": "unchanged"},
        response_expectation={"text_equals": "CPU-only"},
    )
    spec["initial_enrollment_sha256"] = "epoch"
    raw = d.client.canonical(spec["payload"])
    rid = spec["start_id"] + "/request-00000"
    traces = [
        dict(
            kind="client.start",
            client=kernel,
            monotonic_ns=90,
            detail=dict(
                spec_sha256=d.client.sha(d.client.canonical(spec)),
                schedule_anchor_ns=100,
            ),
        ),
        dict(
            kind="request.start",
            client=kernel,
            monotonic_ns=101,
            detail=dict(
                request_id=rid,
                scheduled_ns=100,
                sent_ns=100,
                deadline_ns=10_000_000_100,
                body_base64=base64.b64encode(raw).decode(),
                body_sha256=d.client.sha(raw),
            ),
        ),
    ]
    policy = {"CPU": "only"}
    events = [
        dict(
            kind="authority.start",
            authority=kernel,
            policy_sha256=d.digest(d.canonical(policy)),
            monotonic_ns=1,
            detail={},
        )
    ]
    enrollment = dict(
        sha256="epoch",
        generation=1,
        launch_id="launch1",
        nonce="nonce1",
        membership_epoch="membership1",
        backend={"process_identity": kernel},
    )
    events.append(
        dict(
            kind="backend.enrolled", monotonic_ns=91, detail={"enrollment": enrollment}
        )
    )
    monkeypatch.setattr(d.client, "read_client_trace", lambda path: traces)
    monkeypatch.setattr(d, "read_dynamic_journal", lambda path, domain: events)
    monkeypatch.setattr(d, "verify_enrollment", lambda *args: None)

    def run(**changes):
        args = dict(
            policy=policy,
            frozen_probe={
                "request_payload": spec["payload"],
                "response_expectation": spec["response_expectation"],
            },
            expected_client=kernel,
            fault_ns=200,
            recovery_ns=None,
            allow_incomplete=True,
        )
        args.update(changes)
        return d.verify_native_window(
            spec, tmp_path / "client", tmp_path / "authority", **args
        )

    return spec, traces, events, run, rid, tmp_path


def test_partial_true_fault_preserves_unknown_counts_and_default_rejects(partial):
    _, _, _, run, _, _ = partial
    result = run()
    assert result["coverage"] == "coverage-failed"
    assert result["lost_requests"] is None
    assert (
        result["requests_started"],
        result["requests_finished"],
        result["requests_expected"],
    ) == (1, 0, 60)
    with pytest.raises(GateError, match="incomplete"):
        run(allow_incomplete=False)


@pytest.mark.parametrize("change", ["duplicate", "unknown", "payload", "deadline"])
def test_partial_does_not_hide_corrupt_recorded_requests(partial, change):
    _, traces, _, run, _, _ = partial
    if change == "duplicate":
        traces.append(copy.deepcopy(traces[-1]))
    elif change == "unknown":
        traces[-1]["detail"]["request_id"] = "unknown/request-00000"
    elif change == "payload":
        traces[-1]["detail"]["body_base64"] = base64.b64encode(b"mutated").decode()
    else:
        traces[-1]["detail"]["deadline_ns"] += 1
    with pytest.raises(GateError):
        run()


def test_every_public_release_replayed_even_with_no_client_finish(partial, monkeypatch):
    spec, _, events, run, rid, tmp_path = partial
    journal = tmp_path / "native.jsonl"
    journal.write_bytes(b"CPU mocked full replay boundary\n")
    body = b'{"CPU":"mocked replay boundary"}'
    record = dict(
        response_body_base64=base64.b64encode(body).decode(),
        original_sent_ns=100,
        verified_monotonic_ns=125,
        journal=str(journal),
        phase={"phase_id": "phase0"},
        full_archive={
            "attention_complete_transactions": [
                dict(
                    phase_id="phase0", runtime_request_id="runtime", transaction_id="tx"
                )
            ]
        },
    )
    report = tmp_path / "report.json"
    report.write_bytes(d.canonical(record))
    events.append(
        dict(
            kind="route.open.applied",
            monotonic_ns=92,
            route={"generation": 1},
            detail={"enrollment_sha256": "epoch"},
        )
    )
    common = dict(request_id=rid, admission_id="admission", enrollment_sha256="epoch")
    events += [
        dict(
            kind="request.private-forward",
            monotonic_ns=110,
            detail=dict(
                common,
                method="POST",
                request_sha256=d.client.sha(d.client.canonical(spec["payload"])),
            ),
        ),
        dict(kind="request.peer-bound", monotonic_ns=115, detail=common),
        dict(
            kind="request.public-admit",
            monotonic_ns=130,
            detail=dict(
                common,
                method="POST",
                request_sha256=d.client.sha(d.client.canonical(spec["payload"])),
                status=200,
                body_sha256=d.client.sha(body),
                native_report=reference(report),
                native_verified_ns=125,
                native_prefix_sha256=d.h3_native_collector.native.sha(
                    journal.read_bytes()
                ),
                runtime_request_id="runtime",
                transaction_id="tx",
            ),
        ),
    ]
    for event in events:
        event.setdefault("route", {"generation": 1})
    seen = []

    def replay(ref, **kwargs):
        seen.append(kwargs)
        return record

    monkeypatch.setattr(d, "replay_native_report", replay)
    assert run()["lost_requests"] is None
    assert len(seen) == 1 and seen[0]["request_id"] == rid

    def forged(*args, **kwargs):
        raise GateError("forged native public proof")

    monkeypatch.setattr(d, "replay_native_report", forged)
    with pytest.raises(GateError, match="forged native public proof"):
        run()


def test_closed_native_membership_cannot_reopen_same_epoch(partial):
    _, _, events, run, _, _ = partial
    events += [
        dict(kind="route.closed", monotonic_ns=92, detail={}),
        dict(
            kind="route.open.applied",
            monotonic_ns=93,
            route={"generation": 1},
            detail={"enrollment_sha256": "epoch"},
        ),
    ]
    with pytest.raises(GateError, match="current enrollment"):
        run()


def test_replacement_cannot_reuse_original_api_kernel(partial):
    _, _, events, run, _, _ = partial
    enrollment = copy.deepcopy(events[-1]["detail"]["enrollment"])
    enrollment.update(
        sha256="epoch2",
        generation=2,
        launch_id="launch2",
        nonce="nonce2",
        membership_epoch="membership2",
    )
    events += [
        dict(kind="route.closed", monotonic_ns=92, detail={}),
        dict(
            kind="backend.enrolled", monotonic_ns=93, detail={"enrollment": enrollment}
        ),
    ]
    with pytest.raises(GateError, match="reused"):
        run()
