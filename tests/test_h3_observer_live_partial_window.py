"""Original real chained partial client bytes under distinct v2 window replay.
No model/native proof is mocked into a successful response; this CPU fixture
only bypasses enrollment discovery, then verifies actual prefix/RID semantics.
Source specification only, unrun.
"""

import base64

import pytest

from experiments.formal_campaign import h3_observer_live_delivery as delivery
from vllm_hust_ext.exposure_gate import GateError


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
            live_receipt={"path": "/CPU-only/v2", "sha256": "sha256:CPU-only"},
        )

    write_chain()
    result = verify()
    assert result["coverage"] == "coverage-failed" and result["lost_requests"] is None
    assert (
        result["recovery_ns"] is None
        and result["schema"] == "ecpa-h3-observer-live-finite-delivery/v2"
    )
    original_body = rows[1]["detail"]["body_base64"]
    rows[1]["detail"]["body_base64"] = "***malformed***"
    write_chain()
    with pytest.raises(ValueError):
        verify()
    rows[1]["detail"]["body_base64"] = original_body
    path.unlink()
    with pytest.raises(FileNotFoundError):
        verify()
    rows[1]["detail"]["request_id"] = "unknown-recorded-rid"
    write_chain()
    with pytest.raises(GateError, match="duplicated/unknown"):
        verify()
