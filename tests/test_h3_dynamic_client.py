"""Original 60-attempt CPU HTTP window; no model or formal qualification."""

import copy
import threading
import time

import pytest
from test_h3_dynamic_authority import (
    admit,
    command,
    enroll,
    fixture,
    start_host,
    stop_host,
)

from experiments.formal_campaign.h3_client_trace import (
    process_identity,
    read_client_trace,
    run_client,
)
from experiments.formal_campaign.h3_dynamic_authority import (
    DynamicProxyHandler,
    ThreadingHTTPServer,
    canonical,
    digest,
    read_dynamic_journal,
)
from experiments.formal_campaign.h3_dynamic_client import verify_dynamic_window


def rewrite_chain(path, events):
    previous = "sha256:" + "0" * 64
    lines = []
    for index, event in enumerate(events, 1):
        event["sequence"] = index
        event["previous_sha256"] = previous
        raw = canonical(event)
        lines.append(raw)
        previous = digest(raw)
    path.write_bytes(b"\n".join(lines) + b"\n")


def test_original_full_cpu_window_new_epoch_and_rebinding_negatives(
    tmp_path, monkeypatch
):
    process, members, policy, authority, journal, plan = fixture(tmp_path, monkeypatch)
    server = ThreadingHTTPServer(("127.0.0.1", 0), DynamicProxyHandler)
    server.authority = authority
    threading.Thread(target=server.serve_forever, daemon=True).start()
    replacement = None
    errors = []
    client_thread = None
    try:
        first = enroll(authority, policy, members)
        admit(authority, policy, first)
        spec = {
            "schema": "ecpa-h3-client-window-spec/v1",
            "start_id": policy["start_id"],
            "request_count": 60,
            "concurrency": 8,
            "interval_s": 0.2,
            "timeout_s": 10,
            "dispatch_slack_s": 0.5,
            "retry_policy": "single-attempt-no-retry",
            "request_url": f"http://127.0.0.1:{server.server_port}/v1/completions",
            "payload": {"model": "cpu-fixture"},
            "response_expectation": {"text_equals": "ok"},
            "authority_domain": "ecpa-source-owned-dynamic-backend-enrollment/v1",
            "dynamic_policy_sha256": digest(canonical(policy)),
            "dynamic_registration_sha256": policy["registration_sha256"],
            "initial_enrollment_sha256": first["membership_sha256"],
            "authority_process_identity": process_identity(),
        }

        def run():
            try:
                run_client(
                    spec, tmp_path / "client.jsonl", tmp_path / "client-ready.json"
                )
            except Exception as exc:
                errors.append(exc)

        client_thread = threading.Thread(target=run)
        client_thread.start()
        deadline = time.monotonic() + 5
        while not (tmp_path / "client-ready.json").exists():
            assert time.monotonic() < deadline
            time.sleep(0.01)
        # This CPU protocol test uses graceful EOF, never signals any process.
        time.sleep(1)
        fault = time.monotonic_ns()
        stop_host(process)
        authority.apply(command(policy, "query"))
        replacement, new_members, _, _, _ = start_host(
            tmp_path,
            int(policy["backend_endpoint"].rsplit(":", 1)[1]),
            "phase1",
            plan.plan_id,
        )
        second = enroll(authority, policy, new_members, 1)
        admit(authority, policy, second)
        recovery = time.monotonic_ns()
        client_thread.join(timeout=25)
        assert not client_thread.is_alive() and not errors
        kwargs = {
            "policy": policy,
            "frozen_probe": {
                "request_payload": spec["payload"],
                "response_expectation": spec["response_expectation"],
            },
            "expected_client": process_identity(),
            "fault_ns": fault,
            "recovery_ns": recovery,
        }
        result = verify_dynamic_window(
            spec, tmp_path / "client.jsonl", tmp_path / "authority.jsonl", **kwargs
        )
        assert result["request_count"] == 60 and result["generation_count"] == 2
        # A real CPU restart can finish between two scheduled sends or after
        # the finite window on a loaded runner. Coverage must reflect its actual
        # source-recorded clocks; the fixed60 workload and deadlines stay strict.
        sent = [
            event["detail"]["sent_ns"]
            for event in read_client_trace(tmp_path / "client.jsonl")
            if event["kind"] == "request.start"
        ]
        covered = min(sent) < fault < recovery < max(sent) and any(
            fault <= tick <= recovery for tick in sent
        )
        expected_coverage = (
            "complete-finite-delivery-window"
            if covered
            else "recovery-outside-frozen-window"
        )
        assert result["coverage"] == expected_coverage
        # Classification negative: actual trace bytes stay unchanged, while a
        # recovery marker beyond its last send must never report full coverage.
        outside = verify_dynamic_window(
            spec,
            tmp_path / "client.jsonl",
            tmp_path / "authority.jsonl",
            **dict(kwargs, recovery_ns=max(sent) + 1),
        )
        assert outside["coverage"] == "recovery-outside-frozen-window"
        # Invoked-only delivery cannot establish the original objective, even
        # with full temporal coverage: the production result remains unknown.
        assert outside["objective_met"] is None
        assert (
            result["duplicated_requests"] is None
            and result["objective_met"] is None
            and result["formal_result"] is False
        )
        original = read_dynamic_journal(tmp_path / "authority.jsonl")
        changed = copy.deepcopy(original)
        complete = next(e for e in changed if e["kind"] == "request.complete")
        complete["detail"]["request_id"] = "another-actual-request"
        target = tmp_path / "rebound.jsonl"
        rewrite_chain(target, changed)
        with pytest.raises(Exception, match="completion uses revoked/cross-generation"):
            verify_dynamic_window(spec, tmp_path / "client.jsonl", target, **kwargs)
        changed = copy.deepcopy(original)
        complete = next(e for e in changed if e["kind"] == "request.complete")
        complete["monotonic_ns"] = next(
            e["monotonic_ns"] for e in changed if e["kind"] == "request.peer-bound"
        )
        target = tmp_path / "bad-clock.jsonl"
        rewrite_chain(target, changed)
        with pytest.raises(Exception, match="monotonic|completion"):
            verify_dynamic_window(spec, tmp_path / "client.jsonl", target, **kwargs)
        changed = copy.deepcopy(original)
        changed[-1]["kind"] = "authority.start"
        target = tmp_path / "duplicate-start.jsonl"
        rewrite_chain(target, changed)
        with pytest.raises(Exception, match="start was replayed"):
            read_dynamic_journal(target)
    finally:
        if client_thread is not None:
            client_thread.join(timeout=25)
        stop_host(process)
        if replacement is not None:
            stop_host(replacement)
        server.shutdown()
        server.server_close()
        journal.close()
