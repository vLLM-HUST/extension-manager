"""Real CPU HTTP/process wiring only; these are never model/formal results."""

import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from experiments.exposure_gate import loopback_traffic
from experiments.formal_campaign import h3_client_trace
from experiments.formal_campaign import prospective_h3_client_window as wiring
from experiments.formal_campaign.prospective_h3_client_window import (
    ProspectiveClientWindow,
    current,
    kernel,
)

ROOT = Path(__file__).resolve().parents[1]


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_file(path, child):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if path.exists():
            return
        assert child.poll() is None
        time.sleep(0.01)
    raise TimeoutError(str(path))


def reference(module):
    path = Path(module.__file__).resolve()
    return {"path": str(path), "sha256": h3_client_trace.sha(path.read_bytes())}


def cleanup_only_window(tmp_path, monkeypatch):
    """Isolate lifecycle failures, without manufacturing an authority receipt."""
    monkeypatch.setenv("PYTHONPATH", str(ROOT / "src") + ":" + str(ROOT))
    window = ProspectiveClientWindow.__new__(ProspectiveClientWindow)
    window.spec = {
        "schema": "ecpa-h3-client-window-spec/v1",
        "start_id": "cleanup-only-never-semantic-evidence",
        "request_url": f"http://127.0.0.1:{free_port()}/request",
        "request_count": 100,
        "interval_s": 0.1,
        "timeout_s": 0.1,
        "dispatch_slack_s": 0.5,
        "concurrency": 2,
        "retry_policy": "single-attempt-no-retry",
        "payload": {"model": "test-model"},
        "response_expectation": {"text_equals": "ECPA"},
    }
    window.output = tmp_path / "cleanup-window"
    window.authority = kernel(os.getpid())
    window.authority_source = reference(loopback_traffic)
    window.client_source = reference(h3_client_trace)
    window.process = window.client = window.log = window.client_pidfd = None
    window.fault = window.recovery = None
    window.finished = False
    return window


def test_start_popen_failure_closes_log(tmp_path, monkeypatch):
    window = cleanup_only_window(tmp_path, monkeypatch)

    def fail_launch(*_args, **_kwargs):
        raise OSError("original Popen startup failure")

    monkeypatch.setattr(wiring.subprocess, "Popen", fail_launch)
    with pytest.raises(OSError, match="original Popen startup failure"):
        window.start()
    assert window.log.closed
    window.close()


def test_start_kernel_lookup_failure_reclaims_actual_child(tmp_path, monkeypatch):
    window = cleanup_only_window(tmp_path, monkeypatch)
    original = wiring.kernel

    def fail_client_lookup(pid):
        if pid != os.getpid():
            raise OSError("original client kernel lookup race")
        return original(pid)

    monkeypatch.setattr(wiring, "kernel", fail_client_lookup)
    with pytest.raises(OSError, match="original client kernel lookup race"):
        window.start()
    assert window.process.poll() is not None
    assert window.client_pidfd is None and window.log.closed
    window.close()


def test_finish_timeout_reclaims_actual_client(tmp_path, monkeypatch):
    window = cleanup_only_window(tmp_path, monkeypatch)
    try:
        client = window.start()
        # Only the wait/cleanup branch is under test; no report can be emitted.
        window.fault = {"signal_sent_ns": 1}
        window.recovery = {"monotonic_ns": 2}
        with pytest.raises(subprocess.TimeoutExpired):
            window.finish(tmp_path / "nonexistent-authority", timeout_s=0.001)
        assert not current(client)
        assert window.client_pidfd is None and window.log.closed
        assert not (window.output / "result.json").exists()
    finally:
        window.close()


def test_original_failure_survives_secondary_cleanup_error(tmp_path, monkeypatch):
    window = cleanup_only_window(tmp_path, monkeypatch)
    original_close = window.close
    try:
        window.start()
        window.fault = {"signal_sent_ns": 1}
        window.recovery = {"monotonic_ns": 2}

        def fail_cleanup():
            original_close()
            raise RuntimeError("secondary cleanup failure")

        monkeypatch.setattr(window, "close", fail_cleanup)
        with pytest.raises(subprocess.TimeoutExpired) as caught:
            window.finish(tmp_path / "nonexistent-authority", timeout_s=0.001)
        assert "secondary cleanup failure" in caught.value.cleanup_error
        assert window.process.poll() is not None and window.log.closed
    finally:
        original_close()


def test_real_forward_window_spans_actual_candidate_fault_and_keeps_execution_unknown(
    tmp_path, monkeypatch
):
    # The candidate is not committed: killing it must preserve predecessor
    # traffic. No transactional recovery or accelerator claim follows.
    env = os.environ | {"PYTHONPATH": str(ROOT / "src") + ":" + str(ROOT)}
    monkeypatch.setenv("PYTHONPATH", env["PYTHONPATH"])
    predecessor_port, candidate_port, authority_port = [free_port() for _ in range(3)]
    start_id = "nonformal-prospective-actual-fault"
    registration_sha = "sha256:" + "a" * 64
    binding_path = tmp_path / "binding.json"
    binding_path.write_text(
        json.dumps({"launch_id": start_id, "registration_sha256": registration_sha})
    )
    children = []
    window = None
    with (tmp_path / "children.log").open("wb") as log:
        try:
            registry = {}
            for number, port in enumerate((predecessor_port, candidate_port)):
                ready = tmp_path / f"backend-{number}.ready"
                child = subprocess.Popen(
                    [
                        sys.executable,
                        str(ROOT / "tests/fixtures/h3_window_backend.py"),
                        "--port",
                        str(port),
                        "--ready",
                        str(ready),
                    ],
                    env=env,
                    stdout=log,
                    stderr=log,
                    start_new_session=True,
                )
                children.append(child)
                wait_file(ready, child)
                registry[str(port)] = {
                    "process_identity": {
                        k: kernel(child.pid)[k]
                        for k in ("pid", "start_ticks", "boot_id")
                    },
                    "generation": number,
                    "model": "test-model",
                    "launch_id": f"cpu-backend-{number}",
                }
            registry_path = tmp_path / "backends.json"
            registry_path.write_text(json.dumps(registry))
            authority_socket = tmp_path / "authority.sock"
            authority_journal = tmp_path / "authority.jsonl"
            authority = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(loopback_traffic.__file__).resolve()),
                    "--socket",
                    str(authority_socket),
                    "--journal",
                    str(authority_journal),
                    "--listen-port",
                    str(authority_port),
                    "--predecessor-port",
                    str(predecessor_port),
                    "--candidate-port",
                    str(candidate_port),
                    "--predecessor-snapshot",
                    '{"generation":0}',
                    "--grant-holder",
                    start_id,
                    "--grant-token",
                    "1",
                    "--grant-expires-at",
                    str(int(time.time()) + 60),
                    "--recovery-binding",
                    str(binding_path),
                    "--backend-registration",
                    str(registry_path),
                ],
                env=env,
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
            children.append(authority)
            wait_file(authority_socket, authority)
            spec = {
                "schema": "ecpa-h3-client-window-spec/v1",
                "start_id": start_id,
                "request_url": f"http://127.0.0.1:{authority_port}/request",
                "request_count": 70,
                "interval_s": 0.025,
                "timeout_s": 0.5,
                "dispatch_slack_s": 0.5,
                "concurrency": 8,
                "retry_policy": "single-attempt-no-retry",
                "payload": {
                    "model": "test-model",
                    "prompt": "Reply ECPA",
                    "max_tokens": 8,
                    "temperature": 0,
                    "stream": False,
                },
                "response_expectation": {"text_equals": "ECPA"},
                "authority_registration_sha256": registration_sha,
                "authority_process_identity": {
                    k: kernel(authority.pid)[k]
                    for k in ("pid", "start_ticks", "boot_id")
                },
                "backend_registration": registry,
            }
            with pytest.raises(ValueError, match="cached or unsupported authority"):
                ProspectiveClientWindow(
                    spec,
                    tmp_path / "unsupported",
                    authority_source=reference(h3_client_trace),
                    client_source=reference(h3_client_trace),
                )
            window = ProspectiveClientWindow(
                spec,
                tmp_path / "window",
                authority_source=reference(loopback_traffic),
                client_source=reference(h3_client_trace),
            )
            client = window.start()
            assert current(client)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                events = h3_client_trace.read_client_trace(
                    tmp_path / "window/client.jsonl"
                )
                if any(event["kind"] == "request.finish" for event in events):
                    break
                time.sleep(0.01)
            target = kernel(children[1].pid)
            with pytest.raises(ValueError, match="epoch differs"):
                window.observe_owned_fault(
                    target=target | {"start_ticks": target["start_ticks"] + 1},
                    launcher=target,
                )
            assert current(target)
            window.observe_owned_fault(target=target, launcher=target)
            assert not current(target)
            cached = tmp_path / "cached.jsonl"
            cached.write_text('{"schema":"ecpa-staged-cached-controller/v1"}\n')
            cached.chmod(0o600)
            with pytest.raises(loopback_traffic.GateError):
                window.derive_recovery(cached)
            deadline = time.monotonic() + 5
            while True:
                try:
                    recovery = window.derive_recovery(authority_journal)
                    break
                except ValueError as error:
                    if (
                        "no source-owned postfault" not in str(error)
                        or time.monotonic() > deadline
                    ):
                        raise
                    time.sleep(0.02)
            assert recovery["backend"]["process_identity"]["pid"] == children[0].pid
            result = window.finish(authority_journal)
            assert result["coverage"] == "complete-finite-delivery-window"
            assert (
                result["backend_generation_coverage"]
                == "frozen-live-process-and-response-bound"
            )
            assert result["backend_execution_duplicates"] is None
            assert result["fresh_backend_execution_qualification"] is None
            assert result["reused_successful_response_ids"] == 0
            assert (
                not result["formal_result"] and result["additional_formal_starts"] == 0
            )
            assert not current(client)
        finally:
            if window:
                window.close()
            for child in reversed(children):
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=10)


@pytest.fixture
def recovery_selection(tmp_path, monkeypatch):
    """Deterministic selection unit data only; never an authority receipt."""
    import base64

    window = ProspectiveClientWindow.__new__(ProspectiveClientWindow)
    actual = kernel(os.getpid())
    binding = {
        "process_identity": {k: actual[k] for k in ("pid", "start_ticks", "boot_id")},
        "generation": 0,
        "model": "test-model",
        "launch_id": "CPU_SELECTION_FIXTURE_ONLY",
    }
    window.spec = {
        "start_id": "CPU-selection-only",
        "payload": {"model": "test-model"},
        "response_expectation": {"text_equals": "ECPA"},
        "backend_registration": {"12345": binding},
    }
    window.authority = actual
    window.authority_source = reference(loopback_traffic)
    window.client_source = reference(h3_client_trace)
    window.fault = {"target_gone_ns": 100, "target": {"session": -1}}
    window.output = tmp_path
    window.recovery = None
    events = []

    def append(kind, stamp, detail, **fields):
        event = {
            "sequence": len(events),
            "kind": kind,
            "monotonic_ns": stamp,
            "detail": detail,
            **{"proxy_" + k: actual[k] for k in ("pid", "start_ticks", "boot_id")},
            **fields,
        }
        events.append(event)
        return event

    append(
        "authority.start",
        1,
        {
            "backend_registration_sha256": h3_client_trace.sha(
                h3_client_trace.canonical(window.spec["backend_registration"])
            )
        },
    )

    def pair(index, admitted, completed):
        request_id = f"CPU-selection-only/request-{index:05d}"
        admission_id = f"CPU-admission-{index}"
        admit = append(
            "request.admit",
            admitted,
            {
                "request_id": request_id,
                "admission_id": admission_id,
                "request_sha256": h3_client_trace.sha(
                    h3_client_trace.canonical(window.spec["payload"])
                ),
            },
        )
        raw = h3_client_trace.canonical(
            {
                "id": f"CPU-response-{index}",
                "model": "test-model",
                "choices": [{"index": 0, "text": "ECPA", "finish_reason": "stop"}],
            }
        )
        end = append(
            "request.complete",
            completed,
            {
                "status": 200,
                "request_id": request_id,
                "admission_id": admission_id,
                "backend_port": 12345,
                "backend_identity": binding | {"listener_inode": "123"},
                "body_base64": base64.b64encode(raw).decode(),
                "body_sha256": h3_client_trace.sha(raw),
            },
            route={"generation": 0},
        )
        return admit, end

    monkeypatch.setattr(wiring, "read_traffic_journal", lambda _path: events)
    return window, events, pair


def test_crossfault_inflight_completion_is_skipped_for_later_fresh_request(
    recovery_selection,
):
    window, _, pair = recovery_selection
    pair(0, 90, 110)
    _, fresh = pair(1, 120, 130)
    result = window.derive_recovery("CPU-selection-not-a-real-journal")
    assert result["request_id"] == fresh["detail"]["request_id"]
    assert result["monotonic_ns"] == 130


def test_only_crossfault_inflight_completions_cannot_establish_recovery(
    recovery_selection,
):
    window, events, pair = recovery_selection
    pair(0, 90, 110)
    pair(1, 100, 120)  # Equality is also not a strictly postfault admission.
    events.sort(key=lambda event: event["monotonic_ns"])
    for sequence, event in enumerate(events):
        event["sequence"] = sequence
    with pytest.raises(ValueError, match="no source-owned postfault"):
        window.derive_recovery("CPU-selection-not-a-real-journal")
    assert window.recovery is None


@pytest.mark.parametrize("admitted", [90, 120])
@pytest.mark.parametrize(
    "mutation", ["missing", "duplicate", "wrong-hash", "time-order", "sequence-order"]
)
def test_invalid_original_admission_still_rejects_even_before_later_fresh_request(
    recovery_selection,
    admitted,
    mutation,
):
    import copy

    window, events, pair = recovery_selection
    admit, complete = pair(0, admitted, 130)
    pair(1, 140, 150)
    if mutation == "missing":
        events.remove(admit)
    elif mutation == "duplicate":
        events.insert(2, copy.deepcopy(admit))
    elif mutation == "wrong-hash":
        admit["detail"]["request_sha256"] = "0" * 64
    elif mutation == "time-order":
        admit["monotonic_ns"] = complete["monotonic_ns"]
    else:
        admit["sequence"] = complete["sequence"]
    with pytest.raises(
        ValueError, match="unique chronological fresh request admission"
    ):
        window.derive_recovery("CPU-selection-not-a-real-journal")
    assert window.recovery is None
