"""Actual owned original client and CPU HTTP sockets; no model/native claims."""

from __future__ import annotations

import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from experiments.formal_campaign import h3_client_trace as client
from experiments.formal_campaign.h3_native_http import BoundOriginalClient
from experiments.formal_campaign.h3_worker_relaunch import identity


def test_original60_client_deadlines_and_socket_owner_are_bound(tmp_path):
    observed, errors = [], []
    binding = None

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            try:
                if binding is not None:
                    observed.append(
                        binding.request(
                            self.headers["X-ECPA-Request-ID"], body, self.connection
                        )
                    )
            except Exception as exc:
                errors.append(str(exc))
            self.send_error(503, "no native producer in this CPU test")

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    spec_path, trace, ready = [
        tmp_path / n for n in ("spec.json", "trace.jsonl", "ready.json")
    ]
    spec = {
        "schema": "ecpa-h3-client-window-spec/v1",
        "start_id": "actual-CPU-client",
        "request_count": 60,
        "concurrency": 8,
        "interval_s": 0.2,
        "timeout_s": 10,
        "dispatch_slack_s": 0.5,
        "retry_policy": "single-attempt-no-retry",
        "request_url": f"http://127.0.0.1:{server.server_port}/v1/completions",
        "payload": {"model": "CPU-no-model", "prompt": "unchanged"},
        "response_expectation": {"text_equals": "unused"},
    }
    spec_path.write_bytes(client.canonical(spec))
    process = subprocess.Popen(
        [
            sys.executable,
            str(Path(client.__file__).resolve()),
            "--spec",
            str(spec_path),
            "--trace",
            str(trace),
            "--ready",
            str(ready),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ready.exists()
        binding = BoundOriginalClient(identity(process.pid), spec_path, trace, ready)
        with pytest.raises(urllib.error.HTTPError) as response:
            urllib.request.urlopen(
                urllib.request.Request(
                    spec["request_url"],
                    data=client.canonical(spec["payload"]),
                    headers={"X-ECPA-Request-ID": "actual-CPU-client/request-00000"},
                ),
                timeout=5,
            )
        assert response.value.code == 503
        process.communicate(timeout=25)
        assert process.returncode == 0
        events = client.read_client_trace(trace)
        starts = [e for e in events if e["kind"] == "request.start"]
        assert len(starts) == 60
        assert len(observed) >= 50
        assert all(s["deadline_ns"] - s["sent_ns"] == 10_000_000_000 for s in observed)
        assert any("not owned by the admitted API epoch" in e for e in errors)
        assert all(
            s["body_sha256"] == client.sha(client.canonical(spec["payload"]))
            for s in observed
        )
    finally:
        # The original finite client has a natural12s exit. No signal is sent.
        process.communicate(timeout=25)
        server.shutdown()
        server.server_close()
        thread.join()


def test_private_health_uses_original_launch_deadline_and_no_model_request(tmp_path):
    from experiments.formal_campaign.h3_owned_worker_carrier import wait_native_health

    paths = []

    class Health(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            paths.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Health)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    process = subprocess.Popen(
        [sys.executable, "-c", "import sys;sys.stdin.buffer.read()"],
        stdin=subprocess.PIPE,
    )
    try:
        import os

        observed = {"parent": identity(os.getpid()), "worker": identity(process.pid)}
        marker = {"launched_monotonic_ns": time.monotonic_ns()}
        endpoint = f"http://127.0.0.1:{server.server_port}"
        wait_native_health(endpoint, observed, marker, 5)
        assert paths == ["/health"]
        with pytest.raises(TimeoutError, match="original readiness deadline"):
            wait_native_health(
                endpoint,
                observed,
                {"launched_monotonic_ns": time.monotonic_ns() - 10_000_000_000},
                5,
            )
        assert paths == ["/health"]
    finally:
        process.stdin.close()
        process.wait(timeout=5)
        server.shutdown()
        server.server_close()
        thread.join()


def test_native_ticket_cannot_renew_deadline_or_be_consumed_twice(tmp_path):
    from dataclasses import replace

    from experiments.formal_campaign import h3_native_verifier as verifier

    report = tmp_path / "actual-owned-report.json"
    report.write_bytes(b"owned report bytes")
    now = time.monotonic_ns()
    owner = object()
    proof = verifier.VerifiedNativeRequest(
        "original/request-00000",
        "runtime",
        "transaction",
        "plan",
        "launch",
        "prefix",
        now,
        verifier.native.sha(b"body"),
        now,
        now + 10_000_000_000,
        str(report),
        verifier.native.sha(report.read_bytes()),
        b"full archive",
        owner,
    )
    consumer = verifier.NativeEpochVerifier.__new__(verifier.NativeEpochVerifier)
    consumer._owner = owner
    consumer._issued = {id(proof): proof}
    consumer._consume_lock = threading.Lock()
    consumer._current = lambda: None
    arguments = {"request_id": proof.request_id, "response_body": b"body"}
    with pytest.raises(ValueError, match="forged, replayed"):
        consumer.consume(proof, **arguments, deadline_ns=proof.original_deadline_ns + 1)
    with pytest.raises(ValueError, match="forged, replayed"):
        consumer.consume(
            replace(proof), **arguments, deadline_ns=proof.original_deadline_ns
        )
    assert (
        consumer.consume(proof, **arguments, deadline_ns=proof.original_deadline_ns)
        is proof
    )
    assert verifier.require_verified_native_request(proof) is proof
    with pytest.raises(ValueError, match="forged, replayed"):
        consumer.consume(proof, **arguments, deadline_ns=proof.original_deadline_ns)
