"""CPU protocol fixtures: no model, native proof, qualification or device claims."""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import types
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

from experiments.formal_campaign import h3_client_trace as trace
from experiments.formal_campaign import h3_native_http as native_http
from experiments.formal_campaign import h3_observer_live_http as live_http
from experiments.formal_campaign import h3_observer_loss as loss
from experiments.formal_campaign.h3_observer_authority import NativeAuthority
from vllm_hust_ext.exposure_gate import GateError


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def source_fixture(tmp_path, monkeypatch):
    spec = {
        "start_id": "fixture",
        "initial_enrollment_sha256": "fixture-enrollment",
        "payload": {"model": "no-model", "prompt": "unchanged"},
    }
    spec_path = tmp_path / "runtime-client-spec.json"
    spec_path.write_text(json.dumps(spec, indent=2) + "\n")
    owner = {"pid": 123, "start_ticks": 456, "boot_id": "fixture-only"}
    (tmp_path / "client-ready.json").write_text(json.dumps({"client": owner}))
    events = []
    previous = trace.ZERO
    for kind, detail in [
        (
            "client.start",
            {"start_id": "fixture", "spec_sha256": digest(trace.canonical(spec))},
        ),
        (
            "request.start",
            {
                "request_id": "fixture/request-00000",
                "body_base64": base64.b64encode(
                    trace.canonical(spec["payload"])
                ).decode(),
            },
        ),
    ]:
        event = {
            "schema": trace.SCHEMA,
            "sequence": len(events) + 1,
            "previous_sha256": previous,
            "monotonic_ns": 100 * (len(events) + 1),
            "client": owner,
            "kind": kind,
            "detail": detail,
        }
        events.append(event)
        previous = digest(trace.canonical(event))
    (tmp_path / "client.jsonl").write_bytes(
        b"".join(trace.canonical(e) + b"\n" for e in events)
    )

    class CheckedFixtureClient:
        # Isolate source lineage only; real process/socket checks have their own
        # original tests and are not inferred from this fixture.
        def __init__(self, kernel, path, *_):
            assert kernel == owner
            self.spec_path = Path(path)
            self.spec_raw = self.spec_path.read_bytes()
            self.spec = json.loads(self.spec_raw)

        def verify(self):
            if self.spec_path.read_bytes() != self.spec_raw:
                raise GateError("fixture spec bytes changed")

    monkeypatch.setattr(native_http, "BoundOriginalClient", CheckedFixtureClient)
    monkeypatch.setattr(loss.time, "monotonic_ns", lambda: 300)
    return spec, spec_path, owner


def barrier(tmp_path, owner):
    return loss.observe_original_client_barrier(
        output=tmp_path,
        client_kernel=owner,
        start_id="fixture",
        enrollment="fixture-enrollment",
    )


def replay(tmp_path, value, spec_path, owner, fault_ns=400):
    return loss.verify_first_request_prefix(
        tmp_path / "runner-pre-fault-client-prefix.bin",
        value,
        start_id="fixture",
        enrollment="fixture-enrollment",
        client_spec_path=spec_path,
        expected_client=owner,
        fault_ns=fault_ns,
    )


def test_formatted_spec_canonical_lineage_and_independent_raw_reference(
    tmp_path, monkeypatch
):
    _, path, owner = source_fixture(tmp_path, monkeypatch)
    value = barrier(tmp_path, owner)
    assert digest(path.read_bytes()) != digest(
        trace.canonical(json.loads(path.read_bytes()))
    )
    assert value["client_spec"] == {
        "path": str(path),
        "sha256": digest(path.read_bytes()),
    }
    assert replay(tmp_path, value, path, owner)


def test_legacy_barrier_keeps_canonical_value_contract(tmp_path, monkeypatch):
    _, path, owner = source_fixture(tmp_path, monkeypatch)
    value = barrier(tmp_path, owner)
    del value["client_spec"]
    assert replay(tmp_path, value, path, owner)


@pytest.mark.parametrize("mutation", ["semantic", "raw", "owner", "clock"])
def test_lineage_tampering_still_rejected(tmp_path, monkeypatch, mutation):
    spec, path, owner = source_fixture(tmp_path, monkeypatch)
    value = barrier(tmp_path, owner)
    if mutation == "semantic":
        spec["payload"]["prompt"] = "tampered"
        path.write_text(json.dumps(spec, indent=2) + "\n")
        value["client_spec"]["sha256"] = digest(path.read_bytes())
    elif mutation == "raw":
        path.write_text(json.dumps(spec) + "\n")
    elif mutation == "owner":
        owner = dict(owner, pid=124)
    with pytest.raises(GateError):
        replay(
            tmp_path, value, path, owner, fault_ns=250 if mutation == "clock" else 400
        )


@pytest.mark.parametrize(
    "handler", [native_http.NativeProxyHandler, live_http.LiveProxyHandler]
)
def test_actual_http_first_request_waits_for_validated_client_binding(handler):
    authority = NativeAuthority.__new__(NativeAuthority)
    authority.bound_client = None
    authority.lock = threading.Lock()
    waiting, ready = threading.Event(), threading.Event()
    errors, invoked = [], []

    class ObservedEvent:
        def wait(self, timeout):
            waiting.set()
            return ready.wait(timeout)

    authority._bound_client_ready = ObservedEvent()
    authority.route = None
    authority._record = lambda kind, route, **detail: errors.append((kind, detail))
    client = native_http.BoundOriginalClient.__new__(native_http.BoundOriginalClient)

    def checked_request(self, request_id, body, connection):
        invoked.append((request_id, body))
        raise GateError("CPU fixture stops before all native forwarding")

    client.request = types.MethodType(checked_request, client)
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.authority = authority
    serving = threading.Thread(target=server.serve_forever)
    serving.start()

    def request():
        with pytest.raises(urllib.error.HTTPError) as failure:
            urllib.request.urlopen(
                urllib.request.Request(
                    f"http://127.0.0.1:{server.server_port}/v1/completions",
                    data=b"{}",
                    headers={"X-ECPA-Request-ID": "fixture/request-00000"},
                ),
                timeout=3,
            )
        return failure.value.code

    try:
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(request)
            assert waiting.wait(1)
            assert not future.done() and not invoked
            with authority.lock:
                authority.bound_client = client
                ready.set()
            assert future.result(timeout=2) == 503
        assert invoked == [("fixture/request-00000", b"{}")]
        assert errors[0][1]["error"] == "CPU fixture stops before all native forwarding"
    finally:
        ready.set()
        server.shutdown()
        server.server_close()
        serving.join(timeout=2)
        assert not serving.is_alive()


def test_ready_flag_cannot_substitute_arbitrary_client_object():
    authority = NativeAuthority.__new__(NativeAuthority)
    authority.lock = threading.Lock()
    authority._bound_client_ready = threading.Event()
    authority._bound_client_ready.set()
    authority.bound_client = object()
    with pytest.raises(GateError, match="source-owned"):
        authority.original_client_for_request()
