"""External HTTP requests observe the separately owned route transition."""

from __future__ import annotations

import json
import os
import select
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from experiments.exposure_gate.loopback_traffic import (
    LoopbackTrafficAdapter,
    _Authority,
    _ProxyHandler,
    _ProxyServer,
    _TrafficJournal,
    read_traffic_journal,
)
from vllm_hust_ext.exposure_gate import (
    GateError,
    LeaseGrant,
    OpenProof,
    ReferenceExposureGate,
    RollbackClass,
    RouteState,
)

PREDECESSOR = {"generation": 0, "plan_id": "old", "rendered_inputs": {"route": "old"}}


class _BackendHandler(BaseHTTPRequestHandler):
    server: _BackendServer

    def do_GET(self) -> None:
        payload = self.server.label.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, _format: str, *_args: object) -> None:
        pass


class _BackendServer(ThreadingHTTPServer):
    def __init__(self, label: str):
        super().__init__(("127.0.0.1", 0), _BackendHandler)
        self.label = label


def _get(port: int) -> str:
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as response:
        return response.read().decode()


def test_external_requests_follow_gate_open_and_rollback(tmp_path: Path) -> None:
    predecessor = _BackendServer("old")
    candidate = _BackendServer("new")
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True)
        for server in (predecessor, candidate)
    ]
    for thread in threads:
        thread.start()
    grant = LeaseGrant("gate-test", 7, int(time.time()) + 60)
    socket_path = tmp_path / "authority.sock"
    journal_path = tmp_path / "authority.jsonl"
    environment = {**os.environ, "PYTHONPATH": "src"}
    command = [
        sys.executable,
        "-m",
        "experiments.exposure_gate.loopback_traffic",
        "--socket",
        str(socket_path),
        "--journal",
        str(journal_path),
        "--predecessor-port",
        str(predecessor.server_port),
        "--candidate-port",
        str(candidate.server_port),
        "--predecessor-snapshot",
        json.dumps(PREDECESSOR),
        "--grant-holder",
        grant.holder,
        "--grant-token",
        str(grant.fencing_token),
        "--grant-expires-at",
        str(grant.expires_at),
    ]
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    port: int | None = None
    try:
        assert process.stdout is not None
        ready, _, _ = select.select([process.stdout], [], [], 10)
        assert ready, "traffic authority did not become ready"
        port = json.loads(process.stdout.readline())["port"]
        adapter = LoopbackTrafficAdapter(socket_path, grant)
        gate = ReferenceExposureGate(tmp_path / "gate.db", adapter, clock=time.time)
        assert _get(port) == "old"
        assert gate.stage({"plan_id": "candidate"}, PREDECESSOR) == 1
        gate.close(1)
        assert _get(port) == "old"

        with pytest.raises(GateError, match="lease"):
            adapter.open(
                1,
                "gate-1-invalid",
                {"plan_id": "candidate"},
                LeaseGrant("wrong", 8, grant.expires_at),
                int(time.time()),
            )
        assert _get(port) == "old"

        proof = OpenProof(
            "candidate",
            1,
            1,
            "sha256:" + "1" * 64,
            "sha256:" + "2" * 64,
            grant,
            gate._row()["candidate_digest"],
        )
        gate.open(1, proof)
        assert _get(port) == "new"
        assert gate.rollback(1) is RollbackClass.RESTORED_STRONG
        assert _get(port) == "old"
        adapter.close_all()
        with pytest.raises(urllib.error.HTTPError) as closed:
            _get(port)
        assert closed.value.code == 503
        gate.close_store()
    finally:
        process.terminate()
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
        assert process.poll() is not None
        if port is not None:
            with pytest.raises(urllib.error.URLError):
                _get(port)
        assert _get(predecessor.server_port) == "old"
        assert _get(candidate.server_port) == "new"
        for server in (predecessor, candidate):
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)
    assert not socket_path.exists()
    events = read_traffic_journal(journal_path)
    assert events[0]["kind"] == "authority.start"
    assert events[-1]["kind"] == "authority.stop"
    assert {event["proxy_pid"] for event in events} == {process.pid}
    assert len({event["proxy_start_ticks"] for event in events}) == 1
    assert [
        event["route"]["generation"]
        for event in events
        if event["kind"] == "request.admit"
    ] == [0, 0, 0, 1, 0]
    assert [
        event["route"]["generation"]
        for event in events
        if event["kind"] == "request.reject"
    ] == [None]
    assert [
        event["kind"] for event in events if event["kind"].startswith("route.")
    ] == [
        "route.close_checked",
        "route.open.intent",
        "route.open.applied",
        "route.restore.intent",
        "route.restore.applied",
        "route.close_all",
    ]


def test_journal_rejects_reordering_and_open_failure_closes_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = _TrafficJournal(tmp_path / "authority.jsonl")
    grant = LeaseGrant("gate-test", 7, int(time.time()) + 60)
    route = RouteState(0, "fence-0", PREDECESSOR)
    authority = _Authority(route, grant, ("127.0.0.1", 1), ("127.0.0.1", 2), journal)
    original_record = journal.record

    def fail_open_receipt(kind: str, state: RouteState, **detail: object) -> None:
        if kind == "route.open.applied":
            raise OSError("injected journal failure")
        original_record(kind, state, **detail)

    monkeypatch.setattr(journal, "record", fail_open_receipt)
    with pytest.raises(GateError, match="failed closed"):
        authority.apply(
            {
                "operation": "open",
                "generation": 1,
                "fence": "gate-1-test",
                "snapshot": {"plan_id": "candidate"},
                "grant": grant.__dict__,
                "now": int(time.time()),
            }
        )
    assert authority.route.generation is None
    journal.close()
    events = read_traffic_journal(tmp_path / "authority.jsonl")
    assert [event["kind"] for event in events] == [
        "authority.start",
        "route.open.intent",
    ]
    tampered = tmp_path / "tampered.jsonl"
    tampered.write_bytes(
        (tmp_path / "authority.jsonl")
        .read_bytes()
        .replace(b'"sequence":2', b'"sequence":9')
    )
    tampered.chmod(0o600)
    with pytest.raises(GateError, match="sequence"):
        read_traffic_journal(tampered)
    link = tmp_path / "linked.jsonl"
    link.symlink_to(tmp_path / "authority.jsonl")
    with pytest.raises(GateError, match="opened safely"):
        read_traffic_journal(link)


def test_journal_loss_rejects_external_request_and_closes_route(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    journal = _TrafficJournal(tmp_path / "authority.jsonl")
    grant = LeaseGrant("gate-test", 7, int(time.time()) + 60)
    authority = _Authority(
        RouteState(0, "fence-0", PREDECESSOR),
        grant,
        ("127.0.0.1", 1),
        ("127.0.0.1", 2),
        journal,
    )
    server = _ProxyServer(authority)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    original_record = journal.record

    def fail_admission(kind: str, state: RouteState, **detail: object) -> None:
        if kind == "request.admit":
            raise OSError("injected journal loss")
        original_record(kind, state, **detail)

    monkeypatch.setattr(journal, "record", fail_admission)
    try:
        with pytest.raises(urllib.error.HTTPError) as rejected:
            _get(server.server_port)
        assert rejected.value.code == 503
        assert authority.route.generation is None
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        journal.close()
    assert [
        event["kind"] for event in read_traffic_journal(tmp_path / "authority.jsonl")
    ] == ["authority.start"]


def test_observer_exception_cannot_open_and_query_fails_closed(tmp_path: Path) -> None:
    class BrokenObserver:
        def authorize(self, _snapshot: dict[str, object]) -> str:
            raise RuntimeError("observer unavailable")

        def binding(self) -> dict[str, object]:
            return {}

    journal = _TrafficJournal(tmp_path / "authority.jsonl")
    grant = LeaseGrant("gate-test", 7, int(time.time()) + 60)
    authority = _Authority(
        RouteState(0, "fence-0", PREDECESSOR),
        grant,
        ("127.0.0.1", 1),
        ("127.0.0.1", 2),
        journal,
        BrokenObserver(),  # type: ignore[arg-type]
    )
    with pytest.raises(GateError, match="host observation is unavailable"):
        authority.apply(
            {
                "operation": "open",
                "generation": 1,
                "fence": "gate-1-test",
                "snapshot": {"plan_id": "candidate"},
                "grant": grant.__dict__,
                "now": int(time.time()),
            }
        )
    assert authority.route.generation == 0

    authority.route = RouteState(1, "gate-1-test", {"plan_id": "candidate"})
    assert authority.apply({"operation": "query"})["route"]["generation"] is None
    journal.close()
    events = read_traffic_journal(tmp_path / "authority.jsonl")
    assert events[-1]["kind"] == "route.close_all"
    assert events[-1]["detail"]["reason"] == "host observation lost"


@pytest.mark.parametrize(
    "withdrawal", ["coverage", "close_all", "lease", "truncated", "none"]
)
def test_slow_post_rechecks_authority_after_complete_body(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, withdrawal: str
) -> None:
    """Real HTTP upload pauses before admission; withdrawal wins deterministically."""
    reading = threading.Event()
    received: list[bytes] = []
    coverage = threading.Event()
    coverage.set()

    class Observer:
        def authorize(self, _snapshot: dict[str, object]) -> str:
            if not coverage.is_set():
                raise GateError("coverage withdrawn")
            return "a" * 64

    class CandidateHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            received.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format: str, *_args: object) -> None:
            pass

    original_setup = _ProxyHandler.setup

    def observed_setup(handler: _ProxyHandler) -> None:
        original_setup(handler)
        stream = handler.rfile

        class ObservedReader:
            def read1(self, size: int) -> bytes:
                reading.set()
                return stream.read1(size)

            def read(self, size: int) -> bytes:
                reading.set()
                return stream.read(size)

            def __getattr__(self, name: str) -> object:
                return getattr(stream, name)

        handler.rfile = ObservedReader()  # type: ignore[assignment]

    monkeypatch.setattr(_ProxyHandler, "setup", observed_setup)
    candidate = ThreadingHTTPServer(("127.0.0.1", 0), CandidateHandler)
    journal_path = tmp_path / "authority.jsonl"
    journal = _TrafficJournal(journal_path)
    grant = LeaseGrant("slow-upload", 7, int(time.time()) + 60)
    authority = _Authority(
        RouteState(1, "gate-1-test", {"plan_id": "candidate"}),
        grant,
        ("127.0.0.1", 1),
        ("127.0.0.1", candidate.server_port),
        journal,
        Observer(),  # type: ignore[arg-type]
    )
    proxy = _ProxyServer(authority)
    servers = (candidate, proxy)
    threads = [
        threading.Thread(target=server.serve_forever, daemon=True) for server in servers
    ]
    for thread in threads:
        thread.start()
    try:
        address = ("127.0.0.1", proxy.server_port)
        with socket.create_connection(address, timeout=5) as client:
            client.sendall(
                b"POST /infer HTTP/1.0\r\nHost: localhost\r\n"
                b"Content-Length: 6\r\n\r\nabc"
            )
            assert reading.wait(5), "proxy never began receiving the partial body"
            if withdrawal == "coverage":
                coverage.clear()
            elif withdrawal == "close_all":
                authority.apply({"operation": "close_all"})
            elif withdrawal == "lease":
                with authority.lock:
                    authority.grant = LeaseGrant("slow-upload", 7, int(time.time()) - 1)
            if withdrawal == "truncated":
                client.shutdown(socket.SHUT_WR)
            else:
                client.sendall(b"def")
            response = bytearray()
            while chunk := client.recv(4096):
                response.extend(chunk)
            expected = {"truncated": b"400", "none": b"200"}.get(withdrawal, b"503")
            assert bytes(response).split(b" ", 2)[1] == expected
        expected_bodies = [b"abcdef"] if withdrawal == "none" else []
        assert received == expected_bodies
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=5)
        journal.close()
    events = read_traffic_journal(journal_path)
    admissions = [event for event in events if event["kind"] == "request.admit"]
    assert len(admissions) == (1 if withdrawal == "none" else 0)
    if withdrawal not in {"truncated", "none"}:
        assert events[-1]["kind"] == "request.reject"
