"""SOURCE-ONLY tests: actual CPU TCP kernel witness, never native qualification."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from experiments.formal_campaign import h4_sampled_health as health
from experiments.formal_campaign.h3_worker_relaunch import identity

SERVER = r"""
import sys,time,threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
mode=sys.argv[1]
class Handler(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*a): pass
    def do_GET(self):
        if mode=='headers-drip':
            self.wfile.write(b'HTTP/1.1 200 OK\r\nX-Drip: ');self.wfile.flush()
            while True:
                self.wfile.write(b'x');self.wfile.flush();time.sleep(.02)
        elif mode=='close-framed-drip':
            self.send_response(200);self.send_header('Connection','close');self.end_headers()
            self.wfile.write(b'x');self.wfile.flush();print('body-started',flush=True)
            while True:
                self.wfile.write(b'x');self.wfile.flush();time.sleep(.02)
        elif mode=='body-drip':
            self.send_response(200);self.send_header('Content-Length','4096');self.end_headers()
            while True:
                self.wfile.write(b'x');self.wfile.flush();time.sleep(.02)
        else:
            self.send_response(200);self.send_header('Content-Length','2')
            self.send_header('Connection','close');self.end_headers()
            self.wfile.write(b'{}');self.wfile.flush()
server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
print(server.server_port,flush=True)
threading.Thread(target=server.serve_forever,daemon=True).start()
sys.stdin.readline();server.shutdown();server.server_close()
"""


@pytest.fixture
def actual_server(tmp_path):
    children, observers = [], []

    def start(mode="normal", timeout=2):
        run = tmp_path / f"run-{len(children)}"
        run.mkdir(mode=0o700)
        before, mono = health.raw_ns(), time.monotonic_ns()
        child = subprocess.Popen(
            [sys.executable, "-c", SERVER, mode],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        after = health.raw_ns()
        children.append(child)
        owner = identity(child.pid)
        port = int(child.stdout.readline().strip())
        timing = dict(
            schema="ecpa-h4-sampled-real-product-popen/v1",
            clock="CLOCK_MONOTONIC_RAW",
            before_ns=before,
            after_ns=after,
            before_monotonic_ns=mono,
            actual_kernel=owner,
            argv=[sys.executable, "-c", SERVER, mode],
        )
        timing_path = run / "phase0.product-popen-timing.json"
        timing_path.write_text(json.dumps(timing))
        url = f"http://127.0.0.1:{port}/health"
        observer = health.HealthObserver(run, url, timeout, owner, timing_path)
        observers.append(observer)
        observer.start()
        observer.fixture_process = child
        # Host7-shaped CPU peer only tests join mechanics; there is no original
        # native report, Plan admission or formal-start claim in this fixture.
        api = dict(
            host="vllm",
            pid=owner["pid"],
            start_identity=f"pid:{owner['pid']}:start_ticks:{owner['start_ticks']}",
            process_epoch="CPU-FIXTURE-NOT-FORMAL",
            role="api-server",
            ordinal=0,
            assignment_source="host",
        )
        epoch = dict(roster={"api-server/0": api}, kernels={"api-server/0": owner})
        return run, url, timeout, timing, observer, epoch

    yield start
    for observer in observers:
        observer.finish(cancel=True)
    for child in children:
        if child.poll() is None:
            child.stdin.write("stop\n")
            child.stdin.flush()
            child.wait(timeout=5)


def rewrite_peer_exit_fixture(run, *, mutation=None):
    # Explicit synthetic interrupted source record layered on a real CPU TCP
    # observation. No claim that this CPU server actually exited or is native.
    events = [
        json.loads(line)
        for line in (run / "health-probes.jsonl").read_bytes().splitlines()
    ]
    row = next(value for value in events if value.get("response") is not None)
    row["accepted_peer_terminal"] = dict(
        kind="accepted-peer-stat-ENOENT",
        accepted_peer=copy.deepcopy(row["accepted"]["kernel"]),
        boot_id=row["accepted"]["kernel"]["boot_id"],
        stat_raw=None,
        before_raw_ns=row["received_raw_ns"] + 1,
        after_raw_ns=row["received_raw_ns"] + 1,
        before_monotonic_ns=row["received_monotonic_ns"] + 1,
        after_monotonic_ns=row["received_monotonic_ns"] + 1,
    )
    row["error"] = dict(
        type=health.__name__ + ".HealthAcceptedPeerExited",
        message="synthetic parser fixture",
    )
    row["after"] = None
    if mutation == "peer":
        row["accepted_peer_terminal"]["accepted_peer"]["start_ticks"] += 1
    if mutation == "boot":
        row["accepted_peer_terminal"]["boot_id"] = "wrong-boot"
    if mutation == "body":
        row["response"]["body_sha256"] = "sha256:" + "0" * 64
    if mutation == "before":
        row["before_attempts"][-1]["sha256"] = "0" * 64
    if mutation == "after":
        row["after"] = copy.deepcopy(row["before"])
    previous = "0" * 64
    for value in events:
        value["previous_sha256"] = previous
        value.pop("event_sha256", None)
        value["event_sha256"] = hashlib.sha256(health.canonical(value)).hexdigest()
        previous = value["event_sha256"]
    journal = run / "health-probes.jsonl"
    journal.write_bytes(b"".join(health.canonical(value) + b"\n" for value in events))
    path = run / "health-probe-terminal.json"
    terminal = json.loads(path.read_bytes())
    terminal.update(
        reason="accepted-peer-exited",
        first_success_sequence=None,
        last_event_sha256=previous,
        original_journal=dict(
            path=str(journal), sha256=hashlib.sha256(journal.read_bytes()).hexdigest()
        ),
    )
    path.write_bytes(health.canonical(terminal))


@pytest.mark.parametrize(
    "mutation", [None, "peer", "boot", "body", "before", "after", "epoch"]
)
def test_accepted_peer_exit_is_unknown_and_does_not_excuse_any_present_corruption(
    actual_server, mutation
):
    run, url, timeout, timing, observer, epoch = actual_server()
    observer.finish()
    rewrite_peer_exit_fixture(run, mutation=mutation)
    if mutation == "epoch":
        epoch = copy.deepcopy(epoch)
        epoch["kernels"]["api-server/0"]["start_ticks"] += 1
    if mutation is None:
        replay = health.verify_health(
            run, url, timeout, timing, epoch=epoch, require_terminal=True
        )
        assert (
            replay["first_health"] is None
            and replay["API_epoch_status"] == "unknown-accepted-peer-exited"
        )
        assert replay["requires_authenticated_runtime_failure"] is True
        assert replay["completion_status"] == "accepted-peer-exited"
        assert replay["owner_exit_observations"] == []
        assert len(replay["accepted_peer_exit_observations"]) == 1
    else:
        with pytest.raises(ValueError):
            health.verify_health(
                run, url, timeout, timing, epoch=epoch, require_terminal=True
            )


@pytest.mark.parametrize("mode", ["missing", "zombie", "reuse", "boot"])
def test_accepted_peer_physical_exit_check_does_not_reclassify_kernel_replacement(
    monkeypatch, mode
):
    original_reader = Path.read_text
    stat_path = Path(f"/proc/{os.getpid()}/stat")
    raw = original_reader(stat_path)
    boot = original_reader(Path("/proc/sys/kernel/random/boot_id")).strip()
    expected = health.kernel(raw, boot)
    prefix, rest = raw.rsplit(")", 1)
    fields = rest.split()
    if mode == "zombie":
        fields[0] = "Z"
    if mode == "reuse":
        fields[19] = str(int(fields[19]) + 1)

    def observed(path, *args, **kwargs):
        if path == stat_path:
            if mode == "missing":
                raise FileNotFoundError(str(path))
            return prefix + ") " + " ".join(fields)
        if mode == "boot" and str(path) == "/proc/sys/kernel/random/boot_id":
            return "wrong-boot"
        return original_reader(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", observed)
    if mode in {"missing", "zombie"}:
        with pytest.raises(health.HealthAcceptedPeerExited) as error:
            health.observe_accepted_peer(expected)
        assert error.value.observation["accepted_peer"] == expected
        assert "owner" not in error.value.observation
    else:
        with pytest.raises(health.HealthEvidenceError):
            health.observe_accepted_peer(expected)


@pytest.mark.parametrize("mutation", [None, "missing-peer", "reused-peer"])
def test_independent_root_must_have_observed_exact_accepted_child_separate_from_owner(
    tmp_path, mutation
):
    from experiments.formal_campaign.h4_sampled_intake import bind_health_owner_exit

    owner = dict(pid=100, start_ticks=10, session=100, boot_id="CPU-ONLY")
    peer = dict(pid=200, start_ticks=20, session=100, boot_id="CPU-ONLY")
    terminal = tmp_path / "npu.json"
    terminal.write_text(json.dumps(dict(observed_monotonic_raw_ns=100)))
    root = dict(
        released=True,
        product_root=owner,
        all_observed_epochs=[
            dict(owner, ppid=1, state="S"),
            dict(peer, ppid=100, state="S"),
        ],
        terminal_npu_observation=dict(
            path=str(terminal), sha256=hashlib.sha256(terminal.read_bytes()).hexdigest()
        ),
    )
    readiness = dict(
        requires_authenticated_runtime_failure=True,
        first_health=None,
        product_owner=owner,
        owner_exit_observations=[],
        accepted_peer_exit_observations=[
            dict(accepted_peer=peer, before_raw_ns=30, after_raw_ns=40)
        ],
    )
    if mutation == "missing-peer":
        root["all_observed_epochs"].pop()
    if mutation == "reused-peer":
        root["all_observed_epochs"][1]["start_ticks"] += 1
    if mutation is None:
        bind_health_owner_exit(
            readiness,
            dict(kind="synthetic-helper-only"),
            root,
            dict(owner=owner, after_ns=10),
        )
    else:
        with pytest.raises(ValueError):
            bind_health_owner_exit(
                readiness,
                dict(kind="synthetic-helper-only"),
                root,
                dict(owner=owner, after_ns=10),
            )


def test_normal_complete_peer_keeps_original_strict_positive_flow(actual_server):
    run, url, timeout, timing, observer, epoch = actual_server()
    observer.finish()
    value = health.verify_health(
        run, url, timeout, timing, epoch=epoch, require_terminal=True
    )
    assert value["first_health"] is not None
    assert not value["requires_authenticated_runtime_failure"]
    assert value["accepted_peer_exit_observations"] == []
