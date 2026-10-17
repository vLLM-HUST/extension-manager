"""SOURCE-ONLY tests: actual CPU TCP kernel witness, never native qualification."""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import time

import pytest

from experiments.formal_campaign import h4_sampled_health as health
from experiments.formal_campaign.h3_worker_relaunch import identity

SERVER = r'''
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
'''


@pytest.fixture
def actual_server(tmp_path):
    children, observers = [], []
    def start(mode="normal", timeout=2):
        run = tmp_path / f"run-{len(children)}"
        run.mkdir(mode=0o700)
        before, mono = health.raw_ns(), time.monotonic_ns()
        child = subprocess.Popen([sys.executable, "-c", SERVER, mode], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        after = health.raw_ns()
        children.append(child)
        owner = identity(child.pid)
        port = int(child.stdout.readline().strip())
        timing = dict(schema="ecpa-h4-sampled-real-product-popen/v1", clock="CLOCK_MONOTONIC_RAW",
            before_ns=before, after_ns=after, before_monotonic_ns=mono,
            actual_kernel=owner, argv=[sys.executable, "-c", SERVER, mode])
        timing_path = run / "phase0.product-popen-timing.json"
        timing_path.write_text(json.dumps(timing))
        url = f"http://127.0.0.1:{port}/health"
        observer = health.HealthObserver(run, url, timeout, owner, timing_path)
        observers.append(observer)
        observer.start()
        # Host7-shaped CPU peer only tests join mechanics; there is no original
        # native report, Plan admission or formal-start claim in this fixture.
        api = dict(host="vllm", pid=owner["pid"], start_identity=f"pid:{owner['pid']}:start_ticks:{owner['start_ticks']}",
            process_epoch="CPU-FIXTURE-NOT-FORMAL", role="api-server", ordinal=0, assignment_source="host")
        epoch = dict(roster={"api-server/0": api}, kernels={"api-server/0": owner})
        return run, url, timeout, timing, observer, epoch
    yield start
    for observer in observers:
        observer.finish(cancel=True)
    for child in children:
        if child.poll() is None:
            child.stdin.write("stop\n"); child.stdin.flush()
            child.wait(timeout=5)


def test_actual_kernel_first_health_precedes_later_native_setup_without_releasing_it(actual_server):
    run, url, timeout, timing, observer, epoch = actual_server()
    # This is an independent clock regression, not a fake native setup predicate.
    observer.thread.join(timeout=2)
    assert not observer.thread.is_alive()
    later_native_setup_clock = health.raw_ns()
    observer.finish()
    replay = health.verify_health(run, url, timeout, timing, epoch=epoch, require_terminal=True)
    assert replay["first_health"]["observed_ns"] < later_native_setup_clock
    assert replay["first_health"]["actual_api_kernel4"] == epoch["kernels"]["api-server/0"]
    assert replay["first_health"]["actual_api_host7"] == epoch["roster"]["api-server/0"]
    assert replay["API_epoch_status"] == "verified"
    unknown = health.verify_health(run, url, timeout, timing, epoch=None, require_terminal=True)
    assert unknown["first_health"] is None
    assert unknown["API_epoch_status"] == "unknown-no-enrollment"


def rechain(run, events):
    previous = "0" * 64
    for sequence, event in enumerate(events):
        event.update(sequence=sequence, previous_sha256=previous)
        event.pop("event_sha256", None)
        event["event_sha256"] = hashlib.sha256(health.canonical(event)).hexdigest()
        previous = event["event_sha256"]
    journal = run / "health-probes.jsonl"
    journal.write_bytes(b"".join(health.canonical(e) + b"\n" for e in events))
    terminal_path = run / "health-probe-terminal.json"
    terminal = json.loads(terminal_path.read_bytes())
    terminal.update(last_event_sha256=previous, next_sequence=len(events),
        original_journal=dict(path=str(journal), sha256=hashlib.sha256(journal.read_bytes()).hexdigest()))
    terminal_path.write_bytes(health.canonical(terminal))


@pytest.mark.parametrize("mutation", ["api-epoch", "boot", "inode", "capture-hash", "first-sequence", "deadline", "source", "missing-after"])
def test_complete_health_never_accepts_wrong_raw_peer_clock_or_summary(actual_server, mutation):
    run, url, timeout, timing, observer, epoch = actual_server()
    observer.finish()
    events = [json.loads(x) for x in (run / "health-probes.jsonl").read_bytes().splitlines()]
    response = next(row for row in events if row.get("response") is not None)
    if mutation == "api-epoch":
        epoch = copy.deepcopy(epoch); epoch["kernels"]["api-server/0"]["start_ticks"] += 1
    elif mutation == "boot": events[0]["product_owner"]["boot_id"] = "other-boot"
    elif mutation == "inode": response["accepted"]["inode"] = "123456789"
    elif mutation == "capture-hash": response["before"]["sha256"] = "0" * 64
    elif mutation == "deadline": events[0]["deadline_ns"] += 1
    elif mutation == "source": events[0]["source_sha256"] = "0" * 64
    elif mutation == "missing-after": response["after"] = None
    rechain(run, events)
    if mutation == "first-sequence":
        p = run / "health-probe-terminal.json"; value = json.loads(p.read_bytes())
        value["first_success_sequence"] += 1; p.write_bytes(health.canonical(value))
    with pytest.raises(health.HealthEvidenceError):
        health.verify_health(run, url, timeout, timing, epoch=epoch, require_terminal=True)


@pytest.mark.parametrize("mode", ["headers-drip", "body-drip"])
def test_absolute_startup_deadline_interrupts_ongoing_io_and_never_mints_health(actual_server, mode):
    run, url, timeout, timing, observer, epoch = actual_server(mode, timeout=.6)
    observer.finish()
    result = health.verify_health(run, url, timeout, timing, epoch=epoch, require_terminal=True)
    assert result["first_health"] is None
    assert result["completion_status"] == "deadline"
    assert not observer.thread.is_alive() and not observer.watchdog.is_alive()
    rows = [json.loads(x) for x in (run / "health-probes.jsonl").read_bytes().splitlines()]
    assert rows[-1]["finished_monotonic_ns"] >= result["deadline_ns"]


def test_finally_cancels_only_owned_socket_and_joins_ongoing_body_read(actual_server):
    run, url, timeout, timing, observer, epoch = actual_server("body-drip", timeout=10)
    time.sleep(.1)
    before = time.monotonic()
    observer.finish(cancel=True)
    assert time.monotonic() - before < 5
    assert not observer.thread.is_alive() and not observer.watchdog.is_alive()
    result = health.verify_health(run, url, timeout, timing, epoch=epoch, require_terminal=True)
    assert result["first_health"] is None and result["completion_status"] == "cancelled"


def test_truncated_or_corrupted_journal_never_becomes_unknown_success(actual_server):
    run, url, timeout, timing, observer, epoch = actual_server()
    observer.finish()
    p = run / "health-probes.jsonl"; p.write_bytes(p.read_bytes()[:-1])
    with pytest.raises(health.HealthEvidenceError):
        health.verify_health(run, url, timeout, timing, epoch=epoch, require_terminal=False)


def test_first_observed_200_cannot_be_replaced_by_later_convenient_200(actual_server):
    run, url, timeout, timing, observer, epoch = actual_server()
    observer.finish()
    events = [json.loads(x) for x in (run / "health-probes.jsonl").read_bytes().splitlines()]
    first = next(row for row in events if (row.get("response") or {}).get("status_code") == 200)
    later = copy.deepcopy(first)
    # Even a rehashed, otherwise identical later success is forbidden: the
    # immutable source producer must stop at its first complete on-time200.
    events.append(later)
    rechain(run, events)
    with pytest.raises(health.HealthEvidenceError):
        health.verify_health(run, url, timeout, timing, epoch=epoch, require_terminal=True)
