"""SOURCE-ONLY tests: actual CPU TCP kernel witness, never native qualification."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import select
import os
import time
from pathlib import Path

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
        observer.fixture_process = child
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



def test_local_shutdown_of_close_framed_drip_is_not_remote_completion(actual_server):
    run, url, timeout, timing, observer, epoch = actual_server("close-framed-drip", timeout=10)
    ready, _, _ = select.select([observer.fixture_process.stdout], [], [], 5)
    assert ready, "CPU server never received actual original health request"
    assert observer.fixture_process.stdout.readline().strip() == "body-started"
    observer.finish(cancel=True)
    assert not observer.thread.is_alive() and not observer.watchdog.is_alive()
    replay = health.verify_health(run, url, timeout, timing, epoch=epoch, require_terminal=True)
    assert replay["first_health"] is None and replay["completion_status"] == "cancelled"
    assert any(item["actual_socket_present"] for item in replay["local_cancellations"])
    events = [json.loads(x) for x in (run / "health-probes.jsonl").read_bytes().splitlines()]
    probe = events[-1]
    assert not probe["response_complete"] and probe["response"] is None
    assert probe["interrupted_response"]["body_complete"] is False
    assert probe["local_cancel"]["monotonic_ns"] <= probe["received_monotonic_ns"]


def test_cancellation_after_actual_completion_does_not_erase_prior_health(actual_server):
    run, url, timeout, timing, observer, epoch = actual_server()
    observer.thread.join(timeout=3)
    assert not observer.thread.is_alive()
    observer.finish(cancel=True)
    replay = health.verify_health(run, url, timeout, timing, epoch=epoch, require_terminal=True)
    assert replay["first_health"] is not None
    assert replay["completion_status"] == "success"


@pytest.mark.parametrize("mode", ["missing", "zombie", "reuse", "boot"])
def test_only_exact_owner_absence_or_same_kernel_zombie_is_typed(monkeypatch, mode):
    original_reader = Path.read_text
    stat_path = Path(f"/proc/{os.getpid()}/stat")
    raw = original_reader(stat_path)
    boot = original_reader(Path("/proc/sys/kernel/random/boot_id")).strip()
    owner = health.kernel(raw, boot)
    prefix, rest = raw.rsplit(")", 1)
    fields = rest.split()
    if mode == "zombie": fields[0] = "Z"
    if mode == "reuse": fields[19] = str(int(fields[19]) + 1)
    changed = prefix + ") " + " ".join(fields)
    def observed(path, *args, **kwargs):
        if path == stat_path:
            if mode == "missing": raise FileNotFoundError(str(path))
            return changed
        if mode == "boot" and str(path) == "/proc/sys/kernel/random/boot_id": return "wrong-boot"
        return original_reader(path, *args, **kwargs)
    monkeypatch.setattr(Path, "read_text", observed)
    if mode in {"missing", "zombie"}:
        with pytest.raises(health.HealthOwnerExited) as error:
            health.observe_owner(owner)
        value = error.value.observation
        assert value["owner"] == owner and value["boot_id"] == boot
        assert value["before_monotonic_ns"] <= value["after_monotonic_ns"]
        assert value["kind"] == ("original-owner-stat-ENOENT" if mode == "missing" else "original-owner-zombie")
    else:
        with pytest.raises(health.HealthEvidenceError): health.observe_owner(owner)


@pytest.mark.parametrize("mutation", [None, "no-cause", "wrong-kernel", "wrong-root", "late-exit", "positive"])
def test_owner_loss_needs_original_cause_and_exact_independent_cleanup_join(tmp_path, mutation):
    # A helper-only synthetic join test; production calls the unchanged strict
    # runtime cause/root verifier first. This is not source/start qualification.
    from experiments.formal_campaign.h4_sampled_intake import bind_health_owner_exit
    owner = dict(pid=123, start_ticks=20, session=123, boot_id="CPU-ONLY")
    admission = dict(owner=owner, after_ns=10)
    terminal = tmp_path / "npu-raw.json"
    terminal.write_text(json.dumps(dict(observed_monotonic_raw_ns=100)))
    root = dict(released=True, product_root=owner,
        all_observed_epochs=[dict(owner, state="S", ppid=1)],
        terminal_npu_observation=dict(path=str(terminal), sha256=hashlib.sha256(terminal.read_bytes()).hexdigest()))
    readiness = dict(requires_authenticated_runtime_failure=True, first_health=None,
        product_owner=owner, owner_exit_observations=[dict(before_raw_ns=20, after_raw_ns=30)])
    cause = dict(kind="synthetic-helper-only")
    if mutation == "no-cause": cause = None
    if mutation == "wrong-kernel": root["all_observed_epochs"][0]["start_ticks"] += 1
    if mutation == "wrong-root": root["product_root"] = dict(owner, pid=999)
    if mutation == "late-exit": readiness["owner_exit_observations"][0]["after_raw_ns"] = 101
    if mutation == "positive": readiness["first_health"] = dict(status_code=200)
    if mutation is None: bind_health_owner_exit(readiness, cause, root, admission)
    else:
        with pytest.raises(ValueError): bind_health_owner_exit(readiness, cause, root, admission)


def test_typed_owner_exit_is_unknown_and_corrupt_existing_snapshot_still_rejects(actual_server, monkeypatch, tmp_path):
    run, url, timeout, timing, original, epoch = actual_server("body-drip", timeout=10)
    original.finish(cancel=True)
    # Explicit synthetic source exception, exercising parser/control plumbing;
    # no claim that the still-live CPU fixture actually exited.
    output = tmp_path / "typed-exit-fixture"
    output.mkdir(mode=0o700)
    timing_path = output / "phase0.product-popen-timing.json"
    timing_path.write_text(json.dumps(timing))
    owner = timing["actual_kernel"]
    def source_exit(expected):
        assert expected == owner
        before_raw, before_mono = health.raw_ns(), time.monotonic_ns()
        raise health.HealthOwnerExited(dict(kind="original-owner-stat-ENOENT", owner=owner,
            boot_id=owner["boot_id"], stat_raw=None, before_raw_ns=before_raw,
            before_monotonic_ns=before_mono, after_raw_ns=health.raw_ns(),
            after_monotonic_ns=time.monotonic_ns()))
    monkeypatch.setattr(health, "capture_tree", source_exit)
    observer = health.HealthObserver(output, url, timeout, owner, timing_path)
    observer.start()
    try:
        observer.finish()
        replay = health.verify_health(output, url, timeout, timing, epoch=epoch, require_terminal=True)
        assert replay["first_health"] is None
        assert replay["requires_authenticated_runtime_failure"] is True
        assert replay["completion_status"] == "owner-exited"
        assert replay["API_epoch_status"] == "unknown-owner-exited"
        # Rehashing an owner terminal with a different original kernel cannot
        # turn raw-integrity damage into an admitted runtime interruption.
        journal = output / "health-probes.jsonl"
        rows = [json.loads(line) for line in journal.read_bytes().splitlines()]
        rows[-1]["owner_terminal"]["owner"] = dict(owner, start_ticks=owner["start_ticks"] + 1)
        previous = "0" * 64
        for row in rows:
            row["previous_sha256"] = previous
            row.pop("event_sha256", None)
            row["event_sha256"] = hashlib.sha256(health.canonical(row)).hexdigest()
            previous = row["event_sha256"]
        journal.write_bytes(b"".join(health.canonical(row) + b"\n" for row in rows))
        with pytest.raises(health.HealthEvidenceError):
            health.verify_health(output, url, timeout, timing, epoch=epoch, require_terminal=True)
    finally:
        observer.finish(cancel=True)
