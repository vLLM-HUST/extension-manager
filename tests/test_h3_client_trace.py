"""Real CPU HTTP continuous traffic, stopped backend and raw-trace rejection."""

from __future__ import annotations

import copy
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

from experiments.formal_campaign.h3_client_trace import (
    canonical,
    read_client_trace,
    sha,
    verify_window,
)
from experiments.formal_campaign.h3_phase_barrier import identity

ROOT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_file(path: Path, process: subprocess.Popen) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        assert process.poll() is None
        if path.exists():
            return
        time.sleep(0.01)
    raise TimeoutError(str(path))


def rechain(path: Path, events: list[dict]) -> None:
    previous = "sha256:" + "0" * 64
    lines = []
    for index, event in enumerate(events, 1):
        event.update(sequence=index, previous_sha256=previous)
        line = canonical(event)
        previous = sha(line)
        lines.append(line + b"\n")
    path.write_bytes(b"".join(lines))
    path.chmod(0o600)


def test_real_continuous_http_stop_resume_backend_and_unknown_execution(tmp_path: Path):
    env = os.environ | {"PYTHONPATH": str(ROOT / "src") + ":" + str(ROOT)}
    backend_port, authority_port = free_port(), free_port()
    registration_sha = "sha256:" + "a" * 64
    start_id = "nonformal-cpu-continuous-window"
    binding = tmp_path / "binding.json"
    binding.write_text(
        json.dumps({"launch_id": start_id, "registration_sha256": registration_sha})
    )
    backend_ready = tmp_path / "backend.ready"
    children = []
    with (tmp_path / "processes.log").open("wb") as log:
        try:
            backend = subprocess.Popen(
                [
                    sys.executable,
                    str(ROOT / "tests/fixtures/h3_window_backend.py"),
                    "--port",
                    str(backend_port),
                    "--ready",
                    str(backend_ready),
                ],
                env=env,
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
            children.append(backend)
            wait_file(backend_ready, backend)
            registry = {
                str(backend_port): {
                    "process_identity": {
                        k: identity(backend.pid)[k]
                        for k in ("pid", "start_ticks", "boot_id")
                    },
                    "generation": 0,
                    "model": "test-model",
                    "launch_id": "cpu-backend-epoch-1",
                }
            }
            registry_path = tmp_path / "backend-registration.json"
            registry_path.write_text(json.dumps(registry))
            authority_journal = tmp_path / "authority.jsonl"
            authority_socket = tmp_path / "authority.sock"
            authority = subprocess.Popen(
                [
                    sys.executable,
                    str(ROOT / "experiments/exposure_gate/loopback_traffic.py"),
                    "--socket",
                    str(authority_socket),
                    "--journal",
                    str(authority_journal),
                    "--listen-port",
                    str(authority_port),
                    "--predecessor-port",
                    str(backend_port),
                    "--candidate-port",
                    str(backend_port),
                    "--predecessor-snapshot",
                    '{"generation":0}',
                    "--grant-holder",
                    start_id,
                    "--grant-token",
                    "1",
                    "--grant-expires-at",
                    str(int(time.time()) + 60),
                    "--recovery-binding",
                    str(binding),
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
                "request_count": 60,
                "interval_s": 0.02,
                "timeout_s": 0.08,
                "dispatch_slack_s": 0.15,
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
                    k: identity(authority.pid)[k]
                    for k in ("pid", "start_ticks", "boot_id")
                },
                "backend_registration": registry,
            }
            spec_path = tmp_path / "spec.json"
            spec_path.write_bytes(canonical(spec))
            client_trace = tmp_path / "client.jsonl"
            client_ready = tmp_path / "client.ready"
            client = subprocess.Popen(
                [
                    sys.executable,
                    str(ROOT / "experiments/formal_campaign/h3_client_trace.py"),
                    "--spec",
                    str(spec_path),
                    "--trace",
                    str(client_trace),
                    "--ready",
                    str(client_ready),
                ],
                env=env,
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
            children.append(client)
            wait_file(client_ready, client)
            owner = json.loads(client_ready.read_text())["client"]
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                events = read_client_trace(client_trace)
                if sum(e["kind"] == "request.finish" for e in events) >= 5:
                    break
                time.sleep(0.01)
            else:
                raise TimeoutError("no pre-fault successful client traffic")
            fault_ns = time.monotonic_ns()
            os.kill(backend.pid, signal.SIGSTOP)
            time.sleep(0.25)
            os.kill(backend.pid, signal.SIGCONT)
            recovery_ns = time.monotonic_ns()
            client.wait(timeout=10)
            assert client.returncode == 0
            time.sleep(
                0.1
            )  # bounded drain of timeout attempts at the independent proxy
            kwargs = {
                "expected_client": owner,
                "fault_ns": fault_ns,
                "recovery_ns": recovery_ns,
            }
            result = verify_window(spec, client_trace, authority_journal, **kwargs)
            assert result["coverage"] == "complete-finite-delivery-window"
            assert 0 < result["lost_requests"] < spec["request_count"]
            assert result["duplicated_requests"] is None
            assert result["reused_successful_response_ids"] == 0
            assert result["backend_execution_duplicates"] is None
            assert (
                result["backend_generation_coverage"]
                == "frozen-live-process-and-response-bound"
            )
            assert result["formal_result"] is False
            (tmp_path / "verification.json").write_bytes(canonical(result))
            (tmp_path / "fault-markers.json").write_bytes(canonical(kwargs))
            original = read_client_trace(client_trace)
            incomplete = tmp_path / "incomplete.jsonl"
            rechain(incomplete, copy.deepcopy(original[:-1]))
            assert (
                verify_window(spec, incomplete, authority_journal, **kwargs)[
                    "lost_requests"
                ]
                is None
            )
            changed = copy.deepcopy(spec)
            changed["timeout_s"] = 2
            with pytest.raises(ValueError, match="frozen/start/process"):
                verify_window(changed, client_trace, authority_journal, **kwargs)
            changed = copy.deepcopy(original)
            served = next(
                e
                for e in changed
                if e["kind"] == "request.finish" and e["detail"]["status"] == 200
            )
            served["detail"]["admission_id"] = "replayed-admission"
            fake = tmp_path / "fake.jsonl"
            rechain(fake, changed)
            with pytest.raises(ValueError, match="unique authority"):
                verify_window(spec, fake, authority_journal, **kwargs)
            changed = copy.deepcopy(spec)
            changed["backend_registration"][str(backend_port)]["generation"] = 1
            with pytest.raises(ValueError):
                verify_window(changed, client_trace, authority_journal, **kwargs)
        finally:
            for process in reversed(children):
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGCONT)
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
