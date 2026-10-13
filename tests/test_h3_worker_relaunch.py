from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from experiments.formal_campaign import h3_worker_relaunch as runner

FIXTURE = Path(__file__).parent / "fixtures/h3_worker_relaunch_fixture.py"


def campaign(tmp_path):
    return {
        "schema": "ecpa-h3-worker-relaunch-qualification/v1",
        "classification": "CPU_PREFLIGHT_ONLY",
        "formal_result": False,
        "original_manager_cell_completed": False,
        "recovery_action": "common-external-full-relaunch",
        "policy": {
            "signal": "SIGKILL",
            "relaunches": 1,
            "ready_timeout_s": 3,
            "exit_timeout_s": 3,
            "cleanup_timeout_s": 1,
            "probe_poll_s": 0.01,
            "request_timeout_s": 1,
        },
        "arms": [
            {
                "id": name,
                "activation_contract": contract,
                "argv": [sys.executable, str(FIXTURE)],
                "cwd": str(tmp_path),
                "env": {},
                "probe_command": [sys.executable, "-c", "print('CPU fixture only')"],
                "evidence_protocol": "cpu-fixture-worker/v1",
                "target_ordinal": 0,
                "plan_id": "cpu-plan",
                "sources": [
                    {"role": role, "path": str(FIXTURE), "sha256": runner.sha(FIXTURE)}
                    for role in ("launcher", "host", "mod")
                ],
                "phases": [
                    {
                        "launch_id": name + str(i),
                        "evidence_path": str(tmp_path / (name + str(i) + ".jsonl")),
                    }
                    for i in range(2)
                ],
            }
            for name, contract in runner.ARMS.items()
        ],
    }


@pytest.mark.parametrize("arm", runner.ARMS)
def test_actual_cpu_worker_kill_relaunch_and_cleanup(tmp_path, arm):
    c = campaign(tmp_path)
    result = runner.run_arm(c, arm, tmp_path / "out")
    assert result["passed"], result
    assert result["cleanup_errors"] == []
    targets = [e for e in result["events"] if e["kind"] == "worker-observed"]
    assert len(targets) == 2
    assert targets[0]["identity"] != targets[1]["identity"]
    assert targets[0]["process_epoch"] != targets[1]["process_epoch"]
    assert not any(runner.live(e["identity"]) for e in targets)
    assert result["formal_result"] is False
    assert result["original_manager_cell_completed"] is False
    assert result["lost_requests"] is None
    retained = json.loads((tmp_path / "out/result.json").read_text())
    assert retained == result


def test_stale_worker_epoch_never_receives_fault(tmp_path):
    c = campaign(tmp_path)
    c["arms"][0]["argv"].append("--stale")
    result = runner.run_arm(c, c["arms"][0]["id"], tmp_path / "out")
    assert not result["passed"]
    assert "outside owned launch epoch/session" in result["failure"]
    assert not any(e["kind"] == "signal-delivered" for e in result["events"])
    assert result["cleanup_errors"] == []


def test_unowned_process_is_never_signalled(tmp_path):
    outside = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True
    )
    owner = runner.identity(outside.pid)
    try:
        c = campaign(tmp_path)
        c["arms"][0]["env"]["FIXTURE_OUTSIDE_PID"] = str(outside.pid)
        result = runner.run_arm(c, c["arms"][0]["id"], tmp_path / "out")
        assert not result["passed"]
        assert "outside owned launch epoch/session" in result["failure"]
        assert runner.live(owner)
        assert result["cleanup_errors"] == []
    finally:
        outside.terminate()
        outside.wait(timeout=5)


@pytest.mark.parametrize(
    "mutation,match",
    [
        (lambda c: c.update(formal_result=True), "scope changed"),
        (lambda c: c["arms"].pop(), "all three"),
        (lambda c: c["policy"].update(relaunches=2), "one common"),
        (
            lambda c: c["arms"][0]["phases"][1].update(
                launch_id=c["arms"][0]["phases"][0]["launch_id"]
            ),
            "fresh launch",
        ),
        (
            lambda c: c["arms"][0].update(
                evidence_protocol="vllm-host-worker-event/v1"
            ),
            "fixture evidence",
        ),
        (lambda c: c["arms"][0]["sources"][0].update(sha256="0" * 64), "source bytes"),
    ],
)
def test_frozen_campaign_fails_closed(tmp_path, mutation, match):
    c = copy.deepcopy(campaign(tmp_path))
    mutation(c)
    with pytest.raises(ValueError, match=match):
        runner.validate(c)


def test_cpu_http_fixture_probe_retains_actual_completion_bytes(tmp_path):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            assert json.loads(body)["model"] == "cpu-http-fixture"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(
                json.dumps(
                    {
                        "model": "cpu-http-fixture",
                        "usage": {"completion_tokens": 1},
                        "choices": [{"message": {"content": "fixture only"}}],
                    }
                ).encode()
            )

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        runner.probe(
            {
                "probe": {
                    "url": f"http://127.0.0.1:{server.server_port}/",
                    "payload": {"model": "cpu-http-fixture"},
                },
                "request_timeout_s": 1,
                "probe_poll_s": 0.01,
            },
            "QUALIFIED_NONFORMAL",
            tmp_path,
            0,
            1,
        )
        attempts = json.loads((tmp_path / "phase0.probe-attempts.json").read_text())
        assert len(attempts) == 1 and attempts[0]["accepted"]
        assert json.loads((tmp_path / "phase0.response0.bin").read_bytes())[
            "model"
        ] == ("cpu-http-fixture")
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def test_relaunch_cannot_reuse_process_epoch(tmp_path):
    c = campaign(tmp_path)
    c["arms"][0]["env"]["FIXTURE_EPOCH"] = "17"
    result = runner.run_arm(c, c["arms"][0]["id"], tmp_path / "out")
    assert not result["passed"]
    assert "fresh worker identity/epoch" in result["failure"]
    assert result["cleanup_errors"] == []
    assert not any(
        runner.live(e["identity"])
        for e in result["events"]
        if e["kind"] == "worker-observed"
    )


def test_failed_probe_retains_raw_error_and_cleanup(tmp_path):
    c = campaign(tmp_path)
    c["arms"][0]["probe_command"] = [
        sys.executable,
        "-c",
        "import sys; print('failed fixture probe', file=sys.stderr); sys.exit(7)",
    ]
    result = runner.run_arm(c, c["arms"][0]["id"], tmp_path / "out")
    assert not result["passed"]
    assert result["cleanup_errors"] == []
    assert not any(e["kind"] == "signal-delivered" for e in result["events"])
    assert (tmp_path / "out/phase0.probe.status").read_text() == "7"
    assert (
        b"failed fixture probe" in (tmp_path / "out/phase0.probe.stderr").read_bytes()
    )


def test_supervisor_nested_session_is_owned_and_reclaimed(tmp_path):
    c = campaign(tmp_path)
    c["arms"][2]["argv"].append("--nested")
    result = runner.run_arm(c, "ecpa", tmp_path / "out")
    assert result["passed"], result
    targets = [e for e in result["events"] if e["kind"] == "worker-observed"]
    assert all(len(e["ownership_sessions"]) == 2 for e in targets)
    assert result["cleanup_errors"] == []
    assert not any(runner.live(s) for e in targets for s in e["ownership_sessions"])
