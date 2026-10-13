"""Real interface fixture shutdown classification, never formal qualification."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("shutdown", ["natural", "terminated"])
def test_real_fixture_retains_natural_exit_and_signal_termination(tmp_path, shutdown):
    env = dict(os.environ)
    env.pop("ECPA_FIXTURE_HANDSHAKE", None)
    child = subprocess.Popen(
        [sys.executable, str(ROOT / "tests/fixtures/formal_sut_service.py")],
        cwd=tmp_path,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        request = {
            "command": "shutdown" if shutdown == "natural" else "hold",
            "phase": "shutdown",
            "sequence": 1,
            "challenge": "exit-oracle",
            "plan_id": "interface-only-plan",
            "launch_id": "interface-only-launch",
            "controller_instance": "interface-only-controller",
            "invocation_id": "exit-only",
        }
        assert child.stdin and child.stdout
        child.stdin.write(json.dumps(request) + "\n")
        child.stdin.flush()
        ack = json.loads(child.stdout.readline())
        assert ack == {k: v for k, v in request.items() if k != "command"} | {
            "ack": True
        }
        if shutdown == "terminated":
            assert child.poll() is None
            child.terminate()
        child.wait(timeout=5)
        assert child.returncode == (0 if shutdown == "natural" else -signal.SIGTERM)
        assert not Path(f"/proc/{child.pid}").exists()
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate(timeout=5)
