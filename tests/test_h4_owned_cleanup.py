"""The owned H4 wrapper receives TERM before its fresh child session."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = Path(os.environ.get("ECPA_H4_TEST_BASE", str(ROOT)))


def test_wrapper_gets_snapshot_before_child_exit(tmp_path, monkeypatch):
    monkeypatch.syspath_prepend(str(BASE))
    import experiments.formal_campaign as package

    mirror = ROOT / "experiments/formal_campaign"
    monkeypatch.setattr(package, "__path__", [str(mirror), *package.__path__])
    monkeypatch.syspath_prepend(str(mirror))
    spec = importlib.util.spec_from_file_location(
        "owned_h4_runner_cleanup", mirror / "run_h4.py"
    )
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    from experiments.formal_campaign.h4_owned_resources import OwnedTreeResourceSampler

    marker = tmp_path / "real-snapshot.json"
    code = """import signal,subprocess,sys,json
p=subprocess.Popen([sys.executable,'-c','import sys;sys.stdin.buffer.read()'],
                   stdin=subprocess.PIPE,start_new_session=True)
def done(*_):
    value={'child_alive_at_snapshot':p.poll() is None}
    open(sys.argv[1],'w').write(json.dumps(value))
    p.stdin.close(); p.wait(timeout=5); raise SystemExit(0)
signal.signal(signal.SIGTERM,done)
print('ready',flush=True); sys.stdin.buffer.read()
"""
    process = subprocess.Popen(
        [sys.executable, "-c", code, str(marker)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        assert process.stdout.readline().strip() == b"ready"
        sampler = OwnedTreeResourceSampler(
            process.pid, None, archive=tmp_path / "raw.json"
        )
        sampler.start()
        time.sleep(0.02)
        sampler.finish()
        result = runner.terminate_source_owned(process, sampler, tmp_path)
        assert process.returncode == 0
        assert json.loads(marker.read_bytes())["child_alive_at_snapshot"] is True
        assert result["remaining_exact_epochs"] == []
        assert result["signals"] == [
            {"kernel": sampler.root, "signal": "SIGTERM", "sent": True}
        ]
    finally:
        process.stdin.close()
        process.wait(timeout=5)
