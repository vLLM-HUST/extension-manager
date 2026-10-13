"""Real CPU child-process fixture; this is never Host/model evidence."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path


def fields(pid):
    return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()


if "--worker" in sys.argv:
    pid = int(os.environ.get("FIXTURE_OUTSIDE_PID", os.getpid()))
    ticks = int(fields(pid)[19])
    if "--stale" in sys.argv:
        ticks -= 1
    row = {
        "schema": "cpu-fixture-worker/v1",
        "launch_id": os.environ["VLLM_ECPA_LAUNCH_ID"],
        "plan_id": os.environ["VLLM_ECPA_PLAN_ID"],
        "observed_at_ns": time.time_ns(),
        "process": {
            "pid": pid,
            "start_ticks": ticks,
            "ordinal": 0,
            "process_epoch": int(os.environ.get("FIXTURE_EPOCH", pid)),
        },
    }
    target = Path(os.environ["VLLM_HUST_EXT_EVIDENCE_PATH"])
    temp = target.with_suffix(".tmp")
    temp.write_text(json.dumps(row) + "\n")
    temp.replace(target)
    time.sleep(60)
else:
    process = subprocess.Popen(
        [sys.executable, __file__, "--worker", *sys.argv[1:]],
        start_new_session="--nested" in sys.argv,
    )
    process.wait()
